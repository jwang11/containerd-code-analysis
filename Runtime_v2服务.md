# Runtime_v2服务
> runtime_v2服务和shim_runc_v2垫层（独立进程）通信，做container的执行和管理。以创建容器为例，runtime_v2先启动shim_runc_v2垫层，然后垫层去执行go_runc包装层里的runc。因此，runtime_v2本质上是Container执行任务的管理器。

## 1. [Runtime_v2 Plugin](https://github.com/containerd/containerd/blob/main/runtime/v2/manager.go)
### 1.1 Plugin注册
RuntimePluginV2注册申请，InitFn返回TaskManager，也就是该plugin的instance

```diff
// Config for the v2 runtime
type Config struct {
	// Supported platforms
	Platforms []string `toml:"platforms"`
}

func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.RuntimePluginV2,
+		ID:   "task",
		Requires: []plugin.Type{
			plugin.EventPlugin,
			plugin.MetadataPlugin,
		},
		Config: &Config{
			Platforms: defaultPlatforms(),
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			supportedPlatforms, err := parsePlatforms(ic.Config.(*Config).Platforms)

			ic.Meta.Platforms = supportedPlatforms
			os.MkdirAll(ic.Root, 0711)
			os.MkdirAll(ic.State, 0711)
			m, err := ic.Get(plugin.MetadataPlugin)
			ep, err := ic.GetByID(plugin.EventPlugin, "exchange")
+			cs := metadata.NewContainerStore(m.(*metadata.DB))
			events := ep.(*exchange.Exchange)

+			return New(ic.Context, ic.Root, ic.State, ic.Address, ic.TTRPCAddress, events, cs)
		},
	})
}

// NewContainerStore returns a Store backed by an underlying bolt DB
func NewContainerStore(db *DB) containers.Store {
	return &containerStore{	
+		db: db,	// metadata.DB
	}
}
type containerStore struct {
	db *DB
}

// New task manager for v2 shims
func New(ctx context.Context, root, state, containerdAddress, containerdTTRPCAddress string, events *exchange.Exchange, cs containers.Store) (*TaskManager, error) {
	for _, d := range []string{root, state} {
		os.MkdirAll(d, 0711)
	}
	m := &TaskManager{
		root:                   root,
		state:                  state,
		containerdAddress:      containerdAddress,
		containerdTTRPCAddress: containerdTTRPCAddress,
+		tasks:                  runtime.NewTaskList(),
		events:                 events,
+		containers:             cs,
	}
	m.loadExistingTasks(ctx)
	return m, nil
}

// NewTaskList returns a new TaskList
func NewTaskList() *TaskList {
	return &TaskList{
		tasks: make(map[string]map[string]Task),
	}
}

// TaskList holds and provides locking around tasks
type TaskList struct {
	mu    sync.Mutex
	tasks map[string]map[string]Task
}


```

### 1.2 TaskList
```diff
// Get a task
func (l *TaskList) Get(ctx context.Context, id string) (Task, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	namespace, err := namespaces.NamespaceRequired(ctx)
	tasks, ok := l.tasks[namespace]
	t, ok := tasks[id]
	return t, nil
}

// GetAll tasks under a namespace
func (l *TaskList) GetAll(ctx context.Context, noNS bool) ([]Task, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var o []Task
	if noNS {
		for ns := range l.tasks {
			for _, t := range l.tasks[ns] {
				o = append(o, t)
			}
		}
		return o, nil
	}
	namespace, err := namespaces.NamespaceRequired(ctx)
	tasks, ok := l.tasks[namespace]
	for _, t := range tasks {
		o = append(o, t)
	}
	return o, nil
}

// Add a task
func (l *TaskList) Add(ctx context.Context, t Task) error {
	namespace, err := namespaces.NamespaceRequired(ctx)
	return l.AddWithNamespace(namespace, t)
}

// AddWithNamespace adds a task with the provided namespace
func (l *TaskList) AddWithNamespace(namespace string, t Task) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	id := t.ID()
	if _, ok := l.tasks[namespace]; !ok {
		l.tasks[namespace] = make(map[string]Task)
	}
	if _, ok := l.tasks[namespace][id]; ok {
		return errors.Wrap(ErrTaskAlreadyExists, id)
	}
	l.tasks[namespace][id] = t
	return nil
}
```

## 2. Runtime_v2服务
TaskManager就是Runtime_V2的实现

### 2.1 TasManager
```diff
type TaskManager struct {
	root                   string
	state                  string
	containerdAddress      string
	containerdTTRPCAddress string

	tasks      *runtime.TaskList
	events     *exchange.Exchange
	containers containers.Store
}

// ID of the task manager
func (m *TaskManager) ID() string {
	return fmt.Sprintf("%s.%s", plugin.RuntimePluginV2, "task")
}
```

### 2.2 接口实现
- ***Create***
```diff
- // 在runtime里真正创建一个container
// Create a new task
func (m *TaskManager) Create(ctx context.Context, id string, opts runtime.CreateOpts) (_ runtime.Task, retErr error) {
-	// 准备新的rootfs目录，同时写入spec文件
	bundle, err := NewBundle(ctx, m.root, m.state, id, opts.Spec.Value)
+	shim, err := m.startShim(ctx, bundle, id, opts)
+	t, err := shim.Create(ctx, opts)
	m.tasks.Add(ctx, t)
	return t, nil
}
```
- ***startShim***
```diff
- // 启动shim垫片进程
func (m *TaskManager) startShim(ctx context.Context, bundle *Bundle, id string, opts runtime.CreateOpts) (*shim, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	topts := opts.TaskOptions
	if topts == nil {
		topts = opts.RuntimeOptions
	}

+	b := shimBinary(bundle, opts.Runtime, m.containerdAddress, m.containerdTTRPCAddress)
+	shim, err := b.Start(ctx, topts, func() {
		log.G(ctx).WithField("id", id).Info("shim disconnected")

		cleanupAfterDeadShim(context.Background(), id, ns, m.tasks, m.events, b)
		// Remove self from the runtime task list. Even though the cleanupAfterDeadShim()
		// would publish taskExit event, but the shim.Delete() would always failed with ttrpc
		// disconnect and there is no chance to remove this dead task from runtime task lists.
		// Thus it's better to delete it here.
		m.tasks.Delete(ctx, id)
	})
	return shim, nil
}
```
>> ***shimBinary***和***b.Start***
```diff
func shimBinary(bundle *Bundle, runtime, containerdAddress string, containerdTTRPCAddress string) *binary {
	return &binary{
		bundle:                 bundle,
		runtime:                runtime,
		containerdAddress:      containerdAddress,
		containerdTTRPCAddress: containerdTTRPCAddress,
	}
}

type binary struct {
	runtime                string
	containerdAddress      string
	containerdTTRPCAddress string
	bundle                 *Bundle
}

func (b *binary) Start(ctx context.Context, opts *types.Any, onClose func()) (_ *shim, err error) {
	args := []string{"-id", b.bundle.ID}
-	// 注意，启动shim的时候，有start参数，用处在分析shim的时候讲
	args = append(args, "start")

-	// 构建shim的命令
	cmd, err := client.Command(
		ctx,
		b.runtime,
		b.containerdAddress,
		b.containerdTTRPCAddress,
		b.bundle.Path,
		opts,
		args...,
	)
	// Windows needs a namespace when openShimLog
	ns, _ := namespaces.Namespace(ctx)
	shimCtx, cancelShimLog := context.WithCancel(namespaces.WithNamespace(context.Background(), ns))

-	// 使用fifo文件/var/run/containerd/io.containerd.runtime.v2.task/default/$ID/log来输出shim的log
	f, err := openShimLog(shimCtx, b.bundle, client.AnonDialer)

	// open the log pipe and block until the writer is ready
	// this helps with synchronization of the shim
	// copy the shim's logs to containerd's output
	go func() {
		defer f.Close()
		_, err := io.Copy(os.Stderr, f)
		// To prevent flood of error messages, the expected error
		// should be reset, like os.ErrClosed or os.ErrNotExist, which
		// depends on platform.
		err = checkCopyShimLogError(ctx, err)
	}()
-	// 执行命令	
	out, err := cmd.CombinedOutput()
-	// shim打印address地址
	address := strings.TrimSpace(string(out))
-	// 连接address地址	
	conn, err := client.Connect(address, client.AnonDialer)

	onCloseWithShimLog := func() {
		onClose()
		cancelShimLog()
		f.Close()
	}
-	// 建立ttRPC client	
	client := ttrpc.NewClient(conn, ttrpc.WithOnClose(onCloseWithShimLog))
+	return &shim{
		bundle: b.bundle,
		client: client,
+		task:   task.NewTaskClient(client),
	}, nil
}

func NewTaskClient(client *github_com_containerd_ttrpc.Client) TaskService {
	return &taskClient{
		client: client,
	}
}
```
- ***Get***和***Add***
```diff
// Get a specific task
func (m *TaskManager) Get(ctx context.Context, id string) (runtime.Task, error) {
	return m.tasks.Get(ctx, id)
}

// Add a runtime task
func (m *TaskManager) Add(ctx context.Context, task runtime.Task) error {
	return m.tasks.Add(ctx, task)
}
```

- ***Tasks***和***LoadTasks***
```diff
// Tasks lists all tasks
func (m *TaskManager) Tasks(ctx context.Context, all bool) ([]runtime.Task, error) {
	return m.tasks.GetAll(ctx, all)
}

func (m *TaskManager) loadExistingTasks(ctx context.Context) error {
	nsDirs, err := ioutil.ReadDir(m.state)
	for _, nsd := range nsDirs {
		if !nsd.IsDir() {
			continue
		}
		ns := nsd.Name()
		// skip hidden directories
		if len(ns) > 0 && ns[0] == '.' {
			continue
		}
		log.G(ctx).WithField("namespace", ns).Debug("loading tasks in namespace")
		if err := m.loadTasks(namespaces.WithNamespace(ctx, ns)); err != nil {
			log.G(ctx).WithField("namespace", ns).WithError(err).Error("loading tasks in namespace")
			continue
		}
		if err := m.cleanupWorkDirs(namespaces.WithNamespace(ctx, ns)); err != nil {
			log.G(ctx).WithField("namespace", ns).WithError(err).Error("cleanup working directory in namespace")
			continue
		}
	}
	return nil
}

func (m *TaskManager) loadTasks(ctx context.Context) error {
	ns, err := namespaces.NamespaceRequired(ctx)
	shimDirs, err := ioutil.ReadDir(filepath.Join(m.state, ns))
	for _, sd := range shimDirs {
		if !sd.IsDir() {
			continue
		}
		id := sd.Name()
		// skip hidden directories
		if len(id) > 0 && id[0] == '.' {
			continue
		}
		bundle, err := LoadBundle(ctx, m.state, id)

		// fast path
		bf, err := ioutil.ReadDir(bundle.Path)

		if len(bf) == 0 {
			bundle.Delete()
			continue
		}
		container, err := m.container(ctx, id)
		if err != nil {
			log.G(ctx).WithError(err).Errorf("loading container %s", id)
			if err := mount.UnmountAll(filepath.Join(bundle.Path, "rootfs"), 0); err != nil {
				log.G(ctx).WithError(err).Errorf("forceful unmount of rootfs %s", id)
			}
			bundle.Delete()
			continue
		}
		binaryCall := shimBinary(bundle, container.Runtime.Name, m.containerdAddress, m.containerdTTRPCAddress)
		shim, err := loadShim(ctx, bundle, func() {
			log.G(ctx).WithField("id", id).Info("shim disconnected")

			cleanupAfterDeadShim(context.Background(), id, ns, m.tasks, m.events, binaryCall)
			// Remove self from the runtime task list.
			m.tasks.Delete(ctx, id)
		})
		m.tasks.Add(ctx, shim)
	}
	return nil
}
```
- ***containers***
```diff
func (m *TaskManager) container(ctx context.Context, id string) (*containers.Container, error) {
	container, err := m.containers.Get(ctx, id)
	return &container, nil
}
```

### 2.3 Task Client
负责和Shim进程通信
```diff
type taskClient struct {
	client *github_com_containerd_ttrpc.Client
}

func (c *taskClient) State(ctx context.Context, req *StateRequest) (*StateResponse, error) {
	var resp StateResponse
+	c.client.Call(ctx, "containerd.task.v2.Task", "State", req, &resp)
	return &resp, nil
}

func (c *taskClient) Create(ctx context.Context, req *CreateTaskRequest) (*CreateTaskResponse, error) {
	var resp CreateTaskResponse
+	c.client.Call(ctx, "containerd.task.v2.Task", "Create", req, &resp)
	return &resp, nil
}

func (c *taskClient) Start(ctx context.Context, req *StartRequest) (*StartResponse, error) {
	var resp StartResponse
+	c.client.Call(ctx, "containerd.task.v2.Task", "Start", req, &resp)
	return &resp, nil
}
```

### 2.4 Shim

Shim包含了bundle和task client
```diff
type shim struct {
	bundle *Bundle
	client *ttrpc.Client
	task   task.TaskService
}
// ID of the shim/task
func (s *shim) ID() string {
	return s.bundle.ID
}

// PID of the task
func (s *shim) PID(ctx context.Context) (uint32, error) {
	response, err := s.task.Connect(ctx, &task.ConnectRequest{
		ID: s.ID(),
	})
	return response.TaskPid, nil
}

func (s *shim) Create(ctx context.Context, opts runtime.CreateOpts) (runtime.Task, error) {
	topts := opts.TaskOptions
	if topts == nil {
		topts = opts.RuntimeOptions
	}
	request := &task.CreateTaskRequest{
		ID:         s.ID(),
		Bundle:     s.bundle.Path,
		Stdin:      opts.IO.Stdin,
		Stdout:     opts.IO.Stdout,
		Stderr:     opts.IO.Stderr,
		Terminal:   opts.IO.Terminal,
		Checkpoint: opts.Checkpoint,
		Options:    topts,
	}
	for _, m := range opts.Rootfs {
		request.Rootfs = append(request.Rootfs, &types.Mount{
			Type:    m.Type,
			Source:  m.Source,
			Options: m.Options,
		})
	}
	_, err := s.task.Create(ctx, request)
	return s, nil
}


func (s *shim) Pause(ctx context.Context) error {
	s.task.Pause(ctx, &task.PauseRequest{
		ID: s.ID(),
	})
	return nil
}

func (s *shim) Resume(ctx context.Context) error {
	s.task.Resume(ctx, &task.ResumeRequest{
		ID: s.ID(),
	})
	return nil
}

func (s *shim) Start(ctx context.Context) error {
	_, err := s.task.Start(ctx, &task.StartRequest{
		ID: s.ID(),
	})
	return nil
}

func (s *shim) Kill(ctx context.Context, signal uint32, all bool) error {
	s.task.Kill(ctx, &task.KillRequest{
		ID:     s.ID(),
		Signal: signal,
		All:    all,
	})
	return nil
}

func (s *shim) Exec(ctx context.Context, id string, opts runtime.ExecOpts) (runtime.ExecProcess, error) {
	if err := identifiers.Validate(id); err != nil {
		return nil, errors.Wrapf(err, "invalid exec id %s", id)
	}
	request := &task.ExecProcessRequest{
		ID:       s.ID(),
		ExecID:   id,
		Stdin:    opts.IO.Stdin,
		Stdout:   opts.IO.Stdout,
		Stderr:   opts.IO.Stderr,
		Terminal: opts.IO.Terminal,
		Spec:     opts.Spec,
	}
	s.task.Exec(ctx, request)
	return &process{
		id:   id,
		shim: s,
	}, nil
}

func (s *shim) Pids(ctx context.Context) ([]runtime.ProcessInfo, error) {
	resp, err := s.task.Pids(ctx, &task.PidsRequest{
		ID: s.ID(),
	})

	var processList []runtime.ProcessInfo
	for _, p := range resp.Processes {
		processList = append(processList, runtime.ProcessInfo{
			Pid:  p.Pid,
			Info: p.Info,
		})
	}
	return processList, nil
}

func (s *shim) Wait(ctx context.Context) (*runtime.Exit, error) {
	taskPid, err := s.PID(ctx)
	response, err := s.task.Wait(ctx, &task.WaitRequest{
		ID: s.ID(),
	})
	return &runtime.Exit{
		Pid:       taskPid,
		Timestamp: response.ExitedAt,
		Status:    response.ExitStatus,
	}, nil
}
```

### 2.5 Bundle
```diff
// NewBundle returns a new bundle on disk
func NewBundle(ctx context.Context, root, state, id string, spec []byte) (b *Bundle, err error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	work := filepath.Join(root, ns, id)
	b = &Bundle{
		ID:        id,
		Path:      filepath.Join(state, ns, id),
		Namespace: ns,
	}
	var paths []string
	// create state directory for the bundle
	if err := os.MkdirAll(filepath.Dir(b.Path), 0711); err != nil {
		return nil, err
	}
	if err := os.Mkdir(b.Path, 0700); err != nil {
		return nil, err
	}
	if err := prepareBundleDirectoryPermissions(b.Path, spec); err != nil {
		return nil, err
	}
	paths = append(paths, b.Path)
	// create working directory for the bundle
	if err := os.MkdirAll(filepath.Dir(work), 0711); err != nil {
		return nil, err
	}
	rootfs := filepath.Join(b.Path, "rootfs")
	if err := os.MkdirAll(rootfs, 0711); err != nil {
		return nil, err
	}
	paths = append(paths, rootfs)
	if err := os.Mkdir(work, 0711); err != nil {
		os.RemoveAll(work)
		if err := os.Mkdir(work, 0711); err != nil {
			return nil, err
		}
	}
	paths = append(paths, work)
	// symlink workdir
	if err := os.Symlink(work, filepath.Join(b.Path, "work")); err != nil {
		return nil, err
	}
	// write the spec to the bundle
	err = os.WriteFile(filepath.Join(b.Path, configFilename), spec, 0666)
	return b, err
}

// Bundle represents an OCI bundle
type Bundle struct {
	// ID of the bundle
	ID string
	// Path to the bundle
	Path string
	// Namespace of the bundle
	Namespace string
}
```
