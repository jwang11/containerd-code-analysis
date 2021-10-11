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

// NewContainerStore returns a Store backed by an underlying bolt DB
func NewContainerStore(db *DB) containers.Store {
	return &containerStore{	
+		db: db,	// metadata.DB
	}
}
type containerStore struct {
	db *DB
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
	bundle, err := NewBundle(ctx, m.root, m.state, id, opts.Spec.Value)
	shim, err := m.startShim(ctx, bundle, id, opts)
	t, err := shim.Create(ctx, opts)
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
	switch logrus.GetLevel() {
	case logrus.DebugLevel, logrus.TraceLevel:
		args = append(args, "-debug")
	}
-	// 注意，启动shim的时候，有start参数，用处在分析shim的时候讲
	args = append(args, "start")

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
		if err != nil {
			log.G(ctx).WithError(err).Error("copy shim log")
		}
	}()
	out, err := cmd.CombinedOutput()

	address := strings.TrimSpace(string(out))
	conn, err := client.Connect(address, client.AnonDialer)

	onCloseWithShimLog := func() {
		onClose()
		cancelShimLog()
		f.Close()
	}
	client := ttrpc.NewClient(conn, ttrpc.WithOnClose(onCloseWithShimLog))
	return &shim{
		bundle: b.bundle,
		client: client,
		task:   task.NewTaskClient(client),
	}, nil
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
	if err != nil {
		return err
	}
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
		if err != nil {
			// fine to return error here, it is a programmer error if the context
			// does not have a namespace
			return err
		}
		// fast path
		bf, err := ioutil.ReadDir(bundle.Path)
		if err != nil {
			bundle.Delete()
			log.G(ctx).WithError(err).Errorf("fast path read bundle path for %s", bundle.Path)
			continue
		}
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
