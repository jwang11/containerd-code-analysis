# Tasks服务
> Task代表执行中的Container对象，而Task服务管理这些对象。// Task is the runtime object for an executing container

## 1. 外部服务
### 1.1 Plugin注册
外部服务通过GPRC Plugin注册，ID是“tasks”，类型“plugin.GRPCPlugin”
```diff
func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.GRPCPlugin,
+		ID:   "tasks",
		Requires: []plugin.Type{
			plugin.ServicePlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			plugins, err := ic.GetByType(plugin.ServicePlugin)
			p, ok := plugins[services.TasksService]
			i, err := p.Instance()
+			return &service{local: i.(api.TasksClient)}, nil
		},
	})
}

type service struct {
+	local api.TasksClient
}
```

### 1.2 接口实现
```diff
// TasksServer is the server API for Tasks service.
type TasksServer interface {
	// Create a task.
	Create(context.Context, *CreateTaskRequest) (*CreateTaskResponse, error)
	// Start a process.
	Start(context.Context, *StartRequest) (*StartResponse, error)
	// Delete a task and on disk state.
	Delete(context.Context, *DeleteTaskRequest) (*DeleteResponse, error)
	DeleteProcess(context.Context, *DeleteProcessRequest) (*DeleteResponse, error)
	Get(context.Context, *GetRequest) (*GetResponse, error)
	List(context.Context, *ListTasksRequest) (*ListTasksResponse, error)
	// Kill a task or process.
	Kill(context.Context, *KillRequest) (*types1.Empty, error)
	Exec(context.Context, *ExecProcessRequest) (*types1.Empty, error)
	ResizePty(context.Context, *ResizePtyRequest) (*types1.Empty, error)
	CloseIO(context.Context, *CloseIORequest) (*types1.Empty, error)
	Pause(context.Context, *PauseTaskRequest) (*types1.Empty, error)
	Resume(context.Context, *ResumeTaskRequest) (*types1.Empty, error)
	ListPids(context.Context, *ListPidsRequest) (*ListPidsResponse, error)
	Checkpoint(context.Context, *CheckpointTaskRequest) (*CheckpointTaskResponse, error)
	Update(context.Context, *UpdateTaskRequest) (*types1.Empty, error)
	Metrics(context.Context, *MetricsRequest) (*MetricsResponse, error)
	Wait(context.Context, *WaitRequest) (*WaitResponse, error)
}

func (s *service) Register(server *grpc.Server) error {
	api.RegisterTasksServer(server, s)
	return nil
}

func (s *service) Create(ctx context.Context, r *api.CreateTaskRequest) (*api.CreateTaskResponse, error) {
+	return s.local.Create(ctx, r)
}

func (s *service) Start(ctx context.Context, r *api.StartRequest) (*api.StartResponse, error) {
+	return s.local.Start(ctx, r)
}

func (s *service) Delete(ctx context.Context, r *api.DeleteTaskRequest) (*api.DeleteResponse, error) {
+	return s.local.Delete(ctx, r)
}

func (s *service) DeleteProcess(ctx context.Context, r *api.DeleteProcessRequest) (*api.DeleteResponse, error) {
+	return s.local.DeleteProcess(ctx, r)
}

func (s *service) Get(ctx context.Context, r *api.GetRequest) (*api.GetResponse, error) {
+	return s.local.Get(ctx, r)
}

func (s *service) List(ctx context.Context, r *api.ListTasksRequest) (*api.ListTasksResponse, error) {
+	return s.local.List(ctx, r)
}

func (s *service) Pause(ctx context.Context, r *api.PauseTaskRequest) (*ptypes.Empty, error) {
+	return s.local.Pause(ctx, r)
}
```

## 2. 内部服务
### 2.1 Plugin注册
```diff
func init() {
	plugin.Register(&plugin.Registration{
		Type:     plugin.ServicePlugin,
+		ID:       services.TasksService,
		Requires: tasksServiceRequires,
		InitFn:   initFunc,
	})

	timeout.Set(stateTimeout, 2*time.Second)
}

var tasksServiceRequires = []plugin.Type{
	plugin.EventPlugin,
	plugin.RuntimePlugin,
	plugin.RuntimePluginV2,
	plugin.MetadataPlugin,
	plugin.TaskMonitorPlugin,
}

func initFunc(ic *plugin.InitContext) (interface{}, error) {
	runtimes, err := loadV1Runtimes(ic)
-	// v2_runtime服务
	v2r, err := ic.Get(plugin.RuntimePluginV2)
-	// metadata服务
	m, err := ic.Get(plugin.MetadataPlugin)
	ep, err := ic.Get(plugin.EventPlugin)
-	// TaskMonitor服务
	monitor, err := ic.Get(plugin.TaskMonitorPlugin)

	db := m.(*metadata.DB)
	l := &local{
		runtimes:   runtimes,
+		containers: metadata.NewContainerStore(db),
+		store:      db.ContentStore(),
		publisher:  ep.(events.Publisher),
+		monitor:    monitor.(runtime.TaskMonitor),
+		v2Runtime:  v2r.(*v2.TaskManager),
	}
	for _, r := range runtimes {
		tasks, err := r.Tasks(ic.Context, true)
		for _, t := range tasks {
			l.monitor.Monitor(t, nil)
		}
	}
+	v2Tasks, err := l.v2Runtime.Tasks(ic.Context, true)
	for _, t := range v2Tasks {
		l.monitor.Monitor(t, nil)
	}
	return l, nil
}
```

### 2. 接口实现
- ***接口***
```diff
type TasksClient interface {
	// Create a task.
	Create(ctx context.Context, in *CreateTaskRequest, opts ...grpc.CallOption) (*CreateTaskResponse, error)
	// Start a process.
	Start(ctx context.Context, in *StartRequest, opts ...grpc.CallOption) (*StartResponse, error)
	// Delete a task and on disk state.
	Delete(ctx context.Context, in *DeleteTaskRequest, opts ...grpc.CallOption) (*DeleteResponse, error)
	DeleteProcess(ctx context.Context, in *DeleteProcessRequest, opts ...grpc.CallOption) (*DeleteResponse, error)
	Get(ctx context.Context, in *GetRequest, opts ...grpc.CallOption) (*GetResponse, error)
	List(ctx context.Context, in *ListTasksRequest, opts ...grpc.CallOption) (*ListTasksResponse, error)
	// Kill a task or process.
	Kill(ctx context.Context, in *KillRequest, opts ...grpc.CallOption) (*types1.Empty, error)
	Exec(ctx context.Context, in *ExecProcessRequest, opts ...grpc.CallOption) (*types1.Empty, error)
	ResizePty(ctx context.Context, in *ResizePtyRequest, opts ...grpc.CallOption) (*types1.Empty, error)
	CloseIO(ctx context.Context, in *CloseIORequest, opts ...grpc.CallOption) (*types1.Empty, error)
	Pause(ctx context.Context, in *PauseTaskRequest, opts ...grpc.CallOption) (*types1.Empty, error)
	Resume(ctx context.Context, in *ResumeTaskRequest, opts ...grpc.CallOption) (*types1.Empty, error)
	ListPids(ctx context.Context, in *ListPidsRequest, opts ...grpc.CallOption) (*ListPidsResponse, error)
	Checkpoint(ctx context.Context, in *CheckpointTaskRequest, opts ...grpc.CallOption) (*CheckpointTaskResponse, error)
	Update(ctx context.Context, in *UpdateTaskRequest, opts ...grpc.CallOption) (*types1.Empty, error)
	Metrics(ctx context.Context, in *MetricsRequest, opts ...grpc.CallOption) (*MetricsResponse, error)
	Wait(ctx context.Context, in *WaitRequest, opts ...grpc.CallOption) (*WaitResponse, error)
}
```

- ***Create***
```diff
func (l *local) Create(ctx context.Context, r *api.CreateTaskRequest, _ ...grpc.CallOption) (*api.CreateTaskResponse, error) {
	container, err := l.getContainer(ctx, r.ContainerID)

	opts := runtime.CreateOpts{
		Spec: container.Spec,
		IO: runtime.IO{
			Stdin:    r.Stdin,
			Stdout:   r.Stdout,
			Stderr:   r.Stderr,
			Terminal: r.Terminal,
		},
		Checkpoint:     checkpointPath,
		Runtime:        container.Runtime.Name,
		RuntimeOptions: container.Runtime.Options,
		TaskOptions:    r.Options,
	}
	for _, m := range r.Rootfs {
		opts.Rootfs = append(opts.Rootfs, mount.Mount{
			Type:    m.Type,
			Source:  m.Source,
			Options: m.Options,
		})
	}
	if strings.HasPrefix(container.Runtime.Name, "io.containerd.runtime.v1.") {
		log.G(ctx).Warn("runtime v1 is deprecated since containerd v1.4, consider using runtime v2")
	} else if container.Runtime.Name == plugin.RuntimeRuncV1 {
		log.G(ctx).Warnf("%q is deprecated since containerd v1.4, consider using %q", plugin.RuntimeRuncV1, plugin.RuntimeRuncV2)
	}
	rtime, err := l.getRuntime(container.Runtime.Name)

-	// 得到runtime服务
	_, err = rtime.Get(ctx, r.ContainerID)
	if err == nil {
		return nil, errdefs.ToGRPC(fmt.Errorf("task %s: %w", r.ContainerID, errdefs.ErrAlreadyExists))
	}

+	c, err := rtime.Create(ctx, r.ContainerID, opts)

	labels := map[string]string{"runtime": container.Runtime.Name}
	l.monitor.Monitor(c, labels)
	pid, err := c.PID(ctx)
	return &api.CreateTaskResponse{
		ContainerID: r.ContainerID,
		Pid:         pid,
	}, nil
}

// Create a new task
func (m *TaskManager) Create(ctx context.Context, id string, opts runtime.CreateOpts) (_ runtime.Task, retErr error) {
	bundle, err := NewBundle(ctx, m.root, m.state, id, opts.Spec.Value)
	shim, err := m.startShim(ctx, bundle, id, opts)
	t, err := shim.Create(ctx, opts)
-	// t就是Shim，实现了runtime.Task，加到TaskManger的task_list里	
	m.tasks.Add(ctx, t)
	return t, nil
}
```

- ***Start***
```diff
func (l *local) Start(ctx context.Context, r *api.StartRequest, _ ...grpc.CallOption) (*api.StartResponse, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	p := runtime.Process(t)
	if r.ExecID != "" {
		if p, err = t.Process(ctx, r.ExecID); err != nil {
			return nil, errdefs.ToGRPC(err)
		}
	}
	p.Start(ctx)
	state, err := p.State(ctx)
	return &api.StartResponse{
		Pid: state.Pid,
	}, nil
}

func (l *local) getTask(ctx context.Context, id string) (runtime.Task, error) {
	container, err := l.getContainer(ctx, id)
+	return l.getTaskFromContainer(ctx, container)
}

func (l *local) getTaskFromContainer(ctx context.Context, container *containers.Container) (runtime.Task, error) {
	runtime, err := l.getRuntime(container.Runtime.Name)
+	t, err := runtime.Get(ctx, container.ID)
	return t, nil
}

// Get a specific task
func (m *TaskManager) Get(ctx context.Context, id string) (runtime.Task, error) {
	return m.tasks.Get(ctx, id)
}
```

- ***其它***
```diff
func (l *local) Exec(ctx context.Context, r *api.ExecProcessRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
	if r.ExecID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "exec id cannot be empty")
	}
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	if _, err := t.Exec(ctx, r.ExecID, runtime.ExecOpts{
		Spec: r.Spec,
		IO: runtime.IO{
			Stdin:    r.Stdin,
			Stdout:   r.Stdout,
			Stderr:   r.Stderr,
			Terminal: r.Terminal,
		},
	}); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

func (l *local) Wait(ctx context.Context, r *api.WaitRequest, _ ...grpc.CallOption) (*api.WaitResponse, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	p := runtime.Process(t)
	if r.ExecID != "" {
		t.Process(ctx, r.ExecID)
	}
	exit, err := p.Wait(ctx)
	return &api.WaitResponse{
		ExitStatus: exit.Status,
		ExitedAt:   exit.Timestamp,
	}, nil
}

func getTasksMetrics(ctx context.Context, filter filters.Filter, tasks []runtime.Task, r *api.MetricsResponse) {
	for _, tk := range tasks {
		if !filter.Match(filters.AdapterFunc(func(fieldpath []string) (string, bool) {
			t := tk
			switch fieldpath[0] {
			case "id":
				return t.ID(), true
			case "namespace":
				return t.Namespace(), true
			case "runtime":
				// return t.Info().Runtime, true
			}
			return "", false
		})) {
			continue
		}
		collected := time.Now()
		stats, err := tk.Stats(ctx)
		r.Metrics = append(r.Metrics, &types.Metric{
			Timestamp: collected,
			ID:        tk.ID(),
			Data:      stats,
		})
	}
}

func (l *local) writeContent(ctx context.Context, mediaType, ref string, r io.Reader) (*types.Descriptor, error) {
	writer, err := l.store.Writer(ctx, content.WithRef(ref), content.WithDescriptor(ocispec.Descriptor{MediaType: mediaType}))
	defer writer.Close()
	size, err := io.Copy(writer, r)
	writer.Commit(ctx, 0, "")
	return &types.Descriptor{
		MediaType:   mediaType,
		Digest:      writer.Digest(),
		Size_:       size,
		Annotations: make(map[string]string),
	}, nil
}

func (l *local) getContainer(ctx context.Context, id string) (*containers.Container, error) {
	var container containers.Container
	container, err := l.containers.Get(ctx, id)
	return &container, nil
}


func (l *local) getRuntime(name string) (runtime.PlatformRuntime, error) {
	runtime, ok := l.runtimes[name]
	if !ok {
		// one runtime to rule them all
		return l.v2Runtime, nil
	}
	return runtime, nil
}

func (l *local) allRuntimes() (o []runtime.PlatformRuntime) {
	for _, r := range l.runtimes {
		o = append(o, r)
	}
	o = append(o, l.v2Runtime)
	return o
}
```
