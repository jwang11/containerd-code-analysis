# Task服务
> Task服务负责执行Container里的任务

### Task外部服务GPRC Plugin注册
```
func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.GRPCPlugin,
		ID:   "tasks",
		Requires: []plugin.Type{
			plugin.ServicePlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			plugins, err := ic.GetByType(plugin.ServicePlugin)
			if err != nil {
				return nil, err
			}
			p, ok := plugins[services.TasksService]
			if !ok {
				return nil, errors.New("tasks service not found")
			}
			i, err := p.Instance()
			if err != nil {
				return nil, err
			}
			return &service{local: i.(api.TasksClient)}, nil
		},
	})
}
```
### Task内部服务DevicePlugin注册
```
func init() {
	plugin.Register(&plugin.Registration{
		Type:     plugin.ServicePlugin,
		ID:       services.TasksService,
		Requires: tasksServiceRequires,
		InitFn:   initFunc,
	})

	timeout.Set(stateTimeout, 2*time.Second)
}

func initFunc(ic *plugin.InitContext) (interface{}, error) {
	runtimes, err := loadV1Runtimes(ic)
	if err != nil {
		return nil, err
	}

	v2r, err := ic.Get(plugin.RuntimePluginV2)
	if err != nil {
		return nil, err
	}

	m, err := ic.Get(plugin.MetadataPlugin)
	if err != nil {
		return nil, err
	}

	ep, err := ic.Get(plugin.EventPlugin)
	if err != nil {
		return nil, err
	}

	monitor, err := ic.Get(plugin.TaskMonitorPlugin)
	if err != nil {
		if !errdefs.IsNotFound(err) {
			return nil, err
		}
		monitor = runtime.NewNoopMonitor()
	}

	db := m.(*metadata.DB)
	l := &local{
		runtimes:   runtimes,
		containers: metadata.NewContainerStore(db),
		store:      db.ContentStore(),
		publisher:  ep.(events.Publisher),
		monitor:    monitor.(runtime.TaskMonitor),
		v2Runtime:  v2r.(*v2.TaskManager),
	}
	for _, r := range runtimes {
		tasks, err := r.Tasks(ic.Context, true)
		if err != nil {
			return nil, err
		}
		for _, t := range tasks {
			l.monitor.Monitor(t, nil)
		}
	}
	v2Tasks, err := l.v2Runtime.Tasks(ic.Context, true)
	if err != nil {
		return nil, err
	}
	for _, t := range v2Tasks {
		l.monitor.Monitor(t, nil)
	}
	return l, nil
}
```
### Task外部服务接口实现
- Task外部服务接口
```
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
```

- 接口实现
```
type service struct {
	local api.TasksClient
}

func (s *service) Register(server *grpc.Server) error {
	api.RegisterTasksServer(server, s)
	return nil
}

func (s *service) Create(ctx context.Context, r *api.CreateTaskRequest) (*api.CreateTaskResponse, error) {
	return s.local.Create(ctx, r)
}

func (s *service) Start(ctx context.Context, r *api.StartRequest) (*api.StartResponse, error) {
	return s.local.Start(ctx, r)
}

func (s *service) Delete(ctx context.Context, r *api.DeleteTaskRequest) (*api.DeleteResponse, error) {
	return s.local.Delete(ctx, r)
}

func (s *service) DeleteProcess(ctx context.Context, r *api.DeleteProcessRequest) (*api.DeleteResponse, error) {
	return s.local.DeleteProcess(ctx, r)
}

func (s *service) Get(ctx context.Context, r *api.GetRequest) (*api.GetResponse, error) {
	return s.local.Get(ctx, r)
}

func (s *service) List(ctx context.Context, r *api.ListTasksRequest) (*api.ListTasksResponse, error) {
	return s.local.List(ctx, r)
}

func (s *service) Pause(ctx context.Context, r *api.PauseTaskRequest) (*ptypes.Empty, error) {
	return s.local.Pause(ctx, r)
}

func (s *service) Resume(ctx context.Context, r *api.ResumeTaskRequest) (*ptypes.Empty, error) {
	return s.local.Resume(ctx, r)
}

func (s *service) Kill(ctx context.Context, r *api.KillRequest) (*ptypes.Empty, error) {
	return s.local.Kill(ctx, r)
}

func (s *service) ListPids(ctx context.Context, r *api.ListPidsRequest) (*api.ListPidsResponse, error) {
	return s.local.ListPids(ctx, r)
}

func (s *service) Exec(ctx context.Context, r *api.ExecProcessRequest) (*ptypes.Empty, error) {
	return s.local.Exec(ctx, r)
}

func (s *service) ResizePty(ctx context.Context, r *api.ResizePtyRequest) (*ptypes.Empty, error) {
	return s.local.ResizePty(ctx, r)
}

func (s *service) CloseIO(ctx context.Context, r *api.CloseIORequest) (*ptypes.Empty, error) {
	return s.local.CloseIO(ctx, r)
}

func (s *service) Checkpoint(ctx context.Context, r *api.CheckpointTaskRequest) (*api.CheckpointTaskResponse, error) {
	return s.local.Checkpoint(ctx, r)
}

func (s *service) Update(ctx context.Context, r *api.UpdateTaskRequest) (*ptypes.Empty, error) {
	return s.local.Update(ctx, r)
}

func (s *service) Metrics(ctx context.Context, r *api.MetricsRequest) (*api.MetricsResponse, error) {
	return s.local.Metrics(ctx, r)
}

func (s *service) Wait(ctx context.Context, r *api.WaitRequest) (*api.WaitResponse, error) {
	return s.local.Wait(ctx, r)
}
```

### Task内部服务接口实现
- Task内部服务的结构
```
type local struct {
	runtimes   map[string]runtime.PlatformRuntime
	containers containers.Store
	store      content.Store
	publisher  events.Publisher

	monitor   runtime.TaskMonitor
	v2Runtime *v2.TaskManager
}
```

- Create
```
func (l *local) Create(ctx context.Context, r *api.CreateTaskRequest, _ ...grpc.CallOption) (*api.CreateTaskResponse, error) {
	container, err := l.getContainer(ctx, r.ContainerID)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	checkpointPath, err := getRestorePath(container.Runtime.Name, r.Options)
	if err != nil {
		return nil, err
	}
	// jump get checkpointPath from checkpoint image
	if checkpointPath == "" && r.Checkpoint != nil {
		checkpointPath, err = ioutil.TempDir(os.Getenv("XDG_RUNTIME_DIR"), "ctrd-checkpoint")
		if err != nil {
			return nil, err
		}
		if r.Checkpoint.MediaType != images.MediaTypeContainerd1Checkpoint {
			return nil, fmt.Errorf("unsupported checkpoint type %q", r.Checkpoint.MediaType)
		}
		reader, err := l.store.ReaderAt(ctx, ocispec.Descriptor{
			MediaType:   r.Checkpoint.MediaType,
			Digest:      r.Checkpoint.Digest,
			Size:        r.Checkpoint.Size_,
			Annotations: r.Checkpoint.Annotations,
		})
		if err != nil {
			return nil, err
		}
		_, err = archive.Apply(ctx, checkpointPath, content.NewReader(reader))
		reader.Close()
		if err != nil {
			return nil, err
		}
	}
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
	if err != nil {
		return nil, err
	}
	_, err = rtime.Get(ctx, r.ContainerID)
	if err != nil && err != runtime.ErrTaskNotExists {
		return nil, errdefs.ToGRPC(err)
	}
	if err == nil {
		return nil, errdefs.ToGRPC(fmt.Errorf("task %s already exists", r.ContainerID))
	}
	c, err := rtime.Create(ctx, r.ContainerID, opts)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	labels := map[string]string{"runtime": container.Runtime.Name}
	if err := l.monitor.Monitor(c, labels); err != nil {
		return nil, errors.Wrap(err, "monitor task")
	}
	pid, err := c.PID(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get task pid")
	}
	return &api.CreateTaskResponse{
		ContainerID: r.ContainerID,
		Pid:         pid,
	}, nil
}
```

- Start
```
func (l *local) Start(ctx context.Context, r *api.StartRequest, _ ...grpc.CallOption) (*api.StartResponse, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	p := runtime.Process(t)
	if r.ExecID != "" {
		if p, err = t.Process(ctx, r.ExecID); err != nil {
			return nil, errdefs.ToGRPC(err)
		}
	}
	if err := p.Start(ctx); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	state, err := p.State(ctx)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return &api.StartResponse{
		Pid: state.Pid,
	}, nil
}
```

- Delete
```
func (l *local) Delete(ctx context.Context, r *api.DeleteTaskRequest, _ ...grpc.CallOption) (*api.DeleteResponse, error) {
	container, err := l.getContainer(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}

	// Find runtime manager
	rtime, err := l.getRuntime(container.Runtime.Name)
	if err != nil {
		return nil, err
	}

	// Get task object
	t, err := rtime.Get(ctx, container.ID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "task %v not found", container.ID)
	}

	if err := l.monitor.Stop(t); err != nil {
		return nil, err
	}

	exit, err := rtime.Delete(ctx, r.ContainerID)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return &api.DeleteResponse{
		ExitStatus: exit.Status,
		ExitedAt:   exit.Timestamp,
		Pid:        exit.Pid,
	}, nil
}
```

- DeleteProcess
```
func (l *local) DeleteProcess(ctx context.Context, r *api.DeleteProcessRequest, _ ...grpc.CallOption) (*api.DeleteResponse, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	process, err := t.Process(ctx, r.ExecID)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	exit, err := process.Delete(ctx)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return &api.DeleteResponse{
		ID:         r.ExecID,
		ExitStatus: exit.Status,
		ExitedAt:   exit.Timestamp,
		Pid:        exit.Pid,
	}, nil
}
```
