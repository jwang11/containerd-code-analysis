# Task服务
> Task代表执行中的Container对象，而Task服务管理这些对象。// Task is the runtime object for an executing container

### Task外部服务注册和初始化
- 外部服务通过GPRC Plugin注册，ID是“tasks”，类型“plugin.GRPCPlugin”
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

- 初始化函数InitFn依赖内部服务plugin.ServicePlugin[services.TaskService]，InitFn执行完后返回service结构
```
type service struct {
	local api.TasksClient
}
```

### Task内部服务注册和初始化
- 内部服务Service.Plugin的注册
```diff
func init() {
	plugin.Register(&plugin.Registration{
		Type:     plugin.ServicePlugin,
		ID:       services.TasksService,
+		Requires: tasksServiceRequires,
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
- 初始化函数InitFn依赖(Linux下），plugin.EventPlugin, plugin.RuntimePlugin, plugin.RuntimePluginV2, plugin.MetadataPlugin, plugin.TaskMonitorPlugin,
- InitFn返回local结构
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
- Task内部服务的接口
```
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
- 其它
```
func (l *local) ListPids(ctx context.Context, r *api.ListPidsRequest, _ ...grpc.CallOption) (*api.ListPidsResponse, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	processList, err := t.Pids(ctx)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	var processes []*task.ProcessInfo
	for _, p := range processList {
		pInfo := task.ProcessInfo{
			Pid: p.Pid,
		}
		if p.Info != nil {
			a, err := typeurl.MarshalAny(p.Info)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to marshal process %d info", p.Pid)
			}
			pInfo.Info = a
		}
		processes = append(processes, &pInfo)
	}
	return &api.ListPidsResponse{
		Processes: processes,
	}, nil
}

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

func (l *local) ResizePty(ctx context.Context, r *api.ResizePtyRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
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
	if err := p.ResizePty(ctx, runtime.ConsoleSize{
		Width:  r.Width,
		Height: r.Height,
	}); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

func (l *local) CloseIO(ctx context.Context, r *api.CloseIORequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
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
	if r.Stdin {
		if err := p.CloseIO(ctx); err != nil {
			return nil, errdefs.ToGRPC(err)
		}
	}
	return empty, nil
}

func (l *local) Checkpoint(ctx context.Context, r *api.CheckpointTaskRequest, _ ...grpc.CallOption) (*api.CheckpointTaskResponse, error) {
	container, err := l.getContainer(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	t, err := l.getTaskFromContainer(ctx, container)
	if err != nil {
		return nil, err
	}
	image, err := getCheckpointPath(container.Runtime.Name, r.Options)
	if err != nil {
		return nil, err
	}
	checkpointImageExists := false
	if image == "" {
		checkpointImageExists = true
		image, err = ioutil.TempDir(os.Getenv("XDG_RUNTIME_DIR"), "ctd-checkpoint")
		if err != nil {
			return nil, errdefs.ToGRPC(err)
		}
		defer os.RemoveAll(image)
	}
	if err := t.Checkpoint(ctx, image, r.Options); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	// do not commit checkpoint image if checkpoint ImagePath is passed,
	// return if checkpointImageExists is false
	if !checkpointImageExists {
		return &api.CheckpointTaskResponse{}, nil
	}
	// write checkpoint to the content store
	tar := archive.Diff(ctx, "", image)
	cp, err := l.writeContent(ctx, images.MediaTypeContainerd1Checkpoint, image, tar)
	// close tar first after write
	if err := tar.Close(); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	// write the config to the content store
	data, err := container.Spec.Marshal()
	if err != nil {
		return nil, err
	}
	spec := bytes.NewReader(data)
	specD, err := l.writeContent(ctx, images.MediaTypeContainerd1CheckpointConfig, filepath.Join(image, "spec"), spec)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return &api.CheckpointTaskResponse{
		Descriptors: []*types.Descriptor{
			cp,
			specD,
		},
	}, nil
}

func (l *local) Update(ctx context.Context, r *api.UpdateTaskRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	if err := t.Update(ctx, r.Resources, r.Annotations); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

func (l *local) Metrics(ctx context.Context, r *api.MetricsRequest, _ ...grpc.CallOption) (*api.MetricsResponse, error) {
	filter, err := filters.ParseAll(r.Filters...)
	if err != nil {
		return nil, err
	}
	var resp api.MetricsResponse
	for _, r := range l.allRuntimes() {
		tasks, err := r.Tasks(ctx, false)
		if err != nil {
			return nil, err
		}
		getTasksMetrics(ctx, filter, tasks, &resp)
	}
	return &resp, nil
}

func (l *local) Wait(ctx context.Context, r *api.WaitRequest, _ ...grpc.CallOption) (*api.WaitResponse, error) {
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
	exit, err := p.Wait(ctx)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
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
		if err != nil {
			if !errdefs.IsNotFound(err) {
				log.G(ctx).WithError(err).Errorf("collecting metrics for %s", tk.ID())
			}
			continue
		}
		r.Metrics = append(r.Metrics, &types.Metric{
			Timestamp: collected,
			ID:        tk.ID(),
			Data:      stats,
		})
	}
}

func (l *local) writeContent(ctx context.Context, mediaType, ref string, r io.Reader) (*types.Descriptor, error) {
	writer, err := l.store.Writer(ctx, content.WithRef(ref), content.WithDescriptor(ocispec.Descriptor{MediaType: mediaType}))
	if err != nil {
		return nil, err
	}
	defer writer.Close()
	size, err := io.Copy(writer, r)
	if err != nil {
		return nil, err
	}
	if err := writer.Commit(ctx, 0, ""); err != nil {
		return nil, err
	}
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
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return &container, nil
}

func (l *local) getTask(ctx context.Context, id string) (runtime.Task, error) {
	container, err := l.getContainer(ctx, id)
	if err != nil {
		return nil, err
	}
	return l.getTaskFromContainer(ctx, container)
}

func (l *local) getTaskFromContainer(ctx context.Context, container *containers.Container) (runtime.Task, error) {
	runtime, err := l.getRuntime(container.Runtime.Name)
	if err != nil {
		return nil, errdefs.ToGRPCf(err, "runtime for task %s", container.Runtime.Name)
	}
	t, err := runtime.Get(ctx, container.ID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "task %v not found", container.ID)
	}
	return t, nil
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
