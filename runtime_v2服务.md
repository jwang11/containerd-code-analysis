# Runtime_v2服务
> containerd通过runtime_v2服务做container的执行和管理。以创建容器为例，runtime_v2先启动v2_shim_runc垫层，然后垫层去执行go_runc包装层里的runc。因此，runtime_v2本质上是Container执行任务的管理器。

### Runtime_v2的[注册](https://github.com/containerd/containerd/blob/main/runtime/v2/manager.go)
- RuntimePluginV2注册申请，InitFn返回TaskManager，也就是该plugin的instance
```diff
// Config for the v2 runtime
type Config struct {
	// Supported platforms
	Platforms []string `toml:"platforms"`
}

func init() {
	plugin.Register(&plugin.Registration{
+		Type: plugin.RuntimePluginV2,
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
			if err != nil {
				return nil, err
			}

			ic.Meta.Platforms = supportedPlatforms
			if err := os.MkdirAll(ic.Root, 0711); err != nil {
				return nil, err
			}
			if err := os.MkdirAll(ic.State, 0711); err != nil {
				return nil, err
			}
			m, err := ic.Get(plugin.MetadataPlugin)
			if err != nil {
				return nil, err
			}
			ep, err := ic.GetByID(plugin.EventPlugin, "exchange")
			if err != nil {
				return nil, err
			}
+			cs := metadata.NewContainerStore(m.(*metadata.DB))
			events := ep.(*exchange.Exchange)

+			return New(ic.Context, ic.Root, ic.State, ic.Address, ic.TTRPCAddress, events, cs)
		},
	})
}

// New task manager for v2 shims
func New(ctx context.Context, root, state, containerdAddress, containerdTTRPCAddress string, events *exchange.Exchange, cs containers.Store) (*TaskManager, error) {
	for _, d := range []string{root, state} {
		if err := os.MkdirAll(d, 0711); err != nil {
			return nil, err
		}
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
	if err := m.loadExistingTasks(ctx); err != nil {
		return nil, err
	}
	return m, nil
}
```

### Runtime_v2的实现
- TaskManager
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

- ***Create***
```diff
// Create a new task
func (m *TaskManager) Create(ctx context.Context, id string, opts runtime.CreateOpts) (_ runtime.Task, retErr error) {
	bundle, err := NewBundle(ctx, m.root, m.state, id, opts.Spec.Value)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			bundle.Delete()
		}
	}()

	shim, err := m.startShim(ctx, bundle, id, opts)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			m.deleteShim(shim)
		}
	}()

	t, err := shim.Create(ctx, opts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create shim")
	}

	if err := m.tasks.Add(ctx, t); err != nil {
		return nil, errors.Wrap(err, "failed to add task")
	}

	return t, nil
}
```
- ***startShim***
```diff
func (m *TaskManager) startShim(ctx context.Context, bundle *Bundle, id string, opts runtime.CreateOpts) (*shim, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}

	topts := opts.TaskOptions
	if topts == nil {
		topts = opts.RuntimeOptions
	}

	b := shimBinary(bundle, opts.Runtime, m.containerdAddress, m.containerdTTRPCAddress)
	shim, err := b.Start(ctx, topts, func() {
		log.G(ctx).WithField("id", id).Info("shim disconnected")

		cleanupAfterDeadShim(context.Background(), id, ns, m.tasks, m.events, b)
		// Remove self from the runtime task list. Even though the cleanupAfterDeadShim()
		// would publish taskExit event, but the shim.Delete() would always failed with ttrpc
		// disconnect and there is no chance to remove this dead task from runtime task lists.
		// Thus it's better to delete it here.
		m.tasks.Delete(ctx, id)
	})
	if err != nil {
		return nil, errors.Wrap(err, "start failed")
	}

	return shim, nil
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
	if err != nil {
		return err
	}
	shimDirs, err := ioutil.ReadDir(filepath.Join(m.state, ns))
	if err != nil {
		return err
	}
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
		if err != nil {
			cleanupAfterDeadShim(ctx, id, ns, m.tasks, m.events, binaryCall)
			continue
		}
		m.tasks.Add(ctx, shim)
	}
	return nil
}
```

- ***containers***
```diff
func (m *TaskManager) container(ctx context.Context, id string) (*containers.Container, error) {
	container, err := m.containers.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return &container, nil
}
```
