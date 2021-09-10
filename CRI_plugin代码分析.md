# CRI Plugin代码分析
> CRI（Container Runtime Interface）是 Kubernetes 定义的与 contianer runtime 进行交互的接口<br>
> Containerd在1.1版本直接将cri-containerd内置在Containerd中，作为一个Plugin插件<br>
> CRI插件实现了Kubelet CRI 接口中的 Image Service 和 Runtime Service，管理容器和镜像，调用CNI插件给Pod配置网络

### [外部服务](https://github.com/containerd/containerd/blob/main/pkg/cri/cri.go)
```diff
// Register CRI service plugin
func init() {
	config := criconfig.DefaultConfig()
	plugin.Register(&plugin.Registration{
		Type:   plugin.GRPCPlugin,
		ID:     "cri",
		Config: &config,
		Requires: []plugin.Type{
			plugin.EventPlugin,
			plugin.ServicePlugin,
		},
+		InitFn: initCRIService,
	})
}
```
### ***initCRIService***
```diff
func initCRIService(ic *plugin.InitContext) (interface{}, error) {
	ic.Meta.Platforms = []imagespec.Platform{platforms.DefaultSpec()}
	ic.Meta.Exports = map[string]string{"CRIVersion": constants.CRIVersion, "CRIVersionAlpha": constants.CRIVersionAlpha}
	ctx := ic.Context
	pluginConfig := ic.Config.(*criconfig.PluginConfig)
	if err := criconfig.ValidatePluginConfig(ctx, pluginConfig); err != nil {
		return nil, errors.Wrap(err, "invalid plugin config")
	}

	c := criconfig.Config{
		PluginConfig:       *pluginConfig,
		ContainerdRootDir:  filepath.Dir(ic.Root),
		ContainerdEndpoint: ic.Address,
		RootDir:            ic.Root,
		StateDir:           ic.State,
	}
	log.G(ctx).Infof("Start cri plugin with config %+v", c)

	if err := setGLogLevel(); err != nil {
		return nil, errors.Wrap(err, "failed to set glog level")
	}

-	// 因为是建立一个新的server，它map了一大批依赖服务，
+	servicesOpts, err := getServicesOpts(ic)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get services")
	}

	log.G(ctx).Info("Connect containerd service")
	client, err := containerd.New(
		"",
		containerd.WithDefaultNamespace(constants.K8sContainerdNamespace),
		containerd.WithDefaultPlatform(platforms.Default()),
		containerd.WithServices(servicesOpts...),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create containerd client")
	}

+	s, err := server.NewCRIService(c, client)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create CRI service")
	}

	go func() {
+		if err := s.Run(); err != nil {
			log.G(ctx).WithError(err).Fatal("Failed to run CRI service")
		}
		// TODO(random-liu): Whether and how we can stop containerd.
	}()
	return s, nil
}
```
> ***getServicesOpts***
```diff
// getServicesOpts get service options from plugin context.
func getServicesOpts(ic *plugin.InitContext) ([]containerd.ServicesOpt, error) {
	plugins, err := ic.GetByType(plugin.ServicePlugin)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get service plugin")
	}

	ep, err := ic.Get(plugin.EventPlugin)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get event plugin")
	}

	opts := []containerd.ServicesOpt{
		containerd.WithEventService(ep.(containerd.EventService)),
	}
-	// 生成修改Service的闭包Map	
+	for s, fn := range map[string]func(interface{}) containerd.ServicesOpt{
		services.ContentService: func(s interface{}) containerd.ServicesOpt {
			return containerd.WithContentStore(s.(content.Store))
		},
		services.ImagesService: func(s interface{}) containerd.ServicesOpt {
			return containerd.WithImageClient(s.(images.ImagesClient))
		},
		services.SnapshotsService: func(s interface{}) containerd.ServicesOpt {
			return containerd.WithSnapshotters(s.(map[string]snapshots.Snapshotter))
		},
		services.ContainersService: func(s interface{}) containerd.ServicesOpt {
			return containerd.WithContainerClient(s.(containers.ContainersClient))
		},
		services.TasksService: func(s interface{}) containerd.ServicesOpt {
			return containerd.WithTaskClient(s.(tasks.TasksClient))
		},
		services.DiffService: func(s interface{}) containerd.ServicesOpt {
			return containerd.WithDiffClient(s.(diff.DiffClient))
		},
		services.NamespacesService: func(s interface{}) containerd.ServicesOpt {
			return containerd.WithNamespaceClient(s.(namespaces.NamespacesClient))
		},
		services.LeasesService: func(s interface{}) containerd.ServicesOpt {
			return containerd.WithLeasesService(s.(leases.Manager))
		},
		services.IntrospectionService: func(s interface{}) containerd.ServicesOpt {
			return containerd.WithIntrospectionClient(s.(introspectionapi.IntrospectionClient))
		},
	} {
		p := plugins[s]
		if p == nil {
			return nil, errors.Errorf("service %q not found", s)
		}
		i, err := p.Instance()
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get instance of service %q", s)
		}
		if i == nil {
			return nil, errors.Errorf("instance of service %q not found", s)
		}
-		// 得到service的instance，并生成ServiceOpt
+		opts = append(opts, fn(i))
	}
	return opts, nil
}
```

### NewCRIService
```diff
- criService是整个CRI plugin的处理核心，它实现了一堆接口，包括RuntimeServiceServer和ImageServiceServer
// grpcServices are all the grpc services provided by cri containerd.
type grpcServices interface {
	runtime.RuntimeServiceServer
	runtime.ImageServiceServer
}

// CRIService is the interface implement CRI remote service server.
type CRIService interface {
	Run() error
	// io.Closer is used by containerd to gracefully stop cri service.
	io.Closer
	plugin.Service
	grpcServices
}
```
```diff
// NewCRIService returns a new instance of CRIService
func NewCRIService(config criconfig.Config, client *containerd.Client) (CRIService, error) {
	var err error
	labels := label.NewStore()
	c := &criService{
		config:             config,
		client:             client,
		os:                 osinterface.RealOS{},
		sandboxStore:       sandboxstore.NewStore(labels),
		containerStore:     containerstore.NewStore(labels),
		imageStore:         imagestore.NewStore(client),
		snapshotStore:      snapshotstore.NewStore(),
		sandboxNameIndex:   registrar.NewRegistrar(),
		containerNameIndex: registrar.NewRegistrar(),
		initialized:        atomic.NewBool(false),
	}

+	if client.SnapshotService(c.config.ContainerdConfig.Snapshotter) == nil {
		return nil, errors.Errorf("failed to find snapshotter %q", c.config.ContainerdConfig.Snapshotter)
	}

+	c.imageFSPath = imageFSPath(config.ContainerdRootDir, config.ContainerdConfig.Snapshotter)
	logrus.Infof("Get image filesystem path %q", c.imageFSPath)

+	if err := c.initPlatform(); err != nil {
		return nil, errors.Wrap(err, "initialize platform")
	}

	// prepare streaming server
+	c.streamServer, err = newStreamServer(c, config.StreamServerAddress, config.StreamServerPort, config.StreamIdleTimeout)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create stream server")
	}

	c.eventMonitor = newEventMonitor(c)

+	c.cniNetConfMonitor, err = newCNINetConfSyncer(c.config.NetworkPluginConfDir, c.netPlugin, c.cniLoadOptions())
	if err != nil {
		return nil, errors.Wrap(err, "failed to create cni conf monitor")
	}

	// Preload base OCI specs
+	c.baseOCISpecs, err = loadBaseOCISpecs(&config)
	if err != nil {
		return nil, err
	}

	return c, nil
}
```
> ***c.initPlatform***
```
// initPlatform handles linux specific initialization for the CRI service.
func (c *criService) initPlatform() error {
	var err error

	if userns.RunningInUserNS() {
		if !(c.config.DisableCgroup && !c.apparmorEnabled() && c.config.RestrictOOMScoreAdj) {
			logrus.Warn("Running containerd in a user namespace typically requires disable_cgroup, disable_apparmor, restrict_oom_score_adj set to be true")
		}
	}

	if c.config.EnableSelinux {
		if !selinux.GetEnabled() {
			logrus.Warn("Selinux is not supported")
		}
		if r := c.config.SelinuxCategoryRange; r > 0 {
			selinux.CategoryRange = uint32(r)
		}
	} else {
		selinux.SetDisabled()
	}

	// Pod needs to attach to at least loopback network and a non host network,
	// hence networkAttachCount is 2. If there are more network configs the
	// pod will be attached to all the networks but we will only use the ip
	// of the default network interface as the pod IP.
	c.netPlugin, err = cni.New(cni.WithMinNetworkCount(networkAttachCount),
		cni.WithPluginConfDir(c.config.NetworkPluginConfDir),
		cni.WithPluginMaxConfNum(c.config.NetworkPluginMaxConfNum),
		cni.WithPluginDir([]string{c.config.NetworkPluginBinDir}))
	if err != nil {
		return errors.Wrap(err, "failed to initialize cni")
	}

	if c.allCaps == nil {
		c.allCaps, err = cap.Current()
		if err != nil {
			return errors.Wrap(err, "failed to get caps")
		}
	}

	return nil
}
```

> ***loadBaseOCISpecs***
```diff
func loadOCISpec(filename string) (*oci.Spec, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open base OCI spec: %s", filename)
	}
	defer file.Close()

	spec := oci.Spec{}
	if err := json.NewDecoder(file).Decode(&spec); err != nil {
		return nil, errors.Wrap(err, "failed to parse base OCI spec file")
	}

	return &spec, nil
}

func loadBaseOCISpecs(config *criconfig.Config) (map[string]*oci.Spec, error) {
	specs := map[string]*oci.Spec{}
	for _, cfg := range config.Runtimes {
		if cfg.BaseRuntimeSpec == "" {
			continue
		}

		// Don't load same file twice
		if _, ok := specs[cfg.BaseRuntimeSpec]; ok {
			continue
		}

		spec, err := loadOCISpec(cfg.BaseRuntimeSpec)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load base OCI spec from file: %s", cfg.BaseRuntimeSpec)
		}

		specs[cfg.BaseRuntimeSpec] = spec
	}

	return specs, nil
}
```

### 启动CRI服务
```diff
// Run starts the CRI service.
func (c *criService) Run() error {
	logrus.Info("Start subscribing containerd event")
	c.eventMonitor.subscribe(c.client)

	logrus.Infof("Start recovering state")
	if err := c.recover(ctrdutil.NamespacedContext()); err != nil {
		return errors.Wrap(err, "failed to recover state")
	}

	// Start event handler.
	logrus.Info("Start event monitor")
	eventMonitorErrCh := c.eventMonitor.start()

	// Start snapshot stats syncer, it doesn't need to be stopped.
	logrus.Info("Start snapshots syncer")
	snapshotsSyncer := newSnapshotsSyncer(
		c.snapshotStore,
		c.client.SnapshotService(c.config.ContainerdConfig.Snapshotter),
		time.Duration(c.config.StatsCollectPeriod)*time.Second,
	)
	snapshotsSyncer.start()

	// Start CNI network conf syncer
	logrus.Info("Start cni network conf syncer")
	cniNetConfMonitorErrCh := make(chan error, 1)
	go func() {
		defer close(cniNetConfMonitorErrCh)
		cniNetConfMonitorErrCh <- c.cniNetConfMonitor.syncLoop()
	}()

	// Start streaming server.
	logrus.Info("Start streaming server")
	streamServerErrCh := make(chan error)
	go func() {
		defer close(streamServerErrCh)
		if err := c.streamServer.Start(true); err != nil && err != http.ErrServerClosed {
			logrus.WithError(err).Error("Failed to start streaming server")
			streamServerErrCh <- err
		}
	}()

	// Set the server as initialized. GRPC services could start serving traffic.
	c.initialized.Set()

	var eventMonitorErr, streamServerErr, cniNetConfMonitorErr error
	// Stop the whole CRI service if any of the critical service exits.
	select {
	case eventMonitorErr = <-eventMonitorErrCh:
	case streamServerErr = <-streamServerErrCh:
	case cniNetConfMonitorErr = <-cniNetConfMonitorErrCh:
	}
	if err := c.Close(); err != nil {
		return errors.Wrap(err, "failed to stop cri service")
	}
	// If the error is set above, err from channel must be nil here, because
	// the channel is supposed to be closed. Or else, we wait and set it.
	if err := <-eventMonitorErrCh; err != nil {
		eventMonitorErr = err
	}
	logrus.Info("Event monitor stopped")
	// There is a race condition with http.Server.Serve.
	// When `Close` is called at the same time with `Serve`, `Close`
	// may finish first, and `Serve` may still block.
	// See https://github.com/golang/go/issues/20239.
	// Here we set a 2 second timeout for the stream server wait,
	// if it timeout, an error log is generated.
	// TODO(random-liu): Get rid of this after https://github.com/golang/go/issues/20239
	// is fixed.
	const streamServerStopTimeout = 2 * time.Second
	select {
	case err := <-streamServerErrCh:
		if err != nil {
			streamServerErr = err
		}
		logrus.Info("Stream server stopped")
	case <-time.After(streamServerStopTimeout):
		logrus.Errorf("Stream server is not stopped in %q", streamServerStopTimeout)
	}
	if eventMonitorErr != nil {
		return errors.Wrap(eventMonitorErr, "event monitor error")
	}
	if streamServerErr != nil {
		return errors.Wrap(streamServerErr, "stream server error")
	}
	if cniNetConfMonitorErr != nil {
		return errors.Wrap(cniNetConfMonitorErr, "cni network conf monitor error")
	}
	return nil
}
```
