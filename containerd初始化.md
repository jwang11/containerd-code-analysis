# Containerd初始化

---
>Containerd是一个工业标准的容器运行时，重点是它简洁，健壮，便携，在Linux和window上可以作为一个守护进程运行，它可以管理主机系统上容器的完整的生命周期：镜像传输和存储，容器的执行和监控，低级别的存储和网络。

### 主程序

[cmd/containerd/main.go](https://github.com/containerd/containerd/blob/main/cmd/containerd/main.go)是入口文件，非常简洁

```
func main() {
	app := command.App()
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "containerd: %s\n", err)
		os.Exit(1)
	}
}
```
直接转到
```diff
+ command.App()
```
，初始化的主要步骤都在这里
- 命令行库使用urfave
- 日志库使用logrus

[cmd/containerd/command/main.go](https://github.com/containerd/containerd/blob/main/cmd/containerd/command/main.go#L66)
```diff
// App returns a *cli.App instance.
func App() *cli.App {
	app := cli.NewApp()
	app.Name = "containerd"
	app.Version = version.Version
	app.Usage = usage
	app.Description = `
containerd is a high performance container runtime whose daemon can be started
by using this command. If none of the *config*, *publish*, or *help* commands
are specified, the default action of the **containerd** command is to start the
containerd daemon in the foreground.
A default configuration is used if no TOML configuration is specified or located
at the default file location. The *containerd config* command can be used to
generate the default configuration for containerd. The output of that command
can be used and modified as necessary as a custom configuration.`
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config,c",
			Usage: "path to the configuration file",
			Value: filepath.Join(defaults.DefaultConfigDir, "config.toml"),
		},
		cli.StringFlag{
			Name:  "log-level,l",
			Usage: "set the logging level [trace, debug, info, warn, error, fatal, panic]",
		},
		cli.StringFlag{
			Name:  "address,a",
			Usage: "address for containerd's GRPC server",
		},
		cli.StringFlag{
			Name:  "root",
			Usage: "containerd root directory",
		},
		cli.StringFlag{
			Name:  "state",
			Usage: "containerd state directory",
		},
	}
	app.Flags = append(app.Flags, serviceFlags()...)
	app.Commands = []cli.Command{
		configCommand,
		publishCommand,
		ociHook,
	}
	app.Action = func(context *cli.Context) error {
		var (
			start   = time.Now()
			signals = make(chan os.Signal, 2048)
			serverC = make(chan *server.Server, 1)
			ctx     = gocontext.Background()
			config  = defaultConfig()
		)

		// Only try to load the config if it either exists, or the user explicitly
		// told us to load this path.
		configPath := context.GlobalString("config")
		_, err := os.Stat(configPath)
		if !os.IsNotExist(err) || context.GlobalIsSet("config") {
			if err := srvconfig.LoadConfig(configPath, config); err != nil {
				return err
			}
		}

		// Apply flags to the config
		if err := applyFlags(context, config); err != nil {
			return err
		}
...

		log.G(ctx).WithFields(logrus.Fields{
			"version":  version.Version,
			"revision": version.Revision,
		}).Info("starting containerd")

-		// Server的创建及初始化
+		server, err := server.New(ctx, config)
		if err != nil {
			return err
		}

		// Launch as a Windows Service if necessary
		if err := launchService(server, done); err != nil {
			logrus.Fatal(err)
		}

		serverC <- server

...
		// setup the ttrpc endpoint
		tl, err := sys.GetLocalListener(config.TTRPC.Address, config.TTRPC.UID, config.TTRPC.GID)
		if err != nil {
			return errors.Wrapf(err, "failed to get listener for main ttrpc endpoint")
		}		
+		serve(ctx, tl, server.ServeTTRPC)

		if config.GRPC.TCPAddress != "" {
			l, err := net.Listen("tcp", config.GRPC.TCPAddress)
			if err != nil {
				return errors.Wrapf(err, "failed to get listener for TCP grpc endpoint")
			}
+			serve(ctx, l, server.ServeTCP)
		}
		// setup the main grpc endpoint
		l, err := sys.GetLocalListener(config.GRPC.Address, config.GRPC.UID, config.GRPC.GID)
		if err != nil {
			return errors.Wrapf(err, "failed to get listener for main endpoint")
		}
+		serve(ctx, l, server.ServeGRPC)

		if err := notifyReady(ctx); err != nil {
			log.G(ctx).WithError(err).Warn("notify ready failed")
		}

		log.G(ctx).Infof("containerd successfully booted in %fs", time.Since(start).Seconds())
		<-done
		return nil
	}
	return app
}
```
### Server的创建及初始化
关键的函数是
```diff
+ server, err := server.New(ctx, config)
```
该函数是创建并初始化containerd server，
- 加载plugins，逐个调用p.Init(initContext)来初始化
- 创建GRPCServer，TTRPCServer，tcpServer并注册服务

[service/server/server.go](https://github.com/containerd/containerd/blob/master/services/server/server.go#L83)
```diff
// New creates and initializes a new containerd server
func New(ctx context.Context, config *srvconfig.Config) (*Server, error) {
	if err := apply(ctx, config); err != nil {
		return nil, err
	}
...
-	// 自动在指定路径load plugins
+	plugins, err := LoadPlugins(ctx, config)
...
+	ttrpcServer, err := newTTRPCServer()

	tcpServerOpts := serverOpts
...
	var (
+		grpcServer = grpc.NewServer(serverOpts...)
+		tcpServer  = grpc.NewServer(tcpServerOpts...)

		grpcServices  []plugin.Service
		tcpServices   []plugin.TCPService
		ttrpcServices []plugin.TTRPCService

		s = &Server{
			grpcServer:  grpcServer,
			tcpServer:   tcpServer,
			ttrpcServer: ttrpcServer,
			config:      config,
		}
		// TODO: Remove this in 2.0 and let event plugin crease it
		events      = exchange.NewExchange()
		initialized = plugin.NewPluginSet()
		required    = make(map[string]struct{})
	)
	for _, r := range config.RequiredPlugins {
		required[r] = struct{}{}
	}
	for _, p := range plugins {
		id := p.URI()
		reqID := id
		if config.GetVersion() == 1 {
			reqID = p.ID
		}
		log.G(ctx).WithField("type", p.Type).Infof("loading plugin %q...", id)

		initContext := plugin.NewContext(
			ctx,
			p,
			initialized,
			config.Root,
			config.State,
		)
		initContext.Events = events
		initContext.Address = config.GRPC.Address
		initContext.TTRPCAddress = config.TTRPC.Address

		// load the plugin specific configuration if it is provided
		if p.Config != nil {
			pc, err := config.Decode(p)
			if err != nil {
				return nil, err
			}
			initContext.Config = pc
		}
-		//初始化plugin		
+		result := p.Init(initContext)
+		if err := initialized.Add(result); err != nil {
			return nil, errors.Wrapf(err, "could not add plugin result to plugin set")
		}

		instance, err := result.Instance()
...

		delete(required, reqID)
-		// 把三种类型server的services分别放入各自的列表
		// check for grpc services that should be registered with the server
		if src, ok := instance.(plugin.Service); ok {
+			grpcServices = append(grpcServices, src)
		}
		if src, ok := instance.(plugin.TTRPCService); ok {
+			ttrpcServices = append(ttrpcServices, src)
		}
		if service, ok := instance.(plugin.TCPService); ok {
+			tcpServices = append(tcpServices, service)
		}

		s.plugins = append(s.plugins, result)
	}
	if len(required) != 0 {
		var missing []string
		for id := range required {
			missing = append(missing, id)
		}
		return nil, errors.Errorf("required plugin %s not included", missing)
	}

-	//按照server类型注册services
	// register services after all plugins have been initialized
	for _, service := range grpcServices {
		if err := service.Register(grpcServer); err != nil {
			return nil, err
		}
	}
	for _, service := range ttrpcServices {
		if err := service.RegisterTTRPC(ttrpcServer); err != nil {
			return nil, err
		}
	}
	for _, service := range tcpServices {
		if err := service.RegisterTCP(tcpServer); err != nil {
			return nil, err
		}
	}
	return s, nil
}
```

### 加载Plugins
- 按照Load方式不同，有两类Plugins，一是从指定路径自动加载，二是程序里手动加载，如ContentPlugin, MetadataPlugin

```diff
func LoadPlugins(ctx context.Context, config *srvconfig.Config) ([]*plugin.Registration, error) {
-	// 自动加载Plugins。这些plugins通常被编译成binary，放在指定的目录PlguinDir下
	// load all plugins into containerd
	path := config.PluginDir
	if path == "" {
		path = filepath.Join(config.Root, "plugins")
	}
+	if err := plugin.Load(path); err != nil {
		return nil, err
	}
-	// 部分plugins需要手动加载
	// load additional plugins that don't automatically register themselves
	plugin.Register(&plugin.Registration{
		Type: plugin.ContentPlugin,
		ID:   "content",
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			ic.Meta.Exports["root"] = ic.Root
			return local.NewStore(ic.Root)
		},
	})
	plugin.Register(&plugin.Registration{
		Type: plugin.MetadataPlugin,
		ID:   "bolt",
		Requires: []plugin.Type{
			plugin.ContentPlugin,
			plugin.SnapshotPlugin,
		},
		Config: &srvconfig.BoltConfig{
			ContentSharingPolicy: srvconfig.SharingPolicyShared,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			if err := os.MkdirAll(ic.Root, 0711); err != nil {
				return nil, err
			}
			cs, err := ic.Get(plugin.ContentPlugin)
			if err != nil {
				return nil, err
			}

			snapshottersRaw, err := ic.GetByType(plugin.SnapshotPlugin)
			if err != nil {
				return nil, err
			}

			snapshotters := make(map[string]snapshots.Snapshotter)
			for name, sn := range snapshottersRaw {
				sn, err := sn.Instance()
				if err != nil {
					if !plugin.IsSkipPlugin(err) {
						log.G(ic.Context).WithError(err).
							Warnf("could not use snapshotter %v in metadata plugin", name)
					}
					continue
				}
				snapshotters[name] = sn.(snapshots.Snapshotter)
			}

			shared := true
			ic.Meta.Exports["policy"] = srvconfig.SharingPolicyShared
			if cfg, ok := ic.Config.(*srvconfig.BoltConfig); ok {
				if cfg.ContentSharingPolicy != "" {
					if err := cfg.Validate(); err != nil {
						return nil, err
					}
					if cfg.ContentSharingPolicy == srvconfig.SharingPolicyIsolated {
						ic.Meta.Exports["policy"] = srvconfig.SharingPolicyIsolated
						shared = false
					}

					log.L.WithField("policy", cfg.ContentSharingPolicy).Info("metadata content store policy set")
				}
			}

			path := filepath.Join(ic.Root, "meta.db")
			ic.Meta.Exports["path"] = path

			db, err := bolt.Open(path, 0644, nil)
			if err != nil {
				return nil, err
			}

			var dbopts []metadata.DBOpt
			if !shared {
				dbopts = append(dbopts, metadata.WithPolicyIsolated)
			}
			mdb := metadata.NewDB(db, cs.(content.Store), snapshotters, dbopts...)
			if err := mdb.Init(ic.Context); err != nil {
				return nil, err
			}
			return mdb, nil
		},
	})

...省略proxyplugins部分...

	// return the ordered graph for plugins
+	return plugin.Graph(filter(config.DisabledPlugins)), nil
}
```

### 创建底层Server
- 有3种server：grpcServer，和ttrpcServer，tcpServer
```diff
+	ttrpcServer, err := newTTRPCServer()
+	tcpServerOpts := serverOpts
+	var (
+		grpcServer = grpc.NewServer(serverOpts...)
+		tcpServer  = grpc.NewServer(tcpServerOpts...)

+		grpcServices  []plugin.Service
+		tcpServices   []plugin.TCPService
+		ttrpcServices []plugin.TTRPCService

+		s = &Server{
+			grpcServer:  grpcServer,
+			tcpServer:   tcpServer,
+			ttrpcServer: ttrpcServer,
+			config:      config,
+		}
```
- 根据加载的plugins，分别为3种server注册service
```diff
	// register services after all plugins have been initialized
	for _, service := range grpcServices {
+		if err := service.Register(grpcServer); err != nil {
			return nil, err
		}
	}
	for _, service := range ttrpcServices {
+		if err := service.RegisterTTRPC(ttrpcServer); err != nil {
			return nil, err
		}
	}
	for _, service := range tcpServices {
+		if err := service.RegisterTCP(tcpServer); err != nil {
			return nil, err
		}
	}
```

### 启动服务
- 以grpc server为例，安装serve function
- 回到***cmd/containerd/command/main.go***，在完成server创建和初始化后，每种server都要被serve一次，表示服务开启。
```diff
		l, err := sys.GetLocalListener(config.GRPC.Address, config.GRPC.UID, config.GRPC.GID)
-		// 注意，第三个参数serveFunc = server.ServeGRPC
+		serve(ctx, l, server.ServeGRPC)
```

https://github.com/containerd/containerd/blob/d0be7b90f1306d2c7d59e28d3ffd74eddcddfa21/cmd/containerd/command/main.go#L259
```diff
func serve(ctx gocontext.Context, l net.Listener, serveFunc func(net.Listener) error) {
	path := l.Addr().String()
	log.G(ctx).WithField("address", path).Info("serving...")
	serveSpan, ctx := tracing.StartSpan(ctx, l.Addr().String())
	defer tracing.StopSpan(serveSpan)

	go func() {
		defer l.Close()
+		if err := serveFunc(l); err != nil {
			log.G(ctx).WithError(err).WithField("address", path).Fatal("serve failure")
		}
	}()
}
```
(https://github.com/containerd/containerd/blob/d0be7b90f1306d2c7d59e28d3ffd74eddcddfa21/services/server/server.go#L263)
```diff
// ServeGRPC provides the containerd grpc APIs on the provided listener
func (s *Server) ServeGRPC(l net.Listener) error {
	if s.config.Metrics.GRPCHistogram {
		// enable grpc time histograms to measure rpc latencies
		grpc_prometheus.EnableHandlingTimeHistogram()
	}
	// before we start serving the grpc API register the grpc_prometheus metrics
	// handler.  This needs to be the last service registered so that it can collect
	// metrics for every other service
	grpc_prometheus.Register(s.grpcServer)
+	return trapClosedConnErr(s.grpcServer.Serve(l))
}
```
