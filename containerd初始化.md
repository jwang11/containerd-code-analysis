# Containerd初始化

---
>Containerd是一个工业标准的容器运行时，重点是它简洁，健壮，便携，在Linux和window上可以作为一个守护进程运行，它可以管理主机系统上容器的完整的生命周期：镜像传输和存储，容器的执行和监控，低级别的存储和网络。

## 1. 主程序

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
			srvconfig.LoadConfig(configPath, config)
		}
-		// 命令行flags的优先级比config文件高，要apply一下
		// Apply flags to the config
		applyFlags(context, config)

-		// 建立root和state顶层目录
		// Make sure top-level directories are created early.
		server.CreateTopLevelDirectories(config)

		done := handleSignals(ctx, signals, serverC, cancel)
		// start the signal handler as soon as we can to make sure that
		// we don't miss any signals during boot
		signal.Notify(signals, handledSignals...)

		// cleanup temp mounts
		mount.SetTempMountLocation(filepath.Join(config.Root, "tmpmounts"))
		// unmount all temp mounts on boot for the server
		warnings, err := mount.CleanupTempMounts(0)

		if config.TTRPC.Address == "" {
			// If TTRPC was not explicitly configured, use defaults based on GRPC.
			config.TTRPC.Address = fmt.Sprintf("%s.ttrpc", config.GRPC.Address)
			config.TTRPC.UID = config.GRPC.UID
			config.TTRPC.GID = config.GRPC.GID
		}

		log.G(ctx).WithFields(logrus.Fields{
			"version":  version.Version,
			"revision": version.Revision,
		}).Info("starting containerd")

-		// Server的创建及初始化
		type srvResp struct {
			s   *server.Server
			err error
		}

		// run server initialization in a goroutine so we don't end up blocking important things like SIGTERM handling
		// while the server is initializing.
		// As an example opening the bolt database will block forever if another containerd is already running and containerd
		// will have to be be `kill -9`'ed to recover.
		chsrv := make(chan srvResp)
		go func() {
			defer close(chsrv)
-			// New服务器
+			server, err := server.New(ctx, config)
			select {
			case <-ctx.Done():
				server.Stop()
			case chsrv <- srvResp{s: server}:
			}
		}()

		var server *server.Server
		select {
		case <-ctx.Done():
			return ctx.Err()
		case r := <-chsrv:
			if r.err != nil {
				return err
			}
			server = r.s
		}

		// We don't send the server down serverC directly in the goroutine above because we need it lower down.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case serverC <- server:
		}

		if config.Metrics.Address != "" {
+			l, err := net.Listen("tcp", config.Metrics.Address)
			serve(ctx, l, server.ServeMetrics)
		}
		// setup the ttrpc endpoint
		tl, err := sys.GetLocalListener(config.TTRPC.Address, config.TTRPC.UID, config.TTRPC.GID)
		serve(ctx, tl, server.ServeTTRPC)

		if config.GRPC.TCPAddress != "" {
			l, err := net.Listen("tcp", config.GRPC.TCPAddress)
			serve(ctx, l, server.ServeTCP)
		}
		// setup the main grpc endpoint
		l, err := sys.GetLocalListener(config.GRPC.Address, config.GRPC.UID, config.GRPC.GID)
+		serve(ctx, l, server.ServeGRPC)

-		// 通知systemd，containerd在ready状态
		err := notifyReady(ctx)

		log.G(ctx).Infof("containerd successfully booted in %fs", time.Since(start).Seconds())
		<-done
		return nil
	}
	return app
}
}

// notifyReady notifies systemd that the daemon is ready to serve requests
func notifyReady(ctx context.Context) error {
+	return sdNotify(ctx, sd.SdNotifyReady)
}
```
## 2. Server的创建及初始化

### 2.1 创建Server
主程序里调用`server, err := server.New(ctx, config)`

该函数是创建并初始化containerd server，
- 加载plugins，逐个调用p.Init(initContext)来初始化
- 创建GRPCServer，TTRPCServer，tcpServer并注册服务

[service/server/server.go](https://github.com/containerd/containerd/blob/master/services/server/server.go#L83)
```diff
// New creates and initializes a new containerd server
func New(ctx context.Context, config *srvconfig.Config) (*Server, error) {
-	// apply OOMScore和Cgroup
	apply(ctx, config)
	for key, sec := range config.Timeouts {
		d, err := time.ParseDuration(sec)
		timeout.Set(key, d)
	}
-	// 自动在指定路径load plugins
	plugins, err := LoadPlugins(ctx, config)
-	// 给Diff用的MediaType处理器,用于解压	
	for id, p := range config.StreamProcessors {
		diff.RegisterProcessor(diff.BinaryHandler(id, p.Returns, p.Accepts, p.Path, p.Args, p.Env))
	}
-	// 流式gRPC	
	serverOpts := []grpc.ServerOption{
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
			otelgrpc.StreamServerInterceptor(),
			grpc.StreamServerInterceptor(grpc_prometheus.StreamServerInterceptor),
		)),
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			otelgrpc.UnaryServerInterceptor(),
			grpc.UnaryServerInterceptor(grpc_prometheus.UnaryServerInterceptor),
		)),
	}	
	if config.GRPC.MaxRecvMsgSize > 0 {
		serverOpts = append(serverOpts, grpc.MaxRecvMsgSize(config.GRPC.MaxRecvMsgSize))
	}
	if config.GRPC.MaxSendMsgSize > 0 {
		serverOpts = append(serverOpts, grpc.MaxSendMsgSize(config.GRPC.MaxSendMsgSize))
	}
+	ttrpcServer, err := newTTRPCServer()

	tcpServerOpts := serverOpts
	if config.GRPC.TCPTLSCert != "" {
		log.G(ctx).Info("setting up tls on tcp GRPC services...")

		tlsCert, err := tls.LoadX509KeyPair(config.GRPC.TCPTLSCert, config.GRPC.TCPTLSKey)
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{tlsCert}}

		if config.GRPC.TCPTLSCA != "" {
			caCertPool := x509.NewCertPool()
			caCert, err := os.ReadFile(config.GRPC.TCPTLSCA)
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		tcpServerOpts = append(tcpServerOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}
	
	// grpcService allows GRPC services to be registered with the underlying server
	type grpcService interface {
		Register(*grpc.Server) error
	}

	// tcpService allows GRPC services to be registered with the underlying tcp server
	type tcpService interface {
		RegisterTCP(*grpc.Server) error
	}

	// ttrpcService allows TTRPC services to be registered with the underlying server
	type ttrpcService interface {
		RegisterTTRPC(*ttrpc.Server) error
	}
	
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
			initContext.Config = pc
		}
-		//初始化plugin		
		result := p.Init(initContext)
+		if err := initialized.Add(result); err != nil {
			return nil, errors.Wrapf(err, "could not add plugin result to plugin set")
		}

		instance, err := result.Instance()

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
-		// 运行service里的Register方法	
		if err := service.Register(grpcServer); err != nil {
			return nil, err
		}
	}
	for _, service := range ttrpcServices {
-		// 运行service里的Register方法	
		if err := service.RegisterTTRPC(ttrpcServer); err != nil {
			return nil, err
		}
	}
	
	for _, service := range tcpServices {
-		// 运行service里的Register方法	
		if err := service.RegisterTCP(tcpServer); err != nil {
			return nil, err
		}
	}
	return s, nil
}
```

### 2.2 加载Plugins
Server.New里调用`plugins, err := LoadPlugins(ctx, config)`

按照Load方式不同，有两类Plugins，
- 一是从指定路径自动加载
- 二是程序里手动加载，如ContentPlugin, MetadataPlugin

```diff
func LoadPlugins(ctx context.Context, config *srvconfig.Config) ([]*plugin.Registration, error) {
-	// 自动加载Plugins。这些plugins通常被编译成binary，放在指定的目录PlguinDir下
	// load all plugins into containerd
	path := config.PluginDir
	if path == "" {
		path = filepath.Join(config.Root, "plugins")
	}
-	// 从指定路径自动加载Plugin binary	
	if err := plugin.Load(path); err != nil {
		return nil, err
	}
-	// 部分plugins需要手动加载，详细参看[metadata服务](Metadata服务.md)
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

	clients := &proxyClients{}
	for name, pp := range config.ProxyPlugins {
		var (
			t plugin.Type
			f func(*grpc.ClientConn) interface{}

			address = pp.Address
		)

		switch pp.Type {
		case string(plugin.SnapshotPlugin), "snapshot":
			t = plugin.SnapshotPlugin
			ssname := name
			f = func(conn *grpc.ClientConn) interface{} {
				return ssproxy.NewSnapshotter(ssapi.NewSnapshotsClient(conn), ssname)
			}

		case string(plugin.ContentPlugin), "content":
			t = plugin.ContentPlugin
			f = func(conn *grpc.ClientConn) interface{} {
				return csproxy.NewContentStore(csapi.NewContentClient(conn))
			}
		default:
			log.G(ctx).WithField("type", pp.Type).Warn("unknown proxy plugin type")
		}

		plugin.Register(&plugin.Registration{
			Type: t,
			ID:   name,
			InitFn: func(ic *plugin.InitContext) (interface{}, error) {
				ic.Meta.Exports["address"] = address
				conn, err := clients.getClient(address)
				if err != nil {
					return nil, err
				}
				return f(conn), nil
			},
		})

	}
	filter := srvconfig.V2DisabledFilter
	if config.GetVersion() == 1 {
		filter = srvconfig.V1DisabledFilter
	}
	// return the ordered graph for plugins
+	return plugin.Graph(filter(config.DisabledPlugins)), nil
}
```

### 2.3 启动服务
- 完成server创建和初始化后，每种server都要被serve一次，表示服务开启。
```diff
		l, err := sys.GetLocalListener(config.GRPC.Address, config.GRPC.UID, config.GRPC.GID)
-		// 注意第三个参数serveFunc代表了Server类型
		serve(ctx, l, server.ServeGRPC)
```
```diff
func serve(ctx gocontext.Context, l net.Listener, serveFunc func(net.Listener) error) {
	path := l.Addr().String()
	log.G(ctx).WithField("address", path).Info("serving...")
	serveSpan, ctx := tracing.StartSpan(ctx, l.Addr().String())
	defer tracing.StopSpan(serveSpan)

	go func() {
		defer l.Close()
+		serveFunc(l)
	}()
}

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
