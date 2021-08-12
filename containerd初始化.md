# Containerd初始化

---
>Containerd是一个工业标准的容器运行时，重点是它简洁，健壮，便携，在Linux和window上可以作为一个守护进程运行，它可以管理主机系统上容器的完整的生命周期：镜像传输和存储，容器的执行和监控，低级别的存储和网络。

[cmd/containerd/main.go](https://github.com/containerd/containerd/blob/main/cmd/containerd/main.go)是入口文件，看起来非常简洁

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
```
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

		server, err := server.New(ctx, config)
		if err != nil {
			return err
		}

		// Launch as a Windows Service if necessary
		if err := launchService(server, done); err != nil {
			logrus.Fatal(err)
		}

		serverC <- server

		if config.Debug.Address != "" {
			var l net.Listener
			if isLocalAddress(config.Debug.Address) {
				if l, err = sys.GetLocalListener(config.Debug.Address, config.Debug.UID, config.Debug.GID); err != nil {
					return errors.Wrapf(err, "failed to get listener for debug endpoint")
				}
			} else {
				if l, err = net.Listen("tcp", config.Debug.Address); err != nil {
					return errors.Wrapf(err, "failed to get listener for debug endpoint")
				}
			}
			serve(ctx, l, server.ServeDebug)
		}
		if config.Metrics.Address != "" {
			l, err := net.Listen("tcp", config.Metrics.Address)
			if err != nil {
				return errors.Wrapf(err, "failed to get listener for metrics endpoint")
			}
			serve(ctx, l, server.ServeMetrics)
		}
		// setup the ttrpc endpoint
		tl, err := sys.GetLocalListener(config.TTRPC.Address, config.TTRPC.UID, config.TTRPC.GID)
		if err != nil {
			return errors.Wrapf(err, "failed to get listener for main ttrpc endpoint")
		}
		serve(ctx, tl, server.ServeTTRPC)

		if config.GRPC.TCPAddress != "" {
			l, err := net.Listen("tcp", config.GRPC.TCPAddress)
			if err != nil {
				return errors.Wrapf(err, "failed to get listener for TCP grpc endpoint")
			}
			serve(ctx, l, server.ServeTCP)
		}
		// setup the main grpc endpoint
		l, err := sys.GetLocalListener(config.GRPC.Address, config.GRPC.UID, config.GRPC.GID)
		if err != nil {
			return errors.Wrapf(err, "failed to get listener for main endpoint")
		}
		serve(ctx, l, server.ServeGRPC)

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
## Server的创建及初始化
看`***server, err := server.New(ctx, config)***`函数是创建并初始化containerd server，
- 准备GRPC，TTPRC服务接口
- 加载plugins
[service/server/server.go](https://github.com/containerd/containerd/blob/7d4c95ff04a4b65ddd12963ef20ff7b5d3d24b96/services/server/server.go#L83)
```
// New creates and initializes a new containerd server
func New(ctx context.Context, config *srvconfig.Config) (*Server, error) {
	if err := apply(ctx, config); err != nil {
		return nil, err
	}
	for key, sec := range config.Timeouts {
		d, err := time.ParseDuration(sec)
		if err != nil {
			return nil, errors.Errorf("unable to parse %s into a time duration", sec)
		}
		timeout.Set(key, d)
	}
	plugins, err := LoadPlugins(ctx, config)
	if err != nil {
		return nil, err
	}
	for id, p := range config.StreamProcessors {
		diff.RegisterProcessor(diff.BinaryHandler(id, p.Returns, p.Accepts, p.Path, p.Args, p.Env))
	}

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
	ttrpcServer, err := newTTRPCServer()
	if err != nil {
		return nil, err
	}
	tcpServerOpts := serverOpts
	if config.GRPC.TCPTLSCert != "" {
		log.G(ctx).Info("setting up tls on tcp GRPC services...")

		tlsCert, err := tls.LoadX509KeyPair(config.GRPC.TCPTLSCert, config.GRPC.TCPTLSKey)
		if err != nil {
			return nil, err
		}
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{tlsCert}}

		if config.GRPC.TCPTLSCA != "" {
			caCertPool := x509.NewCertPool()
			caCert, err := ioutil.ReadFile(config.GRPC.TCPTLSCA)
			if err != nil {
				return nil, errors.Wrap(err, "failed to load CA file")
			}
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		tcpServerOpts = append(tcpServerOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}
	var (
		grpcServer = grpc.NewServer(serverOpts...)
		tcpServer  = grpc.NewServer(tcpServerOpts...)

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
		result := p.Init(initContext)
		if err := initialized.Add(result); err != nil {
			return nil, errors.Wrapf(err, "could not add plugin result to plugin set")
		}

		instance, err := result.Instance()
		if err != nil {
			if plugin.IsSkipPlugin(err) {
				log.G(ctx).WithError(err).WithField("type", p.Type).Infof("skip loading plugin %q...", id)
			} else {
				log.G(ctx).WithError(err).Warnf("failed to load plugin %s", id)
			}
			if _, ok := required[reqID]; ok {
				return nil, errors.Wrapf(err, "load required plugin %s", id)
			}
			continue
		}

		delete(required, reqID)
		// check for grpc services that should be registered with the server
		if src, ok := instance.(plugin.Service); ok {
			grpcServices = append(grpcServices, src)
		}
		if src, ok := instance.(plugin.TTRPCService); ok {
			ttrpcServices = append(ttrpcServices, src)
		}
		if service, ok := instance.(plugin.TCPService); ok {
			tcpServices = append(tcpServices, service)
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

// Server is the containerd main daemon
type Server struct {
	grpcServer  *grpc.Server
	ttrpcServer *ttrpc.Server
	tcpServer   *grpc.Server
	config      *srvconfig.Config
	plugins     []*plugin.Plugin
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
	return trapClosedConnErr(s.grpcServer.Serve(l))
}
```
