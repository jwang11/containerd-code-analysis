# shim_runc_v2垫片代码分析
> shim_runc_v2是containerd shim的v2版本。shim是containerd之外的独立进程，用来“垫”在containerd和runc启动的容器之间的，其主要作用是：
> 1. 和containerd端的runtime_v2服务交互，调用runc命令创建、启动、停止、删除容器等
> 2. 作为容器的父进程，当容器中的第一个实例进程被杀死后，负责给其子进程收尸，避免出现僵尸进程
> 3. 监控容器中运行的进程状态，当容器执行完成后，通过exit fifo文件来返回容器进程结束状态

## 1. [主程序](https://github.com/containerd/containerd/blob/main/cmd/containerd-shim-runc-v2/main.go)
```diff
import (
	v2 "github.com/containerd/containerd/runtime/v2/runc/v2"
	"github.com/containerd/containerd/runtime/v2/shim"
)

func main() {
+	shim.Run("io.containerd.runc.v2", v2.New)
}
```

### 1.1 [shim.Run](https://github.com/containerd/containerd/blob/main/runtime/v2/shim/shim.go)，注意参数initFunc=v2.New
```diff
// Run initializes and runs a shim server
func Run(id string, initFunc Init, opts ...BinaryOpts) {
	var config Config
	for _, o := range opts {
		o(&config)
	}
+	run(id, initFunc, config)
}

func parseFlags() {
	flag.BoolVar(&debugFlag, "debug", false, "enable debug output in logs")
	flag.BoolVar(&versionFlag, "v", false, "show the shim version and exit")
	flag.StringVar(&namespaceFlag, "namespace", "", "namespace that owns the shim")
	flag.StringVar(&idFlag, "id", "", "id of the task")
	flag.StringVar(&socketFlag, "socket", "", "socket path to serve")
	flag.StringVar(&bundlePath, "bundle", "", "path to the bundle if not workdir")

	flag.StringVar(&addressFlag, "address", "", "grpc address back to main containerd")
	flag.StringVar(&containerdBinaryFlag, "publish-binary", "containerd", "path to publish binary (used for publishing events)")

	flag.Parse()
	action = flag.Arg(0)
}

func run(id string, initFunc Init, config Config) error {
	parseFlags()
	if versionFlag {
		fmt.Printf("%s:\n", os.Args[0])
		fmt.Println("  Version: ", version.Version)
		fmt.Println("  Revision:", version.Revision)
		fmt.Println("  Go version:", version.GoVersion)
		fmt.Println("")
		return nil
	}

	setRuntime()

	signals, err := setupSignals(config)

-	// 指定shim是subreaper
	if !config.NoSubreaper {
		subreaper()
	}

-	// 环境变量得到ttrpc address
	ttrpcAddress := os.Getenv(ttrpcAddressEnv)
	publisher, err := NewPublisher(ttrpcAddress)
	defer publisher.Close()

	ctx := namespaces.WithNamespace(context.Background(), namespaceFlag)
	ctx = context.WithValue(ctx, OptsKey{}, Opts{BundlePath: bundlePath, Debug: debugFlag})
	ctx = log.WithLogger(ctx, log.G(ctx).WithField("runtime", id))
	ctx, cancel := context.WithCancel(ctx)
-	// 创建task service	
	service, err := initFunc(ctx, idFlag, publisher, cancel)

	// Handle explicit actions
	switch action {
	case "delete":
		logger := logrus.WithFields(logrus.Fields{
			"pid":       os.Getpid(),
			"namespace": namespaceFlag,
		})
		go handleSignals(ctx, logger, signals)
		response, err := service.Cleanup(ctx)
		data, err := proto.Marshal(response)
		os.Stdout.Write(data)
		return nil
	case "start":
		opts := StartOpts{
			ID:               idFlag,
			ContainerdBinary: containerdBinaryFlag,
			Address:          addressFlag,
			TTRPCAddress:     ttrpcAddress,
		}
-		// 启动一个新的shim进程
		address, err := service.StartShim(ctx, opts)
-		// 打印地址，runtime_v2端可以获得		
		os.Stdout.WriteString(address)
		return nil
	}


	if !config.NoSetupLogger {
		setLogger(ctx, idFlag)
	}

	// Register event plugin
	plugin.Register(&plugin.Registration{
		Type: plugin.EventPlugin,
		ID:   "publisher",
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			return publisher, nil
		},
	})

-	// 注册TTRPCPlugin
	// If service is an implementation of the task service, register it as a plugin
	if ts, ok := service.(shimapi.TaskService); ok {
		plugin.Register(&plugin.Registration{
			Type: plugin.TTRPCPlugin,
			ID:   "task",
			InitFn: func(ic *plugin.InitContext) (interface{}, error) {
				return &taskService{ts}, nil
			},
		})
	}

	var (
		initialized   = plugin.NewPluginSet()
		ttrpcServices = []ttrpcService{}
	)
	plugins := plugin.Graph(func(*plugin.Registration) bool { return false })
	for _, p := range plugins {
		id := p.URI()
		log.G(ctx).WithField("type", p.Type).Infof("loading plugin %q...", id)

		initContext := plugin.NewContext(
			ctx,
			p,
			initialized,
			// NOTE: Root is empty since the shim does not support persistent storage,
			// shim plugins should make use state directory for writing files to disk.
			// The state directory will be destroyed when the shim if cleaned up or
			// on reboot
			"",
			bundlePath,
		)
		initContext.Address = addressFlag
		initContext.TTRPCAddress = ttrpcAddress

		// load the plugin specific configuration if it is provided
		//TODO: Read configuration passed into shim, or from state directory?
		//if p.Config != nil {
		//	pc, err := config.Decode(p)
		//	if err != nil {
		//		return nil, err
		//	}
		//	initContext.Config = pc
		//}

		result := p.Init(initContext)
		initialized.Add(result)

		instance, err := result.Instance()
		if src, ok := instance.(ttrpcService); ok {
			logrus.WithField("id", id).Debug("registering ttrpc service")
			ttrpcServices = append(ttrpcServices, src)
		}
	}
-	// 创建ttRPC server
	server, err := newServer()

-	// 调用每个service的RegisterTTRPC方法，完成初始化
	for _, srv := range ttrpcServices {
		srv.RegisterTTRPC(server)
	}

-	// 监听服务端口，ttRPC服务正式上线
	if err := serve(ctx, server, signals); err != nil {
		if err != context.Canceled {
			return err
		}
	}

	// NOTE: If the shim server is down(like oom killer), the address
	// socket might be leaking.
	if address, err := ReadAddress("address"); err == nil {
		_ = RemoveSocket(address)
	}

	select {
	case <-publisher.Done():
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("publisher not closed")
	}
}

func newServer() (*ttrpc.Server, error) {
	return ttrpc.NewServer(ttrpc.WithServerHandshaker(ttrpc.UnixSocketRequireSameUser()))
}
```
>> ***serve(ctx, server, signals)***
```diff
// serve serves the ttrpc API over a unix socket in the current working directory
// and blocks until the context is canceled
func serve(ctx context.Context, server *ttrpc.Server, signals chan os.Signal) error {
	dump := make(chan os.Signal, 32)
	setupDumpStacks(dump)

	path, err := os.Getwd()
	if err != nil {
		return err
	}

+	l, err := serveListener(socketFlag)
	if err != nil {
		return err
	}
	go func() {
		defer l.Close()
		if err := server.Serve(ctx, l); err != nil &&
			!strings.Contains(err.Error(), "use of closed network connection") {
			logrus.WithError(err).Fatal("containerd-shim: ttrpc server failure")
		}
	}()
	logger := logrus.WithFields(logrus.Fields{
		"pid":       os.Getpid(),
		"path":      path,
		"namespace": namespaceFlag,
	})
	go func() {
		for range dump {
			dumpStacks(logger)
		}
	}()
	return handleSignals(ctx, logger, signals)
}
```
>> ***serveListener***
```diff
func serveListener(path string) (net.Listener, error) {
	var (
		l   net.Listener
		err error
	)
	if path == "" {
		l, err = net.FileListener(os.NewFile(3, "socket"))
		path = "[inherited from parent]"
	} else {
		if len(path) > socketPathLimit {
			return nil, errors.Errorf("%q: unix socket path too long (> %d)", path, socketPathLimit)
		}
		l, err = net.Listen("unix", path)
	}
	if err != nil {
		return nil, err
	}
	logrus.WithField("socket", path).Debug("serving api on socket")
	return l, nil
}
```

## 2. Shim_runc服务 
### 2.1 [v2.New](https://github.com/containerd/containerd/blob/main/runtime/v2/runc/v2/service.go)生成shim_runc服务，同时也是task service服务
```diff
// New returns a new shim service that can be used via GRPC
func New(ctx context.Context, id string, publisher shim.Publisher, shutdown func()) (shim.Shim, error) {
	var (
		ep  oom.Watcher
		err error
	)
	if cgroups.Mode() == cgroups.Unified {
		ep, err = oomv2.New(publisher)
	} else {
		ep, err = oomv1.New(publisher)
	}

	go ep.Run(ctx)
-	// 既实现了shim.Shim接口，也实现了taskService接口
	s := &service{
		id:         id,
		context:    ctx,
		events:     make(chan interface{}, 128),
		ec:         reaper.Default.Subscribe(),
		ep:         ep,
		cancel:     shutdown,
		containers: make(map[string]*runc.Container),
	}
	go s.processExits()
	runcC.Monitor = reaper.Default
+	s.initPlatform()
+	go s.forward(ctx, publisher)

	if address, err := shim.ReadAddress("address"); err == nil {
		s.shimAddress = address
	}
	return s, nil
}

// service is the shim implementation of a remote shim over GRPC
type service struct {
	mu          sync.Mutex
	eventSendMu sync.Mutex

	context  context.Context
	events   chan interface{}
	platform stdio.Platform
	ec       chan runcC.Exit
	ep       oom.Watcher

	// id only used in cleanup case
	id string

	containers map[string]*runc.Container

	shimAddress string
	cancel      func()
}

// Shim server interface
type Shim interface {
	Cleanup(ctx context.Context) (*shimapi.DeleteResponse, error)
	StartShim(ctx context.Context, opts StartOpts) (string, error)
}
```

### 2.2 接口实现
- ***shim_runc service***实现
```diff
// initialize a single epoll fd to manage our consoles. `initPlatform` should
// only be called once.
func (s *service) initPlatform() error {
	if s.platform != nil {
		return nil
	}
+	p, err := runc.NewPlatform()
	s.platform = p
	return nil
}

func NewPlatform() (stdio.Platform, error) {
	epoller, err := console.NewEpoller()
	go epoller.Wait()
	return &linuxPlatform{
		epoller: epoller,
	}, nil
}
```
- ***startShim***生成新的Shim进程
```diff
func (s *service) StartShim(ctx context.Context, opts shim.StartOpts) (_ string, retErr error) {
	cmd, err := newCommand(ctx, opts.ID, opts.ContainerdBinary, opts.Address, opts.TTRPCAddress)
	grouping := opts.ID
	spec, err := readSpec()
	for _, group := range groupLabels {
		if groupID, ok := spec.Annotations[group]; ok {
			grouping = groupID
			break
		}
	}
-	// 生成一个新的socket地址给ttRPC server，如/var/run/containerd/2a1ba987aebca5dfa3c99d9158ded473538eb5d2e9a320baf5bcf55abb50a308
	address, err := shim.SocketAddress(ctx, opts.Address, grouping)

-	// 打开address，监听socket地址，注意，这时候socket的fd=3
	socket, err := shim.NewSocket(address)

-	// 把address地址写入文件，以便第二次启动时使用
	// make sure that reexec shim-v2 binary use the value if need
	shim.WriteAddress("address", address)

	f, err := socket.File()

	cmd.ExtraFiles = append(cmd.ExtraFiles, f)
-	// 启动命令
	cmd.Start()
	defer func() {
		if retErr != nil {
			cmd.Process.Kill()
		}
	}()
	// make sure to wait after start
	go cmd.Wait()
	if data, err := ioutil.ReadAll(os.Stdin); err == nil {
		if len(data) > 0 {
			var any ptypes.Any
			if err := proto.Unmarshal(data, &any); err != nil {
				return "", err
			}
			v, err := typeurl.UnmarshalAny(&any)
			if err != nil {
				return "", err
			}
			if opts, ok := v.(*options.Options); ok {
				if opts.ShimCgroup != "" {
					if cgroups.Mode() == cgroups.Unified {
						cg, err := cgroupsv2.LoadManager("/sys/fs/cgroup", opts.ShimCgroup)
						if err != nil {
							return "", errors.Wrapf(err, "failed to load cgroup %s", opts.ShimCgroup)
						}
						if err := cg.AddProc(uint64(cmd.Process.Pid)); err != nil {
							return "", errors.Wrapf(err, "failed to join cgroup %s", opts.ShimCgroup)
						}
					} else {
						cg, err := cgroups.Load(cgroups.V1, cgroups.StaticPath(opts.ShimCgroup))
						if err != nil {
							return "", errors.Wrapf(err, "failed to load cgroup %s", opts.ShimCgroup)
						}
						if err := cg.Add(cgroups.Process{
							Pid: cmd.Process.Pid,
						}); err != nil {
							return "", errors.Wrapf(err, "failed to join cgroup %s", opts.ShimCgroup)
						}
					}
				}
			}
		}
	}
	if err := shim.AdjustOOMScore(cmd.Process.Pid); err != nil {
		return "", errors.Wrap(err, "failed to adjust OOM score for shim")
	}
	return address, nil
}
```
>> ***newCommand***，***SocketAddress***
```diff
func newCommand(ctx context.Context, id, containerdBinary, containerdAddress, containerdTTRPCAddress string) (*exec.Cmd, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	args := []string{
		"-namespace", ns,
		"-id", id,
		"-address", containerdAddress,
	}
	cmd := exec.Command(self, args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "GOMAXPROCS=4")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	return cmd, nil
}

const socketRoot = defaults.DefaultStateDir

// SocketAddress returns a socket address
func SocketAddress(ctx context.Context, socketPath, id string) (string, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return "", err
	}
	d := sha256.Sum256([]byte(filepath.Join(socketPath, ns, id)))
	return fmt.Sprintf("unix://%s/%x", filepath.Join(socketRoot, "s"), d), nil
}
```

## 3. Service实现
- ***Create***
```diff
// Create a new initial process and container with the underlying OCI runtime
func (s *service) Create(ctx context.Context, r *taskAPI.CreateTaskRequest) (_ *taskAPI.CreateTaskResponse, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

+	container, err := runc.NewContainer(ctx, s.platform, r)
	if err != nil {
		return nil, err
	}

	s.containers[r.ID] = container

	s.send(&eventstypes.TaskCreate{
		ContainerID: r.ID,
		Bundle:      r.Bundle,
		Rootfs:      r.Rootfs,
		IO: &eventstypes.TaskIO{
			Stdin:    r.Stdin,
			Stdout:   r.Stdout,
			Stderr:   r.Stderr,
			Terminal: r.Terminal,
		},
		Checkpoint: r.Checkpoint,
		Pid:        uint32(container.Pid()),
	})

	return &taskAPI.CreateTaskResponse{
		Pid: uint32(container.Pid()),
	}, nil
}
```
>> ***runc.NewContainer(ctx, s.platform, r)***
```diff
// NewContainer returns a new runc container
func NewContainer(ctx context.Context, platform stdio.Platform, r *task.CreateTaskRequest) (_ *Container, retErr error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "create namespace")
	}

	var opts options.Options
	if r.Options != nil && r.Options.GetTypeUrl() != "" {
		v, err := typeurl.UnmarshalAny(r.Options)
		if err != nil {
			return nil, err
		}
		opts = *v.(*options.Options)
	}

	var mounts []process.Mount
	for _, m := range r.Rootfs {
		mounts = append(mounts, process.Mount{
			Type:    m.Type,
			Source:  m.Source,
			Target:  m.Target,
			Options: m.Options,
		})
	}

	rootfs := ""
	if len(mounts) > 0 {
		rootfs = filepath.Join(r.Bundle, "rootfs")
		if err := os.Mkdir(rootfs, 0711); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}

	config := &process.CreateConfig{
		ID:               r.ID,
		Bundle:           r.Bundle,
		Runtime:          opts.BinaryName,
		Rootfs:           mounts,
		Terminal:         r.Terminal,
		Stdin:            r.Stdin,
		Stdout:           r.Stdout,
		Stderr:           r.Stderr,
		Checkpoint:       r.Checkpoint,
		ParentCheckpoint: r.ParentCheckpoint,
		Options:          r.Options,
	}

	if err := WriteOptions(r.Bundle, opts); err != nil {
		return nil, err
	}
	// For historical reason, we write opts.BinaryName as well as the entire opts
	if err := WriteRuntime(r.Bundle, opts.BinaryName); err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			if err := mount.UnmountAll(rootfs, 0); err != nil {
				logrus.WithError(err).Warn("failed to cleanup rootfs mount")
			}
		}
	}()
	for _, rm := range mounts {
		m := &mount.Mount{
			Type:    rm.Type,
			Source:  rm.Source,
			Options: rm.Options,
		}
		if err := m.Mount(rootfs); err != nil {
			return nil, errors.Wrapf(err, "failed to mount rootfs component %v", m)
		}
	}

-	// 创建Process对象，代表container里的process
	p, err := newInit(
		ctx,
		r.Bundle,
		filepath.Join(r.Bundle, "work"),
		ns,
		platform,
		config,
		&opts,
		rootfs,
	)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
-	// p是Init,运行Init.Create
	if err := p.Create(ctx, config); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	container := &Container{
		ID:              r.ID,
		Bundle:          r.Bundle,
		process:         p,
		processes:       make(map[string]process.Process),
		reservedProcess: make(map[string]struct{}),
	}
	pid := p.Pid()
	if pid > 0 {
		var cg interface{}
		if cgroups.Mode() == cgroups.Unified {
			g, err := cgroupsv2.PidGroupPath(pid)
			if err != nil {
				logrus.WithError(err).Errorf("loading cgroup2 for %d", pid)
				return container, nil
			}
			cg, err = cgroupsv2.LoadManager("/sys/fs/cgroup", g)
			if err != nil {
				logrus.WithError(err).Errorf("loading cgroup2 for %d", pid)
			}
		} else {
			cg, err = cgroups.Load(cgroups.V1, cgroups.PidPath(pid))
			if err != nil {
				logrus.WithError(err).Errorf("loading cgroup for %d", pid)
			}
		}
		container.cgroup = cg
	}
	return container, nil
}
```
>>> ***newInit***
```diff
func newInit(ctx context.Context, path, workDir, namespace string, platform stdio.Platform,
	r *process.CreateConfig, options *options.Options, rootfs string) (*process.Init, error) {
+	runtime := process.NewRunc(options.Root, path, namespace, options.BinaryName, options.CriuPath, options.SystemdCgroup)
+	p := process.New(r.ID, runtime, stdio.Stdio{
		Stdin:    r.Stdin,
		Stdout:   r.Stdout,
		Stderr:   r.Stderr,
		Terminal: r.Terminal,
	})
	p.Bundle = r.Bundle
	p.Platform = platform
	p.Rootfs = rootfs
	p.WorkDir = workDir
	p.IoUID = int(options.IoUid)
	p.IoGID = int(options.IoGid)
	p.NoPivotRoot = options.NoPivotRoot
	p.NoNewKeyring = options.NoNewKeyring
	p.CriuWorkPath = options.CriuWorkPath
	if p.CriuWorkPath == "" {
		// if criu work path not set, use container WorkDir
		p.CriuWorkPath = p.WorkDir
	}
	return p, nil
}

// NewRunc returns a new runc instance for a process
func NewRunc(root, path, namespace, runtime, criu string, systemd bool) *runc.Runc {
	if root == "" {
		root = RuncRoot
	}
	return &runc.Runc{
		Command:       runtime,
		Log:           filepath.Join(path, "log.json"),
		LogFormat:     runc.JSON,
		PdeathSignal:  unix.SIGKILL,
		Root:          filepath.Join(root, namespace),
		Criu:          criu,
		SystemdCgroup: systemd,
	}
}

// New returns a new process
func New(id string, runtime *runc.Runc, stdio stdio.Stdio) *Init {
	p := &Init{
		id:        id,
		runtime:   runtime,
		pausing:   new(atomicBool),
		stdio:     stdio,
		status:    0,
		waitBlock: make(chan struct{}),
	}
	p.initState = &createdState{p: p}
	return p
}
```

>>> ***p.Create(ctx, config)***
```diff
// Create the process with the provided config
func (p *Init) Create(ctx context.Context, r *CreateConfig) error {
	var (
		err     error
		socket  *runc.Socket
		pio     *processIO
		pidFile = newPidFile(p.Bundle)
	)

	if r.Terminal {
		if socket, err = runc.NewTempConsoleSocket(); err != nil {
			return errors.Wrap(err, "failed to create OCI runtime console socket")
		}
		defer socket.Close()
	} else {
		if pio, err = createIO(ctx, p.id, p.IoUID, p.IoGID, p.stdio); err != nil {
			return errors.Wrap(err, "failed to create init process I/O")
		}
		p.io = pio
	}
	if r.Checkpoint != "" {
		return p.createCheckpointedState(r, pidFile)
	}
	opts := &runc.CreateOpts{
		PidFile:      pidFile.Path(),
		NoPivot:      p.NoPivotRoot,
		NoNewKeyring: p.NoNewKeyring,
	}
	if p.io != nil {
		opts.IO = p.io.IO()
	}
	if socket != nil {
-		// 设置console socket，这个socket会把runc container里的pty的master fd传出来。	
		opts.ConsoleSocket = socket
	}
-	// p.runtime是runc.Runc	
	if err := p.runtime.Create(ctx, r.ID, r.Bundle, opts); err != nil {
		return p.runtimeError(err, "OCI runtime create failed")
	}
	if r.Stdin != "" {
		if err := p.openStdin(r.Stdin); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if socket != nil {
-		// 获取到pty的master fd	
		console, err := socket.ReceiveMaster()
		if err != nil {
			return errors.Wrap(err, "failed to retrieve console master")
		}
-		// 从master fd获取stdin和stdout，交给fifo处理		
		console, err = p.Platform.CopyConsole(ctx, console, p.id, r.Stdin, r.Stdout, r.Stderr, &p.wg)
		if err != nil {
			return errors.Wrap(err, "failed to start console copy")
		}
		p.console = console
	} else {
		if err := pio.Copy(ctx, &p.wg); err != nil {
			return errors.Wrap(err, "failed to start io pipe copy")
		}
	}
	pid, err := pidFile.Read()
	if err != nil {
		return errors.Wrap(err, "failed to retrieve OCI runtime container pid")
	}
	p.pid = pid
	return nil
}
```

>>>> ***p.runtime.Create()***
```diff
// Create creates a new container and returns its pid if it was created successfully
func (r *Runc) Create(context context.Context, id, bundle string, opts *CreateOpts) error {
	args := []string{"create", "--bundle", bundle}
	if opts != nil {
		oargs, err := opts.args()
		if err != nil {
			return err
		}
		args = append(args, oargs...)
	}
	cmd := r.command(context, append(args, id)...)
	if opts != nil && opts.IO != nil {
		opts.Set(cmd)
	}
	cmd.ExtraFiles = opts.ExtraFiles

	if cmd.Stdout == nil && cmd.Stderr == nil {
		data, err := cmdOutput(cmd, true, nil)
		defer putBuf(data)
		if err != nil {
			return fmt.Errorf("%s: %s", err, data.String())
		}
		return nil
	}
-	// 执行runc create --bundle命令	
	ec, err := Monitor.Start(cmd)
	if err != nil {
		return err
	}
	if opts != nil && opts.IO != nil {
		if c, ok := opts.IO.(StartCloser); ok {
			if err := c.CloseAfterStart(); err != nil {
				return err
			}
		}
	}
	status, err := Monitor.Wait(cmd, ec)
	if err == nil && status != 0 {
		err = fmt.Errorf("%s did not terminate successfully: %w", cmd.Args[0], &ExitError{status})
	}
	return err
}
```

### Service.Start启动container
```diff
// Start a process
func (s *service) Start(ctx context.Context, r *taskAPI.StartRequest) (*taskAPI.StartResponse, error) {
+	container, err := s.getContainer(r.ID)

	// hold the send lock so that the start events are sent before any exit events in the error case
	s.eventSendMu.Lock()
+	p, err := container.Start(ctx, r)


	switch r.ExecID {
	case "":
		switch cg := container.Cgroup().(type) {
		case cgroups.Cgroup:
			if err := s.ep.Add(container.ID, cg); err != nil {
				logrus.WithError(err).Error("add cg to OOM monitor")
			}
		case *cgroupsv2.Manager:
			allControllers, err := cg.RootControllers()
			if err != nil {
				logrus.WithError(err).Error("failed to get root controllers")
			} else {
				if err := cg.ToggleControllers(allControllers, cgroupsv2.Enable); err != nil {
					if userns.RunningInUserNS() {
						logrus.WithError(err).Debugf("failed to enable controllers (%v)", allControllers)
					} else {
						logrus.WithError(err).Errorf("failed to enable controllers (%v)", allControllers)
					}
				}
			}
			if err := s.ep.Add(container.ID, cg); err != nil {
				logrus.WithError(err).Error("add cg to OOM monitor")
			}
		}

		s.send(&eventstypes.TaskStart{
			ContainerID: container.ID,
			Pid:         uint32(p.Pid()),
		})
	default:
		s.send(&eventstypes.TaskExecStarted{
			ContainerID: container.ID,
			ExecID:      r.ExecID,
			Pid:         uint32(p.Pid()),
		})
	}
	s.eventSendMu.Unlock()
	return &taskAPI.StartResponse{
		Pid: uint32(p.Pid()),
	}, nil
}
```

- ***start***
```diff
// Start a container process
func (c *Container) Start(ctx context.Context, r *task.StartRequest) (process.Process, error) {
+	p, err := c.Process(r.ExecID)
	if err != nil {
		return nil, err
	}
+	if err := p.Start(ctx); err != nil {
		return nil, err
	}
	if c.Cgroup() == nil && p.Pid() > 0 {
		var cg interface{}
		if cgroups.Mode() == cgroups.Unified {
			g, err := cgroupsv2.PidGroupPath(p.Pid())
			if err != nil {
				logrus.WithError(err).Errorf("loading cgroup2 for %d", p.Pid())
			}
			cg, err = cgroupsv2.LoadManager("/sys/fs/cgroup", g)
			if err != nil {
				logrus.WithError(err).Errorf("loading cgroup2 for %d", p.Pid())
			}
		} else {
			cg, err = cgroups.Load(cgroups.V1, cgroups.PidPath(p.Pid()))
			if err != nil {
				logrus.WithError(err).Errorf("loading cgroup for %d", p.Pid())
			}
		}
		c.cgroup = cg
	}
	return p, nil
}

// Process returns the process by id
func (c *Container) Process(id string) (process.Process, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id == "" {
		if c.process == nil {
			return nil, errors.Wrapf(errdefs.ErrFailedPrecondition, "container must be created")
		}
		return c.process, nil
	}
+	p, ok := c.processes[id]
	if !ok {
		return nil, errors.Wrapf(errdefs.ErrNotFound, "process does not exist %s", id)
	}
	return p, nil
}
```

- ***p.Start()***
```diff
// Start the init process
func (p *Init) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

-	//p.initState在New的时候被赋值createdState{p: p}
	return p.initState.Start(ctx)
}
```

- ***createdState***是负责状态转换
```diff
type createdState struct {
	p *Init
}

func (s *createdState) transition(name string) error {
	switch name {
	case "running":
		s.p.initState = &runningState{p: s.p}
	case "stopped":
		s.p.initState = &stoppedState{p: s.p}
	case "deleted":
		s.p.initState = &deletedState{}
	default:
		return errors.Errorf("invalid state transition %q to %q", stateName(s), name)
	}
	return nil
}

func (s *createdState) Start(ctx context.Context) error {
+	if err := s.p.start(ctx); err != nil {
		return err
	}
-	// 状态改为running	
+	return s.transition("running")
}
```

- ***s.p.start***
```diff
func (p *Init) start(ctx context.Context) error {
-	// p.runtime是runc.Runc，实际运行Runc.Start
	err := p.runtime.Start(ctx, p.id)
	return p.runtimeError(err, "OCI runtime start failed")
}

// Start will start an already created container
func (r *Runc) Start(context context.Context, id string) error {
-	// 运行runc start id
	return r.runOrError(r.command(context, "start", id))
}
```

