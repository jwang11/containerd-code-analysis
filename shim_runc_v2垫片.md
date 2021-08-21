# shim_runc_v2垫片代码分析
> containerd shim_runc_v2是containerd shim的v2版本。shim进程是用来“垫”在containerd和runc启动的容器之间的，其主要作用是：
> 1. 调用runc命令创建、启动、停止、删除容器等
> 2. 作为容器的父进程，当容器中的第一个实例进程被杀死后，负责给其子进程收尸，避免出现僵尸进程
> 3. 监控容器中运行的进程状态，当容器执行完成后，通过exit fifo文件来返回容器进程结束状态

### [主程序](https://github.com/containerd/containerd/blob/main/cmd/containerd-shim-runc-v2/main.go)
```diff
import (
	v2 "github.com/containerd/containerd/runtime/v2/runc/v2"
	"github.com/containerd/containerd/runtime/v2/shim"
)

func main() {
+	shim.Run("io.containerd.runc.v2", v2.New)
}
```
- [shim.Run](https://github.com/containerd/containerd/blob/main/runtime/v2/shim/shim.go)
```diff
// Run initializes and runs a shim server
func Run(id string, initFunc Init, opts ...BinaryOpts) {
	var config Config
	for _, o := range opts {
		o(&config)
	}
+	if err := run(id, initFunc, config); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", id, err)
		os.Exit(1)
	}
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

	if namespaceFlag == "" {
		return fmt.Errorf("shim namespace cannot be empty")
	}

	setRuntime()

	signals, err := setupSignals(config)
	if err != nil {
		return err
	}

	if !config.NoSubreaper {
		if err := subreaper(); err != nil {
			return err
		}
	}

	ttrpcAddress := os.Getenv(ttrpcAddressEnv)
	publisher, err := NewPublisher(ttrpcAddress)
	if err != nil {
		return err
	}
	defer publisher.Close()

	ctx := namespaces.WithNamespace(context.Background(), namespaceFlag)
	ctx = context.WithValue(ctx, OptsKey{}, Opts{BundlePath: bundlePath, Debug: debugFlag})
	ctx = log.WithLogger(ctx, log.G(ctx).WithField("runtime", id))
	ctx, cancel := context.WithCancel(ctx)
+	service, err := initFunc(ctx, idFlag, publisher, cancel)
	if err != nil {
		return err
	}

	switch action {
	case "delete":
		logger := logrus.WithFields(logrus.Fields{
			"pid":       os.Getpid(),
			"namespace": namespaceFlag,
		})
		go handleSignals(ctx, logger, signals)
		response, err := service.Cleanup(ctx)
		if err != nil {
			return err
		}
		data, err := proto.Marshal(response)
		if err != nil {
			return err
		}
		if _, err := os.Stdout.Write(data); err != nil {
			return err
		}
		return nil
	case "start":
		opts := StartOpts{
			ID:               idFlag,
			ContainerdBinary: containerdBinaryFlag,
			Address:          addressFlag,
			TTRPCAddress:     ttrpcAddress,
		}
		address, err := service.StartShim(ctx, opts)
		if err != nil {
			return err
		}
		if _, err := os.Stdout.WriteString(address); err != nil {
			return err
		}
		return nil
	default:
		if !config.NoSetupLogger {
			if err := setLogger(ctx, idFlag); err != nil {
				return err
			}
		}
+		client := NewShimClient(ctx, service, signals)
+		if err := client.Serve(); err != nil {
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
}
```

- [v2.New](https://github.com/containerd/containerd/blob/main/runtime/v2/runc/v2/service.go)
```
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
	if err != nil {
		return nil, err
	}
	go ep.Run(ctx)
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
	if err := s.initPlatform(); err != nil {
		shutdown()
		return nil, errors.Wrap(err, "failed to initialized platform behavior")
	}
	go s.forward(ctx, publisher)

	if address, err := shim.ReadAddress("address"); err == nil {
		s.shimAddress = address
	}
	return s, nil
}
```
