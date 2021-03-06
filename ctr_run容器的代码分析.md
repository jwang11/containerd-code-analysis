# ctr run运行容器的代码分析
> 通过ctr run命令行，指定一个image和ID，运行容器
```
ctr run --net-host --rm -t docker.io/library/busybox:latest mybox1 /bin/sh
```

### Client端命令格式
```
root@jwang-desktop:/home/jwang/go_grpc/server# ctr run --help
NAME:
   ctr run - run a container

USAGE:
   ctr run [command options] [flags] Image|RootFS ID [COMMAND] [ARG...]

OPTIONS:
   --rm                                    remove the container after running
   --null-io                               send all IO to /dev/null
   --log-uri value                         log uri
   --detach, -d                            detach from the task after it has started execution
   --fifo-dir value                        directory used for storing IO FIFOs
   --cgroup value                          cgroup path (To disable use of cgroup, set to "" explicitly)
   --platform value                        run image for specific platform
   --runc-binary value                     specify runc-compatible binary
   --runc-root value                       specify runc-compatible root
   --runc-systemd-cgroup                   start runc with systemd cgroup manager
   --uidmap container-uid:host-uid:length  run inside a user namespace with the specified UID mapping range; specified with the format container-uid:host-uid:length
   --gidmap container-gid:host-gid:length  run inside a user namespace with the specified GID mapping range; specified with the format container-gid:host-gid:length
   --remap-labels                          provide the user namespace ID remapping to the snapshotter via label options; requires snapshotter support
   --cpus value                            set the CFS cpu quota (default: 0)
   --cni                                   enable cni networking for the container
   --snapshotter value                     snapshotter name. Empty value stands for the default value. [$CONTAINERD_SNAPSHOTTER]
   --config value, -c value                path to the runtime-specific spec config file
   --cwd value                             specify the working directory of the process
   --env value                             specify additional container environment variables (e.g. FOO=bar)
   --env-file value                        specify additional container environment variables in a file(e.g. FOO=bar, one per line)
   --label value                           specify additional labels (e.g. foo=bar)
   --mount value                           specify additional container mount (e.g. type=bind,src=/tmp,dst=/host,options=rbind:ro)
   --net-host                              enable host networking for the container
   --privileged                            run privileged container
   --read-only                             set the containers filesystem as readonly
   --runtime value                         runtime name (default: "io.containerd.runc.v2")
   --runtime-config-path value             optional runtime config path
   --tty, -t                               allocate a TTY for the container
   --with-ns value                         specify existing Linux namespaces to join at container runtime (format '<nstype>:<path>')
   --pid-file value                        file path to write the task's pid
   --gpus value                            add gpus to the container (default: 0)
   --allow-new-privs                       turn off OCI spec's NoNewPrivileges feature flag
   --memory-limit value                    memory limit (in bytes) for the container (default: 0)
   --device value                          file path to a device to add to the container; or a path to a directory tree of devices to add to the container
   --seccomp                               enable the default seccomp profile
   --seccomp-profile value                 file path to custom seccomp profile. seccomp must be set to true, before using seccomp-profile
   --apparmor-default-profile value        enable AppArmor with the default profile with the specified name, e.g. "cri-containerd.apparmor.d"
   --apparmor-profile value                enable AppArmor with an existing custom profile
   --rootfs                                use custom rootfs that is not managed by containerd snapshotter
   --no-pivot                              disable use of pivot-root (linux only)
   --cpu-quota value                       Limit CPU CFS quota (default: -1)
   --cpu-period value                      Limit CPU CFS period (default: 0)
```

## 1. 代码流程Overview
- 主要流程其实是分了三步<br>
		1. *创建container对象。这一步没有涉及v2 shim和runc，只是通过container服务在metadata里创建了一个名字是ID的container对象。*<br>
		2. *创建Task，启动v2 shim，然后通过shim运行$runc create image ID。*<br>
		3. *启动Task，相当于$runc start ID* <br>

> 在Linux系统里的缺省设置
```diff
package defaults

const (
	// DefaultMaxRecvMsgSize defines the default maximum message size for
	// receiving protobufs passed over the GRPC API.
	DefaultMaxRecvMsgSize = 16 << 20
	// DefaultMaxSendMsgSize defines the default maximum message size for
	// sending protobufs passed over the GRPC API.
	DefaultMaxSendMsgSize = 16 << 20
	// DefaultRuntimeNSLabel defines the namespace label to check for the
	// default runtime
	DefaultRuntimeNSLabel = "containerd.io/defaults/runtime"
	// DefaultSnapshotterNSLabel defines the namespace label to check for the
	// default snapshotter
	DefaultSnapshotterNSLabel = "containerd.io/defaults/snapshotter"
)
const (
	// DefaultRootDir is the default location used by containerd to store
	// persistent data
	DefaultRootDir = "/var/lib/containerd"
	// DefaultStateDir is the default location used by containerd to store
	// transient data
	DefaultStateDir = "/run/containerd"
	// DefaultAddress is the default unix socket address
	DefaultAddress = "/run/containerd/containerd.sock"
	// DefaultDebugAddress is the default unix socket address for pprof data
	DefaultDebugAddress = "/run/containerd/debug.sock"
	// DefaultFIFODir is the default location used by client-side cio library
	// to store FIFOs.
	DefaultFIFODir = "/run/containerd/fifo"
	// DefaultRuntime is the default linux runtime
	DefaultRuntime = "io.containerd.runc.v2"
	// DefaultConfigDir is the default location for config files.
	DefaultConfigDir = "/etc/containerd"
)
```
- 程序入口
```diff
// Command runs a container
var Command = cli.Command{
	Name:           "run",
	Usage:          "run a container",
	ArgsUsage:      "[flags] Image|RootFS ID [COMMAND] [ARG...]",
	SkipArgReorder: true,
	Flags: append([]cli.Flag{
		cli.BoolFlag{
			Name:  "rm",
			Usage: "remove the container after running",
		},
		cli.BoolFlag{
			Name:  "null-io",
			Usage: "send all IO to /dev/null",
		},
		cli.StringFlag{
			Name:  "log-uri",
			Usage: "log uri",
		},
		cli.BoolFlag{
			Name:  "detach,d",
			Usage: "detach from the task after it has started execution",
		},
		cli.StringFlag{
			Name:  "fifo-dir",
			Usage: "directory used for storing IO FIFOs",
		},
		cli.StringFlag{
			Name:  "cgroup",
			Usage: "cgroup path (To disable use of cgroup, set to \"\" explicitly)",
		},
		cli.StringFlag{
			Name:  "platform",
			Usage: "run image for specific platform",
		},
	}, append(platformRunFlags,
		append(append(commands.SnapshotterFlags, []cli.Flag{commands.SnapshotterLabels}...),
			commands.ContainerFlags...)...)...),
	Action: func(context *cli.Context) error {
		var (
			err error
			id  string
			ref string

			tty       = context.Bool("tty")
			detach    = context.Bool("detach")
			config    = context.IsSet("config")
			enableCNI = context.Bool("cni")
		)

		if config {
			id = context.Args().First()
			if context.NArg() > 1 {
				return errors.New("with spec config file, only container id should be provided")
			}
		} else {
			id = context.Args().Get(1)
			ref = context.Args().First()

			if ref == "" {
				return errors.New("image ref must be provided")
			}
		}
		if id == "" {
			return errors.New("container id must be provided")
		}
		client, ctx, cancel, err := commands.NewClient(context)

		defer cancel()
-		// 创建Container对象，只在containerd端
		container, err := NewContainer(ctx, client, context)
		if context.Bool("rm") && !detach {
			defer container.Delete(ctx, containerd.WithSnapshotCleanup)
		}
		var con console.Console
		if tty {
			con = console.Current()
			defer con.Reset()
			if err := con.SetRaw(); err != nil {
				return err
			}
		}
		var network gocni.CNI
		if enableCNI {
			if network, err = gocni.New(gocni.WithDefaultConf); err != nil {
				return err
			}
		}

		opts := getNewTaskOpts(context)
		ioOpts := []cio.Opt{cio.WithFIFODir(context.String("fifo-dir"))}
-		// 创建真正container - $runc create id
		task, err := tasks.NewTask(ctx, client, container, context.String("checkpoint"), con, context.Bool("null-io"), context.String("log-uri"), ioOpts, opts...)
		var statusC <-chan containerd.ExitStatus
		if !detach {
			defer func() {
				if enableCNI {
					if err := network.Remove(ctx, fullID(ctx, container), ""); err != nil {
						logrus.WithError(err).Error("network review")
					}
				}
				task.Delete(ctx)
			}()

			if statusC, err = task.Wait(ctx); err != nil {
				return err
			}
		}
		if context.IsSet("pid-file") {
			commands.WritePidFile(context.String("pid-file"), int(task.Pid()))
		}
		if enableCNI {
			network.Setup(ctx, fullID(ctx, container), fmt.Sprintf("/proc/%d/ns/net", task.Pid()))
		}
-		// 启动contaienr，runc start id		
		task.Start(ctx)
-		// 如果设置detach，这里就可以退出了		
		if detach {
			return nil
		}
		if tty {
			tasks.HandleConsoleResize(ctx, task, con)
		} else {
			sigc := commands.ForwardAllSignals(ctx, task)
			defer commands.StopCatch(sigc)
		}
-		// 等待container运行结束		
		status := <-statusC
		code, _, err := status.Result()
		task.Delete(ctx)
		return nil
	},
}
```

## 2. 代码流程
### 2.1 创建Contaienr对象
- ***newContainer***是创建一个container对象，通过Continer服务保存在metadata中。注意，这里没有涉及runc
- 主要思路是根据命令行的输入，用opts和cOpts两个闭包数组来构建Spec和Container属性。
```diff
// NewContainer creates a new container
func NewContainer(ctx gocontext.Context, client *containerd.Client, context *cli.Context) (containerd.Container, error) {
	var (
		id     string
		config = context.IsSet("config")
	)
	if config {
		id = context.Args().First()
	} else {
		id = context.Args().Get(1)
	}

	var (
-		// 配置Spec的闭包数组		
		opts  []oci.SpecOpts
-		// 配置Container的闭包数组		
		cOpts []containerd.NewContainerOpts
		spec  containerd.NewContainerOpts
	)
-	// 设置label，支持多个key1=val1,key2=val2...
	cOpts = append(cOpts, containerd.WithContainerLabels(commands.LabelArgs(context.StringSlice("label"))))
	if config {
		opts = append(opts, oci.WithSpecFromFile(context.String("config")))
	} else {
		var (
-			// image reference，如docker.io/library/busybox:latest
			ref = context.Args().First()
			//for container's id is Args[1]
			args = context.Args()[2:]
		)
-		// 设置缺省的spec和devices
		opts = append(opts, oci.WithDefaultSpec(), oci.WithDefaultUnixDevices)
		if ef := context.String("env-file"); ef != "" {
			opts = append(opts, oci.WithEnvFile(ef))
		}
		opts = append(opts, oci.WithEnv(context.StringSlice("env")))
		opts = append(opts, withMounts(context))
-		// 如果命令选项有--rootfs，ref就是本地rootfs的目录，否则ref是registry的地址，如docker.io/library/busybox:latest
		if context.Bool("rootfs") {
			rootfs, err := filepath.Abs(ref)
			opts = append(opts, oci.WithRootFSPath(rootfs))
		} else {
			snapshotter := context.String("snapshotter")
			var image containerd.Image
			i, err := client.ImageService().Get(ctx, ref)
			if ps := context.String("platform"); ps != "" {
				platform, err := platforms.Parse(ps)
				image = containerd.NewImageWithPlatform(client, i, platforms.Only(platform))
			} else {
				image = containerd.NewImage(client, i)
			}

-			// 如果image还没有unpack到snapshotter里，就执行unpack
			unpacked, err := image.IsUnpacked(ctx, snapshotter)
			if !unpacked {
				if err := image.Unpack(ctx, snapshotter); err != nil {
					return nil, err
				}
			}
-			// 从image提取oci config，解析后放入spec		
			opts = append(opts, oci.WithImageConfig(image))
			cOpts = append(cOpts,
				containerd.WithImage(image),
				containerd.WithSnapshotter(snapshotter))
-			// 解析命令行提供的uidmap和gidmap				
			if uidmap, gidmap := context.String("uidmap"), context.String("gidmap"); uidmap != "" && gidmap != "" {
				uidMap, err := parseIDMapping(uidmap)
				gidMap, err := parseIDMapping(gidmap)
				opts = append(opts,
					oci.WithUserNamespace([]specs.LinuxIDMapping{uidMap}, []specs.LinuxIDMapping{gidMap}))
				// use snapshotter opts or the remapped snapshot support to shift the filesystem
				// currently the only snapshotter known to support the labels is fuse-overlayfs:
				// https://github.com/AkihiroSuda/containerd-fuse-overlayfs
				if context.Bool("remap-labels") {
					cOpts = append(cOpts, containerd.WithNewSnapshot(id, image,
						containerd.WithRemapperLabels(0, uidMap.HostID, 0, gidMap.HostID, uidMap.Size)))
				} else {
					cOpts = append(cOpts, containerd.WithRemappedSnapshot(id, image, uidMap.HostID, gidMap.HostID))
				}
			} else {
				// Even when "read-only" is set, we don't use KindView snapshot here. (#1495)
				// We pass writable snapshot to the OCI runtime, and the runtime remounts it as read-only,
				// after creating some mount points on demand.
				// For some snapshotter, such as overlaybd, it can provide 2 kind of writable snapshot(overlayfs dir or block-device)
				// by command label values.
				cOpts = append(cOpts, containerd.WithNewSnapshot(id, image,
					snapshots.WithLabels(commands.LabelArgs(context.StringSlice("snapshotter-label")))))
			}
			cOpts = append(cOpts, containerd.WithImageStopSignal(image, "SIGTERM"))
		}
		if context.Bool("read-only") {
			opts = append(opts, oci.WithRootFSReadonly())
		}
		if len(args) > 0 {
			opts = append(opts, oci.WithProcessArgs(args...))
		}
		if cwd := context.String("cwd"); cwd != "" {
			opts = append(opts, oci.WithProcessCwd(cwd))
		}
-		// 需要tty交互，设置spec.Process.Terminal=true，同时环境变量TERM=xterm		
		if context.Bool("tty") {
			opts = append(opts, oci.WithTTY)
		}
		if context.Bool("privileged") {
			opts = append(opts, oci.WithPrivileged, oci.WithAllDevicesAllowed, oci.WithHostDevices)
		}

-		// 如果容器里使用host的物理网卡
		if context.Bool("net-host") {
			hostname, err := os.Hostname()
			if err != nil {
				return nil, errors.Wrap(err, "get hostname")
			}
			opts = append(opts,
-				// 把spec里的network namespace直接删除，表示默认用host的
				oci.WithHostNamespace(specs.NetworkNamespace),
-				// Mount主机里的/etc/host文件到容器里
				oci.WithHostHostsFile,
-				// Mount主机里/etc/resolve.conf文件到容器里
				oci.WithHostResolvconf,
				oci.WithEnv([]string{fmt.Sprintf("HOSTNAME=%s", hostname)}),
			)
		}

		seccompProfile := context.String("seccomp-profile")

		if !context.Bool("seccomp") && seccompProfile != "" {
			return nil, fmt.Errorf("seccomp must be set to true, if using a custom seccomp-profile")
		}

-		// 如果提供seccomp-profile json文件，把该文件解析到spec.Linux.Seccomp
		if context.Bool("seccomp") {
			if seccompProfile != "" {
				opts = append(opts, seccomp.WithProfile(seccompProfile))
			} else {
				opts = append(opts, seccomp.WithDefaultProfile())
			}
		}

		if s := context.String("apparmor-default-profile"); len(s) > 0 {
			opts = append(opts, apparmor.WithDefaultProfile(s))
		}
-		// 把apparmor-profile设置到spec.Process.ApparmorProfile
		if s := context.String("apparmor-profile"); len(s) > 0 {
			if len(context.String("apparmor-default-profile")) > 0 {
				return nil, fmt.Errorf("apparmor-profile conflicts with apparmor-default-profile")
			}
			opts = append(opts, apparmor.WithProfile(s))
		}

-		// 设置cpu相关的cgroup，包括cpus，cpu-shares，cpu-quota，cpu-period
		if cpus := context.Float64("cpus"); cpus > 0.0 {
			var (
				period = uint64(100000)
				quota  = int64(cpus * 100000.0)
			)
			opts = append(opts, oci.WithCPUCFS(quota, period))
		}

		if shares := context.Int("cpu-shares"); shares > 0 {
			opts = append(opts, oci.WithCPUShares(uint64(shares)))
		}

		quota := context.Int64("cpu-quota")
		period := context.Uint64("cpu-period")
		if quota != -1 || period != 0 {
			if cpus := context.Float64("cpus"); cpus > 0.0 {
				return nil, errors.New("cpus and quota/period should be used separately")
			}
			opts = append(opts, oci.WithCPUCFS(quota, period))
		}

-		// 设置加入指定的namespace，格式是type: path
		joinNs := context.StringSlice("with-ns")
		for _, ns := range joinNs {
			parts := strings.Split(ns, ":")
			if len(parts) != 2 {
				return nil, errors.New("joining a Linux namespace using --with-ns requires the format 'nstype:path'")
			}
			if !validNamespace(parts[0]) {
				return nil, errors.New("the Linux namespace type specified in --with-ns is not valid: " + parts[0])
			}
			opts = append(opts, oci.WithLinuxNamespace(specs.LinuxNamespace{
				Type: specs.LinuxNamespaceType(parts[0]),
				Path: parts[1],
			}))
		}
		if context.IsSet("gpus") {
			opts = append(opts, nvidia.WithGPUs(nvidia.WithDevices(context.IntSlice("gpus")...), nvidia.WithAllCapabilities))
		}
		if context.IsSet("allow-new-privs") {
			opts = append(opts, oci.WithNewPrivileges)
		}
		if context.IsSet("cgroup") {
			// NOTE: can be set to "" explicitly for disabling cgroup.
			opts = append(opts, oci.WithCgroup(context.String("cgroup")))
		}
-		// 设置内存限制spec.Linux.Resources.Memory.Limit 
		limit := context.Uint64("memory-limit")
		if limit != 0 {
			opts = append(opts, oci.WithMemoryLimit(limit))
		}
-		// 设置容器里的device和权限，spec.Linux.Devices和spec.Linux.Resources.Devices		
		for _, dev := range context.StringSlice("device") {
			opts = append(opts, oci.WithDevices(dev, "", "rwm"))
		}

-		// 指定rootfs的propagation类型share, slave, private
		rootfsPropagation := context.String("rootfs-propagation")
		if rootfsPropagation != "" {
			opts = append(opts, func(_ gocontext.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
				if s.Linux != nil {
					s.Linux.RootfsPropagation = rootfsPropagation
				} else {
					s.Linux = &specs.Linux{
						RootfsPropagation: rootfsPropagation,
					}
				}

				return nil
			})
		}
	}

-	// 获得runc的options，包括runc的命令名，root路径和systemdcgroup
	runtimeOpts, err := getRuntimeOptions(context)
	cOpts = append(cOpts, containerd.WithRuntime(context.String("runtime"), runtimeOpts))

	opts = append(opts, oci.WithAnnotations(commands.LabelArgs(context.StringSlice("label"))))
	var s specs.Spec
-	// 生成一个新的spec闭包，它会apply所有opts里定义的操作	
	spec = containerd.WithSpec(&s, opts...)

	cOpts = append(cOpts, spec)

	// oci.WithImageConfig (WithUsername, WithUserID) depends on access to rootfs for resolving via
	// the /etc/{passwd,group} files. So cOpts needs to have precedence over opts.
+	return client.NewContainer(ctx, id, cOpts...)
}
```

>> 在分析client.NewContainer之前，总结一下cOpts和opts定义的闭包操作
```diff
- 设置label
+ cOpts = append(cOpts, containerd.WithContainerLabels(commands.LabelArgs(context.StringSlice("label"))))
// WithContainerLabels sets the provided labels to the container.
// The existing labels are cleared.
// Use WithAdditionalContainerLabels to preserve the existing labels.
func WithContainerLabels(labels map[string]string) NewContainerOpts {
	return func(_ context.Context, _ *Client, c *containers.Container) error {
		c.Labels = labels
		return nil
	}
}

- 设置image和snapshotter
+ cOpts = append(cOpts,
+	containerd.WithImage(image),
+ 	containerd.WithSnapshotter(snapshotter))
// WithImage sets the provided image as the base for the container
func WithImage(i Image) NewContainerOpts {
	return func(ctx context.Context, client *Client, c *containers.Container) error {
		c.Image = i.Name()
		return nil
	}
}
// WithSnapshotter sets the provided snapshotter for use by the container
//
// This option must appear before other snapshotter options to have an effect.
func WithSnapshotter(name string) NewContainerOpts {
	return func(ctx context.Context, client *Client, c *containers.Container) error {
		c.Snapshotter = name
		return nil
	}
}

- 设置Image退出信号
+ cOpts = append(cOpts, containerd.WithImageStopSignal(image, "SIGTERM"))
// WithImageStopSignal sets a well-known containerd label (StopSignalLabel)
// on the container for storing the stop signal specified in the OCI image
// config
func WithImageStopSignal(image Image, defaultSignal string) NewContainerOpts {
	return func(ctx context.Context, _ *Client, c *containers.Container) error {
		if c.Labels == nil {
			c.Labels = make(map[string]string)
		}
		stopSignal, err := GetOCIStopSignal(ctx, image, defaultSignal)
		if err != nil {
			return err
		}
		c.Labels[StopSignalLabel] = stopSignal
		return nil
	}
}
- 生成缺省spec和device
+ opts = append(opts, oci.WithDefaultSpec(), oci.WithDefaultUnixDevices)
// WithDefaultSpec returns a SpecOpts that will populate the spec with default
// values.
//
// Use as the first option to clear the spec, then apply options afterwards.
func WithDefaultSpec() SpecOpts {
	return func(ctx context.Context, _ Client, c *containers.Container, s *Spec) error {
		return generateDefaultSpecWithPlatform(ctx, platforms.DefaultString(), c.ID, s)
	}
}

// WithDefaultUnixDevices adds the default devices for unix such as /dev/null, /dev/random to
// the container's resource cgroup spec
func WithDefaultUnixDevices(_ context.Context, _ Client, _ *containers.Container, s *Spec) error {
	setLinux(s)
	if s.Linux.Resources == nil {
		s.Linux.Resources = &specs.LinuxResources{}
	}
	intptr := func(i int64) *int64 {
		return &i
	}
	s.Linux.Resources.Devices = append(s.Linux.Resources.Devices, []specs.LinuxDeviceCgroup{
		{
			// "/dev/null",
			Type:   "c",
			Major:  intptr(1),
			Minor:  intptr(3),
			Access: rwm,
			Allow:  true,
		},
		{
			// "/dev/random",
			Type:   "c",
			Major:  intptr(1),
			Minor:  intptr(8),
			Access: rwm,
			Allow:  true,
		},
		{
			// "/dev/full",
			Type:   "c",
			Major:  intptr(1),
			Minor:  intptr(7),
			Access: rwm,
			Allow:  true,
		},
		{
			// "/dev/tty",
			Type:   "c",
			Major:  intptr(5),
			Minor:  intptr(0),
			Access: rwm,
			Allow:  true,
		},
		{
			// "/dev/zero",
			Type:   "c",
			Major:  intptr(1),
			Minor:  intptr(5),
			Access: rwm,
			Allow:  true,
		},
		{
			// "/dev/urandom",
			Type:   "c",
			Major:  intptr(1),
			Minor:  intptr(9),
			Access: rwm,
			Allow:  true,
		},
		{
			// "/dev/console",
			Type:   "c",
			Major:  intptr(5),
			Minor:  intptr(1),
			Access: rwm,
			Allow:  true,
		},
		// /dev/pts/ - pts namespaces are "coming soon"
		{
			Type:   "c",
			Major:  intptr(136),
			Access: rwm,
			Allow:  true,
		},
		{
			Type:   "c",
			Major:  intptr(5),
			Minor:  intptr(2),
			Access: rwm,
			Allow:  true,
		},
		{
			// tuntap
			Type:   "c",
			Major:  intptr(10),
			Minor:  intptr(200),
			Access: rwm,
			Allow:  true,
		},
	}...)
	return nil
}

- 如果命令行指定环境变量文件--env-file
+ opts = append(opts, oci.WithEnvFile(ef))
// WithEnvFile adds environment variables from a file to the container's spec
func WithEnvFile(path string) SpecOpts {
	return func(_ context.Context, _ Client, _ *containers.Container, s *Spec) error {
		var vars []string
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		for sc.Scan() {
			vars = append(vars, sc.Text())
		}
		if err = sc.Err(); err != nil {
			return err
		}
		return WithEnv(vars)(nil, nil, nil, s)
	}
}

- 如果命令行指定环境变量--env
+ opts = append(opts, oci.WithEnv(context.StringSlice("env")))
// WithEnv appends environment variables
func WithEnv(environmentVariables []string) SpecOpts {
	return func(_ context.Context, _ Client, _ *containers.Container, s *Spec) error {
		if len(environmentVariables) > 0 {
			setProcess(s)
			s.Process.Env = replaceOrAppendEnvValues(s.Process.Env, environmentVariables)
		}
		return nil
	}
}

- 设置mounts
+ opts = append(opts, withMounts(context))
func withMounts(context *cli.Context) oci.SpecOpts {
	return func(ctx gocontext.Context, client oci.Client, container *containers.Container, s *specs.Spec) error {
		mounts := make([]specs.Mount, 0)
		for _, mount := range context.StringSlice("mount") {
			m, err := parseMountFlag(mount)
			if err != nil {
				return err
			}
			mounts = append(mounts, m)
		}
		return oci.WithMounts(mounts)(ctx, client, container, s)
	}
}
// WithMounts appends mounts
func WithMounts(mounts []specs.Mount) SpecOpts {
	return func(_ context.Context, _ Client, _ *containers.Container, s *Spec) error {
		s.Mounts = append(s.Mounts, mounts...)
		return nil
	}
}

- 如果image指定rootfs
+ opts = append(opts, oci.WithRootFSPath(rootfs))
// WithRootFSPath specifies unmanaged rootfs path.
func WithRootFSPath(path string) SpecOpts {
	return func(_ context.Context, _ Client, _ *containers.Container, s *Spec) error {
		setRoot(s)
		s.Root.Path = path
		// Entrypoint is not set here (it's up to caller)
		return nil
	}
}

- 如果image是ref
+ opts = append(opts, oci.WithImageConfig(image))
// WithImageConfig configures the spec to from the configuration of an Image
func WithImageConfig(image Image) SpecOpts {
	return WithImageConfigArgs(image, nil)
}
// WithImageConfigArgs configures the spec to from the configuration of an Image with additional args that
// replaces the CMD of the image
func WithImageConfigArgs(image Image, args []string) SpecOpts {
	return func(ctx context.Context, client Client, c *containers.Container, s *Spec) error {
-		// 获取image的config
		ic, err := image.Config(ctx)
		if err != nil {
			return err
		}
		var (
			ociimage v1.Image
			config   v1.ImageConfig
		)
		switch ic.MediaType {
		case v1.MediaTypeImageConfig, images.MediaTypeDockerSchema2Config:
			p, err := content.ReadBlob(ctx, image.ContentStore(), ic)
			if err != nil {
				return err
			}

			if err := json.Unmarshal(p, &ociimage); err != nil {
				return err
			}
			config = ociimage.Config
		default:
			return fmt.Errorf("unknown image config media type %s", ic.MediaType)
		}

		setProcess(s)
		if s.Linux != nil {
			defaults := config.Env
			if len(defaults) == 0 {
				defaults = defaultUnixEnv
			}
			s.Process.Env = replaceOrAppendEnvValues(defaults, s.Process.Env)
			cmd := config.Cmd
			if len(args) > 0 {
				cmd = args
			}
			s.Process.Args = append(config.Entrypoint, cmd...)

			cwd := config.WorkingDir
			if cwd == "" {
				cwd = "/"
			}
			s.Process.Cwd = cwd
			if config.User != "" {
				if err := WithUser(config.User)(ctx, client, c, s); err != nil {
					return err
				}
				return WithAdditionalGIDs(fmt.Sprintf("%d", s.Process.User.UID))(ctx, client, c, s)
			}
			// we should query the image's /etc/group for additional GIDs
			// even if there is no specified user in the image config
			return WithAdditionalGIDs("root")(ctx, client, c, s)
		} else if s.Windows != nil {
			s.Process.Env = replaceOrAppendEnvValues(config.Env, s.Process.Env)
			cmd := config.Cmd
			if len(args) > 0 {
				cmd = args
			}
			s.Process.Args = append(config.Entrypoint, cmd...)

			s.Process.Cwd = config.WorkingDir
			s.Process.User = specs.User{
				Username: config.User,
			}
		} else {
			return errors.New("spec does not contain Linux or Windows section")
		}
		return nil
	}
}

- 设置Image config
+ opts = append(opts, oci.WithImageConfig(image))
// WithImageConfig configures the spec to from the configuration of an Image
func WithImageConfig(image Image) SpecOpts {
	return WithImageConfigArgs(image, nil)
}
// WithImageConfigArgs configures the spec to from the configuration of an Image with additional args that
// replaces the CMD of the image
func WithImageConfigArgs(image Image, args []string) SpecOpts {
	return func(ctx context.Context, client Client, c *containers.Container, s *Spec) error {
		ic, err := image.Config(ctx)
		if err != nil {
			return err
		}
		var (
			ociimage v1.Image
			config   v1.ImageConfig
		)
		switch ic.MediaType {
		case v1.MediaTypeImageConfig, images.MediaTypeDockerSchema2Config:
			p, err := content.ReadBlob(ctx, image.ContentStore(), ic)
			if err != nil {
				return err
			}

			if err := json.Unmarshal(p, &ociimage); err != nil {
				return err
			}
			config = ociimage.Config
		default:
			return fmt.Errorf("unknown image config media type %s", ic.MediaType)
		}

		setProcess(s)
		if s.Linux != nil {
			defaults := config.Env
			if len(defaults) == 0 {
				defaults = defaultUnixEnv
			}
			s.Process.Env = replaceOrAppendEnvValues(defaults, s.Process.Env)
			cmd := config.Cmd
			if len(args) > 0 {
				cmd = args
			}
			s.Process.Args = append(config.Entrypoint, cmd...)

			cwd := config.WorkingDir
			if cwd == "" {
				cwd = "/"
			}
			s.Process.Cwd = cwd
			if config.User != "" {
				if err := WithUser(config.User)(ctx, client, c, s); err != nil {
					return err
				}
				return WithAdditionalGIDs(fmt.Sprintf("%d", s.Process.User.UID))(ctx, client, c, s)
			}
			// we should query the image's /etc/group for additional GIDs
			// even if there is no specified user in the image config
			return WithAdditionalGIDs("root")(ctx, client, c, s)
		} else if s.Windows != nil {
			s.Process.Env = replaceOrAppendEnvValues(config.Env, s.Process.Env)
			cmd := config.Cmd
			if len(args) > 0 {
				cmd = args
			}
			s.Process.Args = append(config.Entrypoint, cmd...)

			s.Process.Cwd = config.WorkingDir
			s.Process.User = specs.User{
				Username: config.User,
			}
		} else {
			return errors.New("spec does not contain Linux or Windows section")
		}
		return nil
	}
}

- 如果指定tty
+ opts = append(opts, oci.WithTTY)
// WithTTY sets the information on the spec as well as the environment variables for
// using a TTY
func WithTTY(_ context.Context, _ Client, _ *containers.Container, s *Spec) error {
	setProcess(s)
	s.Process.Terminal = true
	if s.Linux != nil {
		s.Process.Env = append(s.Process.Env, "TERM=xterm")
	}

	return nil
}

- 如果指定net-host
-	opts = append(opts,
-		oci.WithHostNamespace(specs.NetworkNamespace),
-		oci.WithHostHostsFile,
-		oci.WithHostResolvconf,
-		oci.WithEnv([]string{fmt.Sprintf("HOSTNAME=%s", hostname)}),
-	)

- 如果指定cpu（cgroup）个数
+ period = uint64(100000)
+ quota  = int64(cpus * 100000.0)
+ opts = append(opts, oci.WithCPUCFS(quota, period))
// WithCPUCFS sets the container's Completely fair scheduling (CFS) quota and period
func WithCPUCFS(quota int64, period uint64) SpecOpts {
	return func(ctx context.Context, _ Client, c *containers.Container, s *Spec) error {
		setCPU(s)
		s.Linux.Resources.CPU.Quota = &quota
		s.Linux.Resources.CPU.Period = &period
		return nil
	}
}

- 如果指定cpu-shares
+ opts = append(opts, oci.WithCPUShares(uint64(shares)))
// WithCPUShares sets the container's cpu shares
func WithCPUShares(shares uint64) SpecOpts {
	return func(ctx context.Context, _ Client, c *containers.Container, s *Spec) error {
		setCPU(s)
		s.Linux.Resources.CPU.Shares = &shares
		return nil
	}
}

- 如果指定cpu-quota和cpu-period
+ quota := context.Int64("cpu-quota")
+ period := context.Uint64("cpu-period")
+ if quota != -1 || period != 0 
+ opts = append(opts, oci.WithCPUCFS(quota, period))
func WithCPUCFS(quota int64, period uint64) SpecOpts {
	return func(ctx context.Context, _ Client, c *containers.Container, s *Spec) error {
		setCPU(s)
		s.Linux.Resources.CPU.Quota = &quota
		s.Linux.Resources.CPU.Period = &period
		return nil
	}
}

- 如果指定加入namespace，with-ns
+ opts = append(opts, oci.WithLinuxNamespace(specs.LinuxNamespace{
+		Type: specs.LinuxNamespaceType(parts[0]),
+		Path: parts[1],
+		}))
// WithLinuxNamespace uses the passed in namespace for the spec. If a namespace of the same type already exists in the
// spec, the existing namespace is replaced by the one provided.
func WithLinuxNamespace(ns specs.LinuxNamespace) SpecOpts {
	return func(_ context.Context, _ Client, _ *containers.Container, s *Spec) error {
		setLinux(s)
		for i, n := range s.Linux.Namespaces {
			if n.Type == ns.Type {
				s.Linux.Namespaces[i] = ns
				return nil
			}
		}
		s.Linux.Namespaces = append(s.Linux.Namespaces, ns)
		return nil
	}
}

```

- 转入client.NewContainer
```diff 
// NewContainer will create a new container in container with the provided id
// the id must be unique within the namespace
func (c *Client) NewContainer(ctx context.Context, id string, opts ...NewContainerOpts) (Container, error) {
	ctx, done, err := c.WithLease(ctx)
	if err != nil {
		return nil, err
	}
	defer done(ctx)

	container := containers.Container{
		ID: id,
		Runtime: containers.RuntimeInfo{
			Name: c.runtime,
		},
	}
	for _, o := range opts {
		if err := o(ctx, c, &container); err != nil {
			return nil, err
		}
	}
-	// 调用Container外部服务的Create方法    
	r, err := c.ContainerService().Create(ctx, container)
	if err != nil {
		return nil, err
	}
	return containerFromRecord(c, r), nil
}

func containerFromRecord(client *Client, c containers.Container) *container {
	return &container{
		client:   client,
		id:       c.ID,
		metadata: c,
	}
}
```

### 2.2 创建runtime里的container
- NewTask创建Runtime里container
```diff
+		task, err := tasks.NewTask(ctx, client, container, context.String("checkpoint"), con, context.Bool("null-io"), context.String("log-uri"), ioOpts, opts...)
```
```diff
func NewTask(ctx gocontext.Context, client *containerd.Client, container containerd.Container, checkpoint string, con console.Console, nullIO bool, logURI string, ioOpts []cio.Opt, opts ...containerd.NewTaskOpts) (containerd.Task, error) {
	stdinC := &stdinCloser{
		stdin: os.Stdin,
	}
	if checkpoint != "" {
		im, err := client.GetImage(ctx, checkpoint)
		opts = append(opts, containerd.WithTaskCheckpoint(im))
	}
-	// 根据命令行参数，创建ioCreator闭包，处理终端stdin/stdout/stderr	
	var ioCreator cio.Creator
	if con != nil {
		ioCreator = cio.NewCreator(append([]cio.Opt{cio.WithStreams(con, con, nil), cio.WithTerminal}, ioOpts...)...)
	} else if nullIO {
		ioCreator = cio.NullIO
	} else if logURI != "" {
		u, err := url.Parse(logURI)
		ioCreator = cio.LogURI(u)
	} else {
		ioCreator = cio.NewCreator(append([]cio.Opt{cio.WithStreams(stdinC, os.Stdout, os.Stderr)}, ioOpts...)...)
	}

+	t, err := container.NewTask(ctx, ioCreator, opts...)
	stdinC.closer = func() {
		t.CloseIO(ctx, containerd.WithStdinCloser)
	}
	return t, nil
}
```
> 这里把ioOpts总结一下，它是处理container里面的tty IO.
```diff
- 1. 设置fifo路径
cio.WithFIFODir(context.String("fifo-dir"))

// WithFIFODir sets the fifo directory.
// e.g. "/run/containerd/fifo", "/run/users/1001/containerd/fifo"
func WithFIFODir(dir string) Opt {
	return func(opt *Streams) {
		opt.FIFODir = dir
	}
}

-  2. 如果命令行指定tty，把当前console设置给container里的三个streams，同时terminal=true
cio.WithStreams(con, con, nil)

// WithStreams sets the stream options to the specified Reader and Writers
func WithStreams(stdin io.Reader, stdout, stderr io.Writer) Opt {
	return func(opt *Streams) {
		opt.Stdin = stdin
		opt.Stdout = stdout
		opt.Stderr = stderr
	}
}
// WithTerminal sets the terminal option
func WithTerminal(opt *Streams) {
	opt.Terminal = true
}
```

- 用cioOpts创建ioCreator
```diff
// NewCreator returns an IO creator from the options
func NewCreator(opts ...Opt) Creator {
	streams := &Streams{}
	for _, opt := range opts {
		opt(streams)
	}
	if streams.FIFODir == "" {
		streams.FIFODir = defaults.DefaultFIFODir
	}
	return func(id string) (IO, error) {
+		fifos, err := NewFIFOSetInDir(streams.FIFODir, id, streams.Terminal)
		if err != nil {
			return nil, err
		}
		if streams.Stdin == nil {
			fifos.Stdin = ""
		}
		if streams.Stdout == nil {
			fifos.Stdout = ""
		}
		if streams.Stderr == nil {
			fifos.Stderr = ""
		}
+		return copyIO(fifos, streams)
	}
}

// NewFIFOSetInDir returns a new FIFOSet with paths in a temporary directory under root
func NewFIFOSetInDir(root, id string, terminal bool) (*FIFOSet, error) {
	if root != "" {
		if err := os.MkdirAll(root, 0700); err != nil {
			return nil, err
		}
	}
	dir, err := ioutil.TempDir(root, "")
	closer := func() error {
		return os.RemoveAll(dir)
	}
	return NewFIFOSet(Config{
		Stdin:    filepath.Join(dir, id+"-stdin"),
		Stdout:   filepath.Join(dir, id+"-stdout"),
		Stderr:   filepath.Join(dir, id+"-stderr"),
		Terminal: terminal,
	}, closer), nil
}

// NewFIFOSet returns a new FIFOSet from a Config and a close function
func NewFIFOSet(config Config, close func() error) *FIFOSet {
	return &FIFOSet{Config: config, close: close}
}

// FIFOSet is a set of file paths to FIFOs for a task's standard IO streams
type FIFOSet struct {
	Config
	close func() error
}

type pipes struct {
	Stdin  io.WriteCloser
	Stdout io.ReadCloser
	Stderr io.ReadCloser
}

func copyIO(fifos *FIFOSet, ioset *Streams) (*cio, error) {
	var ctx, cancel = context.WithCancel(context.Background())
+	pipes, err := openFifos(ctx, fifos)
-	// 用3个go rouine协程分别处理stdin，stdout和stderr
	if fifos.Stdin != "" {
		go func() {
			p := bufPool.Get().(*[]byte)
			defer bufPool.Put(p)

			io.CopyBuffer(pipes.Stdin, ioset.Stdin, *p)
			pipes.Stdin.Close()
		}()
	}

	var wg = &sync.WaitGroup{}
	if fifos.Stdout != "" {
		wg.Add(1)
		go func() {
			p := bufPool.Get().(*[]byte)
			defer bufPool.Put(p)

			io.CopyBuffer(ioset.Stdout, pipes.Stdout, *p)
			pipes.Stdout.Close()
			wg.Done()
		}()
	}

	if !fifos.Terminal && fifos.Stderr != "" {
		wg.Add(1)
		go func() {
			p := bufPool.Get().(*[]byte)
			defer bufPool.Put(p)

			io.CopyBuffer(ioset.Stderr, pipes.Stderr, *p)
			pipes.Stderr.Close()
			wg.Done()
		}()
	}
	return &cio{
		config:  fifos.Config,
		wg:      wg,
		closers: append(pipes.closers(), fifos),
		cancel:  cancel,
	}, nil
}
```

- container.NewTask。此函数会向containerd中的task service发送创建任务请求，task service中会启动containerd-shim（v2）进程调用runc来创建容器。
```diff
type task struct {
	client *Client
	c      Container
	io  cio.IO
	id  string
	pid uint32
}

func (c *container) NewTask(ctx context.Context, ioCreate cio.Creator, opts ...NewTaskOpts) (_ Task, err error) {
-	// 通过fifo接口接管console
	i, err := ioCreate(c.id)
	cfg := i.Config()
	request := &tasks.CreateTaskRequest{
		ContainerID: c.id,
		Terminal:    cfg.Terminal,
		Stdin:       cfg.Stdin,
		Stdout:      cfg.Stdout,
		Stderr:      cfg.Stderr,
	}
	r, err := c.get(ctx)
	if r.SnapshotKey != "" {
		if r.Snapshotter == "" {
			return nil, errors.Wrapf(errdefs.ErrInvalidArgument, "unable to resolve rootfs mounts without snapshotter on container")
		}

		// get the rootfs from the snapshotter and add it to the request
		s, err := c.client.getSnapshotter(ctx, r.Snapshotter)
		if err != nil {
			return nil, err
		}
-		// 获取mounts的命令行		
		mounts, err := s.Mounts(ctx, r.SnapshotKey)
		if err != nil {
			return nil, err
		}
-		// 得到oci spec		
		spec, err := c.Spec(ctx)
		if err != nil {
			return nil, err
		}
-		// 解析mounts命令行		
		for _, m := range mounts {
			if spec.Linux != nil && spec.Linux.MountLabel != "" {
				context := label.FormatMountLabel("", spec.Linux.MountLabel)
				if context != "" {
					m.Options = append(m.Options, context)
				}
			}
			request.Rootfs = append(request.Rootfs, &types.Mount{
				Type:    m.Type,
				Source:  m.Source,
				Options: m.Options,
			})
		}
	}
	info := TaskInfo{
		runtime: r.Runtime.Name,
	}
-	// apply所有的newTaskOpts	
	for _, o := range opts {
		o(ctx, c.client, &info)
	}
-	// 填好rootfs的mount信息	
	if info.RootFS != nil {
		for _, m := range info.RootFS {
			request.Rootfs = append(request.Rootfs, &types.Mount{
				Type:    m.Type,
				Source:  m.Source,
				Options: m.Options,
			})
		}
	}
-	// 把info里Options信息填入request.Options	
	if info.Options != nil {
		any, err := typeurl.MarshalAny(info.Options)
		if err != nil {
			return nil, err
		}
		request.Options = any
	}
	t := &task{
		client: c.client,
		io:     i,
		id:     c.id,
		c:      c,
	}

-	// 请求task service创建container	
	response, err := c.client.TaskService().Create(ctx, request)
	t.pid = response.Pid
	return t, nil
}
```
- [task结构](https://github.com/containerd/containerd/blob/main/task.go)
```
type task struct {
	client *Client
	c      Container

	io  cio.IO
	id  string
	pid uint32
}

```
- 在分析服务器端的代码之前，总结一下NewTaskOpts有哪些
```diff
- opts := getNewTaskOpts(context)
func getNewTaskOpts(context *cli.Context) []containerd.NewTaskOpts {
	var (
		tOpts []containerd.NewTaskOpts
	)
	if context.Bool("no-pivot") {
		tOpts = append(tOpts, containerd.WithNoPivotRoot)
	}
	if uidmap := context.String("uidmap"); uidmap != "" {
		uidMap, err := parseIDMapping(uidmap)
		if err != nil {
			logrus.WithError(err).Warn("unable to parse uidmap; defaulting to uid 0 IO ownership")
		}
		tOpts = append(tOpts, containerd.WithUIDOwner(uidMap.HostID))
	}
	if gidmap := context.String("gidmap"); gidmap != "" {
		gidMap, err := parseIDMapping(gidmap)
		if err != nil {
			logrus.WithError(err).Warn("unable to parse gidmap; defaulting to gid 0 IO ownership")
		}
		tOpts = append(tOpts, containerd.WithGIDOwner(gidMap.HostID))
	}
	return tOpts
}
```

- 调用TaskService服务Create。
```
response, err := c.client.TaskService().Create(ctx, request)<br>
```

> 通过gRPC调用tasks外部[service](https://github.com/containerd/containerd/blob/main/services/tasks/service.go)<br>
> 外部服务Create -> 内部service.Create -> v2shim.create.
```diff
func (s *service) Create(ctx context.Context, r *api.CreateTaskRequest) (*api.CreateTaskResponse, error) {
	return s.local.Create(ctx, r)
}
```
- 转到内部service
```diff
func (l *local) Create(ctx context.Context, r *api.CreateTaskRequest, _ ...grpc.CallOption) (*api.CreateTaskResponse, error) {
	container, err := l.getContainer(ctx, r.ContainerID)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
...
-	// 为runtime准备options，把reqest里的信息填进去
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
-	// 获取PlatformRuntime，默认是taskmanger_v2_shim。注意，这个runtime不是指runc，其实是runtime的manager。
	rtime, err := l.getRuntime(container.Runtime.Name)
	if err != nil {
		return nil, err
	}
-	// 检查确保是新的task	
	_, err = rtime.Get(ctx, r.ContainerID)
	if err != nil && err != runtime.ErrTaskNotExists {
		return nil, errdefs.ToGRPC(err)
	}
	if err == nil {
		return nil, errdefs.ToGRPC(fmt.Errorf("task %s already exists", r.ContainerID))
	}
-	// 调用taskmanger_v2_shim.Create来创建container，要通过Shim	
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

func (l *local) getRuntime(name string) (runtime.PlatformRuntime, error) {
	runtime, ok := l.runtimes[name]
	if !ok {
		// one runtime to rule them all
		return l.v2Runtime, nil
	}
	return runtime, nil
}
```
- TaskManager_v2_shim实现了PlatformRuntime接口(https://github.com/containerd/containerd/blob/main/runtime/v2/manager.go)，参考Runtime服务.md。这里我们只看Create
```diff
// TaskManager manages v2 shim's and their tasks
type TaskManager struct {
	root                   string
	state                  string
	containerdAddress      string
	containerdTTRPCAddress string

	tasks      *runtime.TaskList
	events     *exchange.Exchange
	containers containers.Store
}

// Create a new task
func (m *TaskManager) Create(ctx context.Context, id string, opts runtime.CreateOpts) (_ runtime.Task, retErr error) {
+	bundle, err := NewBundle(ctx, m.root, m.state, id, opts.Spec.Value)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			bundle.Delete()
		}
	}()

+	shim, err := m.startShim(ctx, bundle, id, opts)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			m.deleteShim(shim)
		}
	}()

+	t, err := shim.Create(ctx, opts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create shim")
	}

+	if err := m.tasks.Add(ctx, t); err != nil {
		return nil, errors.Wrap(err, "failed to add task")
	}

	return t, nil
}
```

> 创建OCI Bundle。准备好rootfs，work，state的目录和并建立spec文件
```diff
func NewBundle(ctx context.Context, root, state, id string, spec []byte) (b *Bundle, err error) {
	if err := identifiers.Validate(id); err != nil {
		return nil, errors.Wrapf(err, "invalid task id %s", id)
	}

	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}
	work := filepath.Join(root, ns, id)
	b = &Bundle{
		ID:        id,
		Path:      filepath.Join(state, ns, id),
		Namespace: ns,
	}
	var paths []string
	defer func() {
		if err != nil {
			for _, d := range paths {
				os.RemoveAll(d)
			}
		}
	}()
	// create state directory for the bundle
	if err := os.MkdirAll(filepath.Dir(b.Path), 0711); err != nil {
		return nil, err
	}
+	if err := os.Mkdir(b.Path, 0711); err != nil {
		return nil, err
	}
	paths = append(paths, b.Path)
	// create working directory for the bundle
	if err := os.MkdirAll(filepath.Dir(work), 0711); err != nil {
		return nil, err
	}
+	rootfs := filepath.Join(b.Path, "rootfs")
	if err := os.MkdirAll(rootfs, 0711); err != nil {
		return nil, err
	}
	paths = append(paths, rootfs)
+	if err := os.Mkdir(work, 0711); err != nil {
		if !os.IsExist(err) {
			return nil, err
		}
		os.RemoveAll(work)
		if err := os.Mkdir(work, 0711); err != nil {
			return nil, err
		}
	}
	paths = append(paths, work)
	// symlink workdir
	if err := os.Symlink(work, filepath.Join(b.Path, "work")); err != nil {
		return nil, err
	}
	// write the spec to the bundle
+	err = ioutil.WriteFile(filepath.Join(b.Path, configFilename), spec, 0666)
	return b, err
}

// Bundle represents an OCI bundle
type Bundle struct {
	// ID of the bundle
	ID string
	// Path to the bundle
	Path string
	// Namespace of the bundle
	Namespace string
}
```
> startShim的实现
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
-	// 命令行格式类似$containerd-shim-runc-shim --ns xxx --address xxx --bundle xxxx --id xxxx
	b := shimBinary(bundle, opts.Runtime, m.containerdAddress, m.containerdTTRPCAddress)
-	// 启动shim进程
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
>> b.start，shimBinary启动
```diff
func shimBinary(bundle *Bundle, runtime, containerdAddress string, containerdTTRPCAddress string) *binary {
	return &binary{
		bundle:                 bundle,
		runtime:                runtime,
		containerdAddress:      containerdAddress,
		containerdTTRPCAddress: containerdTTRPCAddress,
	}
}

- // 启动shim v2
func (b *binary) Start(ctx context.Context, opts *types.Any, onClose func()) (_ *shim, err error) {
	args := []string{"-id", b.bundle.ID}
	switch logrus.GetLevel() {
	case logrus.DebugLevel, logrus.TraceLevel:
		args = append(args, "-debug")
	}
	args = append(args, "start")
-	// 准备shim的命令行和参数
	cmd, err := client.Command(
		ctx,
		b.runtime,
		b.containerdAddress,
		b.containerdTTRPCAddress,
		b.bundle.Path,
		opts,
		args...,
	)
	if err != nil {
		return nil, err
	}
	// Windows needs a namespace when openShimLog
	ns, _ := namespaces.Namespace(ctx)
	shimCtx, cancelShimLog := context.WithCancel(namespaces.WithNamespace(context.Background(), ns))
	defer func() {
		if err != nil {
			cancelShimLog()
		}
	}()
	f, err := openShimLog(shimCtx, b.bundle, client.AnonDialer)
	if err != nil {
		return nil, errors.Wrap(err, "open shim log pipe")
	}
	defer func() {
		if err != nil {
			f.Close()
		}
	}()
	// open the log pipe and block until the writer is ready
	// this helps with synchronization of the shim
	// copy the shim's logs to containerd's output
	go func() {
		defer f.Close()
		_, err := io.Copy(os.Stderr, f)
		// To prevent flood of error messages, the expected error
		// should be reset, like os.ErrClosed or os.ErrNotExist, which
		// depends on platform.
		err = checkCopyShimLogError(ctx, err)
		if err != nil {
			log.G(ctx).WithError(err).Error("copy shim log")
		}
	}()
-	// 运行命令，并返回标准输出和错误	
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, errors.Wrapf(err, "%s", out)
	}
	address := strings.TrimSpace(string(out))
	conn, err := client.Connect(address, client.AnonDialer)
	if err != nil {
		return nil, err
	}
	onCloseWithShimLog := func() {
		onClose()
		cancelShimLog()
		f.Close()
	}
-	// 创建client用来和v2 shim通信
	client := ttrpc.NewClient(conn, ttrpc.WithOnClose(onCloseWithShimLog))
	return &shim{
		bundle: b.bundle,
		client: client,
		task:   task.NewTaskClient(client),
	}, nil
}
```
> client.command
```diff
// Command returns the shim command with the provided args and configuration
func Command(ctx context.Context, runtime, containerdAddress, containerdTTRPCAddress, path string, opts *types.Any, cmdArgs ...string) (*exec.Cmd, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := []string{
		"-namespace", ns,
		"-address", containerdAddress,
		"-publish-binary", self,
	}
	args = append(args, cmdArgs...)
	name := BinaryName(runtime)
	if name == "" {
		return nil, fmt.Errorf("invalid runtime name %s, correct runtime name should format like io.containerd.runc.v1", runtime)
	}

	var cmdPath string
	cmdPathI, cmdPathFound := runtimePaths.Load(name)
	if cmdPathFound {
		cmdPath = cmdPathI.(string)
	} else {
		var lerr error
		binaryPath := BinaryPath(runtime)
		if _, serr := os.Stat(binaryPath); serr == nil {
			cmdPath = binaryPath
		}

		if cmdPath == "" {
			if cmdPath, lerr = exec.LookPath(name); lerr != nil {
				if eerr, ok := lerr.(*exec.Error); ok {
					if eerr.Err == exec.ErrNotFound {
						// Match the calling binaries (containerd) path and see
						// if they are side by side. If so, execute the shim
						// found there.
						testPath := filepath.Join(filepath.Dir(self), name)
						if _, serr := os.Stat(testPath); serr == nil {
							cmdPath = testPath
						}
						if cmdPath == "" {
							return nil, errors.Wrapf(os.ErrNotExist, "runtime %q binary not installed %q", runtime, name)
						}
					}
				}
			}
		}
		cmdPath, err = filepath.Abs(cmdPath)
		if err != nil {
			return nil, err
		}
		if cmdPathI, cmdPathFound = runtimePaths.LoadOrStore(name, cmdPath); cmdPathFound {
			// We didn't store cmdPath we loaded an already cached value. Use it.
			cmdPath = cmdPathI.(string)
		}
	}

	cmd := exec.CommandContext(ctx, cmdPath, args...)
	cmd.Dir = path
	cmd.Env = append(
		os.Environ(),
		"GOMAXPROCS=2",
		fmt.Sprintf("%s=%s", ttrpcAddressEnv, containerdTTRPCAddress),
	)
	cmd.SysProcAttr = getSysProcAttr()
	if opts != nil {
		d, err := proto.Marshal(opts)
		if err != nil {
			return nil, err
		}
		cmd.Stdin = bytes.NewReader(d)
	}
	return cmd, nil
}
```

- shim.Create实现了一个create task的请求
```diff
type shim struct {
	bundle *Bundle
	client *ttrpc.Client
	task   task.TaskService
}

func (s *shim) Create(ctx context.Context, opts runtime.CreateOpts) (runtime.Task, error) {
	topts := opts.TaskOptions
	if topts == nil {
		topts = opts.RuntimeOptions
	}
	request := &task.CreateTaskRequest{
		ID:         s.ID(),
		Bundle:     s.bundle.Path,
		Stdin:      opts.IO.Stdin,
		Stdout:     opts.IO.Stdout,
		Stderr:     opts.IO.Stderr,
		Terminal:   opts.IO.Terminal,
		Checkpoint: opts.Checkpoint,
		Options:    topts,
	}
	for _, m := range opts.Rootfs {
		request.Rootfs = append(request.Rootfs, &types.Mount{
			Type:    m.Type,
			Source:  m.Source,
			Options: m.Options,
		})
	}

	_, err := s.task.Create(ctx, request)
	if err != nil {
		return nil, errdefs.FromGRPC(err)
	}

	return s, nil
}
```

> s.task.Create是调用shim进程里的create服务
```diff
func (c *taskClient) Create(ctx context.Context, req *CreateTaskRequest) (*CreateTaskResponse, error) {
	var resp CreateTaskResponse
	if err := c.client.Call(ctx, "containerd.task.v2.Task", "Create", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
```

- ***Shim进程***
- containerd请求创建Task
```diff
+	c.client.Call(ctx, "containerd.task.v2.Task", "Create", req, &resp)
```
(https://github.com/containerd/containerd/blob/main/runtime/v2/runc/v2/service.go)
```diff
// Create a new initial process and container with the underlying OCI runtime
func (s *service) Create(ctx context.Context, r *taskAPI.CreateTaskRequest) (_ *taskAPI.CreateTaskResponse, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	container, err := runc.NewContainer(ctx, s.platform, r)
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

- runc.NewContainer
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

+	p, err := newInit(
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
+	if err := p.Create(ctx, config); err != nil {
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
> newInit
```diff
func newInit(ctx context.Context, path, workDir, namespace string, platform stdio.Platform,
	r *process.CreateConfig, options *options.Options, rootfs string) (*process.Init, error) {
	runtime := process.NewRunc(options.Root, path, namespace, options.BinaryName, options.CriuPath, options.SystemdCgroup)
	p := process.New(r.ID, runtime, stdio.Stdio{
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

// Init represents an initial process for a container
type Init struct {
	wg        sync.WaitGroup
	initState initState

	// mu is used to ensure that `Start()` and `Exited()` calls return in
	// the right order when invoked in separate go routines.
	// This is the case within the shim implementation as it makes use of
	// the reaper interface.
	mu sync.Mutex

	waitBlock chan struct{}

	WorkDir string

	id       string
	Bundle   string
	console  console.Console
	Platform stdio.Platform
	io       *processIO
	runtime  *runc.Runc
	// pausing preserves the pausing state.
	pausing      *atomicBool
	status       int
	exited       time.Time
	pid          int
	closers      []io.Closer
	stdin        io.Closer
	stdio        stdio.Stdio
	Rootfs       string
	IoUID        int
	IoGID        int
	NoPivotRoot  bool
	NoNewKeyring bool
	CriuWorkPath string
}
```

- p.Create 
```diff
// Create the process with the provided config
func (p *Init) Create(ctx context.Context, r *CreateConfig) error {
	var (
		err     error
		socket  *runc.Socket
		pio     *processIO
		pidFile = newPidFile(p.Bundle)
	)

-	// 如果指定tty，就生成一个socket接收runc里面的masterfd
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
		opts.ConsoleSocket = socket
	}
-	// 启动runc创建container,返回pid	
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
		console, err := socket.ReceiveMaster()
		if err != nil {
			return errors.Wrap(err, "failed to retrieve console master")
		}
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
- p.runtime.Create
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
-	// 启动runc进程	
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

### 步骤三：启动runtime里的container
- task.start
```diff
func (t *task) Start(ctx context.Context) error {
-	// 调用服务器端task servce的Start
	r, err := t.client.TaskService().Start(ctx, &tasks.StartRequest{
		ContainerID: t.id,
	})
	if err != nil {
		if t.io != nil {
			t.io.Cancel()
			t.io.Close()
		}
		return errdefs.FromGRPC(err)
	}
	t.pid = r.Pid
	return nil
}
```

- ***TaskService.Start***调用server端Task Service的Start 
```
func (s *service) Start(ctx context.Context, r *api.StartRequest) (*api.StartResponse, error) {
	return s.local.Start(ctx, r)
}
```
- 转到内部service的Start
```diff
func (l *local) Start(ctx context.Context, r *api.StartRequest, _ ...grpc.CallOption) (*api.StartResponse, error) {
-	// 返回runtime.Task接口类型
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
-	//强制转换到runtime.Process	
	p := runtime.Process(t)
	if r.ExecID != "" {
		if p, err = t.Process(ctx, r.ExecID); err != nil {
			return nil, errdefs.ToGRPC(err)
		}
	}
-	// 启动task，其实就是runc命令行
	if err := p.Start(ctx); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
+	state, err := p.State(ctx)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return &api.StartResponse{
		Pid: state.Pid,
	}, nil
}
```
> 支持函数
```diff
		func (l *local) getTask(ctx context.Context, id string) (runtime.Task, error) {
			container, err := l.getContainer(ctx, id)
			if err != nil {
				return nil, err
			}
			return l.getTaskFromContainer(ctx, container)
		}

		func (l *local) getContainer(ctx context.Context, id string) (*containers.Container, error) {
			var container containers.Container
			container, err := l.containers.Get(ctx, id)
			if err != nil {
				return nil, errdefs.ToGRPC(err)
			}
			return &container, nil
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
```

- p.start 
(https://github.com/containerd/containerd/blob/main/runtime/v2/process.go)
```
// Start the process
func (p *process) Start(ctx context.Context) error {
	_, err := p.shim.task.Start(ctx, &task.StartRequest{
		ID:     p.shim.ID(),
		ExecID: p.id,
	})
	if err != nil {
		return errdefs.FromGRPC(err)
	}
	return nil
}
```

- p.shim.task.Start
```diff
// Start a process
func (s *service) Start(ctx context.Context, r *taskAPI.StartRequest) (*taskAPI.StartResponse, error) {
	container, err := s.getContainer(r.ID)
	if err != nil {
		return nil, err
	}

	// hold the send lock so that the start events are sent before any exit events in the error case
	s.eventSendMu.Lock()
	p, err := container.Start(ctx, r)
	if err != nil {
		s.eventSendMu.Unlock()
		return nil, errdefs.ToGRPC(err)
	}

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

- container.start
```diff
// Start a container process
func (c *Container) Start(ctx context.Context, r *task.StartRequest) (process.Process, error) {
	p, err := c.Process(r.ExecID)
	if err != nil {
		return nil, err
	}
	if err := p.Start(ctx); err != nil {
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
	p, ok := c.processes[id]
	if !ok {
		return nil, errors.Wrapf(errdefs.ErrNotFound, "process does not exist %s", id)
	}
	return p, nil
}
```
- (https://github.com/containerd/containerd/blob/main/pkg/process/init.go)
```diff
// Start the init process
func (p *Init) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.initState.Start(ctx)
}
```

- s.p这里又回到了Init
```diff
func (s *createdState) Start(ctx context.Context) error {
	if err := s.p.start(ctx); err != nil {
		return err
	}
	return s.transition("running")
}
```
- p.runtime实际是runc库(https://github.com/opencontainers/runc),它包装了runc的命令行接口
```diff
func (p *Init) start(ctx context.Context) error {
+	err := p.runtime.Start(ctx, p.id)
	return p.runtimeError(err, "OCI runtime start failed")
}
```

- runc库
```diff
// Start will start an already created container
func (r *Runc) Start(context context.Context, id string) error {
	return r.runOrError(r.command(context, "start", id))
}

// runOrError will run the provided command.  If an error is
// encountered and neither Stdout or Stderr was set the error and the
// stderr of the command will be returned in the format of <error>:
// <stderr>
func (r *Runc) runOrError(cmd *exec.Cmd) error {
	if cmd.Stdout != nil || cmd.Stderr != nil {
-		// 启动runc start进程	
		ec, err := Monitor.Start(cmd)
		if err != nil {
			return err
		}
		status, err := Monitor.Wait(cmd, ec)
		if err == nil && status != 0 {
			err = fmt.Errorf("%s did not terminate successfully: %w", cmd.Args[0], &ExitError{status})
		}
		return err
	}
	data, err := cmdOutput(cmd, true, nil)
	defer putBuf(data)
	if err != nil {
		return fmt.Errorf("%s: %s", err, data.String())
	}
	return nil
}
```
