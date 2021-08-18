# Containerd运行容器的代码分析
> 通过ctr run命令行，指定一个image和ID，运行容器
```
ctr -n default run --null-io --net-host -d \
    --env PASSWORD=$drone_password \
    --mount type=bind,src=/etc,dst=/host-etc,options=rbind:rw \
    --mount type=bind,src=/root/.kube,dst=/root/.kube,options=rbind:rw \
    $image $ID commands
```

### Client端
- ***ctr run***命令
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
		if err != nil {
			return err
		}
		defer cancel()
+		container, err := NewContainer(ctx, client, context)
		if err != nil {
			return err
		}
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
+		task, err := tasks.NewTask(ctx, client, container, context.String("checkpoint"), con, context.Bool("null-io"), context.String("log-uri"), ioOpts, opts...)
		if err != nil {
			return err
		}

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
			if err := commands.WritePidFile(context.String("pid-file"), int(task.Pid())); err != nil {
				return err
			}
		}
		if enableCNI {
			if _, err := network.Setup(ctx, fullID(ctx, container), fmt.Sprintf("/proc/%d/ns/net", task.Pid())); err != nil {
				return err
			}
		}
+		if err := task.Start(ctx); err != nil {
			return err
		}
		if detach {
			return nil
		}
		if tty {
			if err := tasks.HandleConsoleResize(ctx, task, con); err != nil {
				logrus.WithError(err).Error("console resize")
			}
		} else {
			sigc := commands.ForwardAllSignals(ctx, task)
			defer commands.StopCatch(sigc)
		}
		status := <-statusC
		code, _, err := status.Result()
		if err != nil {
			return err
		}
		if _, err := task.Delete(ctx); err != nil {
			return err
		}
		if code != 0 {
			return cli.NewExitError("", int(code))
		}
		return nil
	},
}
```
- ***newContainer***是创建一个container，它分成两部分，前面部分是Linux specific，后面是client.newContainer是通用

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
		opts  []oci.SpecOpts
		cOpts []containerd.NewContainerOpts
		spec  containerd.NewContainerOpts
	)

	cOpts = append(cOpts, containerd.WithContainerLabels(commands.LabelArgs(context.StringSlice("label"))))
	if config {
		opts = append(opts, oci.WithSpecFromFile(context.String("config")))
	} else {
		var (
			ref = context.Args().First()
			//for container's id is Args[1]
			args = context.Args()[2:]
		)
		opts = append(opts, oci.WithDefaultSpec(), oci.WithDefaultUnixDevices)
		if ef := context.String("env-file"); ef != "" {
			opts = append(opts, oci.WithEnvFile(ef))
		}
		opts = append(opts, oci.WithEnv(context.StringSlice("env")))
		opts = append(opts, withMounts(context))

		if context.Bool("rootfs") {
			rootfs, err := filepath.Abs(ref)
			if err != nil {
				return nil, err
			}
			opts = append(opts, oci.WithRootFSPath(rootfs))
		} else {
			snapshotter := context.String("snapshotter")
			var image containerd.Image
			i, err := client.ImageService().Get(ctx, ref)
			if err != nil {
				return nil, err
			}
			if ps := context.String("platform"); ps != "" {
				platform, err := platforms.Parse(ps)
				if err != nil {
					return nil, err
				}
				image = containerd.NewImageWithPlatform(client, i, platforms.Only(platform))
			} else {
				image = containerd.NewImage(client, i)
			}

			unpacked, err := image.IsUnpacked(ctx, snapshotter)
			if err != nil {
				return nil, err
			}
			if !unpacked {
				if err := image.Unpack(ctx, snapshotter); err != nil {
					return nil, err
				}
			}
			opts = append(opts, oci.WithImageConfig(image))
			cOpts = append(cOpts,
				containerd.WithImage(image),
				containerd.WithSnapshotter(snapshotter))
			if uidmap, gidmap := context.String("uidmap"), context.String("gidmap"); uidmap != "" && gidmap != "" {
				uidMap, err := parseIDMapping(uidmap)
				if err != nil {
					return nil, err
				}
				gidMap, err := parseIDMapping(gidmap)
				if err != nil {
					return nil, err
				}
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
		if context.Bool("tty") {
			opts = append(opts, oci.WithTTY)
		}
		if context.Bool("privileged") {
			opts = append(opts, oci.WithPrivileged, oci.WithAllDevicesAllowed, oci.WithHostDevices)
		}
		if context.Bool("net-host") {
			opts = append(opts, oci.WithHostNamespace(specs.NetworkNamespace), oci.WithHostHostsFile, oci.WithHostResolvconf)
		}

		seccompProfile := context.String("seccomp-profile")

		if !context.Bool("seccomp") && seccompProfile != "" {
			return nil, fmt.Errorf("seccomp must be set to true, if using a custom seccomp-profile")
		}

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

		if s := context.String("apparmor-profile"); len(s) > 0 {
			if len(context.String("apparmor-default-profile")) > 0 {
				return nil, fmt.Errorf("apparmor-profile conflicts with apparmor-default-profile")
			}
			opts = append(opts, apparmor.WithProfile(s))
		}

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
		limit := context.Uint64("memory-limit")
		if limit != 0 {
			opts = append(opts, oci.WithMemoryLimit(limit))
		}
		for _, dev := range context.StringSlice("device") {
			opts = append(opts, oci.WithDevices(dev, "", "rwm"))
		}

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

	runtimeOpts, err := getRuntimeOptions(context)
	if err != nil {
		return nil, err
	}
	cOpts = append(cOpts, containerd.WithRuntime(context.String("runtime"), runtimeOpts))

	opts = append(opts, oci.WithAnnotations(commands.LabelArgs(context.StringSlice("label"))))
	var s specs.Spec
	spec = containerd.WithSpec(&s, opts...)

	cOpts = append(cOpts, spec)

	// oci.WithImageConfig (WithUsername, WithUserID) depends on access to rootfs for resolving via
	// the /etc/{passwd,group} files. So cOpts needs to have precedence over opts.
+	return client.NewContainer(ctx, id, cOpts...)
}

```diff 
// NewContainer will create a new container in container with the provided id
// the id must be unique within the namespace
func (c *Client) NewContainer(ctx context.Context, id string, opts ...NewContainerOpts) (Container, error) {
	ctx, done, err := c.WithLease(ctx)
	if err != nil {
		return nil, err
	}
	defer done(ctx)
+   // 来自api/services/containers/v1/containers.pb.go(工具生成）
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
+   // 调用Container外部服务的Create方法    
+	r, err := c.ContainerService().Create(ctx, container)
	if err != nil {
		return nil, err
	}
	return containerFromRecord(c, r), nil
}
```
```
// RuntimeInfo holds runtime specific information
type RuntimeInfo struct {
	Name    string
	Options *types.Any
}
```

### Service端
- ***newContainer***
```
```
