# ctr image pull镜像过程分析
> 针对命令行$ctr image pull image_ref的执行过程，进行代码分析，帮助理解content service，image service和snapshotter。

### 命令行执行
```diff
- 用ctr image pull拉取ubuntu镜像，对比content fetch，从打印信息可以看出来，多了一个unpack过程
sudo ctr i pull docker.io/library/ubuntu:latest@sha256:10cbddb6cf8568f56584ccb6c866203e68ab8e621bb87038e254f6f27f955bbe
[sudo] password for jwang:
docker.io/library/ubuntu:latest@sha256:10cbddb6cf8568f56584ccb6c866203e68ab8e621bb87038e254f6f27f955bbe: resolved       |++++++++++++++++++++++++++++++++++++++|
manifest-sha256:10cbddb6cf8568f56584ccb6c866203e68ab8e621bb87038e254f6f27f955bbe:                        done           |++++++++++++++++++++++++++++++++++++++|
layer-sha256:35807b77a593c1147d13dc926a91dcc3015616ff7307cc30442c5a8e07546283:                           done           |++++++++++++++++++++++++++++++++++++++|
config-sha256:fb52e22af1b01869e23e75089c368a1130fa538946d0411d47f964f8b1076180:                          done           |++++++++++++++++++++++++++++++++++++++|
elapsed: 9.9 s                                                                                           total:  27.2 M (2.8 MiB/s)
unpacking linux/amd64 sha256:10cbddb6cf8568f56584ccb6c866203e68ab8e621bb87038e254f6f27f955bbe...
done: 638.102235ms
```
- 命令***help***
```diff
ctr image pull --help
NAME:
   ctr images pull - pull an image from a remote

USAGE:
   ctr images pull [command options] [flags] <ref>

DESCRIPTION:
   Fetch and prepare an image for use in containerd.

After pulling an image, it should be ready to use the same reference in a run
command. As part of this process, we do the following:

1. Fetch all resources into containerd.
2. Prepare the snapshot filesystem with the pulled resources.
3. Register metadata for the image.


OPTIONS:
   --skip-verify, -k                 skip SSL certificate validation
   --plain-http                      allow connections using plain HTTP
   --user value, -u value            user[:password] Registry user and password
   --refresh value                   refresh token for authorization server
   --hosts-dir value                 Custom hosts configuration directory
   --tlscacert value                 path to TLS root CA
   --tlscert value                   path to TLS client certificate
   --tlskey value                    path to TLS client key
   --http-dump                       dump all HTTP request/responses when interacting with container registry
   --http-trace                      enable HTTP tracing for registry interactions
   --snapshotter value               snapshotter name. Empty value stands for the default value. [$CONTAINERD_SNAPSHOTTER]
   --label value                     labels to attach to the image
   --platform value                  Pull content from a specific platform
   --all-platforms                   pull content and metadata from all platforms
   --all-metadata                    Pull metadata for all platforms
   --print-chainid                   Print the resulting image's chain ID
   --max-concurrent-downloads value  Set the max concurrent downloads for each pull (default: 0)
```

### [命令入口](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/pull.go)
```diff
- 该命令的作用是把image所有相关资源从仓库拉下来，存到content store里，并unpack到snapshotter。
```
```diff
var pullCommand = cli.Command{
	Name:      "pull",
	Usage:     "pull an image from a remote",
	ArgsUsage: "[flags] <ref>",
	Description: `Fetch and prepare an image for use in containerd.
After pulling an image, it should be ready to use the same reference in a run
command. As part of this process, we do the following:
1. Fetch all resources into containerd.
2. Prepare the snapshot filesystem with the pulled resources.
3. Register metadata for the image.
`,
	Flags: append(append(commands.RegistryFlags, append(commands.SnapshotterFlags, commands.LabelFlag)...),
		cli.StringSliceFlag{
			Name:  "platform",
			Usage: "Pull content from a specific platform",
			Value: &cli.StringSlice{},
		},
		cli.BoolFlag{
			Name:  "all-platforms",
			Usage: "pull content and metadata from all platforms",
		},
		cli.BoolFlag{
			Name:  "all-metadata",
			Usage: "Pull metadata for all platforms",
		},
		cli.BoolFlag{
			Name:  "print-chainid",
			Usage: "Print the resulting image's chain ID",
		},
		cli.IntFlag{
			Name:  "max-concurrent-downloads",
			Usage: "Set the max concurrent downloads for each pull",
		},
	),
	Action: func(context *cli.Context) error {
		var (
			ref = context.Args().First()
		)
		client, ctx, cancel, err := commands.NewClient(context)
		defer cancel()

		ctx, done, err := client.WithLease(ctx)
		defer done(ctx)

		config, err := content.NewFetchConfig(ctx, context)
		img, err := content.Fetch(ctx, client, ref, config)

-   		// 前面就是执行$ctr content fetch命令，区别从这里开始
		log.G(ctx).WithField("image", ref).Debug("unpacking")

		// TODO: Show unpack status

-   		// 根据image.Target和命令行参数收集需要unpack的platform
		var p []ocispec.Platform
		if context.Bool("all-platforms") {
			p, err = images.Platforms(ctx, client.ContentStore(), img.Target)
		} else {
			for _, s := range context.StringSlice("platform") {
				ps, err := platforms.Parse(s)
				p = append(p, ps)
			}
		}
		if len(p) == 0 {
			p = append(p, platforms.DefaultSpec())
		}

		start := time.Now()
		for _, platform := range p {
			fmt.Printf("unpacking %s %s...\n", platforms.Format(platform), img.Target.Digest)
-     			// 生成一个client image      
			i := containerd.NewImageWithPlatform(client, img, platforms.Only(platform))
-     			// 把image unpack到snapshotter
      			err = i.Unpack(ctx, context.String("snapshotter"))
			if context.Bool("print-chainid") {
				diffIDs, err := i.RootFS(ctx)
				chainID := identity.ChainID(diffIDs).String()
				fmt.Printf("image chain ID: %s\n", chainID)
			}
		}
		fmt.Printf("done: %s\t\n", time.Since(start))
		return nil
	},
}

// NewImageWithPlatform returns a client image object from the metadata image
func NewImageWithPlatform(client *Client, i images.Image, platform platforms.MatchComparer) Image {
	return &image{
		client:   client,
		i:        i,
		platform: platform,
	}
}
```

- ***image.unpack***
```diff
func (i *image) Unpack(ctx context.Context, snapshotterName string, opts ...UnpackOpt) error {
	ctx, done, err := i.client.WithLease(ctx)
	defer done(ctx)

	var config UnpackConfig
	for _, o := range opts {
		o(ctx, &config)
	}

	manifest, err := i.getManifest(ctx, i.platform)
	layers, err := i.getLayers(ctx, i.platform, manifest)

	var (
		a  = i.client.DiffService()
		cs = i.client.ContentStore()

		chain    []digest.Digest
		unpacked bool
	)
-	// 如果没有指定snapshotter，使用缺省的	
	snapshotterName, err = i.client.resolveSnapshotterName(ctx, snapshotterName)
	sn, err := i.client.getSnapshotter(ctx, snapshotterName)
	if config.CheckPlatformSupported {
		i.checkSnapshotterSupport(ctx, snapshotterName, manifest)
	}

	for _, layer := range layers {
		unpacked, err = rootfs.ApplyLayerWithOpts(ctx, layer, chain, sn, a, config.SnapshotOpts, config.ApplyOpts)
		if unpacked {
			// Set the uncompressed label after the uncompressed
			// digest has been verified through apply.
			cinfo := content.Info{
				Digest: layer.Blob.Digest,
				Labels: map[string]string{
					"containerd.io/uncompressed": layer.Diff.Digest.String(),
				},
			}
			cs.Update(ctx, cinfo, "labels.containerd.io/uncompressed")
		}

		chain = append(chain, layer.Diff.Digest)
	}

	desc, err := i.i.Config(ctx, cs, i.platform)
	rootfs := identity.ChainID(chain).String()
	cinfo := content.Info{
		Digest: desc.Digest,
		Labels: map[string]string{
			fmt.Sprintf("containerd.io/gc.ref.snapshot.%s", snapshotterName): rootfs,
		},
	}

	_, err = cs.Update(ctx, cinfo, fmt.Sprintf("labels.containerd.io/gc.ref.snapshot.%s", snapshotterName))
	return err
}
```
>> getManifest
```diff
func (i *image) getManifest(ctx context.Context, platform platforms.MatchComparer) (ocispec.Manifest, error) {
	cs := i.ContentStore()
	manifest, err := images.Manifest(ctx, cs, i.i.Target, platform)
	return manifest, nil
}
```
>> getLayers
```diff
func (i *image) getLayers(ctx context.Context, platform platforms.MatchComparer, manifest ocispec.Manifest) ([]rootfs.Layer, error) {
	cs := i.ContentStore()
	diffIDs, err := i.i.RootFS(ctx, cs, platform)
	layers := make([]rootfs.Layer, len(diffIDs))
	for i := range diffIDs {
		layers[i].Diff = ocispec.Descriptor{
			// TODO: derive media type from compressed type
			MediaType: ocispec.MediaTypeImageLayer,
			Digest:    diffIDs[i],
		}
		layers[i].Blob = manifest.Layers[i]
	}
	return layers, nil
}
```

- ***ApplyLayerWithOpts***
```diff
// ApplyLayerWithOpts applies a single layer on top of the given provided layer chain,
// using the provided snapshotter, applier, and apply opts. If the layer was unpacked true
// is returned, if the layer already exists false is returned.
func ApplyLayerWithOpts(ctx context.Context, layer Layer, chain []digest.Digest, sn snapshots.Snapshotter, a diff.Applier, opts []snapshots.Opt, applyOpts []diff.ApplyOpt) (bool, error) {
	var (
		chainID = identity.ChainID(append(chain, layer.Diff.Digest)).String()
		applied bool
	)
-	// 如果chainID代表的layer在snapshoter里面没有，就生成一个	
	if _, err := sn.Stat(ctx, chainID); err != nil {
		if !errdefs.IsNotFound(err) {
			return false, errors.Wrapf(err, "failed to stat snapshot %s", chainID)
		}

+		if err := applyLayers(ctx, []Layer{layer}, append(chain, layer.Diff.Digest), sn, a, opts, applyOpts); err != nil {
			if !errdefs.IsAlreadyExists(err) {
				return false, err
			}
		} else {
			applied = true
		}
	}
	return applied, nil

}
```

- ***applylayers***
```diff
- 在snapshotter里增加Layer分三步，prepare，apply和commit
```
```diff
func applyLayers(ctx context.Context, layers []Layer, chain []digest.Digest, sn snapshots.Snapshotter, a diff.Applier, opts []snapshots.Opt, applyOpts []diff.ApplyOpt) error {
	var (
		parent  = identity.ChainID(chain[:len(chain)-1])
		chainID = identity.ChainID(chain)
		layer   = layers[len(layers)-1]
		diff    ocispec.Descriptor
		key     string
		mounts  []mount.Mount
		err     error
	)

	for {
-		// key的产生	
		key = fmt.Sprintf(snapshots.UnpackKeyFormat, uniquePart(), chainID)

		// Prepare snapshot with from parent, label as root
+		mounts, err = sn.Prepare(ctx, key, parent.String(), opts...)
		if err != nil {
			if errdefs.IsNotFound(err) && len(layers) > 1 {
				if err := applyLayers(ctx, layers[:len(layers)-1], chain[:len(chain)-1], sn, a, opts, applyOpts); err != nil {
					if !errdefs.IsAlreadyExists(err) {
						return err
					}
				}
				// Do no try applying layers again
				layers = nil
				continue
			} else if errdefs.IsAlreadyExists(err) {
				// Try a different key
				continue
			}
		}
		break
	}

+	diff, err = a.Apply(ctx, layer.Blob, mounts, applyOpts...)
	if diff.Digest != layer.Diff.Digest {
		err = errors.Errorf("wrong diff id calculated on extraction %q", diff.Digest)
		return err
	}

+	sn.Commit(ctx, chainID.String(), key, opts...)

	return nil
}
```
