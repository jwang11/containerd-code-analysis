# Pull镜像代码分析
> ctr image pull img_ref

### Client端
- 命令格式
```
root@jwang-desktop:/home/jwang/go_grpc/server# ctr image pull --help
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

- 入口代码
（https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/pull.go）
```
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
		if ref == "" {
			return fmt.Errorf("please provide an image reference to pull")
		}

		client, ctx, cancel, err := commands.NewClient(context)
		if err != nil {
			return err
		}
		defer cancel()

		ctx, done, err := client.WithLease(ctx)
		if err != nil {
			return err
		}
		defer done(ctx)

		config, err := content.NewFetchConfig(ctx, context)
		if err != nil {
			return err
		}

		img, err := content.Fetch(ctx, client, ref, config)
		if err != nil {
			return err
		}

		log.G(ctx).WithField("image", ref).Debug("unpacking")

		// TODO: Show unpack status

		var p []ocispec.Platform
		if context.Bool("all-platforms") {
			p, err = images.Platforms(ctx, client.ContentStore(), img.Target)
			if err != nil {
				return errors.Wrap(err, "unable to resolve image platforms")
			}
		} else {
			for _, s := range context.StringSlice("platform") {
				ps, err := platforms.Parse(s)
				if err != nil {
					return errors.Wrapf(err, "unable to parse platform %s", s)
				}
				p = append(p, ps)
			}
		}
		if len(p) == 0 {
			p = append(p, platforms.DefaultSpec())
		}

		start := time.Now()
		for _, platform := range p {
			fmt.Printf("unpacking %s %s...\n", platforms.Format(platform), img.Target.Digest)
			i := containerd.NewImageWithPlatform(client, img, platforms.Only(platform))
			err = i.Unpack(ctx, context.String("snapshotter"))
			if err != nil {
				return err
			}
			if context.Bool("print-chainid") {
				diffIDs, err := i.RootFS(ctx)
				if err != nil {
					return err
				}
				chainID := identity.ChainID(diffIDs).String()
				fmt.Printf("image chain ID: %s\n", chainID)
			}
		}
		fmt.Printf("done: %s\t\n", time.Since(start))
		return nil
	},
}
```
