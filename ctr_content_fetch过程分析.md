# ctr_content_fetch过程分析
> 针对命令行$ctr content fetch image_ref的执行过程，进行代码分析。

### 命令行执行
```diff
- 用ctr content fetch拉取nginx镜像
$ctr content fetch docker.io/library/nginx:latest
docker.io/library/nginx:latest:                                                   resolved       |++++++++++++++++++++++++++++++++++++++|
index-sha256:47ae43cdfc7064d28800bc42e79a429540c7c80168e8c8952778c0d5af1c09db:    done           |++++++++++++++++++++++++++++++++++++++|
manifest-sha256:2f1cd90e00fe2c991e18272bb35d6a8258eeb27785d121aa4cc1ae4235167cfd: done           |++++++++++++++++++++++++++++++++++++++|
layer-sha256:edb81c9bc1f5416a41e5bea21748dc912772fedbd4bd90e5e3ebfe16b453edce:    done           |++++++++++++++++++++++++++++++++++++++|
layer-sha256:b21fed559b9f420d83f8e38ca08d1ac4f15298a3ae02c6de56f364bee2299f78:    done           |++++++++++++++++++++++++++++++++++++++|
layer-sha256:03e6a245275128e26fc650e724e3fc4510d81f8111bae35ece70242b0a638215:    done           |++++++++++++++++++++++++++++++++++++++|
config-sha256:4f380adfc10f4cd34f775ae57a17d2835385efd5251d6dfe0f246b0018fb0399:   done           |++++++++++++++++++++++++++++++++++++++|
layer-sha256:5430e98eba646ef4a34baff035f6f7483761c873711febd48fbcca38d7890c1e:    done           |++++++++++++++++++++++++++++++++++++++|
layer-sha256:b82f7f888feb03d38fed4dad68d7265a8b276f1f0c543d549fc6ef30b42c00eb:    done           |++++++++++++++++++++++++++++++++++++++|
layer-sha256:b4d181a07f8025e00e0cb28f1cc14613da2ce26450b80c54aea537fa93cf3bda:    exists         |++++++++++++++++++++++++++++++++++++++|
elapsed: 7.7 s                                                                    total:  25.4 M (3.3 MiB/s)
```

### [命令入口](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/content/fetch.go)
```diff
var fetchCommand = cli.Command{
	Name:      "fetch",
	Usage:     "fetch all content for an image into containerd",
	ArgsUsage: "[flags] <remote> <object>",
	Description: `Fetch an image into containerd.
	
This command ensures that containerd has all the necessary resources to build
an image's rootfs and convert the configuration to a runtime format supported
by containerd.
This command uses the same syntax, of remote and object, as 'ctr fetch-object'.
We may want to make this nicer, but agnostism is preferred for the moment.
Right now, the responsibility of the daemon and the cli aren't quite clear. Do
not use this implementation as a guide. The end goal should be having metadata,
content and snapshots ready for a direct use via the 'ctr run'.
Most of this is experimental and there are few leaps to make this work.`,
	Flags: append(commands.RegistryFlags, commands.LabelFlag,
		cli.StringSliceFlag{
			Name:  "platform",
			Usage: "Pull content from a specific platform",
		},
		cli.BoolFlag{
			Name:  "all-platforms",
			Usage: "pull content from all platforms",
		},
		cli.BoolFlag{
			Name:  "all-metadata",
			Usage: "Pull metadata for all platforms",
		},
		cli.BoolFlag{
			Name:  "metadata-only",
			Usage: "Pull all metadata including manifests and configs",
		},
	),
	Action: func(clicontext *cli.Context) error {
		var (
			ref = clicontext.Args().First()
		)
    
-   // 创建一个基于gprc的containerd client
+		client, ctx, cancel, err := commands.NewClient(clicontext)
		if err != nil {
			return err
		}
		defer cancel()
    
-   // 生成fetch config    
+		config, err := NewFetchConfig(ctx, clicontext)
		if err != nil {
			return err
		}
    
-   // 根据fetech_config，把image ref从repo拉下来，放进content store
+		_, err = Fetch(ctx, client, ref, config)
		return err
	},
}
```

> ***NewFetchConfig***
```diff
// FetchConfig for content fetch
type FetchConfig struct {
	// Resolver
	Resolver remotes.Resolver
	// ProgressOutput to display progress
	ProgressOutput io.Writer
	// Labels to set on the content
	Labels []string
	// PlatformMatcher matches platforms, supersedes Platforms
	PlatformMatcher platforms.MatchComparer
	// Platforms to fetch
	Platforms []string
	// Whether or not download all metadata
	AllMetadata bool
	// RemoteOpts to configure object resolutions and transfers with remote content providers
	RemoteOpts []containerd.RemoteOpt
	// TraceHTTP writes DNS and connection information to the log when dealing with a container registry
	TraceHTTP bool
}

// NewFetchConfig returns the default FetchConfig from cli flags
func NewFetchConfig(ctx context.Context, clicontext *cli.Context) (*FetchConfig, error) {
	resolver, err := commands.GetResolver(ctx, clicontext)
	if err != nil {
		return nil, err
	}
	config := &FetchConfig{
		Resolver:  resolver,
		Labels:    clicontext.StringSlice("label"),
		TraceHTTP: clicontext.Bool("http-trace"),
	}
	if !clicontext.GlobalBool("debug") {
		config.ProgressOutput = os.Stdout
	}
	if !clicontext.Bool("all-platforms") {
		p := clicontext.StringSlice("platform")
		if len(p) == 0 {
			p = append(p, platforms.DefaultString())
		}
		config.Platforms = p
	}

	if clicontext.Bool("metadata-only") {
		config.AllMetadata = true
		// Any with an empty set is None
		config.PlatformMatcher = platforms.Any()
	} else if clicontext.Bool("all-metadata") {
		config.AllMetadata = true
	}

	if clicontext.IsSet("max-concurrent-downloads") {
		mcd := clicontext.Int("max-concurrent-downloads")
		config.RemoteOpts = append(config.RemoteOpts, containerd.WithMaxConcurrentDownloads(mcd))
	}

	if clicontext.IsSet("max-concurrent-uploaded-layers") {
		mcu := clicontext.Int("max-concurrent-uploaded-layers")
		config.RemoteOpts = append(config.RemoteOpts, containerd.WithMaxConcurrentUploadedLayers(mcu))
	}

	return config, nil
}
```

- ***Fetch***
```diff
// Fetch loads all resources into the content store and returns the image
func Fetch(ctx context.Context, client *containerd.Client, ref string, config *FetchConfig) (images.Image, error) {
	ongoing := NewJobs(ref)

	if config.TraceHTTP {
		ctx = httptrace.WithClientTrace(ctx, commands.NewDebugClientTrace(ctx))
	}

	pctx, stopProgress := context.WithCancel(ctx)
	progress := make(chan struct{})

	go func() {
		if config.ProgressOutput != nil {
			// no progress bar, because it hides some debug logs
			ShowProgress(pctx, ongoing, client.ContentStore(), config.ProgressOutput)
		}
		close(progress)
	}()

	h := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if desc.MediaType != images.MediaTypeDockerSchema1Manifest {
			ongoing.Add(desc)
		}
		return nil, nil
	})

	log.G(pctx).WithField("image", ref).Debug("fetching")
	labels := commands.LabelArgs(config.Labels)
-	// 这里定义了一组fetch context相关的函数
+	opts := []containerd.RemoteOpt{
		containerd.WithPullLabels(labels),
		containerd.WithResolver(config.Resolver),
		containerd.WithImageHandler(h),
		containerd.WithSchema1Conversion,
	}
	opts = append(opts, config.RemoteOpts...)

	if config.AllMetadata {
		opts = append(opts, containerd.WithAllMetadata())
	}

	if config.PlatformMatcher != nil {
		opts = append(opts, containerd.WithPlatformMatcher(config.PlatformMatcher))
	} else {
		for _, platform := range config.Platforms {
			opts = append(opts, containerd.WithPlatform(platform))
		}
	}

+	img, err := client.Fetch(pctx, ref, opts...)
	stopProgress()
	if err != nil {
		return images.Image{}, err
	}

	<-progress
	return img, nil
}
```

- ***client.Fetch(pctx, ref, opts...)***
```diff
// Fetch downloads the provided content into containerd's content store
// and returns a non-platform specific image reference
func (c *Client) Fetch(ctx context.Context, ref string, opts ...RemoteOpt) (images.Image, error) {

+	fetchCtx := defaultRemoteContext()
-	// 把RemoteOpt数组里的函数执行一遍，修改fetchCtx
+	for _, o := range opts {
		if err := o(c, fetchCtx); err != nil {
			return images.Image{}, err
		}
	}

	if fetchCtx.Unpack {
		return images.Image{}, errors.Wrap(errdefs.ErrNotImplemented, "unpack on fetch not supported, try pull")
	}

	if fetchCtx.PlatformMatcher == nil {
		if len(fetchCtx.Platforms) == 0 {
			fetchCtx.PlatformMatcher = platforms.All
		} else {
			var ps []ocispec.Platform
			for _, s := range fetchCtx.Platforms {
				p, err := platforms.Parse(s)
				if err != nil {
					return images.Image{}, errors.Wrapf(err, "invalid platform %s", s)
				}
				ps = append(ps, p)
			}

			fetchCtx.PlatformMatcher = platforms.Any(ps...)
		}
	}

	ctx, done, err := c.WithLease(ctx)
	if err != nil {
		return images.Image{}, err
	}
	defer done(ctx)

	img, err := c.fetch(ctx, fetchCtx, ref, 0)
	if err != nil {
		return images.Image{}, err
	}
	return c.createNewImage(ctx, img)
}

func defaultRemoteContext() *RemoteContext {
	return &RemoteContext{
		Resolver: docker.NewResolver(docker.ResolverOptions{
			Client: http.DefaultClient,
		}),
	}
}
```

- ***c.fetch(ctx, fetchCtx, ref, 0)***
```diff
func (c *Client) fetch(ctx context.Context, rCtx *RemoteContext, ref string, limit int) (images.Image, error) {
	store := c.ContentStore()
-	// 用resovler得到image ref的descriptor
+	name, desc, err := rCtx.Resolver.Resolve(ctx, ref)
	if err != nil {
		return images.Image{}, errors.Wrapf(err, "failed to resolve reference %q", ref)
	}

	fetcher, err := rCtx.Resolver.Fetcher(ctx, name)
	if err != nil {
		return images.Image{}, errors.Wrapf(err, "failed to get fetcher for %q", name)
	}

	var (
		handler images.Handler

		isConvertible bool
		converterFunc func(context.Context, ocispec.Descriptor) (ocispec.Descriptor, error)
		limiter       *semaphore.Weighted
	)

	if desc.MediaType == images.MediaTypeDockerSchema1Manifest && rCtx.ConvertSchema1 {
		schema1Converter := schema1.NewConverter(store, fetcher)

		handler = images.Handlers(append(rCtx.BaseHandlers, schema1Converter)...)

		isConvertible = true

		converterFunc = func(ctx context.Context, _ ocispec.Descriptor) (ocispec.Descriptor, error) {
			return schema1Converter.Convert(ctx)
		}
	} else {
		// Get all the children for a descriptor
		childrenHandler := images.ChildrenHandler(store)
		// Set any children labels for that content
		childrenHandler = images.SetChildrenMappedLabels(store, childrenHandler, rCtx.ChildLabelMap)
		if rCtx.AllMetadata {
			// Filter manifests by platforms but allow to handle manifest
			// and configuration for not-target platforms
			childrenHandler = remotes.FilterManifestByPlatformHandler(childrenHandler, rCtx.PlatformMatcher)
		} else {
			// Filter children by platforms if specified.
			childrenHandler = images.FilterPlatforms(childrenHandler, rCtx.PlatformMatcher)
		}
		// Sort and limit manifests if a finite number is needed
		if limit > 0 {
			childrenHandler = images.LimitManifests(childrenHandler, rCtx.PlatformMatcher, limit)
		}

		// set isConvertible to true if there is application/octet-stream media type
		convertibleHandler := images.HandlerFunc(
			func(_ context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
				if desc.MediaType == docker.LegacyConfigMediaType {
					isConvertible = true
				}

				return []ocispec.Descriptor{}, nil
			},
		)

		appendDistSrcLabelHandler, err := docker.AppendDistributionSourceLabel(store, ref)
		if err != nil {
			return images.Image{}, err
		}

		handlers := append(rCtx.BaseHandlers,
			remotes.FetchHandler(store, fetcher),
			convertibleHandler,
			childrenHandler,
			appendDistSrcLabelHandler,
		)

		handler = images.Handlers(handlers...)

		converterFunc = func(ctx context.Context, desc ocispec.Descriptor) (ocispec.Descriptor, error) {
			return docker.ConvertManifest(ctx, store, desc)
		}
	}

	if rCtx.HandlerWrapper != nil {
		handler = rCtx.HandlerWrapper(handler)
	}

	if rCtx.MaxConcurrentDownloads > 0 {
		limiter = semaphore.NewWeighted(int64(rCtx.MaxConcurrentDownloads))
	}

-	// 开始并行下载所有的children
+	if err := images.Dispatch(ctx, handler, limiter, desc); err != nil {
		return images.Image{}, err
	}

	if isConvertible {
		if desc, err = converterFunc(ctx, desc); err != nil {
			return images.Image{}, err
		}
	}

	return images.Image{
		Name:   name,
		Target: desc,
		Labels: rCtx.Labels,
	}, nil
}
```
