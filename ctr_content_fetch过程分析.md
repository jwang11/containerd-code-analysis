# ctr_content_fetch过程分析
> 针对命令行$ctr content fetch image_ref的执行过程，进行代码分析，帮助理解content service。

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
- 该命令的作用是把image所有相关资源从仓库拉下来，并把config转换成runtime格式。
```
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
-	// 根据option和系统环境建立一个Resolver，帮助从registry拉取image
+	resolver, err := commands.GetResolver(ctx, clicontext)
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
> ***NewFetchConfig -> GetResolver***
```diff
// GetResolver prepares the resolver from the environment and options
func GetResolver(ctx gocontext.Context, clicontext *cli.Context) (remotes.Resolver, error) {
	username := clicontext.String("user")
	var secret string
	if i := strings.IndexByte(username, ':'); i > 0 {
		secret = username[i+1:]
		username = username[0:i]
	}
	options := docker.ResolverOptions{
		Tracker: PushTracker,
	}
	if username != "" {
		if secret == "" {
			fmt.Printf("Password: ")

			var err error
			secret, err = passwordPrompt()
			if err != nil {
				return nil, err
			}

			fmt.Print("\n")
		}
	} else if rt := clicontext.String("refresh"); rt != "" {
		secret = rt
	}

	hostOptions := config.HostOptions{}
	hostOptions.Credentials = func(host string) (string, string, error) {
		// If host doesn't match...
		// Only one host
		return username, secret, nil
	}
	if clicontext.Bool("plain-http") {
		hostOptions.DefaultScheme = "http"
	}
	defaultTLS, err := resolverDefaultTLS(clicontext)
	if err != nil {
		return nil, err
	}
	hostOptions.DefaultTLS = defaultTLS
	if hostDir := clicontext.String("hosts-dir"); hostDir != "" {
		hostOptions.HostDir = config.HostDirFromRoot(hostDir)
	}

	if clicontext.Bool("http-dump") {
		hostOptions.UpdateClient = func(client *http.Client) error {
			client.Transport = &DebugTransport{
				transport: client.Transport,
				writer:    log.G(ctx).Writer(),
			}
			return nil
		}
	}

-	// 根据hostOptions生成RegistryHost函数
+	options.Hosts = config.ConfigureHosts(ctx, hostOptions)

-	// 根据options生成Docker registry的resolver
+	return docker.NewResolver(options), nil
}
```

>> ***NewFetchConfig -> GetResolver -> config.ConfigureHosts***
```diff
type hostConfig struct {
	scheme string
	host   string
	path   string

	capabilities docker.HostCapabilities

	caCerts     []string
	clientPairs [][2]string
	skipVerify  *bool

	header http.Header

	// TODO: Add credential configuration (domain alias, username)
}

// RegistryHost represents a complete configuration for a registry
// host, representing the capabilities, authorizations, connection
// configuration, and location.
type RegistryHost struct {
	Client       *http.Client
	Authorizer   Authorizer
	Host         string
	Scheme       string
	Path         string
	Capabilities HostCapabilities
	Header       http.Header
}

// ConfigureHosts creates a registry hosts function from the provided
// host creation options. The host directory can read hosts.toml or
// certificate files laid out in the Docker specific layout.
// If a `HostDir` function is not required, defaults are used.
func ConfigureHosts(ctx context.Context, options HostOptions) docker.RegistryHosts {
	return func(host string) ([]docker.RegistryHost, error) {
		var hosts []hostConfig
		if options.HostDir != nil {
			dir, err := options.HostDir(host)
			if err != nil && !errdefs.IsNotFound(err) {
				return nil, err
			}
			if dir != "" {
				log.G(ctx).WithField("dir", dir).Debug("loading host directory")
				hosts, err = loadHostDir(ctx, dir)
				if err != nil {
					return nil, err
				}
			}
		}

		// If hosts was not set, add a default host
		// NOTE: Check nil here and not empty, the host may be
		// intentionally configured to not have any endpoints
		if hosts == nil {
			hosts = make([]hostConfig, 1)
		}
		if len(hosts) > 0 && hosts[len(hosts)-1].host == "" {
			if host == "docker.io" {
				hosts[len(hosts)-1].scheme = "https"
				hosts[len(hosts)-1].host = "registry-1.docker.io"
			} else {
				hosts[len(hosts)-1].host = host
				if options.DefaultScheme != "" {
					hosts[len(hosts)-1].scheme = options.DefaultScheme
				} else {
					hosts[len(hosts)-1].scheme = "https"
				}
			}
			hosts[len(hosts)-1].path = "/v2"
			hosts[len(hosts)-1].capabilities = docker.HostCapabilityPull | docker.HostCapabilityResolve | docker.HostCapabilityPush
		}

		var defaultTLSConfig *tls.Config
		if options.DefaultTLS != nil {
			defaultTLSConfig = options.DefaultTLS
		} else {
			defaultTLSConfig = &tls.Config{}
		}

		defaultTransport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:       30 * time.Second,
				KeepAlive:     30 * time.Second,
				FallbackDelay: 300 * time.Millisecond,
			}).DialContext,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			TLSClientConfig:       defaultTLSConfig,
			ExpectContinueTimeout: 5 * time.Second,
		}

		client := &http.Client{
			Transport: defaultTransport,
		}
		if options.UpdateClient != nil {
			if err := options.UpdateClient(client); err != nil {
				return nil, err
			}
		}

		authOpts := []docker.AuthorizerOpt{docker.WithAuthClient(client)}
		if options.Credentials != nil {
			authOpts = append(authOpts, docker.WithAuthCreds(options.Credentials))
		}
		authorizer := docker.NewDockerAuthorizer(authOpts...)

		rhosts := make([]docker.RegistryHost, len(hosts))
		for i, host := range hosts {

			rhosts[i].Scheme = host.scheme
			rhosts[i].Host = host.host
			rhosts[i].Path = host.path
			rhosts[i].Capabilities = host.capabilities
			rhosts[i].Header = host.header

			if host.caCerts != nil || host.clientPairs != nil || host.skipVerify != nil {
				tr := defaultTransport.Clone()
				tlsConfig := tr.TLSClientConfig
				if host.skipVerify != nil {
					tlsConfig.InsecureSkipVerify = *host.skipVerify
				}
				if host.caCerts != nil {
					if tlsConfig.RootCAs == nil {
						rootPool, err := rootSystemPool()
						if err != nil {
							return nil, errors.Wrap(err, "unable to initialize cert pool")
						}
						tlsConfig.RootCAs = rootPool
					}
					for _, f := range host.caCerts {
						data, err := ioutil.ReadFile(f)
						if err != nil {
							return nil, errors.Wrapf(err, "unable to read CA cert %q", f)
						}
						if !tlsConfig.RootCAs.AppendCertsFromPEM(data) {
							return nil, errors.Errorf("unable to load CA cert %q", f)
						}
					}
				}

				if host.clientPairs != nil {
					for _, pair := range host.clientPairs {
						certPEMBlock, err := ioutil.ReadFile(pair[0])
						if err != nil {
							return nil, errors.Wrapf(err, "unable to read CERT file %q", pair[0])
						}
						var keyPEMBlock []byte
						if pair[1] != "" {
							keyPEMBlock, err = ioutil.ReadFile(pair[1])
							if err != nil {
								return nil, errors.Wrapf(err, "unable to read CERT file %q", pair[1])
							}
						} else {
							// Load key block from same PEM file
							keyPEMBlock = certPEMBlock
						}
						cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
						if err != nil {
							return nil, errors.Wrap(err, "failed to load X509 key pair")
						}

						tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
					}
				}

				c := *client
				c.Transport = tr
				if options.UpdateClient != nil {
					if err := options.UpdateClient(&c); err != nil {
						return nil, err
					}
				}

				rhosts[i].Client = &c
				rhosts[i].Authorizer = docker.NewDockerAuthorizer(append(authOpts, docker.WithAuthClient(&c))...)
			} else {
				rhosts[i].Client = client
				rhosts[i].Authorizer = authorizer
			}
		}

		return rhosts, nil
	}

}
```

>> ***NewFetchConfig -> GetResolver -> docker.NewResolver***
```
// NewResolver returns a new resolver to a Docker registry
func NewResolver(options ResolverOptions) remotes.Resolver {
	if options.Tracker == nil {
		options.Tracker = NewInMemoryTracker()
	}

	if options.Headers == nil {
		options.Headers = make(http.Header)
	}
	if _, ok := options.Headers["User-Agent"]; !ok {
		options.Headers.Set("User-Agent", "containerd/"+version.Version)
	}

	resolveHeader := http.Header{}
	if _, ok := options.Headers["Accept"]; !ok {
		// set headers for all the types we support for resolution.
		resolveHeader.Set("Accept", strings.Join([]string{
			images.MediaTypeDockerSchema2Manifest,
			images.MediaTypeDockerSchema2ManifestList,
			ocispec.MediaTypeImageManifest,
			ocispec.MediaTypeImageIndex, "*/*"}, ", "))
	} else {
		resolveHeader["Accept"] = options.Headers["Accept"]
		delete(options.Headers, "Accept")
	}

-	// 如果Hosts函数没有，就生成一个缺省的。
+	if options.Hosts == nil {
		opts := []RegistryOpt{}
		if options.Host != nil {
			opts = append(opts, WithHostTranslator(options.Host))
		}

		if options.Authorizer == nil {
			options.Authorizer = NewDockerAuthorizer(
				WithAuthClient(options.Client),
				WithAuthHeader(options.Headers),
				WithAuthCreds(options.Credentials))
		}
		opts = append(opts, WithAuthorizer(options.Authorizer))

		if options.Client != nil {
			opts = append(opts, WithClient(options.Client))
		}
		if options.PlainHTTP {
			opts = append(opts, WithPlainHTTP(MatchAllHosts))
		} else {
			opts = append(opts, WithPlainHTTP(MatchLocalhost))
		}
+		options.Hosts = ConfigureDefaultRegistries(opts...)
	}
	return &dockerResolver{
		hosts:         options.Hosts,
		header:        options.Headers,
		resolveHeader: resolveHeader,
		tracker:       options.Tracker,
	}
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

-	// 正式开始fetch镜像
+	img, err := c.fetch(ctx, fetchCtx, ref, 0)
	if err != nil {
		return images.Image{}, err
	}
+	return c.createNewImage(ctx, img)
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
// Descriptor describes the disposition of targeted content.
// This structure provides `application/vnd.oci.descriptor.v1+json` mediatype
// when marshalled to JSON.
type Descriptor struct {
	// MediaType is the media type of the object this schema refers to.
	MediaType string `json:"mediaType,omitempty"`

	// Digest is the digest of the targeted content.
	Digest digest.Digest `json:"digest"`

	// Size specifies the size in bytes of the blob.
	Size int64 `json:"size"`

	// URLs specifies a list of URLs from which this object MAY be downloaded
	URLs []string `json:"urls,omitempty"`

	// Annotations contains arbitrary metadata relating to the targeted content.
	Annotations map[string]string `json:"annotations,omitempty"`

	// Platform describes the platform which the image in the manifest runs on.
	//
	// This should only be used when referring to a manifest.
	Platform *Platform `json:"platform,omitempty"`
}

func (r *dockerResolver) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	base, err := r.resolveDockerBase(ref)
	if err != nil {
		return nil, err
	}

	return dockerFetcher{
		dockerBase: base,
	}, nil
}

func (c *Client) fetch(ctx context.Context, rCtx *RemoteContext, ref string, limit int) (images.Image, error) {
	store := c.ContentStore()
-	// 用resovler得到image ref的descriptor
+	name, desc, err := rCtx.Resolver.Resolve(ctx, ref)
	if err != nil {
		return images.Image{}, errors.Wrapf(err, "failed to resolve reference %q", ref)
	}

+	fetcher, err := rCtx.Resolver.Fetcher(ctx, name)
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

-	// 开始并行下载配置好的所有handler
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

>> ***Resolver.Resolve***
```diff
func (r *dockerResolver) Resolve(ctx context.Context, ref string) (string, ocispec.Descriptor, error) {
	base, err := r.resolveDockerBase(ref)
	if err != nil {
		return "", ocispec.Descriptor{}, err
	}
	refspec := base.refspec
	if refspec.Object == "" {
		return "", ocispec.Descriptor{}, reference.ErrObjectRequired
	}

	var (
		firstErr error
		paths    [][]string
		dgst     = refspec.Digest()
		caps     = HostCapabilityPull
	)

	if dgst != "" {
		if err := dgst.Validate(); err != nil {
			// need to fail here, since we can't actually resolve the invalid
			// digest.
			return "", ocispec.Descriptor{}, err
		}

		// turns out, we have a valid digest, make a url.
		paths = append(paths, []string{"manifests", dgst.String()})

		// fallback to blobs on not found.
		paths = append(paths, []string{"blobs", dgst.String()})
	} else {
		// Add
		paths = append(paths, []string{"manifests", refspec.Object})
		caps |= HostCapabilityResolve
	}

	hosts := base.filterHosts(caps)
	if len(hosts) == 0 {
		return "", ocispec.Descriptor{}, errors.Wrap(errdefs.ErrNotFound, "no resolve hosts")
	}

	ctx, err = ContextWithRepositoryScope(ctx, refspec, false)
	if err != nil {
		return "", ocispec.Descriptor{}, err
	}

	for _, u := range paths {
		for _, host := range hosts {
			ctx := log.WithLogger(ctx, log.G(ctx).WithField("host", host.Host))

			req := base.request(host, http.MethodHead, u...)
			if err := req.addNamespace(base.refspec.Hostname()); err != nil {
				return "", ocispec.Descriptor{}, err
			}

			for key, value := range r.resolveHeader {
				req.header[key] = append(req.header[key], value...)
			}

			log.G(ctx).Debug("resolving")
			resp, err := req.doWithRetries(ctx, nil)
			if err != nil {
				if errors.Is(err, ErrInvalidAuthorization) {
					err = errors.Wrapf(err, "pull access denied, repository does not exist or may require authorization")
				}
				// Store the error for referencing later
				if firstErr == nil {
					firstErr = err
				}
				log.G(ctx).WithError(err).Info("trying next host")
				continue // try another host
			}
			resp.Body.Close() // don't care about body contents.

			if resp.StatusCode > 299 {
				if resp.StatusCode == http.StatusNotFound {
					log.G(ctx).Info("trying next host - response was http.StatusNotFound")
					continue
				}
				if resp.StatusCode > 399 {
					// Set firstErr when encountering the first non-404 status code.
					if firstErr == nil {
						firstErr = errors.Errorf("pulling from host %s failed with status code %v: %v", host.Host, u, resp.Status)
					}
					continue // try another host
				}
				return "", ocispec.Descriptor{}, errors.Errorf("pulling from host %s failed with unexpected status code %v: %v", host.Host, u, resp.Status)
			}
			size := resp.ContentLength
			contentType := getManifestMediaType(resp)

			// if no digest was provided, then only a resolve
			// trusted registry was contacted, in this case use
			// the digest header (or content from GET)
			if dgst == "" {
				// this is the only point at which we trust the registry. we use the
				// content headers to assemble a descriptor for the name. when this becomes
				// more robust, we mostly get this information from a secure trust store.
				dgstHeader := digest.Digest(resp.Header.Get("Docker-Content-Digest"))

				if dgstHeader != "" && size != -1 {
					if err := dgstHeader.Validate(); err != nil {
						return "", ocispec.Descriptor{}, errors.Wrapf(err, "%q in header not a valid digest", dgstHeader)
					}
					dgst = dgstHeader
				}
			}
			if dgst == "" || size == -1 {
				log.G(ctx).Debug("no Docker-Content-Digest header, fetching manifest instead")

				req = base.request(host, http.MethodGet, u...)
				if err := req.addNamespace(base.refspec.Hostname()); err != nil {
					return "", ocispec.Descriptor{}, err
				}

				for key, value := range r.resolveHeader {
					req.header[key] = append(req.header[key], value...)
				}

				resp, err := req.doWithRetries(ctx, nil)
				if err != nil {
					return "", ocispec.Descriptor{}, err
				}
				defer resp.Body.Close()

				bodyReader := countingReader{reader: resp.Body}

				contentType = getManifestMediaType(resp)
				if dgst == "" {
					if contentType == images.MediaTypeDockerSchema1Manifest {
						b, err := schema1.ReadStripSignature(&bodyReader)
						if err != nil {
							return "", ocispec.Descriptor{}, err
						}

						dgst = digest.FromBytes(b)
					} else {
						dgst, err = digest.FromReader(&bodyReader)
						if err != nil {
							return "", ocispec.Descriptor{}, err
						}
					}
				} else if _, err := io.Copy(ioutil.Discard, &bodyReader); err != nil {
					return "", ocispec.Descriptor{}, err
				}
				size = bodyReader.bytesRead
			}
			// Prevent resolving to excessively large manifests
			if size > MaxManifestSize {
				if firstErr == nil {
					firstErr = errors.Wrapf(errdefs.ErrNotFound, "rejecting %d byte manifest for %s", size, ref)
				}
				continue
			}

			desc := ocispec.Descriptor{
				Digest:    dgst,
				MediaType: contentType,
				Size:      size,
			}

			log.G(ctx).WithField("desc.digest", desc.Digest).Debug("resolved")
			return ref, desc, nil
		}
	}

	// If above loop terminates without return, then there was an error.
	// "firstErr" contains the first non-404 error. That is, "firstErr == nil"
	// means that either no registries were given or each registry returned 404.

	if firstErr == nil {
		firstErr = errors.Wrap(errdefs.ErrNotFound, ref)
	}

	return "", ocispec.Descriptor{}, firstErr
}

func (r *dockerResolver) resolveDockerBase(ref string) (*dockerBase, error) {
	refspec, err := reference.Parse(ref)
	if err != nil {
		return nil, err
	}

	return r.base(refspec)
}

type dockerBase struct {
	refspec    reference.Spec
	repository string
	hosts      []RegistryHost
	header     http.Header
}

func (r *dockerResolver) base(refspec reference.Spec) (*dockerBase, error) {
	host := refspec.Hostname()
	hosts, err := r.hosts(host)
	if err != nil {
		return nil, err
	}
	return &dockerBase{
		refspec:    refspec,
		repository: strings.TrimPrefix(refspec.Locator, host+"/"),
		hosts:      hosts,
		header:     r.header,
	}, nil
}

```

>>> Reference Spec
```
// Spec defines the main components of a reference specification.
//
// A reference specification is a schema-less URI parsed into common
// components. The two main components, locator and object, are required to be
// supported by remotes. It represents a superset of the naming define in
// docker's reference schema. It aims to be compatible but not prescriptive.
//
// While the interpretation of the components, locator and object, are up to
// the remote, we define a few common parts, accessible via helper methods.
//
// The first is the hostname, which is part of the locator. This doesn't need
// to map to a physical resource, but it must parse as a hostname. We refer to
// this as the namespace.
//
// The other component made accessible by helper method is the digest. This is
// part of the object identifier, always prefixed with an '@'. If present, the
// remote may use the digest portion directly or resolve it against a prefix.
// If the object does not include the `@` symbol, the return value for `Digest`
// will be empty.
type Spec struct {
	// Locator is the host and path portion of the specification. The host
	// portion may refer to an actual host or just a namespace of related
	// images.
	//
	// Typically, the locator may used to resolve the remote to fetch specific
	// resources.
	Locator string

	// Object contains the identifier for the remote resource. Classically,
	// this is a tag but can refer to anything in a remote. By convention, any
	// portion that may be a partial or whole digest will be preceded by an
	// `@`. Anything preceding the `@` will be referred to as the "tag".
	//
	// In practice, we will see this broken down into the following formats:
	//
	// 1. <tag>
	// 2. <tag>@<digest spec>
	// 3. @<digest spec>
	//
	// We define the tag to be anything except '@' and ':'. <digest spec> may
	// be a full valid digest or shortened version, possibly with elided
	// algorithm.
	Object string
}

var splitRe = regexp.MustCompile(`[:@]`)

// Parse parses the string into a structured ref.
func Parse(s string) (Spec, error) {
	if strings.Contains(s, "://") {
		return Spec{}, ErrInvalid
	}

	u, err := url.Parse("dummy://" + s)
	if err != nil {
		return Spec{}, err
	}

	if u.Scheme != "dummy" {
		return Spec{}, ErrInvalid
	}

	if u.Host == "" {
		return Spec{}, ErrHostnameRequired
	}

	var object string

	if idx := splitRe.FindStringIndex(u.Path); idx != nil {
		// This allows us to retain the @ to signify digests or shortened digests in
		// the object.
		object = u.Path[idx[0]:]
		if object[:1] == ":" {
			object = object[1:]
		}
		u.Path = u.Path[:idx[0]]
	}

	return Spec{
		Locator: path.Join(u.Host, u.Path),
		Object:  object,
	}, nil
}

// Hostname returns the hostname portion of the locator.
//
// Remotes are not required to directly access the resources at this host. This
// method is provided for convenience.
func (r Spec) Hostname() string {
	i := strings.Index(r.Locator, "/")

	if i < 0 {
		return r.Locator
	}
	return r.Locator[:i]
}
```
