# Diff服务
> Diff 服务计算上层/下层 mount 目录的差异，遵从 OCI 规范 Changesets (变化集)打包 tar diff 镜像层存储。Apply 接口将ocispec.Descriptor的content放至指定的挂载目录。

### [外部服务](https://github.com/containerd/containerd/blob/main/services/diff/service.go)
```diff
func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.GRPCPlugin,
		ID:   "diff",
		Requires: []plugin.Type{
			plugin.ServicePlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			plugins, err := ic.GetByType(plugin.ServicePlugin)
			if err != nil {
				return nil, err
			}
-			// 依赖的内部服务services.DiffService
+			p, ok := plugins[services.DiffService]
			if !ok {
				return nil, errors.New("diff service not found")
			}
			i, err := p.Instance()
			if err != nil {
				return nil, err
			}
			return &service{local: i.(diffapi.DiffClient)}, nil
		},
	})
}
```

> ***外部服务接口实现***
```diff
type service struct {
	local diffapi.DiffClient
}

var _ diffapi.DiffServer = &service{}

func (s *service) Register(gs *grpc.Server) error {
	diffapi.RegisterDiffServer(gs, s)
	return nil
}

- // 把content放到顶层
func (s *service) Apply(ctx context.Context, er *diffapi.ApplyRequest) (*diffapi.ApplyResponse, error) {
	return s.local.Apply(ctx, er)
}

- // 计算两层的差值
func (s *service) Diff(ctx context.Context, dr *diffapi.DiffRequest) (*diffapi.DiffResponse, error) {
	return s.local.Diff(ctx, dr)
}
```

### [内部服务](https://github.com/containerd/containerd/blob/main/services/diff/local.go)
```diff
func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.ServicePlugin,
		ID:   services.DiffService,
		Requires: []plugin.Type{
			plugin.DiffPlugin,
		},
		Config: defaultDifferConfig,
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
-			// 依赖底层DiffPlugin
+			differs, err := ic.GetByType(plugin.DiffPlugin)
			if err != nil {
				return nil, err
			}

			orderedNames := ic.Config.(*config).Order
			ordered := make([]differ, len(orderedNames))
			for i, n := range orderedNames {
				differp, ok := differs[n]
				if !ok {
					return nil, errors.Errorf("needed differ not loaded: %s", n)
				}
				d, err := differp.Instance()
				if err != nil {
					return nil, errors.Wrapf(err, "could not load required differ due plugin init error: %s", n)
				}

				ordered[i], ok = d.(differ)
				if !ok {
					return nil, errors.Errorf("differ does not implement Comparer and Applier interface: %s", n)
				}
			}

			return &local{
				differs: ordered,
			}, nil
		},
	})
}
```

> ***内部服务接口实现***
```diff
type local struct {
	differs []differ
}

var _ diffapi.DiffClient = &local{}

func (l *local) Apply(ctx context.Context, er *diffapi.ApplyRequest, _ ...grpc.CallOption) (*diffapi.ApplyResponse, error) {
	var (
		ocidesc ocispec.Descriptor
		err     error
		desc    = toDescriptor(er.Diff)
		mounts  = toMounts(er.Mounts)
	)

	var opts []diff.ApplyOpt
	if er.Payloads != nil {
		opts = append(opts, diff.WithPayloads(er.Payloads))
	}

	for _, differ := range l.differs {
		ocidesc, err = differ.Apply(ctx, desc, mounts, opts...)
		if !errdefs.IsNotImplemented(err) {
			break
		}
	}

	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return &diffapi.ApplyResponse{
		Applied: fromDescriptor(ocidesc),
	}, nil

}

func (l *local) Diff(ctx context.Context, dr *diffapi.DiffRequest, _ ...grpc.CallOption) (*diffapi.DiffResponse, error) {
	var (
		ocidesc ocispec.Descriptor
		err     error
		aMounts = toMounts(dr.Left)
		bMounts = toMounts(dr.Right)
	)

	var opts []diff.Opt
	if dr.MediaType != "" {
		opts = append(opts, diff.WithMediaType(dr.MediaType))
	}
	if dr.Ref != "" {
		opts = append(opts, diff.WithReference(dr.Ref))
	}
	if dr.Labels != nil {
		opts = append(opts, diff.WithLabels(dr.Labels))
	}

	for _, d := range l.differs {
		ocidesc, err = d.Compare(ctx, aMounts, bMounts, opts...)
		if !errdefs.IsNotImplemented(err) {
			break
		}
	}
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return &diffapi.DiffResponse{
		Diff: fromDescriptor(ocidesc),
	}, nil
}

func toMounts(apim []*types.Mount) []mount.Mount {
	mounts := make([]mount.Mount, len(apim))
	for i, m := range apim {
		mounts[i] = mount.Mount{
			Type:    m.Type,
			Source:  m.Source,
			Options: m.Options,
		}
	}
	return mounts
}

func toDescriptor(d *types.Descriptor) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType:   d.MediaType,
		Digest:      d.Digest,
		Size:        d.Size_,
		Annotations: d.Annotations,
	}
}

func fromDescriptor(d ocispec.Descriptor) *types.Descriptor {
	return &types.Descriptor{
		MediaType:   d.MediaType,
		Digest:      d.Digest,
		Size_:       d.Size,
		Annotations: d.Annotations,
	}
}
```
### [底层服务plugin.DiffPlugin](https://github.com/containerd/containerd/blob/main/diff/walking/plugin/plugin.go)
```diff
func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.DiffPlugin,
		ID:   "walking",
		Requires: []plugin.Type{
			plugin.MetadataPlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			md, err := ic.Get(plugin.MetadataPlugin)
			if err != nil {
				return nil, err
			}

			ic.Meta.Platforms = append(ic.Meta.Platforms, platforms.DefaultSpec())
			cs := md.(*metadata.DB).ContentStore()

			return diffPlugin{
				Comparer: walking.NewWalkingDiff(cs),
				Applier:  apply.NewFileSystemApplier(cs),
			}, nil
		},
	})
}

type diffPlugin struct {
	diff.Comparer
	diff.Applier
}

// Comparer allows creation of filesystem diffs between mounts
type Comparer interface {
	// Compare computes the difference between two mounts and returns a
	// descriptor for the computed diff. The options can provide
	// a ref which can be used to track the content creation of the diff.
	// The media type which is used to determine the format of the created
	// content can also be provided as an option.
	Compare(ctx context.Context, lower, upper []mount.Mount, opts ...Opt) (ocispec.Descriptor, error)
}

// Applier allows applying diffs between mounts
type Applier interface {
	// Apply applies the content referred to by the given descriptor to
	// the provided mount. The method of applying is based on the
	// implementation and content descriptor. For example, in the common
	// case the descriptor is a file system difference in tar format,
	// that tar would be applied on top of the mounts.
	Apply(ctx context.Context, desc ocispec.Descriptor, mount []mount.Mount, opts ...ApplyOpt) (ocispec.Descriptor, error)
}
```

> ***底层服务接口实现***
```diff
- // walkingDiff实现Comparer接口
// NewWalkingDiff is a generic implementation of diff.Comparer.  The diff is
// calculated by mounting both the upper and lower mount sets and walking the
// mounted directories concurrently. Changes are calculated by comparing files
// against each other or by comparing file existence between directories.
// NewWalkingDiff uses no special characteristics of the mount sets and is
// expected to work with any filesystem.
func NewWalkingDiff(store content.Store) diff.Comparer {
	return &walkingDiff{
		store: store,
	}
}

// Compare creates a diff between the given mounts and uploads the result
// to the content store.
func (s *walkingDiff) Compare(ctx context.Context, lower, upper []mount.Mount, opts ...diff.Opt) (d ocispec.Descriptor, err error) {
	var config diff.Config
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return emptyDesc, err
		}
	}

	var isCompressed bool
	if config.Compressor != nil {
		if config.MediaType == "" {
			return emptyDesc, errors.New("media type must be explicitly specified when using custom compressor")
		}
		isCompressed = true
	} else {
		if config.MediaType == "" {
			config.MediaType = ocispec.MediaTypeImageLayerGzip
		}

		switch config.MediaType {
		case ocispec.MediaTypeImageLayer:
		case ocispec.MediaTypeImageLayerGzip:
			isCompressed = true
		default:
			return emptyDesc, errors.Wrapf(errdefs.ErrNotImplemented, "unsupported diff media type: %v", config.MediaType)
		}
	}

	var ocidesc ocispec.Descriptor
	if err := mount.WithTempMount(ctx, lower, func(lowerRoot string) error {
		return mount.WithTempMount(ctx, upper, func(upperRoot string) error {
			var newReference bool
			if config.Reference == "" {
				newReference = true
				config.Reference = uniqueRef()
			}

			cw, err := s.store.Writer(ctx,
				content.WithRef(config.Reference),
				content.WithDescriptor(ocispec.Descriptor{
					MediaType: config.MediaType, // most contentstore implementations just ignore this
				}))
			if err != nil {
				return errors.Wrap(err, "failed to open writer")
			}

			// errOpen is set when an error occurs while the content writer has not been
			// committed or closed yet to force a cleanup
			var errOpen error
			defer func() {
				if errOpen != nil {
					cw.Close()
					if newReference {
						if abortErr := s.store.Abort(ctx, config.Reference); abortErr != nil {
							log.G(ctx).WithError(abortErr).WithField("ref", config.Reference).Warnf("failed to delete diff upload")
						}
					}
				}
			}()
			if !newReference {
				if errOpen = cw.Truncate(0); errOpen != nil {
					return errOpen
				}
			}

			if isCompressed {
				dgstr := digest.SHA256.Digester()
				var compressed io.WriteCloser
				if config.Compressor != nil {
					compressed, errOpen = config.Compressor(cw, config.MediaType)
					if errOpen != nil {
						return errors.Wrap(errOpen, "failed to get compressed stream")
					}
				} else {
					compressed, errOpen = compression.CompressStream(cw, compression.Gzip)
					if errOpen != nil {
						return errors.Wrap(errOpen, "failed to get compressed stream")
					}
				}
				errOpen = archive.WriteDiff(ctx, io.MultiWriter(compressed, dgstr.Hash()), lowerRoot, upperRoot)
				compressed.Close()
				if errOpen != nil {
					return errors.Wrap(errOpen, "failed to write compressed diff")
				}

				if config.Labels == nil {
					config.Labels = map[string]string{}
				}
				config.Labels[uncompressed] = dgstr.Digest().String()
			} else {
				if errOpen = archive.WriteDiff(ctx, cw, lowerRoot, upperRoot); errOpen != nil {
					return errors.Wrap(errOpen, "failed to write diff")
				}
			}

			var commitopts []content.Opt
			if config.Labels != nil {
				commitopts = append(commitopts, content.WithLabels(config.Labels))
			}

			dgst := cw.Digest()
			if errOpen = cw.Commit(ctx, 0, dgst, commitopts...); errOpen != nil {
				if !errdefs.IsAlreadyExists(errOpen) {
					return errors.Wrap(errOpen, "failed to commit")
				}
				errOpen = nil
			}

			info, err := s.store.Info(ctx, dgst)
			if err != nil {
				return errors.Wrap(err, "failed to get info from content store")
			}
			if info.Labels == nil {
				info.Labels = make(map[string]string)
			}
			// Set uncompressed label if digest already existed without label
			if _, ok := info.Labels[uncompressed]; !ok {
				info.Labels[uncompressed] = config.Labels[uncompressed]
				if _, err := s.store.Update(ctx, info, "labels."+uncompressed); err != nil {
					return errors.Wrap(err, "error setting uncompressed label")
				}
			}

			ocidesc = ocispec.Descriptor{
				MediaType: config.MediaType,
				Size:      info.Size,
				Digest:    info.Digest,
			}
			return nil
		})
	}); err != nil {
		return emptyDesc, err
	}

	return ocidesc, nil
}
```

```diff
- // fsApplier实现Applier接口
func NewFileSystemApplier(cs content.Provider) diff.Applier {
	return &fsApplier{
		store: cs,
	}
}

type fsApplier struct {
	store content.Provider
}

var emptyDesc = ocispec.Descriptor{}

// Apply applies the content associated with the provided digests onto the
// provided mounts. Archive content will be extracted and decompressed if
// necessary.
func (s *fsApplier) Apply(ctx context.Context, desc ocispec.Descriptor, mounts []mount.Mount, opts ...diff.ApplyOpt) (d ocispec.Descriptor, err error) {
	t1 := time.Now()
	defer func() {
		if err == nil {
			log.G(ctx).WithFields(logrus.Fields{
				"d":      time.Since(t1),
				"digest": desc.Digest,
				"size":   desc.Size,
				"media":  desc.MediaType,
			}).Debugf("diff applied")
		}
	}()

	var config diff.ApplyConfig
	for _, o := range opts {
		if err := o(ctx, desc, &config); err != nil {
			return emptyDesc, errors.Wrap(err, "failed to apply config opt")
		}
	}

	ra, err := s.store.ReaderAt(ctx, desc)
	if err != nil {
		return emptyDesc, errors.Wrap(err, "failed to get reader from content store")
	}
	defer ra.Close()

	var processors []diff.StreamProcessor
	processor := diff.NewProcessorChain(desc.MediaType, content.NewReader(ra))
	processors = append(processors, processor)
	for {
		if processor, err = diff.GetProcessor(ctx, processor, config.ProcessorPayloads); err != nil {
			return emptyDesc, errors.Wrapf(err, "failed to get stream processor for %s", desc.MediaType)
		}
		processors = append(processors, processor)
		if processor.MediaType() == ocispec.MediaTypeImageLayer {
			break
		}
	}
	defer processor.Close()

	digester := digest.Canonical.Digester()
	rc := &readCounter{
		r: io.TeeReader(processor, digester.Hash()),
	}

+	if err := apply(ctx, mounts, rc); err != nil {
		return emptyDesc, err
	}

	// Read any trailing data
	if _, err := io.Copy(ioutil.Discard, rc); err != nil {
		return emptyDesc, err
	}

	for _, p := range processors {
		if ep, ok := p.(interface {
			Err() error
		}); ok {
			if err := ep.Err(); err != nil {
				return emptyDesc, err
			}
		}
	}
	return ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayer,
		Size:      rc.c,
		Digest:    digester.Digest(),
	}, nil
}
```
> ***apply***Linux实现
```diff
func apply(ctx context.Context, mounts []mount.Mount, r io.Reader) error {
	switch {
	case len(mounts) == 1 && mounts[0].Type == "overlay":
		// OverlayConvertWhiteout (mknod c 0 0) doesn't work in userns.
		// https://github.com/containerd/containerd/issues/3762
		if userns.RunningInUserNS() {
			break
		}
		path, parents, err := getOverlayPath(mounts[0].Options)
		if err != nil {
			if errdefs.IsInvalidArgument(err) {
				break
			}
			return err
		}
		opts := []archive.ApplyOpt{
			archive.WithConvertWhiteout(archive.OverlayConvertWhiteout),
		}
		if len(parents) > 0 {
			opts = append(opts, archive.WithParents(parents))
		}
-		// 解压tar文件		
+		_, err = archive.Apply(ctx, path, r, opts...)
		return err
	case len(mounts) == 1 && mounts[0].Type == "aufs":
		path, parents, err := getAufsPath(mounts[0].Options)
		if err != nil {
			if errdefs.IsInvalidArgument(err) {
				break
			}
			return err
		}
		opts := []archive.ApplyOpt{
			archive.WithConvertWhiteout(archive.AufsConvertWhiteout),
		}
		if len(parents) > 0 {
			opts = append(opts, archive.WithParents(parents))
		}
		_, err = archive.Apply(ctx, path, r, opts...)
		return err
	}
	return mount.WithTempMount(ctx, mounts, func(root string) error {
		_, err := archive.Apply(ctx, root, r)
		return err
	})
}
```
