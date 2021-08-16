# Snapshot服务
>其服务的核心是实现抽象的 Snapshotter 用于容器的rootfs 挂载和卸载等操作功能。 Snapshotter 设计替代在docker早期版本称之为graphdriver存储驱动的设计。
>为支持更丰富的文件系统如 overlay 文件系统 ，引入上层抽象 snapshot 快照概念，使 docker 存储驱动更加简化同时兼容了块设备快照与 overlay 文件系统。

### 外部服务Snapshot GRPC注册
[services/snapshots/service.go](https://github.com/containerd/containerd/blob/main/services/snapshots/service.go)
```
func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.GRPCPlugin,
		ID:   "snapshots",
		Requires: []plugin.Type{
			plugin.ServicePlugin,
		},
		InitFn: newService,
	})
}

func newService(ic *plugin.InitContext) (interface{}, error) {
	plugins, err := ic.GetByType(plugin.ServicePlugin)
	if err != nil {
		return nil, err
	}
	p, ok := plugins[services.SnapshotsService]
	if !ok {
		return nil, errors.New("snapshots service not found")
	}
	i, err := p.Instance()
	if err != nil {
		return nil, err
	}
	ss := i.(map[string]snapshots.Snapshotter)
	return &service{ss: ss}, nil
}
```

### 内部服务Snapshots ServicePlugin注册
```diff
// snapshotter wraps snapshots.Snapshotter with proper events published.
type snapshotter struct {
	snapshots.Snapshotter
	publisher events.Publisher
}

func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.ServicePlugin,
		ID:   services.SnapshotsService,
		Requires: []plugin.Type{
			plugin.EventPlugin,
			plugin.MetadataPlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			m, err := ic.Get(plugin.MetadataPlugin)
			if err != nil {
				return nil, err
			}
			ep, err := ic.Get(plugin.EventPlugin)
			if err != nil {
				return nil, err
			}

			db := m.(*metadata.DB)
			ss := make(map[string]snapshots.Snapshotter)
			for n, sn := range db.Snapshotters() {
				ss[n] = newSnapshotter(sn, ep.(events.Publisher))
			}
			return ss, nil
		},
	})
}

func newSnapshotter(sn snapshots.Snapshotter, publisher events.Publisher) snapshots.Snapshotter {
	return &snapshotter{
		Snapshotter: sn,
		publisher:   publisher,
	}
}

+ //内部服务snapshoter的Prepare
func (s *snapshotter) Prepare(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	mounts, err := s.Snapshotter.Prepare(ctx, key, parent, opts...)
	if err != nil {
		return nil, err
	}
	if err := s.publisher.Publish(ctx, "/snapshot/prepare", &eventstypes.SnapshotPrepare{
		Key:    key,
		Parent: parent,
	}); err != nil {
		return nil, err
	}
	return mounts, nil
}

+ //内部服务snapshoter的Commit
func (s *snapshotter) Commit(ctx context.Context, name, key string, opts ...snapshots.Opt) error {
	if err := s.Snapshotter.Commit(ctx, name, key, opts...); err != nil {
		return err
	}
	return s.publisher.Publish(ctx, "/snapshot/commit", &eventstypes.SnapshotCommit{
		Key:  key,
		Name: name,
	})
}

+ //内部服务snapshoter的Remove
func (s *snapshotter) Remove(ctx context.Context, key string) error {
	if err := s.Snapshotter.Remove(ctx, key); err != nil {
		return err
	}
	return s.publisher.Publish(ctx, "/snapshot/remove", &eventstypes.SnapshotRemove{
		Key: key,
	})
}
```

### 底层服务SnapshotPlugin的注册
[snapshots/overlay/plugin/plugin.go](https://github.com/containerd/containerd/blob/main/snapshots/overlay/plugin/plugin.go)
```
func init() {
	plugin.Register(&plugin.Registration{
		Type:   plugin.SnapshotPlugin,
		ID:     "overlayfs",
		Config: &Config{},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			ic.Meta.Platforms = append(ic.Meta.Platforms, platforms.DefaultSpec())

			config, ok := ic.Config.(*Config)
			if !ok {
				return nil, errors.New("invalid overlay configuration")
			}

			root := ic.Root
			if config.RootPath != "" {
				root = config.RootPath
			}

			var oOpts []overlay.Opt
			if config.UpperdirLabel {
				oOpts = append(oOpts, overlay.WithUpperdirLabel)
			}

			ic.Meta.Exports["root"] = root
			return overlay.NewSnapshotter(root, append(oOpts, overlay.AsynchronousRemove)...)
		},
	})
}
```

### 外部服务接口的实现
- 外部Service
```
type service struct {
	ss map[string]snapshots.Snapshotter
}
```
- 需实现的外部接口
```
type SnapshotsServer interface {
	Prepare(context.Context, *PrepareSnapshotRequest) (*PrepareSnapshotResponse, error)
	View(context.Context, *ViewSnapshotRequest) (*ViewSnapshotResponse, error)
	Mounts(context.Context, *MountsRequest) (*MountsResponse, error)
	Commit(context.Context, *CommitSnapshotRequest) (*types1.Empty, error)
	Remove(context.Context, *RemoveSnapshotRequest) (*types1.Empty, error)
	Stat(context.Context, *StatSnapshotRequest) (*StatSnapshotResponse, error)
	Update(context.Context, *UpdateSnapshotRequest) (*UpdateSnapshotResponse, error)
	List(*ListSnapshotsRequest, Snapshots_ListServer) error
	Usage(context.Context, *UsageRequest) (*UsageResponse, error)
	Cleanup(context.Context, *CleanupRequest) (*types1.Empty, error)
}
```
- Prepare
```
func (s *service) Prepare(ctx context.Context, pr *snapshotsapi.PrepareSnapshotRequest) (*snapshotsapi.PrepareSnapshotResponse, error) {
	log.G(ctx).WithField("parent", pr.Parent).WithField("key", pr.Key).Debugf("prepare snapshot")
	sn, err := s.getSnapshotter(pr.Snapshotter)
	if err != nil {
		return nil, err
	}

	var opts []snapshots.Opt
	if pr.Labels != nil {
		opts = append(opts, snapshots.WithLabels(pr.Labels))
	}
	mounts, err := sn.Prepare(ctx, pr.Key, pr.Parent, opts...)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return &snapshotsapi.PrepareSnapshotResponse{
		Mounts: fromMounts(mounts),
	}, nil
}
```
-  View
```
func (s *service) View(ctx context.Context, pr *snapshotsapi.ViewSnapshotRequest) (*snapshotsapi.ViewSnapshotResponse, error) {
	log.G(ctx).WithField("parent", pr.Parent).WithField("key", pr.Key).Debugf("prepare view snapshot")
	sn, err := s.getSnapshotter(pr.Snapshotter)
	if err != nil {
		return nil, err
	}
	var opts []snapshots.Opt
	if pr.Labels != nil {
		opts = append(opts, snapshots.WithLabels(pr.Labels))
	}
	mounts, err := sn.View(ctx, pr.Key, pr.Parent, opts...)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return &snapshotsapi.ViewSnapshotResponse{
		Mounts: fromMounts(mounts),
	}, nil
}
```
- Mounts
```
func (s *service) Mounts(ctx context.Context, mr *snapshotsapi.MountsRequest) (*snapshotsapi.MountsResponse, error) {
	log.G(ctx).WithField("key", mr.Key).Debugf("get snapshot mounts")
	sn, err := s.getSnapshotter(mr.Snapshotter)
	if err != nil {
		return nil, err
	}

	mounts, err := sn.Mounts(ctx, mr.Key)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return &snapshotsapi.MountsResponse{
		Mounts: fromMounts(mounts),
	}, nil
}
```

- Commit
```
func (s *service) Commit(ctx context.Context, cr *snapshotsapi.CommitSnapshotRequest) (*ptypes.Empty, error) {
	log.G(ctx).WithField("key", cr.Key).WithField("name", cr.Name).Debugf("commit snapshot")
	sn, err := s.getSnapshotter(cr.Snapshotter)
	if err != nil {
		return nil, err
	}

	var opts []snapshots.Opt
	if cr.Labels != nil {
		opts = append(opts, snapshots.WithLabels(cr.Labels))
	}
	if err := sn.Commit(ctx, cr.Name, cr.Key, opts...); err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return empty, nil
}
```

- Remove
```
func (s *service) Remove(ctx context.Context, rr *snapshotsapi.RemoveSnapshotRequest) (*ptypes.Empty, error) {
	log.G(ctx).WithField("key", rr.Key).Debugf("remove snapshot")
	sn, err := s.getSnapshotter(rr.Snapshotter)
	if err != nil {
		return nil, err
	}

	if err := sn.Remove(ctx, rr.Key); err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return empty, nil
}
```

- Stat
```
func (s *service) Stat(ctx context.Context, sr *snapshotsapi.StatSnapshotRequest) (*snapshotsapi.StatSnapshotResponse, error) {
	log.G(ctx).WithField("key", sr.Key).Debugf("stat snapshot")
	sn, err := s.getSnapshotter(sr.Snapshotter)
	if err != nil {
		return nil, err
	}

	info, err := sn.Stat(ctx, sr.Key)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return &snapshotsapi.StatSnapshotResponse{Info: fromInfo(info)}, nil
}
```

- Udpate
```
func (s *service) Update(ctx context.Context, sr *snapshotsapi.UpdateSnapshotRequest) (*snapshotsapi.UpdateSnapshotResponse, error) {
	log.G(ctx).WithField("key", sr.Info.Name).Debugf("update snapshot")
	sn, err := s.getSnapshotter(sr.Snapshotter)
	if err != nil {
		return nil, err
	}

	info, err := sn.Update(ctx, toInfo(sr.Info), sr.UpdateMask.GetPaths()...)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return &snapshotsapi.UpdateSnapshotResponse{Info: fromInfo(info)}, nil
}
```

- List
```
func (s *service) List(sr *snapshotsapi.ListSnapshotsRequest, ss snapshotsapi.Snapshots_ListServer) error {
	sn, err := s.getSnapshotter(sr.Snapshotter)
	if err != nil {
		return err
	}

	var (
		buffer    []snapshotsapi.Info
		sendBlock = func(block []snapshotsapi.Info) error {
			return ss.Send(&snapshotsapi.ListSnapshotsResponse{
				Info: block,
			})
		}
	)
	err = sn.Walk(ss.Context(), func(ctx context.Context, info snapshots.Info) error {
		buffer = append(buffer, fromInfo(info))

		if len(buffer) >= 100 {
			if err := sendBlock(buffer); err != nil {
				return err
			}

			buffer = buffer[:0]
		}

		return nil
	}, sr.Filters...)
	if err != nil {
		return err
	}
	if len(buffer) > 0 {
		// Send remaining infos
		if err := sendBlock(buffer); err != nil {
			return err
		}
	}

	return nil
}
```

- Usage
```
func (s *service) Usage(ctx context.Context, ur *snapshotsapi.UsageRequest) (*snapshotsapi.UsageResponse, error) {
	sn, err := s.getSnapshotter(ur.Snapshotter)
	if err != nil {
		return nil, err
	}

	usage, err := sn.Usage(ctx, ur.Key)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return fromUsage(usage), nil
}
```

- Cleanup
```
func (s *service) Cleanup(ctx context.Context, cr *snapshotsapi.CleanupRequest) (*ptypes.Empty, error) {
	sn, err := s.getSnapshotter(cr.Snapshotter)
	if err != nil {
		return nil, err
	}

	c, ok := sn.(snapshots.Cleaner)
	if !ok {
		return nil, errdefs.ToGRPCf(errdefs.ErrNotImplemented, "snapshotter does not implement Cleanup method")
	}

	err = c.Cleanup(ctx)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return empty, nil
}
```
