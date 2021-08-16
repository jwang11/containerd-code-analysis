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
