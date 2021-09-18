# Snapshot服务
>其服务的核心是实现抽象的 Snapshotter 用于容器的rootfs 挂载和卸载等操作功能。 Snapshotter 设计替代在docker早期版本称之为graphdriver存储驱动的设计。
>为支持更丰富的文件系统如 overlay 文件系统 ，引入上层抽象 snapshot 快照概念，使 docker 存储驱动更加简化同时兼容了块设备快照与 overlay 文件系统。

### 外部服务Snapshot GRPC注册
[services/snapshots/service.go](https://github.com/containerd/containerd/blob/main/services/snapshots/service.go)
```diff
func init() {
	plugin.Register(&plugin.Registration{
+		Type: plugin.GRPCPlugin,
+		ID:   "snapshots",
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
+	p, ok := plugins[services.SnapshotsService]
	if !ok {
		return nil, errors.New("snapshots service not found")
	}
	i, err := p.Instance()
	if err != nil {
		return nil, err
	}
+	ss := i.(map[string]snapshots.Snapshotter)
+	return &service{ss: ss}, nil
}
```

### 外部服务接口的实现
- 外部Service
```diff
type service struct {
	ss map[string]snapshots.Snapshotter
}
- //获取Snapshot的底层实现，如overlay
func (s *service) getSnapshotter(name string) (snapshots.Snapshotter, error) {
	if name == "" {
		return nil, errdefs.ToGRPCf(errdefs.ErrInvalidArgument, "snapshotter argument missing")
	}

	sn := s.ss[name]
	if sn == nil {
		return nil, errdefs.ToGRPCf(errdefs.ErrInvalidArgument, "snapshotter not loaded: %s", name)
	}
	return sn, nil
}
```
- 需实现的外部接口
```diff
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
```diff
func (s *service) Prepare(ctx context.Context, pr *snapshotsapi.PrepareSnapshotRequest) (*snapshotsapi.PrepareSnapshotResponse, error) {
	log.G(ctx).WithField("parent", pr.Parent).WithField("key", pr.Key).Debugf("prepare snapshot")
-	// 根据Reqeust里的snapshotter名字，获取sn对象	
	sn, err := s.getSnapshotter(pr.Snapshotter)
	if err != nil {
		return nil, err
	}

	var opts []snapshots.Opt
	if pr.Labels != nil {
		opts = append(opts, snapshots.WithLabels(pr.Labels))
	}
-	// 调用内部服务Prepare方法	
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
```diff
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
```diff
func (s *service) Mounts(ctx context.Context, mr *snapshotsapi.MountsRequest) (*snapshotsapi.MountsResponse, error) {
	log.G(ctx).WithField("key", mr.Key).Debugf("get snapshot mounts")
	sn, err := s.getSnapshotter(mr.Snapshotter)
	if err != nil {
		return nil, err
	}
-	// 根据SnapshotKey，返回相应的mounts
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
```diff
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
-	// 调用底层实现的Commit	
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

### 内部服务Snapshots ServicePlugin注册
```diff
// snapshotter wraps snapshots.Snapshotter with proper events published.
type snapshotter struct {
	snapshots.Snapshotter
	publisher events.Publisher
}

func init() {
	plugin.Register(&plugin.Registration{
+		Type: plugin.ServicePlugin,
+		ID:   services.SnapshotsService,
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
+				ss[n] = newSnapshotter(sn, ep.(events.Publisher))
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

- //内部服务snapshoter的Prepare
func (s *snapshotter) Prepare(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
-	// 调用底层服务的prepare
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

- //内部服务snapshoter的Commit
func (s *snapshotter) Commit(ctx context.Context, name, key string, opts ...snapshots.Opt) error {
-	// 调用底层服务的Commit
	if err := s.Snapshotter.Commit(ctx, name, key, opts...); err != nil {
		return err
	}
	return s.publisher.Publish(ctx, "/snapshot/commit", &eventstypes.SnapshotCommit{
		Key:  key,
		Name: name,
	})
}

- //内部服务snapshoter的Remove
func (s *snapshotter) Remove(ctx context.Context, key string) error {
-	// 调用底层服务的Remove
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
```diff
func init() {
	plugin.Register(&plugin.Registration{
+		Type:   plugin.SnapshotPlugin,
+		ID:     "overlayfs",
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
+			return overlay.NewSnapshotter(root, append(oOpts, overlay.AsynchronousRemove)...)
		},
	})
}

// NewSnapshotter returns a Snapshotter which uses overlayfs. The overlayfs
// diffs are stored under the provided root. A metadata file is stored under
// the root.
func NewSnapshotter(root string, opts ...Opt) (snapshots.Snapshotter, error) {
	var config SnapshotterConfig
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return nil, err
		}
	}

	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	supportsDType, err := fs.SupportsDType(root)
	if err != nil {
		return nil, err
	}
	if !supportsDType {
		return nil, fmt.Errorf("%s does not support d_type. If the backing filesystem is xfs, please reformat with ftype=1 to enable d_type support", root)
	}
	ms, err := storage.NewMetaStore(filepath.Join(root, "metadata.db"))
	if err != nil {
		return nil, err
	}

	if err := os.Mkdir(filepath.Join(root, "snapshots"), 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}

	// figure out whether "index=off" option is recognized by the kernel
	var indexOff bool
	if _, err = os.Stat("/sys/module/overlay/parameters/index"); err == nil {
		indexOff = true
	}

	// figure out whether "userxattr" option is recognized by the kernel && needed
	userxattr, err := overlayutils.NeedsUserXAttr(root)
	if err != nil {
		logrus.WithError(err).Warnf("cannot detect whether \"userxattr\" option needs to be used, assuming to be %v", userxattr)
	}

+	return &snapshotter{
		root:          root,
		ms:            ms,
		asyncRemove:   config.asyncRemove,
		upperdirLabel: config.upperdirLabel,
		indexOff:      indexOff,
		userxattr:     userxattr,
	}, nil
}
```
### 底层服务接口实现
- ***Stat***
```diff
// Stat returns the info for an active or committed snapshot by name or
// key.
//
// Should be used for parent resolution, existence checks and to discern
// the kind of snapshot.
func (o *snapshotter) Stat(ctx context.Context, key string) (snapshots.Info, error) {
	ctx, t, err := o.ms.TransactionContext(ctx, false)
	if err != nil {
		return snapshots.Info{}, err
	}
	defer t.Rollback()
	id, info, _, err := storage.GetInfo(ctx, key)
	if err != nil {
		return snapshots.Info{}, err
	}

	if o.upperdirLabel {
		if info.Labels == nil {
			info.Labels = make(map[string]string)
		}
		info.Labels[upperdirKey] = o.upperPath(id)
	}

	return info, nil
}
```
> *storage.GetInfo(ctx, info.Name)*
```diff
// GetInfo returns the snapshot Info directly from the metadata. Requires a
// context with a storage transaction.
func GetInfo(ctx context.Context, key string) (string, snapshots.Info, snapshots.Usage, error) {
	var (
		id uint64
		su snapshots.Usage
		si = snapshots.Info{
			Name: key,
		}
	)
	err := withSnapshotBucket(ctx, key, func(ctx context.Context, bkt, pbkt *bolt.Bucket) error {
		getUsage(bkt, &su)
		return readSnapshot(bkt, &id, &si)
	})
	if err != nil {
		return "", snapshots.Info{}, snapshots.Usage{}, err
	}

	return fmt.Sprintf("%d", id), si, su, nil
}
```

- ***Update***
```diff
func (o *snapshotter) Update(ctx context.Context, info snapshots.Info, fieldpaths ...string) (snapshots.Info, error) {
	ctx, t, err := o.ms.TransactionContext(ctx, true)
	if err != nil {
		return snapshots.Info{}, err
	}

+	info, err = storage.UpdateInfo(ctx, info, fieldpaths...)
	if err != nil {
		t.Rollback()
		return snapshots.Info{}, err
	}

	if err := t.Commit(); err != nil {
		return snapshots.Info{}, err
	}

	if o.upperdirLabel {
+		id, _, _, err := storage.GetInfo(ctx, info.Name)
		if err != nil {
			return snapshots.Info{}, err
		}
		if info.Labels == nil {
			info.Labels = make(map[string]string)
		}
		info.Labels[upperdirKey] = o.upperPath(id)
	}

	return info, nil
}
```
> *storage.UpdateInfo(ctx, info, fieldpaths...)*
```diff
// UpdateInfo updates an existing snapshot info's data
func UpdateInfo(ctx context.Context, info snapshots.Info, fieldpaths ...string) (snapshots.Info, error) {
	updated := snapshots.Info{
		Name: info.Name,
	}
	err := withBucket(ctx, func(ctx context.Context, bkt, pbkt *bolt.Bucket) error {
		sbkt := bkt.Bucket([]byte(info.Name))
		if sbkt == nil {
			return errors.Wrap(errdefs.ErrNotFound, "snapshot does not exist")
		}
		if err := readSnapshot(sbkt, nil, &updated); err != nil {
			return err
		}

		if len(fieldpaths) > 0 {
			for _, path := range fieldpaths {
				if strings.HasPrefix(path, "labels.") {
					if updated.Labels == nil {
						updated.Labels = map[string]string{}
					}

					key := strings.TrimPrefix(path, "labels.")
					updated.Labels[key] = info.Labels[key]
					continue
				}

				switch path {
				case "labels":
					updated.Labels = info.Labels
				default:
					return errors.Wrapf(errdefs.ErrInvalidArgument, "cannot update %q field on snapshot %q", path, info.Name)
				}
			}
		} else {
			// Set mutable fields
			updated.Labels = info.Labels
		}
		updated.Updated = time.Now().UTC()
		if err := boltutil.WriteTimestamps(sbkt, updated.Created, updated.Updated); err != nil {
			return err
		}

		return boltutil.WriteLabels(sbkt, updated.Labels)
	})
	if err != nil {
		return snapshots.Info{}, err
	}
	return updated, nil
}
```
- ***Usage***
```diff
// Usage returns the resources taken by the snapshot identified by key.
//
// For active snapshots, this will scan the usage of the overlay "diff" (aka
// "upper") directory and may take some time.
//
// For committed snapshots, the value is returned from the metadata database.
func (o *snapshotter) Usage(ctx context.Context, key string) (snapshots.Usage, error) {
	ctx, t, err := o.ms.TransactionContext(ctx, false)
	if err != nil {
		return snapshots.Usage{}, err
	}
	id, info, usage, err := storage.GetInfo(ctx, key)
	t.Rollback() // transaction no longer needed at this point.

	if err != nil {
		return snapshots.Usage{}, err
	}

	if info.Kind == snapshots.KindActive {
		upperPath := o.upperPath(id)
		du, err := fs.DiskUsage(ctx, upperPath)
		if err != nil {
			// TODO(stevvooe): Consider not reporting an error in this case.
			return snapshots.Usage{}, err
		}

		usage = snapshots.Usage(du)
	}

	return usage, nil
}
```
- ***Prepare***
```
func (o *snapshotter) Prepare(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
+	return o.createSnapshot(ctx, snapshots.KindActive, key, parent, opts)
}
```
> *o.createSnapshot(ctx, snapshots.KindActive, key, parent, opts)*
```diff
func (o *snapshotter) createSnapshot(ctx context.Context, kind snapshots.Kind, key, parent string, opts []snapshots.Opt) (_ []mount.Mount, err error) {
	ctx, t, err := o.ms.TransactionContext(ctx, true)
	if err != nil {
		return nil, err
	}

	var td, path string
	defer func() {
		if err != nil {
			if td != "" {
				if err1 := os.RemoveAll(td); err1 != nil {
					log.G(ctx).WithError(err1).Warn("failed to cleanup temp snapshot directory")
				}
			}
			if path != "" {
				if err1 := os.RemoveAll(path); err1 != nil {
					log.G(ctx).WithError(err1).WithField("path", path).Error("failed to reclaim snapshot directory, directory may need removal")
					err = errors.Wrapf(err, "failed to remove path: %v", err1)
				}
			}
		}
	}()

	snapshotDir := filepath.Join(o.root, "snapshots")
	td, err = o.prepareDirectory(ctx, snapshotDir, kind)
	if err != nil {
		if rerr := t.Rollback(); rerr != nil {
			log.G(ctx).WithError(rerr).Warn("failed to rollback transaction")
		}
		return nil, errors.Wrap(err, "failed to create prepare snapshot dir")
	}
	rollback := true
	defer func() {
		if rollback {
			if rerr := t.Rollback(); rerr != nil {
				log.G(ctx).WithError(rerr).Warn("failed to rollback transaction")
			}
		}
	}()

	s, err := storage.CreateSnapshot(ctx, kind, key, parent, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create snapshot")
	}

	if len(s.ParentIDs) > 0 {
		st, err := os.Stat(o.upperPath(s.ParentIDs[0]))
		if err != nil {
			return nil, errors.Wrap(err, "failed to stat parent")
		}

		stat := st.Sys().(*syscall.Stat_t)

		if err := os.Lchown(filepath.Join(td, "fs"), int(stat.Uid), int(stat.Gid)); err != nil {
			if rerr := t.Rollback(); rerr != nil {
				log.G(ctx).WithError(rerr).Warn("failed to rollback transaction")
			}
			return nil, errors.Wrap(err, "failed to chown")
		}
	}

	path = filepath.Join(snapshotDir, s.ID)
	if err = os.Rename(td, path); err != nil {
		return nil, errors.Wrap(err, "failed to rename")
	}
	td = ""

	rollback = false
	if err = t.Commit(); err != nil {
		return nil, errors.Wrap(err, "commit failed")
	}

+	return o.mounts(s), nil
}
```
> *o.mounts(s)*
```diff
func (o *snapshotter) mounts(s storage.Snapshot) []mount.Mount {
	if len(s.ParentIDs) == 0 {
		// if we only have one layer/no parents then just return a bind mount as overlay
		// will not work
		roFlag := "rw"
		if s.Kind == snapshots.KindView {
			roFlag = "ro"
		}

		return []mount.Mount{
			{
				Source: o.upperPath(s.ID),
				Type:   "bind",
				Options: []string{
					roFlag,
					"rbind",
				},
			},
		}
	}
	var options []string

	// set index=off when mount overlayfs
	if o.indexOff {
		options = append(options, "index=off")
	}

	if o.userxattr {
		options = append(options, "userxattr")
	}

	if s.Kind == snapshots.KindActive {
		options = append(options,
			fmt.Sprintf("workdir=%s", o.workPath(s.ID)),
			fmt.Sprintf("upperdir=%s", o.upperPath(s.ID)),
		)
	} else if len(s.ParentIDs) == 1 {
		return []mount.Mount{
			{
				Source: o.upperPath(s.ParentIDs[0]),
				Type:   "bind",
				Options: []string{
					"ro",
					"rbind",
				},
			},
		}
	}

	parentPaths := make([]string, len(s.ParentIDs))
	for i := range s.ParentIDs {
		parentPaths[i] = o.upperPath(s.ParentIDs[i])
	}

	options = append(options, fmt.Sprintf("lowerdir=%s", strings.Join(parentPaths, ":")))
	return []mount.Mount{
		{
			Type:    "overlay",
			Source:  "overlay",
			Options: options,
		},
	}

}
```

- ***View***
```diff
func (o *snapshotter) View(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
+	return o.createSnapshot(ctx, snapshots.KindView, key, parent, opts)
}
```

- ***Mounts***
```diff
// Mounts returns the mounts for the transaction identified by key. Can be
// called on an read-write or readonly transaction.
//
// This can be used to recover mounts after calling View or Prepare.
func (o *snapshotter) Mounts(ctx context.Context, key string) ([]mount.Mount, error) {
	ctx, t, err := o.ms.TransactionContext(ctx, false)
	if err != nil {
		return nil, err
	}
	s, err := storage.GetSnapshot(ctx, key)
	t.Rollback()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get active mount")
	}
+	return o.mounts(s), nil
}
```

- ***Commit***
```diff
func (o *snapshotter) Commit(ctx context.Context, name, key string, opts ...snapshots.Opt) error {
	ctx, t, err := o.ms.TransactionContext(ctx, true)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			if rerr := t.Rollback(); rerr != nil {
				log.G(ctx).WithError(rerr).Warn("failed to rollback transaction")
			}
		}
	}()

	// grab the existing id
+	id, _, _, err := storage.GetInfo(ctx, key)
	if err != nil {
		return err
	}

	usage, err := fs.DiskUsage(ctx, o.upperPath(id))
	if err != nil {
		return err
	}

+	if _, err = storage.CommitActive(ctx, key, name, snapshots.Usage(usage), opts...); err != nil {
		return errors.Wrap(err, "failed to commit snapshot")
	}
	return t.Commit()
}
```
> *storage.CommitActive(ctx, key, name, snapshots.Usage(usage), opts...)*
```diff
// CommitActive renames the active snapshot transaction referenced by `key`
// as a committed snapshot referenced by `Name`. The resulting snapshot  will be
// committed and readonly. The `key` reference will no longer be available for
// lookup or removal. The returned string identifier for the committed snapshot
// is the same identifier of the original active snapshot. The provided context
// must contain a writable transaction.
func CommitActive(ctx context.Context, key, name string, usage snapshots.Usage, opts ...snapshots.Opt) (string, error) {
	var (
		id   uint64
		base snapshots.Info
	)
	for _, opt := range opts {
		if err := opt(&base); err != nil {
			return "", err
		}
	}

	if err := withBucket(ctx, func(ctx context.Context, bkt, pbkt *bolt.Bucket) error {
		dbkt, err := bkt.CreateBucket([]byte(name))
		if err != nil {
			if err == bolt.ErrBucketExists {
				err = errdefs.ErrAlreadyExists
			}
			return errors.Wrapf(err, "committed snapshot %v", name)
		}
		sbkt := bkt.Bucket([]byte(key))
		if sbkt == nil {
			return errors.Wrapf(errdefs.ErrNotFound, "failed to get active snapshot %q", key)
		}

		var si snapshots.Info
		if err := readSnapshot(sbkt, &id, &si); err != nil {
			return errors.Wrapf(err, "failed to read active snapshot %q", key)
		}

		if si.Kind != snapshots.KindActive {
			return errors.Wrapf(errdefs.ErrFailedPrecondition, "snapshot %q is not active", key)
		}
		si.Kind = snapshots.KindCommitted
		si.Created = time.Now().UTC()
		si.Updated = si.Created

		// Replace labels, do not inherit
		si.Labels = base.Labels

		if err := putSnapshot(dbkt, id, si); err != nil {
			return err
		}
		if err := putUsage(dbkt, usage); err != nil {
			return err
		}
		if err := bkt.DeleteBucket([]byte(key)); err != nil {
			return errors.Wrapf(err, "failed to delete active snapshot %q", key)
		}
		if si.Parent != "" {
			spbkt := bkt.Bucket([]byte(si.Parent))
			if spbkt == nil {
				return errors.Wrapf(errdefs.ErrNotFound, "missing parent %q of snapshot %q", si.Parent, key)
			}
			pid := readID(spbkt)

			// Updates parent back link to use new key
			if err := pbkt.Put(parentKey(pid, id), []byte(name)); err != nil {
				return errors.Wrapf(err, "failed to update parent link %q from %q to %q", pid, key, name)
			}
		}

		return nil
	}); err != nil {
		return "", err
	}

	return fmt.Sprintf("%d", id), nil
}
```
- ***Remove***
```diff
// Remove abandons the snapshot identified by key. The snapshot will
// immediately become unavailable and unrecoverable. Disk space will
// be freed up on the next call to `Cleanup`.
func (o *snapshotter) Remove(ctx context.Context, key string) (err error) {
	ctx, t, err := o.ms.TransactionContext(ctx, true)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if rerr := t.Rollback(); rerr != nil {
				log.G(ctx).WithError(rerr).Warn("failed to rollback transaction")
			}
		}
	}()

	_, _, err = storage.Remove(ctx, key)
	if err != nil {
		return errors.Wrap(err, "failed to remove")
	}

	if !o.asyncRemove {
		var removals []string
		removals, err = o.getCleanupDirectories(ctx, t)
		if err != nil {
			return errors.Wrap(err, "unable to get directories for removal")
		}

		// Remove directories after the transaction is closed, failures must not
		// return error since the transaction is committed with the removal
		// key no longer available.
		defer func() {
			if err == nil {
				for _, dir := range removals {
					if err := os.RemoveAll(dir); err != nil {
						log.G(ctx).WithError(err).WithField("path", dir).Warn("failed to remove directory")
					}
				}
			}
		}()

	}

	return t.Commit()
}
```

- ***Walk***
```diff
// Walk the snapshots.
func (o *snapshotter) Walk(ctx context.Context, fn snapshots.WalkFunc, fs ...string) error {
	ctx, t, err := o.ms.TransactionContext(ctx, false)
	if err != nil {
		return err
	}
	defer t.Rollback()
	if o.upperdirLabel {
		return storage.WalkInfo(ctx, func(ctx context.Context, info snapshots.Info) error {
			id, _, _, err := storage.GetInfo(ctx, info.Name)
			if err != nil {
				return err
			}
			if info.Labels == nil {
				info.Labels = make(map[string]string)
			}
			info.Labels[upperdirKey] = o.upperPath(id)
			return fn(ctx, info)
		}, fs...)
	}
+	return storage.WalkInfo(ctx, fn, fs...)
}
```

> *storage.WalkInfo(ctx, fn, fs...)*
```diff
// WalkInfo iterates through all metadata Info for the stored snapshots and
// calls the provided function for each. Requires a context with a storage
// transaction.
func WalkInfo(ctx context.Context, fn snapshots.WalkFunc, fs ...string) error {
	filter, err := filters.ParseAll(fs...)
	if err != nil {
		return err
	}
	// TODO: allow indexes (name, parent, specific labels)
	return withBucket(ctx, func(ctx context.Context, bkt, pbkt *bolt.Bucket) error {
		return bkt.ForEach(func(k, v []byte) error {
			// skip non buckets
			if v != nil {
				return nil
			}
			var (
				sbkt = bkt.Bucket(k)
				si   = snapshots.Info{
					Name: string(k),
				}
			)
			if err := readSnapshot(sbkt, nil, &si); err != nil {
				return err
			}
			if !filter.Match(adaptSnapshot(si)) {
				return nil
			}

			return fn(ctx, si)
		})
	})
}
```
- ***Others***
```diff
// Cleanup cleans up disk resources from removed or abandoned snapshots
func (o *snapshotter) Cleanup(ctx context.Context) error {
	cleanup, err := o.cleanupDirectories(ctx)
	if err != nil {
		return err
	}

	for _, dir := range cleanup {
		if err := os.RemoveAll(dir); err != nil {
			log.G(ctx).WithError(err).WithField("path", dir).Warn("failed to remove directory")
		}
	}

	return nil
}

func (o *snapshotter) cleanupDirectories(ctx context.Context) ([]string, error) {
	// Get a write transaction to ensure no other write transaction can be entered
	// while the cleanup is scanning.
	ctx, t, err := o.ms.TransactionContext(ctx, true)
	if err != nil {
		return nil, err
	}

	defer t.Rollback()
	return o.getCleanupDirectories(ctx, t)
}

func (o *snapshotter) getCleanupDirectories(ctx context.Context, t storage.Transactor) ([]string, error) {
	ids, err := storage.IDMap(ctx)
	if err != nil {
		return nil, err
	}

	snapshotDir := filepath.Join(o.root, "snapshots")
	fd, err := os.Open(snapshotDir)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	dirs, err := fd.Readdirnames(0)
	if err != nil {
		return nil, err
	}

	cleanup := []string{}
	for _, d := range dirs {
		if _, ok := ids[d]; ok {
			continue
		}

		cleanup = append(cleanup, filepath.Join(snapshotDir, d))
	}

	return cleanup, nil
}


func (o *snapshotter) prepareDirectory(ctx context.Context, snapshotDir string, kind snapshots.Kind) (string, error) {
	td, err := ioutil.TempDir(snapshotDir, "new-")
	if err != nil {
		return "", errors.Wrap(err, "failed to create temp dir")
	}

	if err := os.Mkdir(filepath.Join(td, "fs"), 0755); err != nil {
		return td, err
	}

	if kind == snapshots.KindActive {
		if err := os.Mkdir(filepath.Join(td, "work"), 0711); err != nil {
			return td, err
		}
	}

	return td, nil
}

func (o *snapshotter) upperPath(id string) string {
	return filepath.Join(o.root, "snapshots", id, "fs")
}

func (o *snapshotter) workPath(id string) string {
	return filepath.Join(o.root, "snapshots", id, "work")
}

// Close closes the snapshotter
func (o *snapshotter) Close() error {
	return o.ms.Close()
}
```
