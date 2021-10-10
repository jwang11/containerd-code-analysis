# Snapshot服务
>其服务的核心是实现抽象的 Snapshotter 用于容器的rootfs 挂载和卸载等操作功能。 Snapshotter 设计替代在docker早期版本称之为graphdriver存储驱动的设计。
>为支持更丰富的文件系统如 overlay 文件系统 ，引入上层抽象 snapshot 快照概念，使 docker 存储驱动更加简化同时兼容了块设备快照与 overlay 文件系统。

## 1. 外部服务
### 1.1 Plugin注册
[services/snapshots/service.go](https://github.com/containerd/containerd/blob/main/services/snapshots/service.go)
```diff
func init() {
	plugin.Register(&plugin.Registration{
+		Type: plugin.GRPCPlugin,
+		ID:   "snapshots",
		Requires: []plugin.Type{
			plugin.ServicePlugin,
		},
+		InitFn: newService,
	})
}

func newService(ic *plugin.InitContext) (interface{}, error) {
	plugins, err := ic.GetByType(plugin.ServicePlugin)
	if err != nil {
		return nil, err
	}
+	p, ok := plugins[services.SnapshotsService]
	i, err := p.Instance()
+	ss := i.(map[string]snapshots.Snapshotter)
+	return &service{ss: ss}, nil
}
```

### 1.2 接口实现
- 外部Service
```diff
type service struct {
	ss map[string]snapshots.Snapshotter
}
```

- ***getSnapshotter***
获取Snapshot的底层实现，如overlay
```diff
func (s *service) getSnapshotter(name string) (snapshots.Snapshotter, error) {
	sn := s.ss[name]
	return sn, nil
}
```

- ***Prepare***
```diff
func (s *service) Prepare(ctx context.Context, pr *snapshotsapi.PrepareSnapshotRequest) (*snapshotsapi.PrepareSnapshotResponse, error) {
	log.G(ctx).WithField("parent", pr.Parent).WithField("key", pr.Key).Debugf("prepare snapshot")
-	// 根据Reqeust里的snapshotter名字，获取sn对象	
	sn, err := s.getSnapshotter(pr.Snapshotter)
	var opts []snapshots.Opt
	if pr.Labels != nil {
		opts = append(opts, snapshots.WithLabels(pr.Labels))
	}
-	// 调用内部服务Prepare方法	
	mounts, err := sn.Prepare(ctx, pr.Key, pr.Parent, opts...)
	return &snapshotsapi.PrepareSnapshotResponse{
		Mounts: fromMounts(mounts),
	}, nil
}
```
- ***View***
```diff
func (s *service) View(ctx context.Context, pr *snapshotsapi.ViewSnapshotRequest) (*snapshotsapi.ViewSnapshotResponse, error) {
	log.G(ctx).WithField("parent", pr.Parent).WithField("key", pr.Key).Debugf("prepare view snapshot")
	sn, err := s.getSnapshotter(pr.Snapshotter)
	var opts []snapshots.Opt
	if pr.Labels != nil {
		opts = append(opts, snapshots.WithLabels(pr.Labels))
	}
	mounts, err := sn.View(ctx, pr.Key, pr.Parent, opts...)
	return &snapshotsapi.ViewSnapshotResponse{
		Mounts: fromMounts(mounts),
	}, nil
}
```
- ***Mounts***
```diff
func (s *service) Mounts(ctx context.Context, mr *snapshotsapi.MountsRequest) (*snapshotsapi.MountsResponse, error) {
	log.G(ctx).WithField("key", mr.Key).Debugf("get snapshot mounts")
+	sn, err := s.getSnapshotter(mr.Snapshotter)
-	// 根据SnapshotKey，返回相应的mounts
	mounts, err := sn.Mounts(ctx, mr.Key)
	return &snapshotsapi.MountsResponse{
		Mounts: fromMounts(mounts),
	}, nil
}
```

- ***Commit***
```diff
func (s *service) Commit(ctx context.Context, cr *snapshotsapi.CommitSnapshotRequest) (*ptypes.Empty, error) {
	log.G(ctx).WithField("key", cr.Key).WithField("name", cr.Name).Debugf("commit snapshot")
	sn, err := s.getSnapshotter(cr.Snapshotter)
	var opts []snapshots.Opt
	if cr.Labels != nil {
		opts = append(opts, snapshots.WithLabels(cr.Labels))
	}	
+	if err := sn.Commit(ctx, cr.Name, cr.Key, opts...); err != nil {}
	return empty, nil
}
```

- ***Remove***
```diff
func (s *service) Remove(ctx context.Context, rr *snapshotsapi.RemoveSnapshotRequest) (*ptypes.Empty, error) {
	log.G(ctx).WithField("key", rr.Key).Debugf("remove snapshot")
+	sn, err := s.getSnapshotter(rr.Snapshotter)
+	if err := sn.Remove(ctx, rr.Key); err != nil {}
	return empty, nil
}
```

- ***Stat***
```diff
func (s *service) Stat(ctx context.Context, sr *snapshotsapi.StatSnapshotRequest) (*snapshotsapi.StatSnapshotResponse, error) {
	log.G(ctx).WithField("key", sr.Key).Debugf("stat snapshot")
	sn, err := s.getSnapshotter(sr.Snapshotter)
+	info, err := sn.Stat(ctx, sr.Key)
	return &snapshotsapi.StatSnapshotResponse{Info: fromInfo(info)}, nil
}
```

- ***Udpate***
```diff
func (s *service) Update(ctx context.Context, sr *snapshotsapi.UpdateSnapshotRequest) (*snapshotsapi.UpdateSnapshotResponse, error) {
	log.G(ctx).WithField("key", sr.Info.Name).Debugf("update snapshot")
	sn, err := s.getSnapshotter(sr.Snapshotter)
+	info, err := sn.Update(ctx, toInfo(sr.Info), sr.UpdateMask.GetPaths()...)
	return &snapshotsapi.UpdateSnapshotResponse{Info: fromInfo(info)}, nil
}
```

- ***List***
```diff
func (s *service) List(sr *snapshotsapi.ListSnapshotsRequest, ss snapshotsapi.Snapshots_ListServer) error {
	sn, err := s.getSnapshotter(sr.Snapshotter)
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
			if err := sendBlock(buffer); err != nil {}
			buffer = buffer[:0]
		}

		return nil
	}, sr.Filters...)

	if len(buffer) > 0 {
		// Send remaining infos
		if err := sendBlock(buffer); err != nil {}
	}

	return nil
}
```

- ***Usage***
```
func (s *service) Usage(ctx context.Context, ur *snapshotsapi.UsageRequest) (*snapshotsapi.UsageResponse, error) {
	sn, err := s.getSnapshotter(ur.Snapshotter)
	usage, err := sn.Usage(ctx, ur.Key)
	return fromUsage(usage), nil
}
```

## 2. 内部服务
### 2.1 Plugin注册
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
			ep, err := ic.Get(plugin.EventPlugin)
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
```

### 2.2 接口实现
- ***Prepare***
```diff
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
```

- ***Commit***
```diff
func (s *snapshotter) Commit(ctx context.Context, name, key string, opts ...snapshots.Opt) error {
-	// 调用底层服务的Commit
	if err := s.Snapshotter.Commit(ctx, name, key, opts...); err != nil {}
	return s.publisher.Publish(ctx, "/snapshot/commit", &eventstypes.SnapshotCommit{
		Key:  key,
		Name: name,
	})
}
```

## 3. 底层服务Overlay
[snapshots/overlay/plugin/plugin.go](https://github.com/containerd/containerd/blob/main/snapshots/overlay/plugin/plugin.go)
###  3.1 Plugin注册
```diff
func init() {
	plugin.Register(&plugin.Registration{
+		Type:   plugin.SnapshotPlugin,
+		ID:     "overlayfs",
		Config: &Config{},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			ic.Meta.Platforms = append(ic.Meta.Platforms, platforms.DefaultSpec())
			config, ok := ic.Config.(*Config)
			root := ic.Root
			var oOpts []overlay.Opt
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
		if err := opt(&config); err != nil {}
	}

	if err := os.MkdirAll(root, 0700); err != nil {}
	supportsDType, err := fs.SupportsDType(root)
+	ms, err := storage.NewMetaStore(filepath.Join(root, "metadata.db"))

	if err := os.Mkdir(filepath.Join(root, "snapshots"), 0700); err != nil && !os.IsExist(err) {}

	// figure out whether "index=off" option is recognized by the kernel
	var indexOff bool
	if _, err = os.Stat("/sys/module/overlay/parameters/index"); err == nil {
		indexOff = true
	}

	// figure out whether "userxattr" option is recognized by the kernel && needed
	userxattr, err := overlayutils.NeedsUserXAttr(root)
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
### 3.2 接口实现
```diff
- bolt数据库里的snapshot
//        ├──snapshots
//        │  ╘══*snapshotter*
//        │     ╘══*snapshot key*
//        │        ├──name : <string>            - Snapshot name in backend
//        │        ├──createdat : <binary time>  - Created at
//        │        ├──updatedat : <binary time>  - Updated at
//        │        ├──parent : <string>          - Parent snapshot name
//        │        ├──children
//        │        │  ╘══*snapshot key* : <nil>  - Child snapshot reference
//        │        └──labels
//        │           ╘══*key* : <string>        - Label value
```
- ***Stat***
```diff
// Stat returns the info for an active or committed snapshot by name or
// key.
//
// Should be used for parent resolution, existence checks and to discern
// the kind of snapshot.
func (o *snapshotter) Stat(ctx context.Context, key string) (snapshots.Info, error) {
	ctx, t, err := o.ms.TransactionContext(ctx, false)
	defer t.Rollback()
	id, info, _, err := storage.GetInfo(ctx, key)
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
	return fmt.Sprintf("%d", id), si, su, nil
}
```

- ***Update***
```diff
func (o *snapshotter) Update(ctx context.Context, info snapshots.Info, fieldpaths ...string) (snapshots.Info, error) {
	ctx, t, err := o.ms.TransactionContext(ctx, true)
+	info, err = storage.UpdateInfo(ctx, info, fieldpaths...)
	if err := t.Commit(); err != nil {}

	if o.upperdirLabel {
+		id, _, _, err := storage.GetInfo(ctx, info.Name)
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
		if err := readSnapshot(sbkt, nil, &updated); err != nil {}

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
		if err := boltutil.WriteTimestamps(sbkt, updated.Created, updated.Updated); err != nil {}
		return boltutil.WriteLabels(sbkt, updated.Labels)
	})
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
	id, info, usage, err := storage.GetInfo(ctx, key)
	t.Rollback() // transaction no longer needed at this point.
	if info.Kind == snapshots.KindActive {
		upperPath := o.upperPath(id)
		du, err := fs.DiskUsage(ctx, upperPath)
		usage = snapshots.Usage(du)
	}
	return usage, nil
}
```
- ***Prepare***
```diff
func (o *snapshotter) Prepare(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
-	// kind=snapshots.KindActive表明prepare一个active的snapshot
+	return o.createSnapshot(ctx, snapshots.KindActive, key, parent, opts)
}

func (o *snapshotter) createSnapshot(ctx context.Context, kind snapshots.Kind, key, parent string, opts []snapshots.Opt) (_ []mount.Mount, err error) {
+	ctx, t, err := o.ms.TransactionContext(ctx, true)
	var td, path string

	snapshotDir := filepath.Join(o.root, "snapshots")
-	// 建立/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/$id/{fs,work}目录	
	td, err = o.prepareDirectory(ctx, snapshotDir, kind)
	rollback := true
-	// 把新的snapshot信息写入bolt数据库	
	s, err := storage.CreateSnapshot(ctx, kind, key, parent, opts...)

	if len(s.ParentIDs) > 0 {
		st, err := os.Stat(o.upperPath(s.ParentIDs[0]))
		stat := st.Sys().(*syscall.Stat_t)
		os.Lchown(filepath.Join(td, "fs"), int(stat.Uid), int(stat.Gid))
	}

	path = filepath.Join(snapshotDir, s.ID)
	os.Rename(td, path)
	td = ""

	rollback = false
-	// bolt库内容提交	
	t.Commit()
+	return o.mounts(s), nil
}

// TransactionContext creates a new transaction context. The writable value
// should be set to true for transactions which are expected to mutate data.
func (ms *MetaStore) TransactionContext(ctx context.Context, writable bool) (context.Context, Transactor, error) {
	ms.dbL.Lock()
	if ms.db == nil {
		db, err := bolt.Open(ms.dbfile, 0600, nil)
+		ms.db = db
	}
	ms.dbL.Unlock()

	tx, err := ms.db.Begin(writable)
	ctx = context.WithValue(ctx, transactionKey{}, tx)
	return ctx, tx, nil
}
```
> o.mounts(s)返回mount的全部参数信息
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
	s, err := storage.GetSnapshot(ctx, key)
	t.Rollback()
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

	// grab the existing id
+	id, _, _, err := storage.GetInfo(ctx, key)
	usage, err := fs.DiskUsage(ctx, o.upperPath(id))
+	if _, err = storage.CommitActive(ctx, key, name, snapshots.Usage(usage), opts...); err != nil {}
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
		if err := opt(&base); err != nil {}
	}

	if err := withBucket(ctx, func(ctx context.Context, bkt, pbkt *bolt.Bucket) error {
		dbkt, err := bkt.CreateBucket([]byte(name))
		sbkt := bkt.Bucket([]byte(key))

		var si snapshots.Info
		if err := readSnapshot(sbkt, &id, &si); err != nil {}

		si.Kind = snapshots.KindCommitted
		si.Created = time.Now().UTC()
		si.Updated = si.Created

		// Replace labels, do not inherit
		si.Labels = base.Labels

		if err := putSnapshot(dbkt, id, si); err}
		if err := putUsage(dbkt, usage); err != nil {}
		if err := bkt.DeleteBucket([]byte(key)); err != nil {}
		if si.Parent != "" {
			spbkt := bkt.Bucket([]byte(si.Parent))
			pid := readID(spbkt)

			// Updates parent back link to use new key
			if err := pbkt.Put(parentKey(pid, id), []byte(name)); err != nil {}
		}
		return nil
	})

	return fmt.Sprintf("%d", id), nil
}
```

- ***Walk***
```diff
// Walk the snapshots.
func (o *snapshotter) Walk(ctx context.Context, fn snapshots.WalkFunc, fs ...string) error {
	ctx, t, err := o.ms.TransactionContext(ctx, false)
	defer t.Rollback()
	if o.upperdirLabel {
		return storage.WalkInfo(ctx, func(ctx context.Context, info snapshots.Info) error {
			id, _, _, err := storage.GetInfo(ctx, info.Name)
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

> storage.WalkInfo(ctx, fn, fs...)
```diff
// WalkInfo iterates through all metadata Info for the stored snapshots and
// calls the provided function for each. Requires a context with a storage
// transaction.
func WalkInfo(ctx context.Context, fn snapshots.WalkFunc, fs ...string) error {
	filter, err := filters.ParseAll(fs...)
	// TODO: allow indexes (name, parent, specific labels)
	return withBucket(ctx, func(ctx context.Context, bkt, pbkt *bolt.Bucket) error {
		return bkt.ForEach(func(k, v []byte) error {
			var (
				sbkt = bkt.Bucket(k)
				si   = snapshots.Info{
					Name: string(k),
				}
			)
			if err := readSnapshot(sbkt, nil, &si); err != nil {}
			if !filter.Match(adaptSnapshot(si)) {
				return nil
			}
			return fn(ctx, si)
		})
	})
}
```
