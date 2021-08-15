> metadata建立一个bolt键值数据库

## Metadata服务的初始化

- Metadata服务是在***loadPlugins***里被注册的，它依赖ContentPlugin和SnapshotPlugin，***InitFn***返回metadata.DB对象
(https://github.com/containerd/containerd/blob/main/services/server/server.go)
```diff
func LoadPlugins(ctx context.Context, config *srvconfig.Config) ([]*plugin.Registration, error) {
...
	// load additional plugins that don't automatically register themselves
	plugin.Register(&plugin.Registration{
		Type: plugin.ContentPlugin,
		ID:   "content",
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			ic.Meta.Exports["root"] = ic.Root
			return local.NewStore(ic.Root)
		},
	})
  
  	plugin.Register(&plugin.Registration{
		Type: plugin.MetadataPlugin,
		ID:   "bolt",
		Requires: []plugin.Type{
			plugin.ContentPlugin,
			plugin.SnapshotPlugin,
		},
		Config: &srvconfig.BoltConfig{
			ContentSharingPolicy: srvconfig.SharingPolicyShared,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			if err := os.MkdirAll(ic.Root, 0711); err != nil {
				return nil, err
			}
+			// 得到第一个ContentPlugin的instance，也就是content.Store
			cs, err := ic.Get(plugin.ContentPlugin)
			if err != nil {
				return nil, err
			}

			snapshottersRaw, err := ic.GetByType(plugin.SnapshotPlugin)
			if err != nil {
				return nil, err
			}

			snapshotters := make(map[string]snapshots.Snapshotter)
			for name, sn := range snapshottersRaw {
				sn, err := sn.Instance()
				if err != nil {
					if !plugin.IsSkipPlugin(err) {
						log.G(ic.Context).WithError(err).
							Warnf("could not use snapshotter %v in metadata plugin", name)
					}
					continue
				}
+				// 得到所有的Snapshotter				
+				snapshotters[name] = sn.(snapshots.Snapshotter)
			}

			shared := true
			ic.Meta.Exports["policy"] = srvconfig.SharingPolicyShared
			if cfg, ok := ic.Config.(*srvconfig.BoltConfig); ok {
				if cfg.ContentSharingPolicy != "" {
					if err := cfg.Validate(); err != nil {
						return nil, err
					}
					if cfg.ContentSharingPolicy == srvconfig.SharingPolicyIsolated {
						ic.Meta.Exports["policy"] = srvconfig.SharingPolicyIsolated
						shared = false
					}

					log.L.WithField("policy", cfg.ContentSharingPolicy).Info("metadata content store policy set")
				}
			}

			path := filepath.Join(ic.Root, "meta.db")
			ic.Meta.Exports["path"] = path
+			// 创建bolt数据库
+			db, err := bolt.Open(path, 0644, nil)
			if err != nil {
				return nil, err
			}

			var dbopts []metadata.DBOpt
			if !shared {
				dbopts = append(dbopts, metadata.WithPolicyIsolated)
			}
+			mdb := metadata.NewDB(db, cs.(content.Store), snapshotters, dbopts...)
			if err := mdb.Init(ic.Context); err != nil {
				return nil, err
			}
			return mdb, nil
		},
	})
...
}
```

### ContentPlugin注册
- ContentPlugin注册后，除了被metadata需要，以后还会在Content的SevicePlugin里被用到
(https://github.com/containerd/containerd/blob/main/content/local/store.go)
```diff
// NewStore returns a local content store
func NewStore(root string) (content.Store, error) {
	return NewLabeledStore(root, nil)
}

// NewLabeledStore returns a new content store using the provided label store
//
// Note: content stores which are used underneath a metadata store may not
// require labels and should use `NewStore`. `NewLabeledStore` is primarily
// useful for tests or standalone implementations.
func NewLabeledStore(root string, ls LabelStore) (content.Store, error) {
	if err := os.MkdirAll(filepath.Join(root, "ingest"), 0777); err != nil {
		return nil, err
	}

	return &store{
		root: root,
		ls:   ls,
	}, nil
}

+// Store存放的内容都是有摘要的，可以校验内容完整性
// Store is digest-keyed store for content. All data written into the store is
// stored under a verifiable digest.
//
// Store can generally support multi-reader, single-writer ingest of data,
// including resumable ingest.
type store struct {
	root string
	ls   LabelStore
}
```

### Metadata DB的实现
- Metadata DB包括了bolt数据库，新的***contentStore***（基于contentPlugin里的content.Store），snapshotters
```
/ DB represents a metadata database backed by a bolt
// database. The database is fully namespaced and stores
// image, container, namespace, snapshot, and content data
// while proxying data shared across namespaces to backend
// datastores for content and snapshots.
type DB struct {
	db *bolt.DB
	ss map[string]*snapshotter
	cs *contentStore

	// wlock is used to protect access to the data structures during garbage
	// collection. While the wlock is held no writable transactions can be
	// opened, preventing changes from occurring between the mark and
	// sweep phases without preventing read transactions.
	wlock sync.RWMutex

	// dirty flag indicates that references have been removed which require
	// a garbage collection to ensure the database is clean. This tracks
	// the number of dirty operations. This should be updated and read
	// atomically if outside of wlock.Lock.
	dirty uint32

	// dirtySS and dirtyCS flags keeps track of datastores which have had
	// deletions since the last garbage collection. These datastores will
	// be garbage collected during the next garbage collection. These
	// should only be updated inside of a write transaction or wlock.Lock.
	dirtySS map[string]struct{}
	dirtyCS bool

	// mutationCallbacks are called after each mutation with the flag
	// set indicating whether any dirty flags are set
	mutationCallbacks []func(bool)

	dbopts dbOptions
}
```

- 创建Metadata DB
```
// NewDB creates a new metadata database using the provided
// bolt database, content store, and snapshotters.
func NewDB(db *bolt.DB, cs content.Store, ss map[string]snapshots.Snapshotter, opts ...DBOpt) *DB {
	m := &DB{
		db:      db,
		ss:      make(map[string]*snapshotter, len(ss)),
		dirtySS: map[string]struct{}{},
		dbopts: dbOptions{
			shared: true,
		},
	}

	for _, opt := range opts {
		opt(&m.dbopts)
	}

	// Initialize data stores
	m.cs = newContentStore(m, m.dbopts.shared, cs)
	for name, sn := range ss {
		m.ss[name] = newSnapshotter(m, name, sn)
	}

	return m
}

- newContentStore会返回一个有Namespace的Content Store
```
// newContentStore returns a namespaced content store using an existing
// content store interface.
// policy defines the sharing behavior for content between namespaces. Both
// modes will result in shared storage in the backend for committed. Choose
// "shared" to prevent separate namespaces from having to pull the same content
// twice.  Choose "isolated" if the content must not be shared between
// namespaces.
//
// If the policy is "shared", writes will try to resolve the "expected" digest
// against the backend, allowing imports of content from other namespaces. In
// "isolated" mode, the client must prove they have the content by providing
// the entire blob before the content can be added to another namespace.
//
// Since we have only two policies right now, it's simpler using bool to
// represent it internally.
func newContentStore(db *DB, shared bool, cs content.Store) *contentStore {
	return &contentStore{
		Store:  cs,
		db:     db,
		shared: shared,
	}
}


type contentStore struct {
	content.Store
	db     *DB
	shared bool
	l      sync.RWMutex
}
```

### contentStores实现
- contentStore结构里面包括了content.Store接口，同样需要实现content.Store接口
- ***Info***是实现label的读取以及create/update时间戳。根据digest作为key，查找bolt数据库，返回键值对
```
func (cs *contentStore) Info(ctx context.Context, dgst digest.Digest) (content.Info, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return content.Info{}, err
	}

	var info content.Info
	if err := view(ctx, cs.db, func(tx *bolt.Tx) error {
		bkt := getBlobBucket(tx, ns, dgst)
		if bkt == nil {
			// try to find shareable bkt before erroring
			bkt = getShareableBucket(tx, dgst)
		}
		if bkt == nil {
			return errors.Wrapf(errdefs.ErrNotFound, "content digest %v", dgst)
		}

		info.Digest = dgst
		return readInfo(&info, bkt)
	}); err != nil {
		return content.Info{}, err
	}

	return info, nil
}

func readInfo(info *content.Info, bkt *bolt.Bucket) error {
	if err := boltutil.ReadTimestamps(bkt, &info.CreatedAt, &info.UpdatedAt); err != nil {
		return err
	}

	labels, err := boltutil.ReadLabels(bkt)
	if err != nil {
		return err
	}
	info.Labels = labels

	if v := bkt.Get(bucketKeySize); len(v) > 0 {
		info.Size, _ = binary.Varint(v)
	}

	return nil
}
```
- Update实现label的写入，同时更新时间戳
```
func (cs *contentStore) Update(ctx context.Context, info content.Info, fieldpaths ...string) (content.Info, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return content.Info{}, err
	}

	cs.l.RLock()
	defer cs.l.RUnlock()

	updated := content.Info{
		Digest: info.Digest,
	}
	if err := update(ctx, cs.db, func(tx *bolt.Tx) error {
		bkt := getBlobBucket(tx, ns, info.Digest)
		if bkt == nil {
			// try to find a shareable bkt before erroring
			bkt = getShareableBucket(tx, info.Digest)
		}
		if bkt == nil {
			return errors.Wrapf(errdefs.ErrNotFound, "content digest %v", info.Digest)
		}
		if err := readInfo(&updated, bkt); err != nil {
			return errors.Wrapf(err, "info %q", info.Digest)
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
					return errors.Wrapf(errdefs.ErrInvalidArgument, "cannot update %q field on content info %q", path, info.Digest)
				}
			}
		} else {
			// Set mutable fields
			updated.Labels = info.Labels
		}
		if err := validateInfo(&updated); err != nil {
			return err
		}

		updated.UpdatedAt = time.Now().UTC()
		return writeInfo(&updated, bkt)
	}); err != nil {
		return content.Info{}, err
	}
	return updated, nil
}

// update gets a writable bolt db transaction either from the context
// or starts a new one with the provided bolt database.
func update(ctx context.Context, db transactor, fn func(*bolt.Tx) error) error {
	tx, ok := ctx.Value(transactionKey{}).(*bolt.Tx)
	if !ok {
		return db.Update(fn)
	} else if !tx.Writable() {
		return errors.Wrap(bolt.ErrTxNotWritable, "unable to use transaction from context")
	}
	return fn(tx)
}
```
