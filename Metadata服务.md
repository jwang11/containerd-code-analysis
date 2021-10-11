# Metadata服务
> metadata服务通过基于bolt键值数据库以及local文件库的contentStore来管理各种meta信息，包括label, content，time, manifest，config以及blob。<br>
> metadata服务作为数据读写接口的中间层，支持其它上层和中层的服务

## 1. Metadata DB
### 1.1 Plugin注册
Metadata服务是在***loadPlugins***里被注册的，它依赖ContentPlugin和SnapshotPlugin两个底层plugins，***InitFn***返回metadata.DB对象
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
+		ID:   "bolt",
		Requires: []plugin.Type{
			plugin.ContentPlugin,
			plugin.SnapshotPlugin,
		},
		Config: &srvconfig.BoltConfig{
			ContentSharingPolicy: srvconfig.SharingPolicyShared,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			os.MkdirAll(ic.Root, 0711)
-			// 得到第一个ContentPlugin的instance，也就是content.Store
			cs, err := ic.Get(plugin.ContentPlugin)
			snapshottersRaw, err := ic.GetByType(plugin.SnapshotPlugin)
			snapshotters := make(map[string]snapshots.Snapshotter)
			for name, sn := range snapshottersRaw {
				sn, err := sn.Instance()
-				// 得到所有的Snapshotter				
				snapshotters[name] = sn.(snapshots.Snapshotter)
			}

			shared := true
			ic.Meta.Exports["policy"] = srvconfig.SharingPolicyShared
			if cfg, ok := ic.Config.(*srvconfig.BoltConfig); ok {
				if cfg.ContentSharingPolicy != "" {
					if cfg.ContentSharingPolicy == srvconfig.SharingPolicyIsolated {
						ic.Meta.Exports["policy"] = srvconfig.SharingPolicyIsolated
						shared = false
					}

					log.L.WithField("policy", cfg.ContentSharingPolicy).Info("metadata content store policy set")
				}
			}

			path := filepath.Join(ic.Root, "meta.db")
			ic.Meta.Exports["path"] = path
-			// 创建bolt数据库
			db, err := bolt.Open(path, 0644, nil)

			var dbopts []metadata.DBOpt
			if !shared {
				dbopts = append(dbopts, metadata.WithPolicyIsolated)
			}
+			mdb := metadata.NewDB(db, cs.(content.Store), snapshotters, dbopts...)
+			mdb.Init(ic.Context)
			return mdb, nil
		},
	})
...
}
```

### 1.2 创建DB
Metadata DB包括了bolt数据库，新的***contentStore***（基于local Store），以及snapshotters
```diff
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

// NewDB creates a new metadata database using the provided
// bolt database, content store, and snapshotters.
func NewDB(db *bolt.DB, cs content.Store, ss map[string]snapshots.Snapshotter, opts ...DBOpt) *DB {
	m := &DB{
+		db:      db,
+		ss:      make(map[string]*snapshotter, len(ss)),
		dirtySS: map[string]struct{}{},
		dbopts: dbOptions{
			shared: true,
		},
	}

	for _, opt := range opts {
		opt(&m.dbopts)
	}

	// Initialize data stores
+	m.cs = newContentStore(m, m.dbopts.shared, cs)
	for name, sn := range ss {
+		m.ss[name] = newSnapshotter(m, name, sn)
	}

	return m
}
```

### 1.3 Metadata Bolt数据库设计
```
// Below is the current database schema. This should be updated each time
// the structure is changed in addition to adding a migration and incrementing
// the database version. Note that `╘══*...*` refers to maps with arbitrary
// keys.
//  ├──version : <varint>                        - Latest version, see migrations
//  └──v1                                        - Schema version bucket
//     ╘══*namespace*
//        ├──labels
//        │  ╘══*key* : <string>                 - Label value
//        ├──image
//        │  ╘══*image name*
//        │     ├──createdat : <binary time>     - Created at
//        │     ├──updatedat : <binary time>     - Updated at
//        │     ├──target
//        │     │  ├──digest : <digest>          - Descriptor digest
//        │     │  ├──mediatype : <string>       - Descriptor media type
//        │     │  └──size : <varint>            - Descriptor size
//        │     └──labels
//        │        ╘══*key* : <string>           - Label value
//        ├──containers
//        │  ╘══*container id*
//        │     ├──createdat : <binary time>     - Created at
//        │     ├──updatedat : <binary time>     - Updated at
//        │     ├──spec : <binary>               - Proto marshaled spec
//        │     ├──image : <string>              - Image name
//        │     ├──snapshotter : <string>        - Snapshotter name
//        │     ├──snapshotKey : <string>        - Snapshot key
//        │     ├──runtime
//        │     │  ├──name : <string>            - Runtime name
//        │     │  ├──extensions
//        │     │  │  ╘══*name* : <binary>       - Proto marshaled extension
//        │     │  └──options : <binary>         - Proto marshaled options
//        │     └──labels
//        │        ╘══*key* : <string>           - Label value
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
//        ├──content
//        │  ├──blob
//        │  │  ╘══*blob digest*
//        │  │     ├──createdat : <binary time>  - Created at
//        │  │     ├──updatedat : <binary time>  - Updated at
//        │  │     ├──size : <varint>            - Blob size
//        │  │     └──labels
//        │  │        ╘══*key* : <string>        - Label value
//        │  └──ingests
//        │     ╘══*ingest reference*
//        │        ├──ref : <string>             - Ingest reference in backend
//        │        ├──expireat : <binary time>   - Time to expire ingest
//        │        └──expected : <digest>        - Expected commit digest
//        └──leases
//           ╘══*lease id*
//              ├──createdat : <binary time>     - Created at
//              ├──labels
//              │  ╘══*key* : <string>           - Label value
//              ├──snapshots
//              │  ╘══*snapshotter*
//              │     ╘══*snapshot key* : <nil>  - Snapshot reference
//              ├──content
//              │  ╘══*blob digest* : <nil>      - Content blob reference
//              └──ingests
//                 ╘══*ingest reference* : <nil> - Content ingest reference
```
- Bucket Key的定义
```
var (
	bucketKeyVersion          = []byte(schemaVersion)
	bucketKeyDBVersion        = []byte("version")    // stores the version of the schema
	bucketKeyObjectLabels     = []byte("labels")     // stores the labels for a namespace.
	bucketKeyObjectImages     = []byte("images")     // stores image objects
	bucketKeyObjectContainers = []byte("containers") // stores container objects
	bucketKeyObjectSnapshots  = []byte("snapshots")  // stores snapshot references
	bucketKeyObjectContent    = []byte("content")    // stores content references
	bucketKeyObjectBlob       = []byte("blob")       // stores content links
	bucketKeyObjectIngests    = []byte("ingests")    // stores ingest objects
	bucketKeyObjectLeases     = []byte("leases")     // stores leases

	bucketKeyDigest      = []byte("digest")
	bucketKeyMediaType   = []byte("mediatype")
	bucketKeySize        = []byte("size")
	bucketKeyImage       = []byte("image")
	bucketKeyRuntime     = []byte("runtime")
	bucketKeyName        = []byte("name")
	bucketKeyParent      = []byte("parent")
	bucketKeyChildren    = []byte("children")
	bucketKeyOptions     = []byte("options")
	bucketKeySpec        = []byte("spec")
	bucketKeySnapshotKey = []byte("snapshotKey")
	bucketKeySnapshotter = []byte("snapshotter")
	bucketKeyTarget      = []byte("target")
	bucketKeyExtensions  = []byte("extensions")
	bucketKeyCreatedAt   = []byte("createdat")
	bucketKeyExpected    = []byte("expected")
	bucketKeyRef         = []byte("ref")
	bucketKeyExpireAt    = []byte("expireat")

	deprecatedBucketKeyObjectIngest = []byte("ingest") // stores ingest links, deprecated in v1.2
)
```

### 1.4 Metadata DB接口实现
```diff
// Init ensures the database is at the correct version
// and performs any needed migrations.
func (m *DB) Init(ctx context.Context) error {
	// errSkip is used when no migration or version needs to be written
	// to the database and the transaction can be immediately rolled
	// back rather than performing a much slower and unnecessary commit.
	var errSkip = errors.New("skip update")

	err := m.db.Update(func(tx *bolt.Tx) error {
		var (
			// current schema and version
			schema  = "v0"
			version = 0
		)

...

+		bkt, err := tx.CreateBucketIfNotExists(bucketKeyVersion)
+		versionEncoded, err := encodeInt(dbVersion)
+		return bkt.Put(bucketKeyDBVersion, versionEncoded)
	})
	return err
}

// ContentStore returns a namespaced content store
// proxied to a content store.
func (m *DB) ContentStore() content.Store {
	return m.cs
}

// Snapshotter returns a namespaced content store for
// the requested snapshotter name proxied to a snapshotter.
func (m *DB) Snapshotter(name string) snapshots.Snapshotter {
	sn, ok := m.ss[name]
	return sn
}

// Snapshotters returns all available snapshotters.
func (m *DB) Snapshotters() map[string]snapshots.Snapshotter {
	ss := make(map[string]snapshots.Snapshotter, len(m.ss))
	for n, sn := range m.ss {
		ss[n] = sn
	}
	return ss
}

// View runs a readonly transaction on the metadata store.
func (m *DB) View(fn func(*bolt.Tx) error) error {
	return m.db.View(fn)
}

// Update runs a writable transaction on the metadata store.
func (m *DB) Update(fn func(*bolt.Tx) error) error {
	m.wlock.RLock()
	defer m.wlock.RUnlock()
	err := m.db.Update(fn)
	if err == nil {
		dirty := atomic.LoadUint32(&m.dirty) > 0
		for _, fn := range m.mutationCallbacks {
			fn(dirty)
		}
	}
	return err
}
```

## 2. Content服务
### 2.1 Plugin注册
```diff
func LoadPlugins(ctx context.Context, config *srvconfig.Config) ([]*plugin.Registration, error) {
...
	// load additional plugins that don't automatically register themselves
	plugin.Register(&plugin.Registration{
		Type: plugin.ContentPlugin,
+		ID:   "content",
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			ic.Meta.Exports["root"] = ic.Root
+			return local.NewStore(ic.Root)
		},
	})
...
}

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
	os.MkdirAll(filepath.Join(root, "ingest"), 0777)
	return &store{
		root: root,
		ls:   ls,
	}, nil
}
```

### 2.2 接口实现
local store是基于文件系统的，可以为Meta里面content store提供基础功能
[local store](https://github.com/containerd/containerd/blob/main/content/local/store.go)
```diff
-// Store存放的内容都是有摘要的，可以校验内容完整性
// Store is digest-keyed store for content. All data written into the store is
// stored under a verifiable digest.
//
// Store can generally support multi-reader, single-writer ingest of data,
// including resumable ingest.
type store struct {
	root string
	ls   LabelStore
}

func (s *store) blobPath(dgst digest.Digest) (string, error) {
	return filepath.Join(s.root, "blobs", dgst.Algorithm().String(), dgst.Hex()), nil
}

func (s *store) ingestRoot(ref string) string {
	// we take a digest of the ref to keep the ingest paths constant length.
	// Note that this is not the current or potential digest of incoming content.
	dgst := digest.FromString(ref)
	return filepath.Join(s.root, "ingest", dgst.Hex())
}

// ingestPaths are returned. The paths are the following:
//
// - root: entire ingest directory
// - ref: name of the starting ref, must be unique
// - data: file where data is written
//
func (s *store) ingestPaths(ref string) (string, string, string) {
	var (
		fp = s.ingestRoot(ref)
		rp = filepath.Join(fp, "ref")
		dp = filepath.Join(fp, "data")
	)

	return fp, rp, dp
}

func readFileString(path string) (string, error) {
	p, err := ioutil.ReadFile(path)
	return string(p), err
}

// readFileTimestamp reads a file with just a timestamp present.
func readFileTimestamp(p string) (time.Time, error) {
	b, err := ioutil.ReadFile(p)
	var t time.Time
	t.UnmarshalText(b)
	return t, nil
}

func writeTimestampFile(p string, t time.Time) error {
	b, err := t.MarshalText()
	return writeToCompletion(p, b, 0666)
}

func writeToCompletion(path string, data []byte, mode os.FileMode) error {
	tmp := fmt.Sprintf("%s.tmp", path)
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_SYNC, mode)
	_, err = f.Write(data)
	f.Close()
	err = os.Rename(tmp, path)
	return nil
}
```

- ***Writer***
Writer的设计是支持简单的事务处理，内容先写入ingest里，commit的时候再导入blob

```diff
// Writer begins or resumes the active writer identified by ref. If the writer
// is already in use, an error is returned. Only one writer may be in use per
// ref at a time.
//
// The argument `ref` is used to uniquely identify a long-lived writer transaction.
func (s *store) Writer(ctx context.Context, opts ...content.WriterOpt) (content.Writer, error) {
	var wOpts content.WriterOpts
	for _, opt := range opts {
		opt(&wOpts)
	}

	var lockErr error
	for count := uint64(0); count < 10; count++ {
		if err := tryLock(wOpts.Ref); err != nil {
			lockErr = err
		} else {
			lockErr = nil
			break
		}
		time.Sleep(time.Millisecond * time.Duration(rand.Intn(1<<count)))
	}
	w, err := s.writer(ctx, wOpts.Ref, wOpts.Desc.Size, wOpts.Desc.Digest)
	return w, nil // lock is now held by w.
}

// writer provides the main implementation of the Writer method. The caller
// must hold the lock correctly and release on error if there is a problem.
func (s *store) writer(ctx context.Context, ref string, total int64, expected digest.Digest) (content.Writer, error) {
	// TODO(stevvooe): Need to actually store expected here. We have
	// code in the service that shouldn't be dealing with this.
	if expected != "" {
		p, err := s.blobPath(expected)
	}

	path, refp, data := s.ingestPaths(ref)

	var (
		digester  = digest.Canonical.Digester()
		offset    int64
		startedAt time.Time
		updatedAt time.Time
	)

	foundValidIngest := false
	// ensure that the ingest path has been created.
	if err := os.Mkdir(path, 0755); err != nil {
		status, err := s.resumeStatus(ref, total, digester)
		if err == nil {
			foundValidIngest = true
			updatedAt = status.UpdatedAt
			startedAt = status.StartedAt
			total = status.Total
			offset = status.Offset
		}
	}

	if !foundValidIngest {
		startedAt = time.Now()
		updatedAt = startedAt

		// the ingest is new, we need to setup the target location.
		// write the ref to a file for later use
		WriteFile(refp, []byte(ref), 0666)
		writeTimestampFile(filepath.Join(path, "startedat"), startedAt)
		writeTimestampFile(filepath.Join(path, "updatedat"), startedAt)

		if total > 0 {
			ioutil.WriteFile(filepath.Join(path, "total"), []byte(fmt.Sprint(total)), 0666)
		}
	}

	fp, err := os.OpenFile(data, os.O_WRONLY|os.O_CREATE, 0666)
	fp.Seek(offset, io.SeekStart)

	return &writer{
		s:         s,
		fp:        fp,
		ref:       ref,
		path:      path,
		offset:    offset,
		total:     total,
		digester:  digester,
		startedAt: startedAt,
		updatedAt: updatedAt,
	}, nil
}
```

- ***ReaderAt***
```diff
// ReaderAt returns an io.ReaderAt for the blob.
func (s *store) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	p, err := s.blobPath(desc.Digest)
	reader, err := OpenReader(p)
	return reader, nil
}

// OpenReader creates ReaderAt from a file
func OpenReader(p string) (content.ReaderAt, error) {
	fi, err := os.Stat(p)
	fp, err := os.Open(p)
	return sizeReaderAt{size: fi.Size(), fp: fp}, nil
}
```

## 3. Content Store
Metadata DB里最重要的成员之一是Content Store，它基于local store，充当Metadata DB读写的接口

### 3.1 创建Content Store
```diff
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
-		// 保存local Store	
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

### 3.2 contentStores接口实现
contentStore结构实现了content.Store接口

- ***Info***
实现xbel的读取以及create/update时间戳。根据digest作为key，查找bolt数据库，返回键值对
```diff
func (cs *contentStore) Info(ctx context.Context, dgst digest.Digest) (content.Info, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	var info content.Info
	view(ctx, cs.db, func(tx *bolt.Tx) error {
		bkt := getBlobBucket(tx, ns, dgst)
		info.Digest = dgst
		return readInfo(&info, bkt)
	})
	return info, nil
}

func readInfo(info *content.Info, bkt *bolt.Bucket) error {
	boltutil.ReadTimestamps(bkt, &info.CreatedAt, &info.UpdatedAt)
	labels, err := boltutil.ReadLabels(bkt)
	info.Labels = labels
	if v := bkt.Get(bucketKeySize); len(v) > 0 {
		info.Size, _ = binary.Varint(v)
	}
	return nil
}
```

- ***Update***
Update实现Info的修改，如label，同时更新时间戳
```
func (cs *contentStore) Update(ctx context.Context, info content.Info, fieldpaths ...string) (content.Info, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
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
		readInfo(&updated, bkt)

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
		updated.UpdatedAt = time.Now().UTC()
		return writeInfo(&updated, bkt)
	}); err != nil {
		return content.Info{}, err
	}
	return updated, nil
}

func writeInfo(info *content.Info, bkt *bolt.Bucket) error {
	boltutil.WriteTimestamps(bkt, info.CreatedAt, info.UpdatedAt)
	boltutil.WriteLabels(bkt, info.Labels)
	// Write size
	sizeEncoded, err := encodeInt(info.Size)
	return bkt.Put(bucketKeySize, sizeEncoded)
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

- ***Writer***
```
func (cs *contentStore) Writer(ctx context.Context, opts ...content.WriterOpt) (content.Writer, error) {
	var wOpts content.WriterOpts
	for _, opt := range opts {
		err := opt(&wOpts)
	}
	ns, err := namespaces.NamespaceRequired(ctx)
	cs.l.RLock()
	defer cs.l.RUnlock()

	var (
		w      content.Writer
		exists bool
		bref   string
	)
	if err := update(ctx, cs.db, func(tx *bolt.Tx) error {
		var shared bool
		if wOpts.Desc.Digest != "" {
			cbkt := getBlobBucket(tx, ns, wOpts.Desc.Digest)
			if cbkt != nil {
				// Add content to lease to prevent other reference removals
				// from effecting this object during a provided lease
				addContentLease(ctx, tx, wOpts.Desc.Digest)
				// Return error outside of transaction to ensure
				// commit succeeds with the lease.
				exists = true
				return nil
			}

			if cs.shared {
				if st, err := cs.Store.Info(ctx, wOpts.Desc.Digest); err == nil {
					// Ensure the expected size is the same, it is likely
					// an error if the size is mismatched but the caller
					// must resolve this on commit
					if wOpts.Desc.Size == 0 || wOpts.Desc.Size == st.Size {
						shared = true
						wOpts.Desc.Size = st.Size
					}
				}
			}
		}

		bkt, err := createIngestBucket(tx, ns, wOpts.Ref)
		leased, err := addIngestLease(ctx, tx, wOpts.Ref)
		brefb := bkt.Get(bucketKeyRef)
		if brefb == nil {
			sid, err := bkt.NextSequence()
			bref = createKey(sid, ns, wOpts.Ref)
			bkt.Put(bucketKeyRef, []byte(bref))
		} else {
			bref = string(brefb)
		}
		if !leased {
			// Add timestamp to allow aborting once stale
			// When lease is set the ingest should be aborted
			// after lease it belonged to is deleted.
			// Expiration can be configurable in the future to
			// give more control to the daemon, however leases
			// already give users more control of expiration.
			expireAt := time.Now().UTC().Add(24 * time.Hour)
			writeExpireAt(expireAt, bkt)
		}

		if shared {
			bkt.Put(bucketKeyExpected, []byte(wOpts.Desc.Digest))
		} else {
			// Do not use the passed in expected value here since it was
			// already checked against the user metadata. The content must
			// be committed in the namespace before it will be seen as
			// available in the current namespace.
			desc := wOpts.Desc
			desc.Digest = ""
			w, err = cs.Store.Writer(ctx, content.WithRef(bref), content.WithDescriptor(desc))
		}
		return err
	}); err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.Wrapf(errdefs.ErrAlreadyExists, "content %v", wOpts.Desc.Digest)
	}

	return &namespacedWriter{
		ctx:       ctx,
		ref:       wOpts.Ref,
		namespace: ns,
		db:        cs.db,
		provider:  cs.Store,
		l:         &cs.l,
		w:         w,
		bref:      bref,
		started:   time.Now(),
		desc:      wOpts.Desc,
	}, nil
}

type namespacedWriter struct {
	ctx       context.Context
	ref       string
	namespace string
	db        transactor
	provider  interface {
		content.Provider
		content.Ingester
	}
	l *sync.RWMutex

	w content.Writer

	bref    string
	started time.Time
	desc    ocispec.Descriptor
}

func (nw *namespacedWriter) Write(p []byte) (int, error) {
	return nw.w.Write(p)
}

func (nw *namespacedWriter) Digest() digest.Digest {
	if nw.w != nil {
		return nw.w.Digest()
	}
	return nw.desc.Digest
}

func (nw *namespacedWriter) Truncate(size int64) error {
	if nw.w != nil {
		return nw.w.Truncate(size)
	}
	desc := nw.desc
	desc.Size = size
	desc.Digest = ""
	return nw.createAndCopy(nw.ctx, desc)
}

func (nw *namespacedWriter) createAndCopy(ctx context.Context, desc ocispec.Descriptor) error {
	nwDescWithoutDigest := desc
	nwDescWithoutDigest.Digest = ""
	w, err := nw.provider.Writer(ctx, content.WithRef(nw.bref), content.WithDescriptor(nwDescWithoutDigest))
	if desc.Size > 0 {
		ra, err := nw.provider.ReaderAt(ctx, nw.desc)
		defer ra.Close()
		if err := content.CopyReaderAt(w, ra, desc.Size); err != nil {
			nw.w.Close()
			nw.w = nil
			return err
		}
	}
	nw.w = w
	return nil
}

func (nw *namespacedWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	ctx = namespaces.WithNamespace(ctx, nw.namespace)

	nw.l.RLock()
	defer nw.l.RUnlock()

	var innerErr error

	update(ctx, nw.db, func(tx *bolt.Tx) error {
		dgst, err := nw.commit(ctx, tx, size, expected, opts...)
		bkt := getIngestsBucket(tx, nw.namespace)
		if bkt != nil {
			bkt.DeleteBucket([]byte(nw.ref))
		}
		removeIngestLease(ctx, tx, nw.ref)
		return addContentLease(ctx, tx, dgst)
	})

	return innerErr
}

func (nw *namespacedWriter) commit(ctx context.Context, tx *bolt.Tx, size int64, expected digest.Digest, opts ...content.Opt) (digest.Digest, error) {
	var base content.Info
	for _, opt := range opts {
		opt(&base)
	}
	var actual digest.Digest
	if nw.w == nil {
		size = nw.desc.Size
		actual = nw.desc.Digest
	} else {
		status, err := nw.w.Status()
		size = status.Offset
		nw.w.Commit(ctx, size, expected)
		actual = nw.w.Digest()
	}

	bkt, err := createBlobBucket(tx, nw.namespace, actual)
	commitTime := time.Now().UTC()

	sizeEncoded, err := encodeInt(size)
	boltutil.WriteTimestamps(bkt, commitTime, commitTime)
	boltutil.WriteLabels(bkt, base.Labels)
	return actual, bkt.Put(bucketKeySize, sizeEncoded)
}

func (nw *namespacedWriter) Status() (st content.Status, err error) {
	if nw.w != nil {
		st, err = nw.w.Status()
	} else {
		st.Offset = nw.desc.Size
		st.Total = nw.desc.Size
		st.StartedAt = nw.started
		st.UpdatedAt = nw.started
		st.Expected = nw.desc.Digest
	}
	if err == nil {
		st.Ref = nw.ref
	}
	return
}
```

- ***ReaderAt***
```diff
func (cs *contentStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	cs.checkAccess(ctx, desc.Digest)
-	// 直接调用local Store的实现
	return cs.Store.ReaderAt(ctx, desc)
}
```
