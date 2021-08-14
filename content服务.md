# Content服务
> Content是提供数据存储和查询的服务，主要包括index、manifests、config.json、image layer。Content主要用来进行独立执行或者测试使用，查询通常还是通过metadata。

## Content服务的初始化
- Content是在***loadPlugins***里被注册的，***InitFn***返回content.Store对象
```
	// load additional plugins that don't automatically register themselves
	plugin.Register(&plugin.Registration{
		Type: plugin.ContentPlugin,
		ID:   "content",
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			ic.Meta.Exports["root"] = ic.Root
			return local.NewStore(ic.Root)
		},
	})
```

```
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
```

- ***Store***存放的内容都是有摘要的，可以校验内容完整性
```
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

### ***Store***接口实现
- Store定义了4类接口
```
// Store combines the methods of content-oriented interfaces into a set that
// are commonly provided by complete implementations.
type Store interface {
	Manager
	Provider
	IngestManager
	Ingester
}
```


- Manager 提供了基础内容管理方法如内容元信息获取、更新、列表查找、删除
```
// Manager provides methods for inspecting, listing and removing content.
type Manager interface {
	// Info will return metadata about content available in the content store.
	//
	// If the content is not present, ErrNotFound will be returned.
	Info(ctx context.Context, dgst digest.Digest) (Info, error)

	// Update updates mutable information related to content.
	// If one or more fieldpaths are provided, only those
	// fields will be updated.
	// Mutable fields:
	//  labels.*
	Update(ctx context.Context, info Info, fieldpaths ...string) (Info, error)

	// Walk will call fn for each item in the content store which
	// match the provided filters. If no filters are given all
	// items will be walked.
	Walk(ctx context.Context, fn WalkFunc, filters ...string) error

	// Delete removes the content from the store.
	Delete(ctx context.Context, dgst digest.Digest) error
}
```
- Provider 提供了 content 的读取接口，返回一个内容读取器对象 ReaderAt
```
// Provider provides a reader interface for specific content
type Provider interface {
	// ReaderAt only requires desc.Digest to be set.
	// Other fields in the descriptor may be used internally for resolving
	// the location of the actual data.
	ReaderAt(ctx context.Context, desc ocispec.Descriptor) (ReaderAt, error)
}
```
- IngestManager 写管理接口(存写状态获取、中止操作)
```
// IngestManager provides methods for managing ingests.
type IngestManager interface {
	// Status returns the status of the provided ref.
	Status(ctx context.Context, ref string) (Status, error)

	// ListStatuses returns the status of any active ingestions whose ref match the
	// provided regular expression. If empty, all active ingestions will be
	// returned.
	ListStatuses(ctx context.Context, filters ...string) ([]Status, error)

	// Abort completely cancels the ingest operation targeted by ref.
	Abort(ctx context.Context, ref string) error
}
```
- Ingester 提供了 content 的存写接口，返回一个内容写入器对象 Writer
```
// Writer handles the write of content into a content store
type Writer interface {
	// Close closes the writer, if the writer has not been
	// committed this allows resuming or aborting.
	// Calling Close on a closed writer will not error.
	io.WriteCloser

	// Digest may return empty digest or panics until committed.
	Digest() digest.Digest

	// Commit commits the blob (but no roll-back is guaranteed on an error).
	// size and expected can be zero-value when unknown.
	// Commit always closes the writer, even on error.
	// ErrAlreadyExists aborts the writer.
	Commit(ctx context.Context, size int64, expected digest.Digest, opts ...Opt) error

	// Status returns the current state of write
	Status() (Status, error)

	// Truncate updates the size of the target blob
	Truncate(size int64) error
}
```

- Store的接口实现
```
// ReaderAt returns an io.ReaderAt for the blob.
func (s *store) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	p, err := s.blobPath(desc.Digest)
	if err != nil {
		return nil, errors.Wrapf(err, "calculating blob path for ReaderAt")
	}

	reader, err := OpenReader(p)
	if err != nil {
		return nil, errors.Wrapf(err, "blob %s expected at %s", desc.Digest, p)
	}

	return reader, nil
}
```

- 
