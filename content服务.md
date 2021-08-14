# Content服务
> Content是提供数据存储和查询的服务，主要包括index、manifests、config.json、image layer。Content主要用来进行独立执行或者测试使用，查询通常还是通过metadata。

## Content服务的初始化
- Content是在***loadPlugins()***里被注册的，***InitFn***返回content.Store对象
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

- ***Store***实现的方法
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
