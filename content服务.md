# Content服务
> Content是提供数据存储和查询的服务，主要包括index、manifests、config.json、image layer。Content主要用来进行独立执行或者测试使用，查询通常还是通过metadata。



### ***Content.Store***接口定义
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

## Content GRPC注册与Server实现
- Content GRPC注册
```
func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.GRPCPlugin,
		ID:   "content",
		Requires: []plugin.Type{
			plugin.ServicePlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			plugins, err := ic.GetByType(plugin.ServicePlugin)
			if err != nil {
				return nil, err
			}
			p, ok := plugins[services.ContentService]
			if !ok {
				return nil, errors.New("content store service not found")
			}
			cs, err := p.Instance()
			if err != nil {
				return nil, err
			}
			return contentserver.New(cs.(content.Store)), nil
		},
	})
}
```

- Content Service的注册
[services/content/store.go](https://github.com/containerd/containerd/blob/main/services/content/store.go)
```diff
func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.ServicePlugin,
		ID:   services.ContentService,
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
+			// 直接复用metadata.DB里的ContentStore
+			s, err := newContentStore(m.(*metadata.DB).ContentStore(), ep.(events.Publisher))
			return s, err
		},
	})
}

func newContentStore(cs content.Store, publisher events.Publisher) (content.Store, error) {
	return &store{
		Store:     cs,
		publisher: publisher,
	}, nil
}

// store wraps content.Store with proper event published.
type store struct {
	content.Store
	publisher events.Publisher
}
```

- ***contentserver.New***创建content server
```
// New returns the content GRPC server
func New(cs content.Store) api.ContentServer {
	return &service{store: cs}
}

type service struct {
	store content.Store
}
```
- content server的service需要实现的interface
// ContentServer is the server API for Content service.
type ContentServer interface {
	// Info returns information about a committed object.
	//
	// This call can be used for getting the size of content and checking for
	// existence.
	Info(context.Context, *InfoRequest) (*InfoResponse, error)
	// Update updates content metadata.
	//
	// This call can be used to manage the mutable content labels. The
	// immutable metadata such as digest, size, and committed at cannot
	// be updated.
	Update(context.Context, *UpdateRequest) (*UpdateResponse, error)
	// List streams the entire set of content as Info objects and closes the
	// stream.
	//
	// Typically, this will yield a large response, chunked into messages.
	// Clients should make provisions to ensure they can handle the entire data
	// set.
	List(*ListContentRequest, Content_ListServer) error
	// Delete will delete the referenced object.
	Delete(context.Context, *DeleteContentRequest) (*types.Empty, error)
	// Read allows one to read an object based on the offset into the content.
	//
	// The requested data may be returned in one or more messages.
	Read(*ReadContentRequest, Content_ReadServer) error
	// Status returns the status for a single reference.
	Status(context.Context, *StatusRequest) (*StatusResponse, error)
	// ListStatuses returns the status of ongoing object ingestions, started via
	// Write.
	//
	// Only those matching the regular expression will be provided in the
	// response. If the provided regular expression is empty, all ingestions
	// will be provided.
	ListStatuses(context.Context, *ListStatusesRequest) (*ListStatusesResponse, error)
	// Write begins or resumes writes to a resource identified by a unique ref.
	// Only one active stream may exist at a time for each ref.
	//
	// Once a write stream has started, it may only write to a single ref, thus
	// once a stream is started, the ref may be omitted on subsequent writes.
	//
	// For any write transaction represented by a ref, only a single write may
	// be made to a given offset. If overlapping writes occur, it is an error.
	// Writes should be sequential and implementations may throw an error if
	// this is required.
	//
	// If expected_digest is set and already part of the content store, the
	// write will fail.
	//
	// When completed, the commit flag should be set to true. If expected size
	// or digest is set, the content will be validated against those values.
	Write(Content_WriteServer) error
	// Abort cancels the ongoing write named in the request. Any resources
	// associated with the write will be collected.
	Abort(context.Context, *AbortRequest) (*types.Empty, error)
}
```

### Content Service的实现
```
func (s *service) Register(server *grpc.Server) error {
	api.RegisterContentServer(server, s)
	return nil
}

func (s *service) Info(ctx context.Context, req *api.InfoRequest) (*api.InfoResponse, error) {
	if err := req.Digest.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%q failed validation", req.Digest)
	}

	bi, err := s.store.Info(ctx, req.Digest)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return &api.InfoResponse{
		Info: infoToGRPC(bi),
	}, nil
}
```
