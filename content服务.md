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
```
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
- register
```
func (s *service) Register(server *grpc.Server) error {
	api.RegisterContentServer(server, s)
	return nil
}
```
- Info
```
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
- Update
```
func (s *service) Update(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
	if err := req.Info.Digest.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%q failed validation", req.Info.Digest)
	}

	info, err := s.store.Update(ctx, infoFromGRPC(req.Info), req.UpdateMask.GetPaths()...)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return &api.UpdateResponse{
		Info: infoToGRPC(info),
	}, nil
}
```
- List
```
func (s *service) List(req *api.ListContentRequest, session api.Content_ListServer) error {
	var (
		buffer    []api.Info
		sendBlock = func(block []api.Info) error {
			// send last block
			return session.Send(&api.ListContentResponse{
				Info: block,
			})
		}
	)

	if err := s.store.Walk(session.Context(), func(info content.Info) error {
		buffer = append(buffer, api.Info{
			Digest:    info.Digest,
			Size_:     info.Size,
			CreatedAt: info.CreatedAt,
			Labels:    info.Labels,
		})

		if len(buffer) >= 100 {
			if err := sendBlock(buffer); err != nil {
				return err
			}

			buffer = buffer[:0]
		}

		return nil
	}, req.Filters...); err != nil {
		return errdefs.ToGRPC(err)
	}

	if len(buffer) > 0 {
		// send last block
		if err := sendBlock(buffer); err != nil {
			return err
		}
	}

	return nil
}
```
- Delete
```
func (s *service) Delete(ctx context.Context, req *api.DeleteContentRequest) (*ptypes.Empty, error) {
	log.G(ctx).WithField("digest", req.Digest).Debugf("delete content")
	if err := req.Digest.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	if err := s.store.Delete(ctx, req.Digest); err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return &ptypes.Empty{}, nil
}
```

- Read
```
func (s *service) Read(req *api.ReadContentRequest, session api.Content_ReadServer) error {
	if err := req.Digest.Validate(); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v: %v", req.Digest, err)
	}

	oi, err := s.store.Info(session.Context(), req.Digest)
	if err != nil {
		return errdefs.ToGRPC(err)
	}

	ra, err := s.store.ReaderAt(session.Context(), ocispec.Descriptor{Digest: req.Digest})
	if err != nil {
		return errdefs.ToGRPC(err)
	}
	defer ra.Close()

	var (
		offset = req.Offset
		// size is read size, not the expected size of the blob (oi.Size), which the caller might not be aware of.
		// offset+size can be larger than oi.Size.
		size = req.Size_

		// TODO(stevvooe): Using the global buffer pool. At 32KB, it is probably
		// little inefficient for work over a fast network. We can tune this later.
		p = bufPool.Get().(*[]byte)
	)
	defer bufPool.Put(p)

	if offset < 0 {
		offset = 0
	}

	if offset > oi.Size {
		return status.Errorf(codes.OutOfRange, "read past object length %v bytes", oi.Size)
	}

	if size <= 0 || offset+size > oi.Size {
		size = oi.Size - offset
	}

	_, err = io.CopyBuffer(
		&readResponseWriter{session: session},
		io.NewSectionReader(ra, offset, size), *p)
	return errdefs.ToGRPC(err)
}
```
- Write
```
func (s *service) Write(session api.Content_WriteServer) (err error) {
	var (
		ctx      = session.Context()
		msg      api.WriteContentResponse
		req      *api.WriteContentRequest
		ref      string
		total    int64
		expected digest.Digest
	)

	defer func(msg *api.WriteContentResponse) {
		// pump through the last message if no error was encountered
		if err != nil {
			if s, ok := status.FromError(err); ok && s.Code() != codes.AlreadyExists {
				// TODO(stevvooe): Really need a log line here to track which
				// errors are actually causing failure on the server side. May want
				// to configure the service with an interceptor to make this work
				// identically across all GRPC methods.
				//
				// This is pretty noisy, so we can remove it but leave it for now.
				log.G(ctx).WithError(err).Error("(*service).Write failed")
			}

			return
		}

		err = session.Send(msg)
	}(&msg)

	// handle the very first request!
	req, err = session.Recv()
	if err != nil {
		return err
	}

	ref = req.Ref

	if ref == "" {
		return status.Errorf(codes.InvalidArgument, "first message must have a reference")
	}

	fields := logrus.Fields{
		"ref": ref,
	}
	total = req.Total
	expected = req.Expected
	if total > 0 {
		fields["total"] = total
	}

	if expected != "" {
		fields["expected"] = expected
	}

	ctx = log.WithLogger(ctx, log.G(ctx).WithFields(fields))

	log.G(ctx).Debug("(*service).Write started")
	// this action locks the writer for the session.
	wr, err := s.store.Writer(ctx,
		content.WithRef(ref),
		content.WithDescriptor(ocispec.Descriptor{Size: total, Digest: expected}))
	if err != nil {
		return errdefs.ToGRPC(err)
	}
	defer wr.Close()

	for {
		msg.Action = req.Action
		ws, err := wr.Status()
		if err != nil {
			return errdefs.ToGRPC(err)
		}

		msg.Offset = ws.Offset // always set the offset.

		// NOTE(stevvooe): In general, there are two cases underwhich a remote
		// writer is used.
		//
		// For pull, we almost always have this before fetching large content,
		// through descriptors. We allow predeclaration of the expected size
		// and digest.
		//
		// For push, it is more complex. If we want to cut through content into
		// storage, we may have no expectation until we are done processing the
		// content. The case here is the following:
		//
		// 	1. Start writing content.
		// 	2. Compress inline.
		// 	3. Validate digest and size (maybe).
		//
		// Supporting these two paths is quite awkward but it lets both API
		// users use the same writer style for each with a minimum of overhead.
		if req.Expected != "" {
			if expected != "" && expected != req.Expected {
				log.G(ctx).Debugf("commit digest differs from writer digest: %v != %v", req.Expected, expected)
			}
			expected = req.Expected

			if _, err := s.store.Info(session.Context(), req.Expected); err == nil {
				if err := wr.Close(); err != nil {
					log.G(ctx).WithError(err).Error("failed to close writer")
				}
				if err := s.store.Abort(session.Context(), ref); err != nil {
					log.G(ctx).WithError(err).Error("failed to abort write")
				}

				return status.Errorf(codes.AlreadyExists, "blob with expected digest %v exists", req.Expected)
			}
		}

		if req.Total > 0 {
			// Update the expected total. Typically, this could be seen at
			// negotiation time or on a commit message.
			if total > 0 && req.Total != total {
				log.G(ctx).Debugf("commit size differs from writer size: %v != %v", req.Total, total)
			}
			total = req.Total
		}

		switch req.Action {
		case api.WriteActionStat:
			msg.Digest = wr.Digest()
			msg.StartedAt = ws.StartedAt
			msg.UpdatedAt = ws.UpdatedAt
			msg.Total = total
		case api.WriteActionWrite, api.WriteActionCommit:
			if req.Offset > 0 {
				// validate the offset if provided
				if req.Offset != ws.Offset {
					return status.Errorf(codes.OutOfRange, "write @%v must occur at current offset %v", req.Offset, ws.Offset)
				}
			}

			if req.Offset == 0 && ws.Offset > 0 {
				if err := wr.Truncate(req.Offset); err != nil {
					return errors.Wrapf(err, "truncate failed")
				}
				msg.Offset = req.Offset
			}

			// issue the write if we actually have data.
			if len(req.Data) > 0 {
				// While this looks like we could use io.WriterAt here, because we
				// maintain the offset as append only, we just issue the write.
				n, err := wr.Write(req.Data)
				if err != nil {
					return errdefs.ToGRPC(err)
				}

				if n != len(req.Data) {
					// TODO(stevvooe): Perhaps, we can recover this by including it
					// in the offset on the write return.
					return status.Errorf(codes.DataLoss, "wrote %v of %v bytes", n, len(req.Data))
				}

				msg.Offset += int64(n)
			}

			if req.Action == api.WriteActionCommit {
				var opts []content.Opt
				if req.Labels != nil {
					opts = append(opts, content.WithLabels(req.Labels))
				}
				if err := wr.Commit(ctx, total, expected, opts...); err != nil {
					return errdefs.ToGRPC(err)
				}
			}

			msg.Digest = wr.Digest()
		}

		if err := session.Send(&msg); err != nil {
			return err
		}

		req, err = session.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}

			return err
		}
	}
}
```
