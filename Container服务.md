# Container服务
> container服务提供对container对象的管理，包括增删改标签（label），但不包括执行

```
NAME:
   ctr containers - manage containers

USAGE:
   ctr containers command [command options] [arguments...]

COMMANDS:
   create           create container
   delete, del, rm  delete one or more existing containers
   info             get info about a container
   list, ls         list containers
   label            set and clear labels for a container
   checkpoint       checkpoint a container
   restore          restore a container from checkpoint

OPTIONS:
   --help, -h  show help
```

### Container外部服务注册
[services/containers/service.go](https://github.com/containerd/containerd/blob/main/services/containers/service.go)
```diff
func init() {
	plugin.Register(&plugin.Registration{
+		Type: plugin.GRPCPlugin,
+		ID:   "containers",
		Requires: []plugin.Type{
			plugin.ServicePlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			plugins, err := ic.GetByType(plugin.ServicePlugin)
			if err != nil {
				return nil, err
			}
-			// 依赖内部服务services.ContainersService			
			p, ok := plugins[services.ContainersService]
			if !ok {
				return nil, errors.New("containers service not found")
			}
			i, err := p.Instance()
			if err != nil {
				return nil, err
			}
+			return &service{local: i.(api.ContainersClient)}, nil
		},
	})
}
```

### 外部服务实现
```diff
type service struct {
	local api.ContainersClient
}

var _ api.ContainersServer = &service{}

func (s *service) Register(server *grpc.Server) error {
	api.RegisterContainersServer(server, s)
	return nil
}

func (s *service) Get(ctx context.Context, req *api.GetContainerRequest) (*api.GetContainerResponse, error) {
+	return s.local.Get(ctx, req)
}

func (s *service) List(ctx context.Context, req *api.ListContainersRequest) (*api.ListContainersResponse, error) {
+	return s.local.List(ctx, req)
}

func (s *service) ListStream(req *api.ListContainersRequest, stream api.Containers_ListStreamServer) error {
+	containers, err := s.local.ListStream(stream.Context(), req)
	if err != nil {
		return err
	}
	for {
		select {
		case <-stream.Context().Done():
			return nil
		default:
			c, err := containers.Recv()
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			if err := stream.Send(c); err != nil {
				return err
			}
		}
	}
}

func (s *service) Create(ctx context.Context, req *api.CreateContainerRequest) (*api.CreateContainerResponse, error) {
+	return s.local.Create(ctx, req)
}

func (s *service) Update(ctx context.Context, req *api.UpdateContainerRequest) (*api.UpdateContainerResponse, error) {
+	return s.local.Update(ctx, req)
}

func (s *service) Delete(ctx context.Context, req *api.DeleteContainerRequest) (*ptypes.Empty, error) {
+	return s.local.Delete(ctx, req)
}
```

### Container内部服务注册
```diff
func init() {
	plugin.Register(&plugin.Registration{
+		Type: plugin.ServicePlugin,
+		ID:   services.ContainersService,
		Requires: []plugin.Type{
			plugin.EventPlugin,
			plugin.MetadataPlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
-			// 依赖底层服务MetadataPlugin
			m, err := ic.Get(plugin.MetadataPlugin)
			if err != nil {
				return nil, err
			}
			ep, err := ic.Get(plugin.EventPlugin)
			if err != nil {
				return nil, err
			}

+			db := m.(*metadata.DB)
			return &local{
-				// 在metadata的db基础上，实现container store
				Store:     metadata.NewContainerStore(db),
-				// metadata的db其实是bolt数据库加content-store				
				db:        db,
				publisher: ep.(events.Publisher),
			}, nil
		},
	})
}

type local struct {
	containers.Store
	db        *metadata.DB
	publisher events.Publisher
}
```

### Container内部服务实现
```diff
func (l *local) Get(ctx context.Context, req *api.GetContainerRequest, _ ...grpc.CallOption) (*api.GetContainerResponse, error) {
	var resp api.GetContainerResponse

	return &resp, errdefs.ToGRPC(l.withStoreView(ctx, func(ctx context.Context) error {
		container, err := l.Store.Get(ctx, req.ID)
		if err != nil {
			return err
		}
		containerpb := containerToProto(&container)
		resp.Container = containerpb

		return nil
	}))
}

func (l *local) List(ctx context.Context, req *api.ListContainersRequest, _ ...grpc.CallOption) (*api.ListContainersResponse, error) {
	var resp api.ListContainersResponse
	return &resp, errdefs.ToGRPC(l.withStoreView(ctx, func(ctx context.Context) error {
		containers, err := l.Store.List(ctx, req.Filters...)
		if err != nil {
			return err
		}
		resp.Containers = containersToProto(containers)
		return nil
	}))
}

func (l *local) ListStream(ctx context.Context, req *api.ListContainersRequest, _ ...grpc.CallOption) (api.Containers_ListStreamClient, error) {
	stream := &localStream{
		ctx: ctx,
	}
	return stream, errdefs.ToGRPC(l.withStoreView(ctx, func(ctx context.Context) error {
		containers, err := l.Store.List(ctx, req.Filters...)
		if err != nil {
			return err
		}
		stream.containers = containersToProto(containers)
		return nil
	}))
}

func (l *local) Create(ctx context.Context, req *api.CreateContainerRequest, _ ...grpc.CallOption) (*api.CreateContainerResponse, error) {
	var resp api.CreateContainerResponse

	if err := l.withStoreUpdate(ctx, func(ctx context.Context) error {
		container := containerFromProto(&req.Container)

		created, err := l.Store.Create(ctx, container)
		if err != nil {
			return err
		}

		resp.Container = containerToProto(&created)

		return nil
	}); err != nil {
		return &resp, errdefs.ToGRPC(err)
	}
	if err := l.publisher.Publish(ctx, "/containers/create", &eventstypes.ContainerCreate{
		ID:    resp.Container.ID,
		Image: resp.Container.Image,
		Runtime: &eventstypes.ContainerCreate_Runtime{
			Name:    resp.Container.Runtime.Name,
			Options: resp.Container.Runtime.Options,
		},
	}); err != nil {
		return &resp, err
	}

	return &resp, nil
}

func (l *local) Update(ctx context.Context, req *api.UpdateContainerRequest, _ ...grpc.CallOption) (*api.UpdateContainerResponse, error) {
	if req.Container.ID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Container.ID required")
	}
	var (
		resp      api.UpdateContainerResponse
		container = containerFromProto(&req.Container)
	)

	if err := l.withStoreUpdate(ctx, func(ctx context.Context) error {
		var fieldpaths []string
		if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
			fieldpaths = append(fieldpaths, req.UpdateMask.Paths...)
		}

		updated, err := l.Store.Update(ctx, container, fieldpaths...)
		if err != nil {
			return err
		}

		resp.Container = containerToProto(&updated)
		return nil
	}); err != nil {
		return &resp, errdefs.ToGRPC(err)
	}

	if err := l.publisher.Publish(ctx, "/containers/update", &eventstypes.ContainerUpdate{
		ID:          resp.Container.ID,
		Image:       resp.Container.Image,
		Labels:      resp.Container.Labels,
		SnapshotKey: resp.Container.SnapshotKey,
	}); err != nil {
		return &resp, err
	}

	return &resp, nil
}

func (l *local) Delete(ctx context.Context, req *api.DeleteContainerRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
	if err := l.withStoreUpdate(ctx, func(ctx context.Context) error {
		return l.Store.Delete(ctx, req.ID)
	}); err != nil {
		return &ptypes.Empty{}, errdefs.ToGRPC(err)
	}

	if err := l.publisher.Publish(ctx, "/containers/delete", &eventstypes.ContainerDelete{
		ID: req.ID,
	}); err != nil {
		return &ptypes.Empty{}, err
	}

	return &ptypes.Empty{}, nil
}

func (l *local) withStore(ctx context.Context, fn func(ctx context.Context) error) func(tx *bolt.Tx) error {
	return func(tx *bolt.Tx) error {
		return fn(metadata.WithTransactionContext(ctx, tx))
	}
}

func (l *local) withStoreView(ctx context.Context, fn func(ctx context.Context) error) error {
	return l.db.View(l.withStore(ctx, fn))
}

func (l *local) withStoreUpdate(ctx context.Context, fn func(ctx context.Context) error) error {
	return l.db.Update(l.withStore(ctx, fn))
}


```

### Container底层服务
- metadta.NewContainerStore
```diff
// NewContainerStore returns a Store backed by an underlying bolt DB
func NewContainerStore(db *DB) containers.Store {
	return &containerStore{
-		// 这个db是metadata.DB，实现了transaction接口，可以直接bolt操作。	
		db: db,
	}
}
func (s *containerStore) Get(ctx context.Context, id string) (containers.Container, error) {
	namespace, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return containers.Container{}, err
	}

	container := containers.Container{ID: id}

	if err := view(ctx, s.db, func(tx *bolt.Tx) error {
		bkt := getContainerBucket(tx, namespace, id)
		if bkt == nil {
			return errors.Wrapf(errdefs.ErrNotFound, "container %q in namespace %q", id, namespace)
		}

		if err := readContainer(&container, bkt); err != nil {
			return errors.Wrapf(err, "failed to read container %q", id)
		}

		return nil
	}); err != nil {
		return containers.Container{}, err
	}

	return container, nil
}

func (s *containerStore) List(ctx context.Context, fs ...string) ([]containers.Container, error) {
	namespace, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}

	filter, err := filters.ParseAll(fs...)
	if err != nil {
		return nil, errors.Wrap(errdefs.ErrInvalidArgument, err.Error())
	}

	var m []containers.Container

	if err := view(ctx, s.db, func(tx *bolt.Tx) error {
		bkt := getContainersBucket(tx, namespace)
		if bkt == nil {
			return nil // empty store
		}

		return bkt.ForEach(func(k, v []byte) error {
			cbkt := bkt.Bucket(k)
			if cbkt == nil {
				return nil
			}
			container := containers.Container{ID: string(k)}

			if err := readContainer(&container, cbkt); err != nil {
				return errors.Wrapf(err, "failed to read container %q", string(k))
			}

			if filter.Match(adaptContainer(container)) {
				m = append(m, container)
			}
			return nil
		})
	}); err != nil {
		return nil, err
	}

	return m, nil
}

func (s *containerStore) Create(ctx context.Context, container containers.Container) (containers.Container, error) {
	namespace, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return containers.Container{}, err
	}

	if err := validateContainer(&container); err != nil {
		return containers.Container{}, errors.Wrap(err, "create container failed validation")
	}

	if err := update(ctx, s.db, func(tx *bolt.Tx) error {
		bkt, err := createContainersBucket(tx, namespace)
		if err != nil {
			return err
		}

		cbkt, err := bkt.CreateBucket([]byte(container.ID))
		if err != nil {
			if err == bolt.ErrBucketExists {
				err = errors.Wrapf(errdefs.ErrAlreadyExists, "container %q", container.ID)
			}
			return err
		}

		container.CreatedAt = time.Now().UTC()
		container.UpdatedAt = container.CreatedAt
		if err := writeContainer(cbkt, &container); err != nil {
			return errors.Wrapf(err, "failed to write container %q", container.ID)
		}

		return nil
	}); err != nil {
		return containers.Container{}, err
	}

	return container, nil
}

func (s *containerStore) Update(ctx context.Context, container containers.Container, fieldpaths ...string) (containers.Container, error) {
	namespace, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return containers.Container{}, err
	}

	if container.ID == "" {
		return containers.Container{}, errors.Wrapf(errdefs.ErrInvalidArgument, "must specify a container id")
	}

	var updated containers.Container
	if err := update(ctx, s.db, func(tx *bolt.Tx) error {
		bkt := getContainersBucket(tx, namespace)
		if bkt == nil {
			return errors.Wrapf(errdefs.ErrNotFound, "cannot update container %q in namespace %q", container.ID, namespace)
		}

		cbkt := bkt.Bucket([]byte(container.ID))
		if cbkt == nil {
			return errors.Wrapf(errdefs.ErrNotFound, "container %q", container.ID)
		}

		if err := readContainer(&updated, cbkt); err != nil {
			return errors.Wrapf(err, "failed to read container %q", container.ID)
		}
		createdat := updated.CreatedAt
		updated.ID = container.ID

		if len(fieldpaths) == 0 {
			// only allow updates to these field on full replace.
			fieldpaths = []string{"labels", "spec", "extensions", "image", "snapshotkey"}

			// Fields that are immutable must cause an error when no field paths
			// are provided. This allows these fields to become mutable in the
			// future.
			if updated.Snapshotter != container.Snapshotter {
				return errors.Wrapf(errdefs.ErrInvalidArgument, "container.Snapshotter field is immutable")
			}

			if updated.Runtime.Name != container.Runtime.Name {
				return errors.Wrapf(errdefs.ErrInvalidArgument, "container.Runtime.Name field is immutable")
			}
		}

		// apply the field mask. If you update this code, you better follow the
		// field mask rules in field_mask.proto. If you don't know what this
		// is, do not update this code.
		for _, path := range fieldpaths {
			if strings.HasPrefix(path, "labels.") {
				if updated.Labels == nil {
					updated.Labels = map[string]string{}
				}
				key := strings.TrimPrefix(path, "labels.")
				updated.Labels[key] = container.Labels[key]
				continue
			}

			if strings.HasPrefix(path, "extensions.") {
				if updated.Extensions == nil {
					updated.Extensions = map[string]types.Any{}
				}
				key := strings.TrimPrefix(path, "extensions.")
				updated.Extensions[key] = container.Extensions[key]
				continue
			}

			switch path {
			case "labels":
				updated.Labels = container.Labels
			case "spec":
				updated.Spec = container.Spec
			case "extensions":
				updated.Extensions = container.Extensions
			case "image":
				updated.Image = container.Image
			case "snapshotkey":
				updated.SnapshotKey = container.SnapshotKey
			default:
				return errors.Wrapf(errdefs.ErrInvalidArgument, "cannot update %q field on %q", path, container.ID)
			}
		}

		if err := validateContainer(&updated); err != nil {
			return errors.Wrap(err, "update failed validation")
		}

		updated.CreatedAt = createdat
		updated.UpdatedAt = time.Now().UTC()
		if err := writeContainer(cbkt, &updated); err != nil {
			return errors.Wrapf(err, "failed to write container %q", container.ID)
		}

		return nil
	}); err != nil {
		return containers.Container{}, err
	}

	return updated, nil
}

func (s *containerStore) Delete(ctx context.Context, id string) error {
	namespace, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return err
	}

	return update(ctx, s.db, func(tx *bolt.Tx) error {
		bkt := getContainersBucket(tx, namespace)
		if bkt == nil {
			return errors.Wrapf(errdefs.ErrNotFound, "cannot delete container %q in namespace %q", id, namespace)
		}

		if err := bkt.DeleteBucket([]byte(id)); err != nil {
			if err == bolt.ErrBucketNotFound {
				err = errors.Wrapf(errdefs.ErrNotFound, "container %v", id)
			}
			return err
		}

		atomic.AddUint32(&s.db.dirty, 1)

		return nil
	})
}

```
