# Container服务
> container服务提供对container对象的管理，包括增删改标签（label），但不包括执行<br>
> container的信息记录在metedata的bolt库里

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

## 1. 外部服务
[services/containers/service.go](https://github.com/containerd/containerd/blob/main/services/containers/service.go)
### 1.1 Plugin注册
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
-			// 依赖内部服务services.ContainersService			
			p, ok := plugins[services.ContainersService]
			i, err := p.Instance()
+			return &service{local: i.(api.ContainersClient)}, nil
		},
	})
}
```

## 1.2 接口实现
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
	for {
		select {
		case <-stream.Context().Done():
			return nil
		default:
			c, err := containers.Recv()
			stream.Send(c)
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

## 2. 内部服务
### 2.2 Plugin注册
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
			ep, err := ic.Get(plugin.EventPlugin)

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

### 2.2 接口实现
```diff
func (l *local) Get(ctx context.Context, req *api.GetContainerRequest, _ ...grpc.CallOption) (*api.GetContainerResponse, error) {
	var resp api.GetContainerResponse

	return &resp, errdefs.ToGRPC(l.withStoreView(ctx, func(ctx context.Context) error {
		container, err := l.Store.Get(ctx, req.ID)
		containerpb := containerToProto(&container)
		resp.Container = containerpb

		return nil
	}))
}

func (l *local) List(ctx context.Context, req *api.ListContainersRequest, _ ...grpc.CallOption) (*api.ListContainersResponse, error) {
	var resp api.ListContainersResponse
	return &resp, errdefs.ToGRPC(l.withStoreView(ctx, func(ctx context.Context) error {
		containers, err := l.Store.List(ctx, req.Filters...)
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
		stream.containers = containersToProto(containers)
		return nil
	}))
}

func (l *local) Create(ctx context.Context, req *api.CreateContainerRequest, _ ...grpc.CallOption) (*api.CreateContainerResponse, error) {
	var resp api.CreateContainerResponse

	if err := l.withStoreUpdate(ctx, func(ctx context.Context) error {
		container := containerFromProto(&req.Container)
		created, err := l.Store.Create(ctx, container)
		resp.Container = containerToProto(&created)

		return nil
	})
	
	if err := l.publisher.Publish(ctx, "/containers/create", &eventstypes.ContainerCreate{
		ID:    resp.Container.ID,
		Image: resp.Container.Image,
		Runtime: &eventstypes.ContainerCreate_Runtime{
			Name:    resp.Container.Runtime.Name,
			Options: resp.Container.Runtime.Options,
		},
	})

	return &resp, nil
}

func (l *local) Update(ctx context.Context, req *api.UpdateContainerRequest, _ ...grpc.CallOption) (*api.UpdateContainerResponse, error) {
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
		resp.Container = containerToProto(&updated)
		return nil
	})

	if err := l.publisher.Publish(ctx, "/containers/update", &eventstypes.ContainerUpdate{
		ID:          resp.Container.ID,
		Image:       resp.Container.Image,
		Labels:      resp.Container.Labels,
		SnapshotKey: resp.Container.SnapshotKey,
	})

	return &resp, nil
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

##  3. 底层服务

### 3.1 建立ContainerStore
```diff
// NewContainerStore returns a Store backed by an underlying bolt DB
func NewContainerStore(db *DB) containers.Store {
	return &containerStore{
-		// 这个db是metadata.DB，实现了transaction接口，可以直接bolt操作。	
		db: db,
	}
}
```

### 3.2 接口实现
```diff
-  bolt数据库里的Container
//  └──v1                                        - Schema version bucket
//     ╘══*namespace*
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
```
- ***Get***
```diff
func (s *containerStore) Get(ctx context.Context, id string) (containers.Container, error) {
	namespace, err := namespaces.NamespaceRequired(ctx)
	container := containers.Container{ID: id}

	if err := view(ctx, s.db, func(tx *bolt.Tx) error {
		bkt := getContainerBucket(tx, namespace, id)
		readContainer(&container, bkt)
		return nil
	})
	return container, nil
}
```

- ***List***
```diff
func (s *containerStore) List(ctx context.Context, fs ...string) ([]containers.Container, error) {
	namespace, err := namespaces.NamespaceRequired(ctx)
	filter, err := filters.ParseAll(fs...)
	var m []containers.Container

	if err := view(ctx, s.db, func(tx *bolt.Tx) error {
		bkt := getContainersBucket(tx, namespace)

		return bkt.ForEach(func(k, v []byte) error {
			cbkt := bkt.Bucket(k)
			container := containers.Container{ID: string(k)}
+			readContainer(&container, cbkt)
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
```

- ***Create***
```diff
func (s *containerStore) Create(ctx context.Context, container containers.Container) (containers.Container, error) {
	namespace, err := namespaces.NamespaceRequired(ctx)
	if err := validateContainer(&container); err != nil {}
	if err := update(ctx, s.db, func(tx *bolt.Tx) error {
		bkt, err := createContainersBucket(tx, namespace)
		cbkt, err := bkt.CreateBucket([]byte(container.ID))

		container.CreatedAt = time.Now().UTC()
		container.UpdatedAt = container.CreatedAt
+		writeContainer(cbkt, &container)

		return nil
	})

	return container, nil
}
```
- ***Update***
```diff
func (s *containerStore) Update(ctx context.Context, container containers.Container, fieldpaths ...string) (containers.Container, error) {
	namespace, err := namespaces.NamespaceRequired(ctx)

	var updated containers.Container
	if err := update(ctx, s.db, func(tx *bolt.Tx) error {
		bkt := getContainersBucket(tx, namespace)
		cbkt := bkt.Bucket([]byte(container.ID))

+		readContainer(&updated, cbkt)
		createdat := updated.CreatedAt
		updated.ID = container.ID

		if len(fieldpaths) == 0 {
			// only allow updates to these field on full replace.
			fieldpaths = []string{"labels", "spec", "extensions", "image", "snapshotkey"}

			// Fields that are immutable must cause an error when no field paths
			// are provided. This allows these fields to become mutable in the
			// future.
			if updated.Snapshotter != container.Snapshotter {}

			if updated.Runtime.Name != container.Runtime.Name {}
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

		if err := validateContainer(&updated); err != nil {}

		updated.CreatedAt = createdat
		updated.UpdatedAt = time.Now().UTC()
+		if err := writeContainer(cbkt, &updated); err != nil {}
		return nil
	})
	return updated, nil
}
```

