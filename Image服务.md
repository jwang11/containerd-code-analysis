# Images服务
> Image服务提供镜像的pull，push等操作

### 外部服务GPRCPlugin的注册
[services/images/service.go](https://github.com/containerd/containerd/blob/main/services/images/service.go)
```
func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.GRPCPlugin,
		ID:   "images",
		Requires: []plugin.Type{
			plugin.ServicePlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			plugins, err := ic.GetByType(plugin.ServicePlugin)
			if err != nil {
				return nil, err
			}
			p, ok := plugins[services.ImagesService]
			if !ok {
				return nil, errors.New("images service not found")
			}
			i, err := p.Instance()
			if err != nil {
				return nil, err
			}
			return &service{local: i.(imagesapi.ImagesClient)}, nil
		},
	})
}
```

### 内部服务ServicePlugin的注册
- 依赖两个底层服务MetadataPlugin和GCPlugin
```
func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.ServicePlugin,
		ID:   services.ImagesService,
		Requires: []plugin.Type{
			plugin.MetadataPlugin,
			plugin.GCPlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			m, err := ic.Get(plugin.MetadataPlugin)
			if err != nil {
				return nil, err
			}
			g, err := ic.Get(plugin.GCPlugin)
			if err != nil {
				return nil, err
			}

			return &local{
				store:     metadata.NewImageStore(m.(*metadata.DB)),
				publisher: ic.Events,
				gc:        g.(gcScheduler),
			}, nil
		},
	})
}
```

### 底层实现
```
// Image provides the model for how containerd views container images.
type Image struct {
	// Name of the image.
	//
	// To be pulled, it must be a reference compatible with resolvers.
	//
	// This field is required.
	Name string

	// Labels provide runtime decoration for the image record.
	//
	// There is no default behavior for how these labels are propagated. They
	// only decorate the static metadata object.
	//
	// This field is optional.
	Labels map[string]string

	// Target describes the root content for this image. Typically, this is
	// a manifest, index or manifest list.
	Target ocispec.Descriptor

	CreatedAt, UpdatedAt time.Time
}
```
### 外部接口的实现
```
type service struct {
	local imagesapi.ImagesClient
}

var _ imagesapi.ImagesServer = &service{}

func (s *service) Register(server *grpc.Server) error {
	imagesapi.RegisterImagesServer(server, s)
	return nil
}

func (s *service) Get(ctx context.Context, req *imagesapi.GetImageRequest) (*imagesapi.GetImageResponse, error) {
	return s.local.Get(ctx, req)
}

func (s *service) List(ctx context.Context, req *imagesapi.ListImagesRequest) (*imagesapi.ListImagesResponse, error) {
	return s.local.List(ctx, req)
}

func (s *service) Create(ctx context.Context, req *imagesapi.CreateImageRequest) (*imagesapi.CreateImageResponse, error) {
	return s.local.Create(ctx, req)
}

func (s *service) Update(ctx context.Context, req *imagesapi.UpdateImageRequest) (*imagesapi.UpdateImageResponse, error) {
	return s.local.Update(ctx, req)
}

func (s *service) Delete(ctx context.Context, req *imagesapi.DeleteImageRequest) (*ptypes.Empty, error) {
	return s.local.Delete(ctx, req)
}
```
