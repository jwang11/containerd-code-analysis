# Images服务
> Image服务提供镜像的list，create，update，delete等操作，但不负责pull和push。<br>
> image的信息记录在metedata的bolt库里。

## 1. 外部服务
### 1.1 Plugin注册
[services/images/service.go](https://github.com/containerd/containerd/blob/main/services/images/service.go)
```diff
func init() {
	plugin.Register(&plugin.Registration{
+		Type: plugin.GRPCPlugin,
+		ID:   "images",
		Requires: []plugin.Type{
			plugin.ServicePlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			plugins, err := ic.GetByType(plugin.ServicePlugin)
			p, ok := plugins[services.ImagesService]
			i, err := p.Instance()

+			return &service{local: i.(imagesapi.ImagesClient)}, nil
		},
	})
}
```
### 1.2 接口实现
```diff
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

## 2. 内部服务
### 2.1 Plugin注册
- 依赖两个底层服务MetadataPlugin和GCPlugin
```diff
func init() {
	plugin.Register(&plugin.Registration{
+		Type: plugin.ServicePlugin,
+		ID:   services.ImagesService,
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

+			return &local{
+				store:     metadata.NewImageStore(m.(*metadata.DB)),
+				publisher: ic.Events,
				gc:        g.(gcScheduler),
			}, nil
		},
	})
}
```

### 2.2 接口实现
```diff
type local struct {
	store     images.Store
	gc        gcScheduler
	publisher events.Publisher
}

var _ imagesapi.ImagesClient = &local{}

func (l *local) Get(ctx context.Context, req *imagesapi.GetImageRequest, _ ...grpc.CallOption) (*imagesapi.GetImageResponse, error) {
+	image, err := l.store.Get(ctx, req.Name)
	imagepb := imageToProto(&image)
	return &imagesapi.GetImageResponse{
		Image: &imagepb,
	}, nil
}

func (l *local) List(ctx context.Context, req *imagesapi.ListImagesRequest, _ ...grpc.CallOption) (*imagesapi.ListImagesResponse, error) {
+	images, err := l.store.List(ctx, req.Filters...)
	return &imagesapi.ListImagesResponse{
		Images: imagesToProto(images),
	}, nil
}

func (l *local) Create(ctx context.Context, req *imagesapi.CreateImageRequest, _ ...grpc.CallOption) (*imagesapi.CreateImageResponse, error) {
	log.G(ctx).WithField("name", req.Image.Name).WithField("target", req.Image.Target.Digest).Debugf("create image")

	var (
		image = imageFromProto(&req.Image)
		resp  imagesapi.CreateImageResponse
	)
+	created, err := l.store.Create(ctx, image)
	resp.Image = imageToProto(&created)
	if err := l.publisher.Publish(ctx, "/images/create", &eventstypes.ImageCreate{
		Name:   resp.Image.Name,
		Labels: resp.Image.Labels,
	})
	return &resp, nil
}

func (l *local) Update(ctx context.Context, req *imagesapi.UpdateImageRequest, _ ...grpc.CallOption) (*imagesapi.UpdateImageResponse, error) {
	var (
		image      = imageFromProto(&req.Image)
		resp       imagesapi.UpdateImageResponse
		fieldpaths []string
	)

	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		fieldpaths = append(fieldpaths, req.UpdateMask.Paths...)
	}

	updated, err := l.store.Update(ctx, image, fieldpaths...)
	resp.Image = imageToProto(&updated)
	if err := l.publisher.Publish(ctx, "/images/update", &eventstypes.ImageUpdate{
		Name:   resp.Image.Name,
		Labels: resp.Image.Labels,
	});

	return &resp, nil
}

func (l *local) Delete(ctx context.Context, req *imagesapi.DeleteImageRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
	log.G(ctx).WithField("name", req.Name).Debugf("delete image")

+	if err := l.store.Delete(ctx, req.Name); err != nil {}

	if err := l.publisher.Publish(ctx, "/images/delete", &eventstypes.ImageDelete{
		Name: req.Name,
	})

	if req.Sync {
		if _, err := l.gc.ScheduleAndWait(ctx); err != nil {}
	}

	return &ptypes.Empty{}, nil
}
```

## 3. 底层实现

### 建立imageStore
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

-	// 这个descriptor是Manifest或者manifest list
	// Target describes the root content for this image. Typically, this is
	// a manifest, index or manifest list.
	Target ocispec.Descriptor

	CreatedAt, UpdatedAt time.Time
}

- // imageStore是基于metadata.DB上封装
type imageStore struct {
	db *DB
}

// NewImageStore returns a store backed by a bolt DB
func NewImageStore(db *DB) images.Store {
	return &imageStore{db: db}
}
```

### 3.2 接口实现
```diff
- bolt数据库里的image
//  └──v1                                        - Schema version bucket
//     ╘══*namespace*
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
```
- ***Get***
```
func (s *imageStore) Get(ctx context.Context, name string) (images.Image, error) {
	var image images.Image

	namespace, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return images.Image{}, err
	}

	if err := view(ctx, s.db, func(tx *bolt.Tx) error {
		bkt := getImagesBucket(tx, namespace)
		if bkt == nil || bkt.Bucket([]byte(name)) == nil {
			nsbkt := getNamespacesBucket(tx)
			cur := nsbkt.Cursor()
			for k, _ := cur.First(); k != nil; k, _ = cur.Next() {
				// If this namespace has the sharedlabel
				if hasSharedLabel(tx, string(k)) {
					// and has the image we are looking for
					bkt = getImagesBucket(tx, string(k))
					ibkt := bkt.Bucket([]byte(name))
					// we are done
					break
				}

			}
		}

		ibkt := bkt.Bucket([]byte(name))
		image.Name = name
+		if err := readImage(&image, ibkt); err != nil {}
		return nil
	})
	return image, nil
}
```
> Get -> readImage
```
func readImage(image *images.Image, bkt *bolt.Bucket) error {
	if err := boltutil.ReadTimestamps(bkt, &image.CreatedAt, &image.UpdatedAt); err != nil {}

	labels, err := boltutil.ReadLabels(bkt)
	image.Labels = labels
	image.Target.Annotations, err = boltutil.ReadAnnotations(bkt)
	tbkt := bkt.Bucket(bucketKeyTarget)

	return tbkt.ForEach(func(k, v []byte) error {
		// TODO(stevvooe): This is why we need to use byte values for
		// keys, rather than full arrays.
		switch string(k) {
		case string(bucketKeyDigest):
			image.Target.Digest = digest.Digest(v)
		case string(bucketKeyMediaType):
			image.Target.MediaType = string(v)
		case string(bucketKeySize):
			image.Target.Size, _ = binary.Varint(v)
		}

		return nil
	})
}
```

- ***List***
```
func (s *imageStore) List(ctx context.Context, fs ...string) ([]images.Image, error) {
	namespace, err := namespaces.NamespaceRequired(ctx)
	filter, err := filters.ParseAll(fs...)

	var m []images.Image
	if err := view(ctx, s.db, func(tx *bolt.Tx) error {
		bkt := getImagesBucket(tx, namespace)
		return bkt.ForEach(func(k, v []byte) error {
			var (
				image = images.Image{
					Name: string(k),
				}
				kbkt = bkt.Bucket(k)
			)

			if err := readImage(&image, kbkt); err != nil {}

			if filter.Match(adaptImage(image)) {
				m = append(m, image)
			}
			return nil
		})
	})

	return m, nil
}
```

- ***Create***
```diff
func (s *imageStore) Create(ctx context.Context, image images.Image) (images.Image, error) {
	namespace, err := namespaces.NamespaceRequired(ctx)
	if err := update(ctx, s.db, func(tx *bolt.Tx) error {

		bkt, err := createImagesBucket(tx, namespace)

		ibkt, err := bkt.CreateBucket([]byte(image.Name))

		image.CreatedAt = time.Now().UTC()
		image.UpdatedAt = image.CreatedAt
+		return writeImage(ibkt, &image)
	})

	return image, nil
}
```
> Create -> writeImage
```diff
func writeImage(bkt *bolt.Bucket, image *images.Image) error {
	if err := boltutil.WriteTimestamps(bkt, image.CreatedAt, image.UpdatedAt); err != nil {}

	if err := boltutil.WriteLabels(bkt, image.Labels); err != nil {}

	if err := boltutil.WriteAnnotations(bkt, image.Target.Annotations); err != nil {}

	// write the target bucket
	tbkt, err := bkt.CreateBucketIfNotExists(bucketKeyTarget)

	sizeEncoded, err := encodeInt(image.Target.Size)

	for _, v := range [][2][]byte{
		{bucketKeyDigest, []byte(image.Target.Digest)},
		{bucketKeyMediaType, []byte(image.Target.MediaType)},
		{bucketKeySize, sizeEncoded},
	}

	return nil
}
```

- ***Update***
```
func (s *imageStore) Update(ctx context.Context, image images.Image, fieldpaths ...string) (images.Image, error) {
	namespace, err := namespaces.NamespaceRequired(ctx)
	var updated images.Image

	if err := update(ctx, s.db, func(tx *bolt.Tx) error {
		bkt, err := createImagesBucket(tx, namespace)
		ibkt := bkt.Bucket([]byte(image.Name))
		if err := readImage(&updated, ibkt); err != nil {}
		createdat := updated.CreatedAt
		updated.Name = image.Name

		if len(fieldpaths) > 0 {
			for _, path := range fieldpaths {
				if strings.HasPrefix(path, "labels.") {
					if updated.Labels == nil {
						updated.Labels = map[string]string{}
					}

					key := strings.TrimPrefix(path, "labels.")
					updated.Labels[key] = image.Labels[key]
					continue
				} else if strings.HasPrefix(path, "annotations.") {
					if updated.Target.Annotations == nil {
						updated.Target.Annotations = map[string]string{}
					}

					key := strings.TrimPrefix(path, "annotations.")
					updated.Target.Annotations[key] = image.Target.Annotations[key]
					continue
				}

				switch path {
				case "labels":
					updated.Labels = image.Labels
				case "target":
					// NOTE(stevvooe): While we allow setting individual labels, we
					// only support replacing the target as a unit, since that is
					// commonly pulled as a unit from other sources. It often doesn't
					// make sense to modify the size or digest without touching the
					// mediatype, as well, for example.
					updated.Target = image.Target
				case "annotations":
					updated.Target.Annotations = image.Target.Annotations
				default:
					return errors.Wrapf(errdefs.ErrInvalidArgument, "cannot update %q field on image %q", path, image.Name)
				}
			}
		} else {
			updated = image
		}

		if err := validateImage(&updated); err != nil {}

		updated.CreatedAt = createdat
		updated.UpdatedAt = time.Now().UTC()
		return writeImage(ibkt, &updated)
	})
	return updated, nil

}
```

- ***Delete***
```
func (s *imageStore) Delete(ctx context.Context, name string, opts ...images.DeleteOpt) error {
	namespace, err := namespaces.NamespaceRequired(ctx)
	return update(ctx, s.db, func(tx *bolt.Tx) error {
		bkt := getImagesBucket(tx, namespace)
		if err = bkt.DeleteBucket([]byte(name)); err != nil {}
		atomic.AddUint32(&s.db.dirty, 1)
		return nil
	})
}
```
