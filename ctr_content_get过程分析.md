# ctr_content_get过程分析
> 针对命令行$ctr content get DIGEST的执行过程，进行代码分析。DIGEST对象可以是manifest, config，layer blob

### 命令行执行
```diff
- 先用ctr content fetch拉取nginx镜像
$ctr content fetch docker.io/library/nginx:latest
docker.io/library/nginx:latest:                                                   resolved       |++++++++++++++++++++++++++++++++++++++|
index-sha256:47ae43cdfc7064d28800bc42e79a429540c7c80168e8c8952778c0d5af1c09db:    done           |++++++++++++++++++++++++++++++++++++++|
manifest-sha256:2f1cd90e00fe2c991e18272bb35d6a8258eeb27785d121aa4cc1ae4235167cfd: done           |++++++++++++++++++++++++++++++++++++++|
layer-sha256:edb81c9bc1f5416a41e5bea21748dc912772fedbd4bd90e5e3ebfe16b453edce:    done           |++++++++++++++++++++++++++++++++++++++|
layer-sha256:b21fed559b9f420d83f8e38ca08d1ac4f15298a3ae02c6de56f364bee2299f78:    done           |++++++++++++++++++++++++++++++++++++++|
layer-sha256:03e6a245275128e26fc650e724e3fc4510d81f8111bae35ece70242b0a638215:    done           |++++++++++++++++++++++++++++++++++++++|
config-sha256:4f380adfc10f4cd34f775ae57a17d2835385efd5251d6dfe0f246b0018fb0399:   done           |++++++++++++++++++++++++++++++++++++++|
layer-sha256:5430e98eba646ef4a34baff035f6f7483761c873711febd48fbcca38d7890c1e:    done           |++++++++++++++++++++++++++++++++++++++|
layer-sha256:b82f7f888feb03d38fed4dad68d7265a8b276f1f0c543d549fc6ef30b42c00eb:    done           |++++++++++++++++++++++++++++++++++++++|
layer-sha256:b4d181a07f8025e00e0cb28f1cc14613da2ce26450b80c54aea537fa93cf3bda:    exists         |++++++++++++++++++++++++++++++++++++++|
elapsed: 7.7 s                                                                    total:  25.4 M (3.3 MiB/s)

根据上面output的DIGEST信息，
- 获取index内容
$ ctr content get sha256:47ae43cdfc7064d28800bc42e79a429540c7c80168e8c8952778c0d5af1c09db|jq
{
  "manifests": [
    {
      "digest": "sha256:2f1cd90e00fe2c991e18272bb35d6a8258eeb27785d121aa4cc1ae4235167cfd",
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "platform": {
        "architecture": "amd64",
        "os": "linux"
      },
      "size": 1570
    },
    {
      "digest": "sha256:97e6b328ee95a13a70f7ce1c2b3dca2b7308904f62f495bca018916a7fdd6b2f",
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "platform": {
        "architecture": "arm",
        "os": "linux",
        "variant": "v5"
      },
      "size": 1570
    },
    {
      "digest": "sha256:f8b719df74acd257398d3932ff7dc10baf83f8f9502c902967fe65cc902c3c2e",
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "platform": {
        "architecture": "arm",
        "os": "linux",
        "variant": "v7"
      },
      "size": 1570
    },
    {
      "digest": "sha256:7c91baa42a9371c925b909701b84ee543aa2d6e9fda4543225af2e17f531a243",
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "platform": {
        "architecture": "arm64",
        "os": "linux",
        "variant": "v8"
      },
      "size": 1570
    },
    {
      "digest": "sha256:42dd8fe2877e2d3ff756b4043094240825ef8a48608c4dc62696dc02dbb8d40d",
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "platform": {
        "architecture": "386",
        "os": "linux"
      },
      "size": 1570
    },
    {
      "digest": "sha256:ed30eb3fa0b5b5cf3c2a52fa27003c0fffef534f215b0e005ba1c010d3946a2b",
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "platform": {
        "architecture": "mips64le",
        "os": "linux"
      },
      "size": 1570
    },
    {
      "digest": "sha256:8d980a1beb6dbf8c220cd8dd12e57e14f8e88c3966d44a440dc390c059e130e8",
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "platform": {
        "architecture": "ppc64le",
        "os": "linux"
      },
      "size": 1570
    },
    {
      "digest": "sha256:f76f0a37630ab0ec24263dc1c1d12f0ff749d4bb1fb610d2ba8f1fdd63bbe6df",
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "platform": {
        "architecture": "s390x",
        "os": "linux"
      },
      "size": 1570
    }
  ],
  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
  "schemaVersion": 2
}

- 获取manifest内容
$ ctr content get sha256:2f1cd90e00fe2c991e18272bb35d6a8258eeb27785d121aa4cc1ae4235167cfd|jq
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {
    "mediaType": "application/vnd.docker.container.image.v1+json",
    "size": 7733,
    "digest": "sha256:4f380adfc10f4cd34f775ae57a17d2835385efd5251d6dfe0f246b0018fb0399"
  },
  "layers": [
    {
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "size": 27145851,
      "digest": "sha256:b4d181a07f8025e00e0cb28f1cc14613da2ce26450b80c54aea537fa93cf3bda"
    },
    {
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "size": 26580118,
      "digest": "sha256:edb81c9bc1f5416a41e5bea21748dc912772fedbd4bd90e5e3ebfe16b453edce"
    },
    {
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "size": 602,
      "digest": "sha256:b21fed559b9f420d83f8e38ca08d1ac4f15298a3ae02c6de56f364bee2299f78"
    },
    {
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "size": 895,
      "digest": "sha256:03e6a245275128e26fc650e724e3fc4510d81f8111bae35ece70242b0a638215"
    },
    {
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "size": 667,
      "digest": "sha256:b82f7f888feb03d38fed4dad68d7265a8b276f1f0c543d549fc6ef30b42c00eb"
    },
    {
      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
      "size": 1397,
      "digest": "sha256:5430e98eba646ef4a34baff035f6f7483761c873711febd48fbcca38d7890c1e"
    }
  ]
}

- 获取config内容
$ ctr content get sha256:4f380adfc10f4cd34f775ae57a17d2835385efd5251d6dfe0f246b0018fb0399|jq
{
  "architecture": "amd64",
  "config": {
    "Hostname": "",
    "Domainname": "",
    "User": "",
    "AttachStdin": false,
    "AttachStdout": false,
    "AttachStderr": false,
    "ExposedPorts": {
      "80/tcp": {}
    },
    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "NGINX_VERSION=1.21.0",
      "NJS_VERSION=0.5.3",
      "PKG_RELEASE=1~buster"
    ],
    "Cmd": [
      "nginx",
      "-g",
      "daemon off;"
    ],
    "Image": "sha256:9744b368223627a752e61f1f86e59867eecaa50fab1478b7ab8877bcf281d86a",
    "Volumes": null,
    "WorkingDir": "",
    "Entrypoint": [
      "/docker-entrypoint.sh"
    ],
    "OnBuild": null,
    "Labels": {
      "maintainer": "NGINX Docker Maintainers <docker-maint@nginx.com>"
    },
    "StopSignal": "SIGQUIT"
  },
  "container": "1c3bd13decef5a10e1d1b38f86e46ce54caa491da25fb6a89af1d5a83238069e",
  "container_config": {
    "Hostname": "1c3bd13decef",
    "Domainname": "",
    "User": "",
    "AttachStdin": false,
    "AttachStdout": false,
    "AttachStderr": false,
    "ExposedPorts": {
      "80/tcp": {}
    },
    "Tty": false,
    "OpenStdin": false,
    "StdinOnce": false,
    "Env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "NGINX_VERSION=1.21.0",
      "NJS_VERSION=0.5.3",
      "PKG_RELEASE=1~buster"
    ],
    "Cmd": [
      "/bin/sh",
      "-c",
      "#(nop) ",
      "CMD [\"nginx\" \"-g\" \"daemon off;\"]"
    ],
    "Image": "sha256:9744b368223627a752e61f1f86e59867eecaa50fab1478b7ab8877bcf281d86a",
    "Volumes": null,
    "WorkingDir": "",
    "Entrypoint": [
      "/docker-entrypoint.sh"
    ],
    "OnBuild": null,
    "Labels": {
      "maintainer": "NGINX Docker Maintainers <docker-maint@nginx.com>"
    },
    "StopSignal": "SIGQUIT"
  },
  "created": "2021-06-23T07:16:26.291103784Z",
  "docker_version": "19.03.12",
  "history": [
    {
      "created": "2021-06-23T00:20:40.386610922Z",
      "created_by": "/bin/sh -c #(nop) ADD file:4903a19c327468b0e08e4f463cfc162c66b85b4618b5803d71365862f6302e0b in / "
    },
    {
      "created": "2021-06-23T00:20:40.842961608Z",
      "created_by": "/bin/sh -c #(nop)  CMD [\"bash\"]",
      "empty_layer": true
    },
    {
      "created": "2021-06-23T07:15:51.828594217Z",
      "created_by": "/bin/sh -c #(nop)  LABEL maintainer=NGINX Docker Maintainers <docker-maint@nginx.com>",
      "empty_layer": true
    },
    {
      "created": "2021-06-23T07:15:52.021471131Z",
      "created_by": "/bin/sh -c #(nop)  ENV NGINX_VERSION=1.21.0",
      "empty_layer": true
    },
    {
      "created": "2021-06-23T07:15:52.218261311Z",
      "created_by": "/bin/sh -c #(nop)  ENV NJS_VERSION=0.5.3",
      "empty_layer": true
    },
    {
      "created": "2021-06-23T07:15:52.424497479Z",
      "created_by": "/bin/sh -c #(nop)  ENV PKG_RELEASE=1~buster",
      "empty_layer": true
    }
  ],
  "os": "linux",
  "rootfs": {
    "type": "layers",
    "diff_ids": [
      "sha256:764055ebc9a7a290b64d17cf9ea550f1099c202d83795aa967428ebdf335c9f7",
      "sha256:2418679ca01f484b28bdcd8606d1d5313013cccfbd395123716000c2a25eec09",
      "sha256:cf388fcf3527352baa4ee5bedafd223b2224b13aac5f2df1ea0be47422789892",
      "sha256:165eb6c3c0d39f8c99de581f1bf9cc094e7823a838fbe5c51574c7beb3f6c4ee",
      "sha256:b50a193ebf2e2579b49d30beb9798078e22db0d4490bf51b9b3bb0d8bb7a3833",
      "sha256:c6d74dcb7fe747fac8e74e9453156380ea3ffddf97ed0e6c71e75400d938216e"
    ]
  }
}

- 获取layer的内容
$ctr content get sha256:5430e98eba646ef4a34baff035f6f7483761c873711febd48fbcca38d7890c1e | tar zxvf -
docker-entrypoint.d/
docker-entrypoint.d/30-tune-worker-processes.sh
```

### [代码入口](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/content/content.go)
```diff
	getCommand = cli.Command{
		Name:        "get",
		Usage:       "get the data for an object",
		ArgsUsage:   "[<digest>, ...]",
		Description: "display the image object",
		Action: func(context *cli.Context) error {
			dgst, err := digest.Parse(context.Args().First())
			if err != nil {
				return err
			}
			client, ctx, cancel, err := commands.NewClient(context)
			if err != nil {
				return err
			}
			defer cancel()
+			cs := client.ContentStore()
-			// 根据digest，得到remote的ReaderAt对象
+			ra, err := cs.ReaderAt(ctx, ocispec.Descriptor{Digest: dgst})
			if err != nil {
				return err
			}
			defer ra.Close()

			// use 1MB buffer like we do for ingesting
			buf := make([]byte, 1<<20)
-			// 隐式调用ReaderAt对象里的ReadAt方法
+			_, err = io.CopyBuffer(os.Stdout, content.NewReader(ra), buf)
			return err
		},
	}
```

- *** client.ContentStore***
```diff
// ContentStore returns the underlying content Store
func (c *Client) ContentStore() content.Store {
	if c.contentStore != nil {
		return c.contentStore
	}
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return contentproxy.NewContentStore(contentapi.NewContentClient(c.conn))
}

func NewContentStore(client contentapi.ContentClient) content.Store {
	return &proxyContentStore{
		client: client,
	}
}
```
- ***cs.ReaderAt***
```diff
// ReaderAt ignores MediaType.
func (pcs *proxyContentStore) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	i, err := pcs.Info(ctx, desc.Digest)
	if err != nil {
		return nil, err
	}

	return &remoteReaderAt{
		ctx:    ctx,
		digest: desc.Digest,
-   // 通过前面Info得到content的size
+		size:   i.Size,
		client: pcs.client,
	}, nil
}

// Info holds content specific information
//
// TODO(stevvooe): Consider a very different name for this struct. Info is way
// to general. It also reads very weird in certain context, like pluralization.
type Info struct {
	Digest    digest.Digest
	Size      int64
	CreatedAt time.Time
	UpdatedAt time.Time
	Labels    map[string]string
}
```

> ***remoteReaderAt***
```diff
type remoteReaderAt struct {
	ctx    context.Context
	digest digest.Digest
	size   int64
	client contentapi.ContentClient
}

func (ra *remoteReaderAt) Size() int64 {
	return ra.size
}

func (ra *remoteReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	rr := &contentapi.ReadContentRequest{
		Digest: ra.digest,
		Offset: off,
		Size_:  int64(len(p)),
	}
	// we need a child context with cancel, or the eventually called
	// grpc.NewStream will leak the goroutine until the whole thing is cleared.
	// See comment at https://godoc.org/google.golang.org/grpc#ClientConn.NewStream
	childCtx, cancel := context.WithCancel(ra.ctx)
	// we MUST cancel the child context; see comment above
	defer cancel()
- // 调用server端的/containerd.services.content.v1.Content/Read
+	rc, err := ra.client.Read(childCtx, rr)
	if err != nil {
		return 0, err
	}

	for len(p) > 0 {
		var resp *contentapi.ReadContentResponse
		// fill our buffer up until we can fill p.
		resp, err = rc.Recv()
		if err != nil {
			return n, err
		}

		copied := copy(p, resp.Data)
		n += copied
		p = p[copied:]
	}
	return n, nil
}
```

>> ***Server端content Service.Read***
```diff
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

- ***content.NewReader(ra)***
```
// NewReader returns a io.Reader from a ReaderAt
func NewReader(ra ReaderAt) io.Reader {
	rd := io.NewSectionReader(ra, 0, ra.Size())
	return rd
}
```
