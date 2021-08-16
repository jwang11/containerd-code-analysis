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

### 底层服务
