# Diff服务
> Diff 服务计算上层/下层 mount 目录的差异，遵从 OCI 规范 Changesets (变化集)打包 tar diff 镜像层存储。Apply 接口将ocispec.Descriptor的content放至指定的挂载目录。

### 顶层服务入口（https://github.com/containerd/containerd/blob/main/services/diff/service.go）
```diff
func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.GRPCPlugin,
		ID:   "diff",
		Requires: []plugin.Type{
			plugin.ServicePlugin,
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			plugins, err := ic.GetByType(plugin.ServicePlugin)
			if err != nil {
				return nil, err
			}
			p, ok := plugins[services.DiffService]
			if !ok {
				return nil, errors.New("diff service not found")
			}
			i, err := p.Instance()
			if err != nil {
				return nil, err
			}
			return &service{local: i.(diffapi.DiffClient)}, nil
		},
	})
}
```
