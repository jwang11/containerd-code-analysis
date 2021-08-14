# Content服务
> Content是提供数据存储和查询的服务，主要包括index、manifests、config.json、image layer。Content主要用来进行独立执行或者测试使用，查询通常还是通过metadata。

## Content服务的初始化
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
