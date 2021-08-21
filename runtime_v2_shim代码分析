# Runtime_v2_shim分析
> containerd不是直接执行runc，而是通过v2_shim垫层，然后go_runc包装层，最后才是runc

### v2_shim的注册
(https://github.com/containerd/containerd/blob/main/runtime/v2/manager.go)
- RuntimePluginV2注册
```
// Config for the v2 runtime
type Config struct {
	// Supported platforms
	Platforms []string `toml:"platforms"`
}

func init() {
	plugin.Register(&plugin.Registration{
		Type: plugin.RuntimePluginV2,
		ID:   "task",
		Requires: []plugin.Type{
			plugin.EventPlugin,
			plugin.MetadataPlugin,
		},
		Config: &Config{
			Platforms: defaultPlatforms(),
		},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			supportedPlatforms, err := parsePlatforms(ic.Config.(*Config).Platforms)
			if err != nil {
				return nil, err
			}

			ic.Meta.Platforms = supportedPlatforms
			if err := os.MkdirAll(ic.Root, 0711); err != nil {
				return nil, err
			}
			if err := os.MkdirAll(ic.State, 0711); err != nil {
				return nil, err
			}
			m, err := ic.Get(plugin.MetadataPlugin)
			if err != nil {
				return nil, err
			}
			ep, err := ic.GetByID(plugin.EventPlugin, "exchange")
			if err != nil {
				return nil, err
			}
			cs := metadata.NewContainerStore(m.(*metadata.DB))
			events := ep.(*exchange.Exchange)

			return New(ic.Context, ic.Root, ic.State, ic.Address, ic.TTRPCAddress, events, cs)
		},
	})
}
```

- New返回TaskManager
```
// New task manager for v2 shims
func New(ctx context.Context, root, state, containerdAddress, containerdTTRPCAddress string, events *exchange.Exchange, cs containers.Store) (*TaskManager, error) {
	for _, d := range []string{root, state} {
		if err := os.MkdirAll(d, 0711); err != nil {
			return nil, err
		}
	}
	m := &TaskManager{
		root:                   root,
		state:                  state,
		containerdAddress:      containerdAddress,
		containerdTTRPCAddress: containerdTTRPCAddress,
		tasks:                  runtime.NewTaskList(),
		events:                 events,
		containers:             cs,
	}
	if err := m.loadExistingTasks(ctx); err != nil {
		return nil, err
	}
	return m, nil
}
```
