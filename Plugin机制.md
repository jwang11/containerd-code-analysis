# Containerd里的Plugin
>containerd使用了Plugin注册机制，将task、content、snapshot、namespace、event、containers等服务以插件的方式注册然后提供服务。

## Plugin的类型，目前有12种
```
const (
	// InternalPlugin implements an internal plugin to containerd
	InternalPlugin Type = "io.containerd.internal.v1"
	// RuntimePlugin implements a runtime
	RuntimePlugin Type = "io.containerd.runtime.v1"
	// RuntimePluginV2 implements a runtime v2
	RuntimePluginV2 Type = "io.containerd.runtime.v2"
	// ServicePlugin implements a internal service
	ServicePlugin Type = "io.containerd.service.v1"
	// GRPCPlugin implements a grpc service
	GRPCPlugin Type = "io.containerd.grpc.v1"
	// SnapshotPlugin implements a snapshotter
	SnapshotPlugin Type = "io.containerd.snapshotter.v1"
	// TaskMonitorPlugin implements a task monitor
	TaskMonitorPlugin Type = "io.containerd.monitor.v1"
	// DiffPlugin implements a differ
	DiffPlugin Type = "io.containerd.differ.v1"
	// MetadataPlugin implements a metadata store
	MetadataPlugin Type = "io.containerd.metadata.v1"
	// ContentPlugin implements a content store
	ContentPlugin Type = "io.containerd.content.v1"
	// GCPlugin implements garbage collection policy
	GCPlugin Type = "io.containerd.gc.v1"
	// EventPlugin implements event handling
	EventPlugin Type = "io.containerd.event.v1"
)
```

## Plugin的注册是通过Registration结构
- plugin被containerd接受前，必须先定义一个Registeration结构，并填好必要的信息。
- Registration初始化入口是Init， Init执行完后，构造Plugin结构作为返回结果
- InitFn是由plugin提供的初始化函数，它会在Init里被调用，返回结果存入Registration.instance

```
// Registration contains information for registering a plugin
type Registration struct {
	// Type of the plugin
	Type Type
	// ID of the plugin
	ID string
	// Config specific to the plugin
	Config interface{}
	// Requires is a list of plugins that the registered plugin requires to be available
	Requires []Type

	// InitFn is called when initializing a plugin. The registration and
	// context are passed in. The init function may modify the registration to
	// add exports, capabilities and platform support declarations.
	InitFn func(*InitContext) (interface{}, error)
	// Disable the plugin from loading
	Disable bool
}

// Init the registered plugin
func (r *Registration) Init(ic *InitContext) *Plugin {
	p, err := r.InitFn(ic)
	return &Plugin{
		Registration: r,
		Config:       ic.Config,
		Meta:         ic.Meta,
		instance:     p,
		err:          err,
	}
}

// URI returns the full plugin URI
func (r *Registration) URI() string {
	return fmt.Sprintf("%s.%s", r.Type, r.ID)
}
```

- 系统定义了一个全局变量register，所有注册的plugin都放在register.Registration数组里
```
var register = struct {
	sync.RWMutex
	r []*Registration
}{}
```

### InitContext是Init的参数，提供plugin初始化需要的上下文信息
```diff
// InitContext is used for plugin inititalization
type InitContext struct {
	Context      context.Context
+	//plugin的根目录
	Root         string
	State        string
	Config       interface{}
+	//grpc地址
	Address      string
+	//ttrpc地址
	TTRPCAddress string

	// deprecated: will be removed in 2.0, use plugin.EventType
	Events *exchange.Exchange

	Meta *Meta // plugins can fill in metadata at init.
+	//已经注册过的所有同类型plugin集合
	plugins *Set
}

// Get returns the first plugin by its type
func (i *InitContext) Get(t Type) (interface{}, error) {
	return i.plugins.Get(t)
}
```

- 创建InitContext
```
// NewContext returns a new plugin InitContext
func NewContext(ctx context.Context, r *Registration, plugins *Set, root, state string) *InitContext {
	return &InitContext{
		Context: ctx,
		Root:    filepath.Join(root, r.URI()),
		State:   filepath.Join(state, r.URI()),
		Meta: &Meta{
			Exports: map[string]string{},
		},
		plugins: plugins,
	}
}
```
