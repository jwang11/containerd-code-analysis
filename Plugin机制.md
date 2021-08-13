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

## Plugin的注册是基于Registration结构
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
