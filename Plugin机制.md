# Containerd里的Plugin（插件）
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

## plugin的注册是通过Registration结构(初始化前）
- 要注册plugin，必须先定义一个Registeration结构，并填好必要的信息。
- Registration初始化入口是Init， Init被执行后，表示初始化完成，才生成Plugin结构作为返回结果。
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

- 系统定义了一个全局变量register，所有准备注册的plugin都放在register.Registration数组里
```
var register = struct {
	sync.RWMutex
	r []*Registration
}{}
```

### Plugin结构和Plugin Set
- plugin初始化完成后，就会产生一个Plugin结构实例
```
// Plugin represents an initialized plugin, used with an init context.
type Plugin struct {
	Registration *Registration // registration, as initialized
	Config       interface{}   // config, as initialized
	Meta         *Meta

	instance interface{}
	err      error // will be set if there was an error initializing the plugin
}

// Err returns the errors during initialization.
// returns nil if not error was encountered
func (p *Plugin) Err() error {
	return p.err
}

// Instance returns the instance and any initialization error of the plugin
func (p *Plugin) Instance() (interface{}, error) {
	return p.instance, p.err
}
```

- Plugin Set代表一个Plugin集合，在后面InitContext会使用到
```
// Set defines a plugin collection, used with InitContext.
//
// This maintains ordering and unique indexing over the set.
//
// After iteratively instantiating plugins, this set should represent, the
// ordered, initialization set of plugins for a containerd instance.
type Set struct {
	ordered     []*Plugin // order of initialization
	byTypeAndID map[Type]map[string]*Plugin
}

// NewPluginSet returns an initialized plugin set
func NewPluginSet() *Set {
	return &Set{
		byTypeAndID: make(map[Type]map[string]*Plugin),
	}
}

// Add a plugin to the set
func (ps *Set) Add(p *Plugin) error {
	if byID, typeok := ps.byTypeAndID[p.Registration.Type]; !typeok {
		ps.byTypeAndID[p.Registration.Type] = map[string]*Plugin{
			p.Registration.ID: p,
		}
	} else if _, idok := byID[p.Registration.ID]; !idok {
		byID[p.Registration.ID] = p
	} else {
		return errors.Wrapf(errdefs.ErrAlreadyExists, "plugin %v already initialized", p.Registration.URI())
	}

	ps.ordered = append(ps.ordered, p)
	return nil
}

// Get returns the first plugin by its type
func (ps *Set) Get(t Type) (interface{}, error) {
	for _, v := range ps.byTypeAndID[t] {
		return v.Instance()
	}
	return nil, errors.Wrapf(errdefs.ErrNotFound, "no plugins registered for %s", t)
}
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
