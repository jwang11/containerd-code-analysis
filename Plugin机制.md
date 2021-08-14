# Containerd里的Plugin（插件）
>containerd使用了Plugin注册机制，将task、content、snapshot、namespace、event、containers等服务以插件的方式注册然后提供服务。

## Plugin的类型
- 目前共12种Plugin，
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
主要分成三个层次。
1. GPRCPlugin属于顶层，包括
  	- content
  	- snapshots
  	- image
	- diff
	- containers
	- events
	- tasks
	- namespaces
	- leases
	- introspection

2. ServicePlugin属于服务层，包括
```
const (
	// ContentService is id of content service.
	ContentService = "content-service"
	// SnapshotsService is id of snapshots service.
	SnapshotsService = "snapshots-service"
	// ImagesService is id of images service.
	ImagesService = "images-service"
	// ContainersService is id of containers service.
	ContainersService = "containers-service"
	// TasksService is id of tasks service.
	TasksService = "tasks-service"
	// NamespacesService is id of namespaces service.
	NamespacesService = "namespaces-service"
	// LeasesService is id of leases service.
	LeasesService = "leases-service"
	// DiffService is id of diff service.
	DiffService = "diff-service"
	// IntrospectionService is the id of introspection service
	IntrospectionService = "introspection-service"
)
```
3. SnapshotPlugin，ContentPlugin，MetadataPlugin属于底层实现。

- plugin要通过注册和初始化两步，才能在containerd里生效。

## Plugin的注册
- 注册plugin，必须先定义一个***Registeration***结构作为注册申请，并填好必要的信息。
```diff
// Registration contains information for registering a plugin
type Registration struct {
+	// 类型，就是12种之一
	// Type of the plugin
	Type Type
+	// 唯一的ID，同类型可以多个Plugin	
	// ID of the plugin
	ID string
	// Config specific to the plugin
	Config interface{}
+	// 依赖的plugins，必须是已经注册过的
	// Requires is a list of plugins that the registered plugin requires to be available
	Requires []Type

	// InitFn is called when initializing a plugin. The registration and
	// context are passed in. The init function may modify the registration to
	// add exports, capabilities and platform support declarations.
	InitFn func(*InitContext) (interface{}, error)
	// Disable the plugin from loading
	Disable bool
}

// URI returns the full plugin URI
func (r *Registration) URI() string {
	return fmt.Sprintf("%s.%s", r.Type, r.ID)
}
```
- 调用***plugin.Register***函数，把***Registration***结构作为该函数的参数。
- 系统定义了一个全局变量***register***，所有注册的Registration都放在***register.Registration***数组里
```diff
var register = struct {
	sync.RWMutex
+	r []*Registration
}{}

// Register allows plugins to register
func Register(r *Registration) {
	register.Lock()
	defer register.Unlock()

	if r.Type == "" {
		panic(ErrNoType)
	}
	if r.ID == "" {
		panic(ErrNoPluginID)
	}
	if err := checkUnique(r); err != nil {
		panic(err)
	}

	for _, requires := range r.Requires {
		if requires == "*" && len(r.Requires) != 1 {
			panic(ErrInvalidRequires)
		}
	}

+	register.r = append(register.r, r)
}

```

## Plugin的初始化
- Plugin的初始化入口是***Registration.Init***。顺利执行如果没有错误，表示初始化完成，生成***Plugin***结构作为返回结果。
- ***InitFn***是由plugin提供的初始化函数，它会在***Registration.Init***里被调用，返回结果（通常是service）存入***Registration.instance***。
```diff
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
```

### Plugin结构和Plugin Set
- Plugin初始化完成后，就会产生***Plugin***结构实例
```diff
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

- Plugin ***Set***代表一个Plugin集合，在后面InitContext会使用到
```diff
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

+ //返回该类型的第一个plugin的Instance
// Get returns the first plugin by its type
func (ps *Set) Get(t Type) (interface{}, error) {
	for _, v := range ps.byTypeAndID[t] {
		return v.Instance()
	}
	return nil, errors.Wrapf(errdefs.ErrNotFound, "no plugins registered for %s", t)
}
```

### InitContext初始化上下文
- ***InitContext***是Init函数的入口参数，提供plugin初始化需要的上下文信息
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

// Meta contains information gathered from the registration and initialization
// process.
type Meta struct {
	Platforms    []ocispec.Platform // platforms supported by plugin
	Exports      map[string]string  // values exported by plugin
	Capabilities []string           // feature switches for plugin
}

// Get returns the first plugin by its type
func (i *InitContext) Get(t Type) (interface{}, error) {
	return i.plugins.Get(t)
}

// GetAll plugins in the set
func (i *InitContext) GetAll() []*Plugin {
	return i.plugins.ordered
}

// GetByID returns the plugin of the given type and ID
func (i *InitContext) GetByID(t Type, id string) (interface{}, error) {
	ps, err := i.GetByType(t)
	if err != nil {
		return nil, err
	}
	p, ok := ps[id]
	if !ok {
		return nil, errors.Wrapf(errdefs.ErrNotFound, "no %s plugins with id %s", t, id)
	}
	return p.Instance()
}

// GetByType returns all plugins with the specific type.
func (i *InitContext) GetByType(t Type) (map[string]*Plugin, error) {
	p, ok := i.plugins.byTypeAndID[t]
	if !ok {
		return nil, errors.Wrapf(errdefs.ErrNotFound, "no plugins registered for %s", t)
	}

	return p, nil
}
```

- 创建InitContext
```diff
// NewContext returns a new plugin InitContext
func NewContext(ctx context.Context, r *Registration, plugins *Set, root, state string) *InitContext {
	return &InitContext{
		Context: ctx,
+		// 比如/var/lib/containerd/io.containerd.content.v1.content		
		Root:    filepath.Join(root, r.URI()),
		State:   filepath.Join(state, r.URI()),
		Meta: &Meta{
			Exports: map[string]string{},
		},
		plugins: plugins,
	}
}
```

## Plugin完整的注册和初始化过程
- Plugin注册
```diff
+	plugins, err := LoadPlugins(ctx, config)
```

```diff
// LoadPlugins loads all plugins into containerd and generates an ordered graph
// of all plugins.
func LoadPlugins(ctx context.Context, config *srvconfig.Config) ([]*plugin.Registration, error) {
...
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
- Plugin初始化
```diff
	var (
		grpcServer = grpc.NewServer(serverOpts...)
		tcpServer  = grpc.NewServer(tcpServerOpts...)

		grpcServices  []plugin.Service
		tcpServices   []plugin.TCPService
		ttrpcServices []plugin.TTRPCService

+		s = &Server{
			grpcServer:  grpcServer,
			tcpServer:   tcpServer,
			ttrpcServer: ttrpcServer,
			config:      config,
		}
		// TODO: Remove this in 2.0 and let event plugin crease it
		events      = exchange.NewExchange()
+		//收集在初始化过程中，已经完成初始化的plugins，最后会放在InitContext里
+		initialized = plugin.NewPluginSet()
		required    = make(map[string]struct{})
	)
	
	for _, p := range plugins {
		id := p.URI()
		reqID := id
		if config.GetVersion() == 1 {
			reqID = p.ID
		}
		log.G(ctx).WithField("type", p.Type).Infof("loading plugin %q...", id)

+		initContext := plugin.NewContext(
			ctx,
			p,
+			initialized,
			config.Root,
			config.State,
		)
		initContext.Events = events
		initContext.Address = config.GRPC.Address
		initContext.TTRPCAddress = config.TTRPC.Address

		// load the plugin specific configuration if it is provided
		if p.Config != nil {
			pc, err := config.Decode(p)
			if err != nil {
				return nil, err
			}
			initContext.Config = pc
		}
+		result := p.Init(initContext)
+		//按照plugin的类型和ID，加入Set
+		if err := initialized.Add(result); err != nil {
			return nil, errors.Wrapf(err, "could not add plugin result to plugin set")
		}
+		// instance里放的是plugin需要输出的service
+		instance, err := result.Instance()
...

		delete(required, reqID)
		// check for grpc services that should be registered with the server
		if src, ok := instance.(plugin.Service); ok {
			grpcServices = append(grpcServices, src)
		}
		if src, ok := instance.(plugin.TTRPCService); ok {
			ttrpcServices = append(ttrpcServices, src)
		}
		if service, ok := instance.(plugin.TCPService); ok {
			tcpServices = append(tcpServices, service)
		}
+		//把完成初始化的plugin加到Server.plugins
+		s.plugins = append(s.plugins, result)
	}
```
