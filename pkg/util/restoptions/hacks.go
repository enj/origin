package restoptions

import (
	genericrest "k8s.io/kubernetes/pkg/registry/generic"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/storage"
	etcdstorage "k8s.io/kubernetes/pkg/storage/etcd"
	"k8s.io/kubernetes/pkg/storage/storagebackend"
	"k8s.io/kubernetes/pkg/storage/storagebackend/factory"
)

// Temporary hack until rebase of upstream PR 37770 ///////////////////////////////////////////////

// RESTOptions is set of configuration options to generic registries.
type RESTOptions struct {
	StorageConfig           *storagebackend.Config
	Decorator               StorageDecorator
	DeleteCollectionWorkers int

	ResourcePrefix string
}

// StorageDecorator is a function signature for producing
// a storage.Interface from given parameters.
type StorageDecorator func(
	config *storagebackend.Config,
	capacity int,
	objectType runtime.Object,
	resourcePrefix string,
	keyFunc func(obj runtime.Object) (string, error),
	newListFunc func() runtime.Object,
	trigger storage.TriggerPublisherFunc) (storage.Interface, factory.DestroyFunc)

// Creates a cacher based given storageConfig.
func storageWithCacher(
	storageConfig *storagebackend.Config,
	capacity int,
	objectType runtime.Object,
	resourcePrefix string,
	keyFunc func(obj runtime.Object) (string, error),
	newListFunc func() runtime.Object,
	triggerFunc storage.TriggerPublisherFunc) (storage.Interface, factory.DestroyFunc) {

	s, d := genericrest.NewRawStorage(storageConfig)
	// TODO: we would change this later to make storage always have cacher and hide low level KV layer inside.
	// Currently it has two layers of same storage interface -- cacher and low level kv.
	cacherConfig := storage.CacherConfig{
		CacheCapacity:        capacity,
		Storage:              s,
		Versioner:            etcdstorage.APIObjectVersioner{},
		Type:                 objectType,
		ResourcePrefix:       resourcePrefix,
		KeyFunc:              keyFunc,
		NewListFunc:          newListFunc,
		TriggerPublisherFunc: triggerFunc,
		Codec:                storageConfig.Codec,
	}
	cacher := storage.NewCacherFromConfig(cacherConfig)
	destroyFunc := func() {
		cacher.Stop()
		d()
	}

	return cacher, destroyFunc
}

// Returns given 'storageInterface' without any decoration.
func undecoratedStorage(
	config *storagebackend.Config,
	capacity int,
	objectType runtime.Object,
	resourcePrefix string,
	keyFunc func(obj runtime.Object) (string, error),
	newListFunc func() runtime.Object,
	trigger storage.TriggerPublisherFunc) (storage.Interface, factory.DestroyFunc) {
	return genericrest.NewRawStorage(config)
}

// End temporary hack /////////////////////////////////////////////////////////////////////////////
