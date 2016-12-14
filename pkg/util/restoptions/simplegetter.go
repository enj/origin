package restoptions

import (
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/storage/storagebackend"
)

type simpleGetter struct {
	storage *storagebackend.Config
}

func NewSimpleGetter(storage *storagebackend.Config) Getter {
	return &simpleGetter{storage: storage}
}

func (s *simpleGetter) GetRESTOptions(resource unversioned.GroupResource) (RESTOptions, error) {
	return RESTOptions{
		StorageConfig:           s.storage,
		Decorator:               undecoratedStorage,
		DeleteCollectionWorkers: 1,
		ResourcePrefix:          resource.Resource,
	}, nil
}
