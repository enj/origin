package helpers

import (
	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/rest"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/watch"
)

type ObjectDecoratorFunc func(obj runtime.Object) runtime.Object
type ObjectFilterFunc func(ctx kapi.Context, obj runtime.Object) error

type ListDecoratorFunc func(obj runtime.Object) runtime.Object
type ListFilterFunc func(ctx kapi.Context, options *kapi.ListOptions) error

type ObjectNameMutatorFunc func(ctx kapi.Context, name string) (string, error)

type filterConverter struct {
	storage ReadAndDeleteStorage
	objDec  ObjectDecoratorFunc
	objFil  ObjectFilterFunc
	listDec ListDecoratorFunc
	listFil ListFilterFunc
	namer   ObjectNameMutatorFunc
}

type ReadAndDeleteStorage interface {
	rest.Getter
	rest.Lister
	rest.GracefulDeleter
	rest.CollectionDeleter
	rest.Watcher
}

var _ ReadAndDeleteStorage = &filterConverter{}

func NewFilterConverter(
	storage ReadAndDeleteStorage,
	objDec ObjectDecoratorFunc,
	objFil ObjectFilterFunc,
	listDec ListDecoratorFunc,
	listFil ListFilterFunc,
	namer ObjectNameMutatorFunc,
) *filterConverter {
	return &filterConverter{
		storage: storage,
		objDec:  objDec,
		objFil:  objFil,
		listDec: listDec,
		listFil: listFil,
		namer:   namer,
	}
}

func (s *filterConverter) Get(ctx kapi.Context, name string) (runtime.Object, error) {
	name, err := s.namer(ctx, name)
	if err != nil {
		return nil, err
	}
	obj, err := s.storage.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	if err := s.objFil(ctx, obj); err != nil {
		return nil, err
	}
	return s.objDec(obj), nil
}

func (s *filterConverter) NewList() runtime.Object {
	return s.storage.NewList() // needed to implement rest.Lister (NewList + List)
}

func (s *filterConverter) List(ctx kapi.Context, options *kapi.ListOptions) (runtime.Object, error) {
	if err := s.listFil(ctx, options); err != nil {
		return nil, err
	}
	list, err := s.storage.List(ctx, options)
	if err != nil {
		return nil, err
	}
	return s.listDec(list), nil
}

func (s *filterConverter) Delete(ctx kapi.Context, name string, options *kapi.DeleteOptions) (runtime.Object, error) {
	name, err := s.namer(ctx, name)
	if err != nil {
		return nil, err
	}
	if _, err := s.Get(ctx, name); err != nil {
		return nil, err
	}
	obj, err := s.storage.Delete(ctx, name, options)
	if err != nil {
		return nil, err
	}
	return s.objDec(obj), nil
}

func (s *filterConverter) DeleteCollection(ctx kapi.Context, options *kapi.DeleteOptions, listOptions *kapi.ListOptions) (runtime.Object, error) {
	if err := s.listFil(ctx, listOptions); err != nil {
		return nil, err
	}
	list, err := s.storage.DeleteCollection(ctx, options, listOptions)
	if err != nil {
		return nil, err
	}
	return s.listDec(list), nil
}

func (s *filterConverter) Watch(ctx kapi.Context, options *kapi.ListOptions) (watch.Interface, error) {
	if err := s.listFil(ctx, options); err != nil {
		return nil, err
	}
	w, err := s.storage.Watch(ctx, options)
	if err != nil {
		return nil, err
	}
	return watch.Filter(w, func(in watch.Event) (watch.Event, bool) {
		if in.Type != watch.Error {
			in.Object = s.objDec(in.Object)
		}
		return in, true
	}), nil
}
