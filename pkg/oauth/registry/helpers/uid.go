package helpers

import (
	kapi "k8s.io/kubernetes/pkg/api"
	kubeerr "k8s.io/kubernetes/pkg/api/errors"
	"k8s.io/kubernetes/pkg/fields"
	"k8s.io/kubernetes/pkg/labels"
	"k8s.io/kubernetes/pkg/registry/generic/registry"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/watch"
)

type ListDecoratorFunc func(obj runtime.Object) runtime.Object

type UIDEnforcer struct {
	registry.Store
	ListDecoratorFunc
	UserUIDField string
}

func (s *UIDEnforcer) Get(ctx kapi.Context, name string) (runtime.Object, error) {
	obj, err := s.Store.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	user, ok := kapi.UserFrom(ctx)
	if !ok {
		return nil, kubeerr.NewBadRequest("User parameter required.")
	}
	uid := user.GetUID()
	if len(uid) != 0 {
		if matched, err := s.Store.PredicateFunc(labels.Everything(), fields.OneTermEqualSelector(s.UserUIDField, uid)).Matches(obj); !matched || err != nil {
			return nil, kubeerr.NewNotFound(s.QualifiedResource, name)
		}
	}
	return obj, nil
}

func (s *UIDEnforcer) NewList() runtime.Object {
	return s.Store.NewList() // needed to implement rest.Lister (NewList + List)
}

func (s *UIDEnforcer) List(ctx kapi.Context, options *kapi.ListOptions) (runtime.Object, error) {
	if err := s.forceUID(ctx, options); err != nil {
		return nil, err
	}
	list, err := s.Store.List(ctx, options)
	if err != nil {
		return nil, err
	}
	return s.ListDecoratorFunc(list), nil
}

func (s *UIDEnforcer) Delete(ctx kapi.Context, name string, options *kapi.DeleteOptions) (runtime.Object, error) {
	if _, err := s.Get(ctx, name); err != nil {
		return nil, err
	}
	return s.Store.Delete(ctx, name, options)

}

func (s *UIDEnforcer) DeleteCollection(ctx kapi.Context, options *kapi.DeleteOptions, listOptions *kapi.ListOptions) (runtime.Object, error) {
	if err := s.forceUID(ctx, listOptions); err != nil {
		return nil, err
	}
	list, err := s.Store.DeleteCollection(ctx, options, listOptions)
	if err != nil {
		return nil, err
	}
	return s.ListDecoratorFunc(list), nil
}

func (s *UIDEnforcer) Watch(ctx kapi.Context, options *kapi.ListOptions) (watch.Interface, error) {
	if err := s.forceUID(ctx, options); err != nil {
		return nil, err
	}
	return s.Store.Watch(ctx, options) //TODO use ListDecoratorFunc ?
}

func (s *UIDEnforcer) forceUID(ctx kapi.Context, options *kapi.ListOptions) error {
	user, ok := kapi.UserFrom(ctx)
	if !ok {
		return kubeerr.NewBadRequest("User parameter required.")
	}
	uid := user.GetUID()
	if len(uid) == 0 {
		return nil
	}
	if options == nil {
		options = &kapi.ListOptions{}
	}
	if options.FieldSelector == nil {
		options.FieldSelector = fields.OneTermEqualSelector(s.UserUIDField, uid)
	} else {
		options.FieldSelector, _ = options.FieldSelector.Transform(func(string, string) (string, string, error) {
			return s.UserUIDField, uid, nil
		})
	}
	return nil
}
