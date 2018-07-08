// Code generated by informer-gen. DO NOT EDIT.

package internalversion

import (
	"fmt"

	authorization "github.com/openshift/origin/pkg/authorization/apis/authorization"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	cache "k8s.io/client-go/tools/cache"
)

// GenericInformer is type of SharedIndexInformer which will locate and delegate to other
// sharedInformers based on type
type GenericInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() cache.GenericLister
}

type genericInformer struct {
	informer cache.SharedIndexInformer
	resource schema.GroupResource
}

// Informer returns the SharedIndexInformer.
func (f *genericInformer) Informer() cache.SharedIndexInformer {
	return f.informer
}

// Lister returns the GenericLister.
func (f *genericInformer) Lister() cache.GenericLister {
	return cache.NewGenericLister(f.Informer().GetIndexer(), f.resource)
}

// ForResource gives generic access to a shared informer of the matching type
// TODO extend this to unknown resources with a client pool
func (f *sharedInformerFactory) ForResource(resource schema.GroupVersionResource) (GenericInformer, error) {
	switch resource {
	// Group=authorization.openshift.io, Version=internalVersion
	case authorization.SchemeGroupVersion.WithResource("accessrestrictions"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Authorization().InternalVersion().AccessRestrictions().Informer()}, nil
	case authorization.SchemeGroupVersion.WithResource("clusterroles"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Authorization().InternalVersion().ClusterRoles().Informer()}, nil
	case authorization.SchemeGroupVersion.WithResource("clusterrolebindings"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Authorization().InternalVersion().ClusterRoleBindings().Informer()}, nil
	case authorization.SchemeGroupVersion.WithResource("roles"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Authorization().InternalVersion().Roles().Informer()}, nil
	case authorization.SchemeGroupVersion.WithResource("rolebindings"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Authorization().InternalVersion().RoleBindings().Informer()}, nil
	case authorization.SchemeGroupVersion.WithResource("rolebindingrestrictions"):
		return &genericInformer{resource: resource.GroupResource(), informer: f.Authorization().InternalVersion().RoleBindingRestrictions().Informer()}, nil

	}

	return nil, fmt.Errorf("no informer found for %v", resource)
}
