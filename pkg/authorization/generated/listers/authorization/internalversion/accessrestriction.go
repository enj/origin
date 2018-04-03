// This file was automatically generated by lister-gen

package internalversion

import (
	authorization "github.com/openshift/origin/pkg/authorization/apis/authorization"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// AccessRestrictionLister helps list AccessRestrictions.
type AccessRestrictionLister interface {
	// List lists all AccessRestrictions in the indexer.
	List(selector labels.Selector) (ret []*authorization.AccessRestriction, err error)
	// Get retrieves the AccessRestriction from the index for a given name.
	Get(name string) (*authorization.AccessRestriction, error)
	AccessRestrictionListerExpansion
}

// accessRestrictionLister implements the AccessRestrictionLister interface.
type accessRestrictionLister struct {
	indexer cache.Indexer
}

// NewAccessRestrictionLister returns a new AccessRestrictionLister.
func NewAccessRestrictionLister(indexer cache.Indexer) AccessRestrictionLister {
	return &accessRestrictionLister{indexer: indexer}
}

// List lists all AccessRestrictions in the indexer.
func (s *accessRestrictionLister) List(selector labels.Selector) (ret []*authorization.AccessRestriction, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*authorization.AccessRestriction))
	})
	return ret, err
}

// Get retrieves the AccessRestriction from the index for a given name.
func (s *accessRestrictionLister) Get(name string) (*authorization.AccessRestriction, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(authorization.Resource("accessrestriction"), name)
	}
	return obj.(*authorization.AccessRestriction), nil
}
