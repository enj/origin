package restoptions

import "k8s.io/kubernetes/pkg/api/unversioned"

type Getter interface {
	GetRESTOptions(resource unversioned.GroupResource) (RESTOptions, error)
}
