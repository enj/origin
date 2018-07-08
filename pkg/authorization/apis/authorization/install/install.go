package install

import (
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/kubernetes/pkg/api/legacyscheme"

	authorizationapi "github.com/openshift/origin/pkg/authorization/apis/authorization"
	"github.com/openshift/origin/pkg/authorization/apis/authorization/rbacconversion"
	authorizationapiv1 "github.com/openshift/origin/pkg/authorization/apis/authorization/v1"
	authorizationapiv1alpha1 "github.com/openshift/origin/pkg/authorization/apis/authorization/v1alpha1"
)

func init() {
	Install(legacyscheme.Scheme)
}

// Install registers the API group and adds types to a scheme
func Install(scheme *runtime.Scheme) {
	utilruntime.Must(authorizationapi.AddToScheme(scheme))
	utilruntime.Must(rbacconversion.AddToScheme(scheme))
	utilruntime.Must(authorizationapiv1.AddToScheme(scheme))
	utilruntime.Must(authorizationapiv1alpha1.AddToScheme(scheme))
	utilruntime.Must(scheme.SetVersionPriority(authorizationapiv1.SchemeGroupVersion))
}
