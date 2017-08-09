package bootstrappolicy

import (
	"fmt"

	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/rbac"
	rbacbootstrappolicy "k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac/bootstrappolicy"

	authorizationapi "github.com/openshift/origin/pkg/authorization/apis/authorization"
)

// TODO: this needs some work since we are double converting

func Policy() *rbacbootstrappolicy.PolicyData {
	return &rbacbootstrappolicy.PolicyData{
		ClusterRoles:        GetBootstrapClusterRoles(),
		ClusterRoleBindings: GetBootstrapClusterRoleBindings(),
		Roles: map[string][]rbac.Role{
			DefaultOpenShiftSharedResourcesNamespace: GetBootstrapOpenshiftRoles(DefaultOpenShiftSharedResourcesNamespace),
		},
		RoleBindings: map[string][]rbac.RoleBinding{
			DefaultOpenShiftSharedResourcesNamespace: GetBootstrapOpenshiftRoleBindings(DefaultOpenShiftSharedResourcesNamespace),
		},
	}
}

func ConvertToOriginClusterRolesOrDie(in []rbac.ClusterRole) []authorizationapi.ClusterRole {
	out := []authorizationapi.ClusterRole{}
	errs := []error{}

	for i := range in {
		newRole := &authorizationapi.ClusterRole{}
		if err := kapi.Scheme.Convert(&in[i], newRole, nil); err != nil {
			errs = append(errs, fmt.Errorf("error converting %q: %v", in[i].Name, err))
			continue
		}
		out = append(out, *newRole)
	}

	if len(errs) > 0 {
		panic(errs)
	}

	return out
}

func ConvertToOriginClusterRoleBindingsOrDie(in []rbac.ClusterRoleBinding) []authorizationapi.ClusterRoleBinding {
	out := []authorizationapi.ClusterRoleBinding{}
	errs := []error{}

	for i := range in {
		newRoleBinding := &authorizationapi.ClusterRoleBinding{}
		if err := kapi.Scheme.Convert(&in[i], newRoleBinding, nil); err != nil {
			errs = append(errs, fmt.Errorf("error converting %q: %v", in[i].Name, err))
			continue
		}
		out = append(out, *newRoleBinding)
	}

	if len(errs) > 0 {
		panic(errs)
	}

	return out
}

func ConvertToOriginRolesOrDie(in []rbac.Role) []authorizationapi.Role {
	out := []authorizationapi.Role{}
	errs := []error{}

	for i := range in {
		newRole := &authorizationapi.Role{}
		if err := kapi.Scheme.Convert(&in[i], newRole, nil); err != nil {
			errs = append(errs, fmt.Errorf("error converting %q: %v", in[i].Name, err))
			continue
		}
		out = append(out, *newRole)
	}

	if len(errs) > 0 {
		panic(errs)
	}

	return out
}
