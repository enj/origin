package integration

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	kapierror "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/kubernetes/pkg/api/legacyscheme"

	authorizationv1 "github.com/openshift/api/authorization/v1"
	"github.com/openshift/origin/pkg/api/legacy"
	authorizationclient "github.com/openshift/origin/pkg/authorization/generated/internalclientset"
	authorizationclientscheme "github.com/openshift/origin/pkg/authorization/generated/internalclientset/scheme"
	testutil "github.com/openshift/origin/test/util"
	testserver "github.com/openshift/origin/test/util/server"
)

// TestLegacyLocalRoleBindingEndpoint exercises the legacy rolebinding endpoint that is proxied to rbac
func TestLegacyLocalRoleBindingEndpoint(t *testing.T) {
	masterConfig, clusterAdminKubeConfig, err := testserver.StartTestMasterAPI()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer testserver.CleanupMasterEtcd(t, masterConfig)

	clusterAdminClientConfig, err := testutil.GetClusterAdminClientConfig(clusterAdminKubeConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	clusterAdmin := authorizationclient.NewForConfigOrDie(clusterAdminClientConfig)

	namespace := "testproject"
	_, _, err = testserver.CreateNewProject(clusterAdminClientConfig, namespace, "testuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	roleBindingsPath := "/apis/authorization.openshift.io/v1/namespaces/" + namespace + "/rolebindings"
	testBindingName := "testrole"

	// install the legacy types into the client for decoding
	legacy.InstallInternalLegacyAuthorization(authorizationclientscheme.Scheme)

	// create rolebinding
	roleBindingToCreate := &authorizationv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: testBindingName,
		},
		Subjects: []corev1.ObjectReference{
			{
				Kind: rbacv1.UserKind,
				Name: "testuser",
			},
		},
		RoleRef: corev1.ObjectReference{
			Kind:      "Role",
			Name:      "edit",
			Namespace: namespace,
		},
	}
	roleBindingToCreateBytes, err := runtime.Encode(legacyscheme.Codecs.LegacyCodec(schema.GroupVersion{Version: "v1"}), roleBindingToCreate)
	if err != nil {
		t.Fatal(err)
	}

	roleBindingCreated := &authorizationv1.RoleBinding{}
	err = clusterAdmin.Authorization().RESTClient().Post().AbsPath(roleBindingsPath).Body(roleBindingToCreateBytes).Do().Into(roleBindingCreated)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if roleBindingCreated.Name != roleBindingToCreate.Name {
		t.Errorf("expected rolebinding %s, got %s", roleBindingToCreate.Name, roleBindingCreated.Name)
	}

	// list rolebindings
	roleBindingList := &authorizationv1.RoleBindingList{}
	err = clusterAdmin.Authorization().RESTClient().Get().AbsPath(roleBindingsPath).Do().Into(roleBindingList)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	checkBindings := sets.String{}
	for _, rb := range roleBindingList.Items {
		checkBindings.Insert(rb.Name)
	}

	// check for the created rolebinding in the list
	if !checkBindings.HasAll(testBindingName) {
		t.Errorf("rolebinding list does not have the expected bindings")
	}

	// edit rolebinding
	roleBindingToEdit := &authorizationv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: testBindingName,
		},
		Subjects: []corev1.ObjectReference{
			{
				Kind: rbacv1.UserKind,
				Name: "testuser",
			},
			{
				Kind: rbacv1.UserKind,
				Name: "testuser2",
			},
		},
		RoleRef: corev1.ObjectReference{
			Kind:      "Role",
			Name:      "edit",
			Namespace: namespace,
		},
	}
	roleBindingToEditBytes, err := runtime.Encode(legacyscheme.Codecs.LegacyCodec(schema.GroupVersion{Version: "v1"}), roleBindingToEdit)
	if err != nil {
		t.Fatal(err)
	}

	roleBindingEdited := &authorizationv1.RoleBinding{}
	err = clusterAdmin.Authorization().RESTClient().Patch(types.StrategicMergePatchType).AbsPath(roleBindingsPath).Name(roleBindingToEdit.Name).Body(roleBindingToEditBytes).Do().Into(roleBindingEdited)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if roleBindingEdited.Name != roleBindingToEdit.Name {
		t.Errorf("expected rolebinding %s, got %s", roleBindingToEdit.Name, roleBindingEdited.Name)
	}

	checkSubjects := sets.String{}
	for _, subj := range roleBindingEdited.Subjects {
		checkSubjects.Insert(subj.Name)
	}
	if !checkSubjects.HasAll("testuser", "testuser2") {
		t.Errorf("rolebinding not edited")
	}

	// get rolebinding by name
	getRoleBinding := &authorizationv1.RoleBinding{}
	err = clusterAdmin.Authorization().RESTClient().Get().AbsPath(roleBindingsPath).Name(testBindingName).Do().Into(getRoleBinding)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if getRoleBinding.Name != testBindingName {
		t.Errorf("expected rolebinding %s, got %s", testBindingName, getRoleBinding.Name)
	}

	// delete rolebinding
	err = clusterAdmin.Authorization().RESTClient().Delete().AbsPath(roleBindingsPath).Name(testBindingName).Do().Error()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// confirm deletion
	getRoleBinding = &authorizationv1.RoleBinding{}
	err = clusterAdmin.Authorization().RESTClient().Get().AbsPath(roleBindingsPath).Name(testBindingName).Do().Into(getRoleBinding)
	if err == nil {
		t.Errorf("expected error")
	} else if !kapierror.IsNotFound(err) {
		t.Errorf("unexpected error: %v", err)
	}

	// create local rolebinding for cluster role
	localClusterRoleBindingToCreate := &authorizationv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-crb",
			Namespace: namespace,
		},
		Subjects: []corev1.ObjectReference{
			{
				Kind: rbacv1.UserKind,
				Name: "testuser",
			},
		},
		RoleRef: corev1.ObjectReference{
			Kind: "ClusterRole",
			Name: "edit",
		},
	}
	localClusterRoleBindingToCreateBytes, err := runtime.Encode(legacyscheme.Codecs.LegacyCodec(schema.GroupVersion{Version: "v1"}), localClusterRoleBindingToCreate)
	if err != nil {
		t.Fatal(err)
	}

	localClusterRoleBindingCreated := &authorizationv1.RoleBinding{}
	err = clusterAdmin.Authorization().RESTClient().Post().AbsPath(roleBindingsPath).Body(localClusterRoleBindingToCreateBytes).Do().Into(localClusterRoleBindingCreated)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if localClusterRoleBindingCreated.Name != localClusterRoleBindingToCreate.Name {
		t.Errorf("expected clusterrolebinding %s, got %s", localClusterRoleBindingToCreate.Name, localClusterRoleBindingCreated.Name)
	}

}

// TestLegacyClusterRoleBindingEndpoint exercises the legacy clusterrolebinding endpoint that is proxied to rbac
func TestLegacyClusterRoleBindingEndpoint(t *testing.T) {
	masterConfig, clusterAdminKubeConfig, err := testserver.StartTestMasterAPI()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer testserver.CleanupMasterEtcd(t, masterConfig)

	clusterAdminClientConfig, err := testutil.GetClusterAdminClientConfig(clusterAdminKubeConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	clusterAdmin := authorizationclient.NewForConfigOrDie(clusterAdminClientConfig)

	// install the legacy types into the client for decoding
	legacy.InstallInternalLegacyAuthorization(authorizationclientscheme.Scheme)

	clusterRoleBindingsPath := "/apis/authorization.openshift.io/v1/clusterrolebindings"
	testBindingName := "testbinding"

	// list clusterrole bindings
	clusterRoleBindingList := &authorizationv1.ClusterRoleBindingList{}
	err = clusterAdmin.Authorization().RESTClient().Get().AbsPath(clusterRoleBindingsPath).Do().Into(clusterRoleBindingList)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	checkBindings := sets.String{}
	for _, rb := range clusterRoleBindingList.Items {
		checkBindings.Insert(rb.Name)
	}

	// ensure there are at least some of the expected bindings in the list
	if !checkBindings.HasAll("basic-users", "cluster-admin", "cluster-admins", "cluster-readers") {
		t.Errorf("clusterrolebinding list does not have the expected bindings")
	}

	// create clusterrole binding
	clusterRoleBindingToCreate := &authorizationv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: testBindingName,
		},
		Subjects: []corev1.ObjectReference{
			{
				Kind: rbacv1.UserKind,
				Name: "testuser",
			},
		},
		RoleRef: corev1.ObjectReference{
			Kind: "ClusterRole",
			Name: "edit",
		},
	}
	clusterRoleBindingToCreateBytes, err := runtime.Encode(legacyscheme.Codecs.LegacyCodec(schema.GroupVersion{Version: "v1"}), clusterRoleBindingToCreate)
	if err != nil {
		t.Fatal(err)
	}

	clusterRoleBindingCreated := &authorizationv1.ClusterRoleBinding{}
	err = clusterAdmin.Authorization().RESTClient().Post().AbsPath(clusterRoleBindingsPath).Body(clusterRoleBindingToCreateBytes).Do().Into(clusterRoleBindingCreated)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if clusterRoleBindingCreated.Name != clusterRoleBindingToCreate.Name {
		t.Errorf("expected clusterrolebinding %s, got %s", clusterRoleBindingToCreate.Name, clusterRoleBindingCreated.Name)
	}

	// edit clusterrole binding
	clusterRoleBindingToEdit := &authorizationv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: testBindingName,
		},
		Subjects: []corev1.ObjectReference{
			{
				Kind: rbacv1.UserKind,
				Name: "testuser",
			},
			{
				Kind: rbacv1.UserKind,
				Name: "testuser2",
			},
		},
		RoleRef: corev1.ObjectReference{
			Kind: "ClusterRole",
			Name: "edit",
		},
	}
	clusterRoleBindingToEditBytes, err := runtime.Encode(legacyscheme.Codecs.LegacyCodec(schema.GroupVersion{Version: "v1"}), clusterRoleBindingToEdit)
	if err != nil {
		t.Fatal(err)
	}

	clusterRoleBindingEdited := &authorizationv1.ClusterRoleBinding{}
	err = clusterAdmin.Authorization().RESTClient().Patch(types.StrategicMergePatchType).AbsPath(clusterRoleBindingsPath).Name(clusterRoleBindingToEdit.Name).Body(clusterRoleBindingToEditBytes).Do().Into(clusterRoleBindingEdited)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if clusterRoleBindingEdited.Name != clusterRoleBindingToEdit.Name {
		t.Errorf("expected clusterrolebinding %s, got %s", clusterRoleBindingToEdit.Name, clusterRoleBindingEdited.Name)
	}

	checkSubjects := sets.String{}
	for _, subj := range clusterRoleBindingEdited.Subjects {
		checkSubjects.Insert(subj.Name)
	}
	if !checkSubjects.HasAll("testuser", "testuser2") {
		t.Errorf("clusterrolebinding not edited")
	}

	// get clusterrolebinding by name
	getRoleBinding := &authorizationv1.ClusterRoleBinding{}
	err = clusterAdmin.Authorization().RESTClient().Get().AbsPath(clusterRoleBindingsPath).Name(testBindingName).Do().Into(getRoleBinding)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if getRoleBinding.Name != testBindingName {
		t.Errorf("expected clusterrolebinding %s, got %s", testBindingName, getRoleBinding.Name)
	}

	// delete clusterrolebinding
	err = clusterAdmin.Authorization().RESTClient().Delete().AbsPath(clusterRoleBindingsPath).Name(testBindingName).Do().Error()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// confirm deletion
	getRoleBinding = &authorizationv1.ClusterRoleBinding{}
	err = clusterAdmin.Authorization().RESTClient().Get().AbsPath(clusterRoleBindingsPath).Name(testBindingName).Do().Into(getRoleBinding)
	if err == nil {
		t.Errorf("expected error")
	} else if !kapierror.IsNotFound(err) {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestLegacyClusterRoleEndpoint exercises the legacy clusterrole endpoint that is proxied to rbac
func TestLegacyClusterRoleEndpoint(t *testing.T) {
	masterConfig, clusterAdminKubeConfig, err := testserver.StartTestMasterAPI()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer testserver.CleanupMasterEtcd(t, masterConfig)

	clusterAdminClientConfig, err := testutil.GetClusterAdminClientConfig(clusterAdminKubeConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	clusterAdmin := authorizationclient.NewForConfigOrDie(clusterAdminClientConfig)

	// install the legacy types into the client for decoding
	legacy.InstallInternalLegacyAuthorization(authorizationclientscheme.Scheme)

	clusterRolesPath := "/apis/authorization.openshift.io/v1/clusterroles"
	testRole := "testrole"

	// list clusterroles
	clusterRoleList := &authorizationv1.ClusterRoleList{}
	err = clusterAdmin.Authorization().RESTClient().Get().AbsPath(clusterRolesPath).Do().Into(clusterRoleList)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	checkRoles := sets.String{}
	for _, role := range clusterRoleList.Items {
		checkRoles.Insert(role.Name)
	}
	// ensure there are at least some of the expected roles in the clusterrole list
	if !checkRoles.HasAll("admin", "basic-user", "cluster-admin", "edit", "sudoer") {
		t.Errorf("clusterrole list does not have the expected roles")
	}

	// create clusterrole
	clusterRoleToCreate := &authorizationv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: testRole},
		Rules: []authorizationv1.PolicyRule{
			{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"services"},
			},
		},
	}
	clusterRoleToCreateBytes, err := runtime.Encode(legacyscheme.Codecs.LegacyCodec(schema.GroupVersion{Version: "v1"}), clusterRoleToCreate)
	if err != nil {
		t.Fatal(err)
	}
	createdClusterRole := &authorizationv1.ClusterRole{}
	err = clusterAdmin.Authorization().RESTClient().Post().AbsPath(clusterRolesPath).Body(clusterRoleToCreateBytes).Do().Into(createdClusterRole)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if createdClusterRole.Name != clusterRoleToCreate.Name {
		t.Errorf("expected to create %v, got %v", clusterRoleToCreate.Name, createdClusterRole.Name)
	}

	if !sets.NewString(createdClusterRole.Rules[0].Verbs...).Has("get") {
		t.Errorf("expected clusterrole to have a get rule")
	}

	// update clusterrole
	clusterRoleUpdate := &authorizationv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: testRole},
		Rules: []authorizationv1.PolicyRule{
			{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{""},
				Resources: []string{"services"},
			},
		},
	}

	clusterRoleUpdateBytes, err := runtime.Encode(legacyscheme.Codecs.LegacyCodec(schema.GroupVersion{Version: "v1"}), clusterRoleUpdate)
	if err != nil {
		t.Fatal(err)
	}

	updatedClusterRole := &authorizationv1.ClusterRole{}
	err = clusterAdmin.Authorization().RESTClient().Patch(types.StrategicMergePatchType).AbsPath(clusterRolesPath).Name(testRole).Body(clusterRoleUpdateBytes).Do().Into(updatedClusterRole)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if updatedClusterRole.Name != clusterRoleUpdate.Name {
		t.Errorf("expected to update %s, got %s", clusterRoleUpdate.Name, updatedClusterRole.Name)
	}

	if !sets.NewString(updatedClusterRole.Rules[0].Verbs...).HasAll("get", "list") {
		t.Errorf("expected clusterrole to have a get and list rule")
	}

	// get clusterrole
	getRole := &authorizationv1.ClusterRole{}
	err = clusterAdmin.Authorization().RESTClient().Get().AbsPath(clusterRolesPath).Name(testRole).Do().Into(getRole)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if getRole.Name != testRole {
		t.Errorf("expected %s role, got %s instead", testRole, getRole.Name)
	}

	// delete clusterrole
	err = clusterAdmin.Authorization().RESTClient().Delete().AbsPath(clusterRolesPath).Name(testRole).Do().Error()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// confirm deletion
	getRole = &authorizationv1.ClusterRole{}
	err = clusterAdmin.Authorization().RESTClient().Get().AbsPath(clusterRolesPath).Name(testRole).Do().Into(getRole)
	if err == nil {
		t.Errorf("expected error")
	} else if !kapierror.IsNotFound(err) {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestLegacyLocalRoleEndpoint exercises the legacy role endpoint that is proxied to rbac
func TestLegacyLocalRoleEndpoint(t *testing.T) {
	masterConfig, clusterAdminKubeConfig, err := testserver.StartTestMasterAPI()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer testserver.CleanupMasterEtcd(t, masterConfig)

	clusterAdminClientConfig, err := testutil.GetClusterAdminClientConfig(clusterAdminKubeConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	clusterAdmin := authorizationclient.NewForConfigOrDie(clusterAdminClientConfig)

	namespace := "testproject"
	_, _, err = testserver.CreateNewProject(clusterAdminClientConfig, namespace, "testuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// install the legacy types into the client for decoding
	legacy.InstallInternalLegacyAuthorization(authorizationclientscheme.Scheme)

	rolesPath := "/apis/authorization.openshift.io/v1/namespaces/" + namespace + "/roles"
	testRole := "testrole"

	// create role
	roleToCreate := &authorizationv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRole,
			Namespace: namespace,
		},
		Rules: []authorizationv1.PolicyRule{
			{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"services"},
			},
		},
	}
	roleToCreateBytes, err := runtime.Encode(legacyscheme.Codecs.LegacyCodec(schema.GroupVersion{Version: "v1"}), roleToCreate)
	if err != nil {
		t.Fatal(err)
	}
	createdRole := &authorizationv1.Role{}
	err = clusterAdmin.Authorization().RESTClient().Post().AbsPath(rolesPath).Body(roleToCreateBytes).Do().Into(createdRole)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if createdRole.Name != roleToCreate.Name {
		t.Errorf("expected to create %v, got %v", roleToCreate.Name, createdRole.Name)
	}

	if !sets.NewString(createdRole.Rules[0].Verbs...).Has("get") {
		t.Errorf("expected clusterRole to have a get rule")
	}

	// list roles
	roleList := &authorizationv1.RoleList{}
	err = clusterAdmin.Authorization().RESTClient().Get().AbsPath(rolesPath).Do().Into(roleList)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	checkRoles := sets.String{}
	for _, role := range roleList.Items {
		checkRoles.Insert(role.Name)
	}
	// ensure the role list has the created role
	if !checkRoles.HasAll(testRole) {
		t.Errorf("role list does not have the expected roles")
	}

	// update role
	roleUpdate := &authorizationv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRole,
			Namespace: namespace,
		},
		Rules: []authorizationv1.PolicyRule{
			{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{""},
				Resources: []string{"services"},
			},
		},
	}

	roleUpdateBytes, err := runtime.Encode(legacyscheme.Codecs.LegacyCodec(schema.GroupVersion{Version: "v1"}), roleUpdate)
	if err != nil {
		t.Fatal(err)
	}

	updatedRole := &authorizationv1.Role{}
	err = clusterAdmin.Authorization().RESTClient().Patch(types.StrategicMergePatchType).AbsPath(rolesPath).Name(testRole).Body(roleUpdateBytes).Do().Into(updatedRole)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if updatedRole.Name != roleUpdate.Name {
		t.Errorf("expected to update %s, got %s", roleUpdate.Name, updatedRole.Name)
	}

	if !sets.NewString(updatedRole.Rules[0].Verbs...).HasAll("get", "list") {
		t.Errorf("expected role to have a get and list rule")
	}

	// get role
	getRole := &authorizationv1.Role{}
	err = clusterAdmin.Authorization().RESTClient().Get().AbsPath(rolesPath).Name(testRole).Do().Into(getRole)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if getRole.Name != testRole {
		t.Errorf("expected %s role, got %s instead", testRole, getRole.Name)
	}

	// delete role
	err = clusterAdmin.Authorization().RESTClient().Delete().AbsPath(rolesPath).Name(testRole).Do().Error()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// confirm deletion
	getRole = &authorizationv1.Role{}
	err = clusterAdmin.Authorization().RESTClient().Get().AbsPath(rolesPath).Name(testRole).Do().Into(getRole)
	if err == nil {
		t.Errorf("expected error")
	} else if !kapierror.IsNotFound(err) {
		t.Errorf("unexpected error: %v", err)
	}
}
