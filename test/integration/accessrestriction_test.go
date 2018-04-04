package integration

import (
	"strings"
	"testing"
	"time"

	"github.com/openshift/origin/pkg/authorization/apis/authorization"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/pkg/apis/rbac"
	rbacinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/rbac/internalversion"

	"github.com/openshift/api/authorization/v1alpha1"
	authorizationinternalversion "github.com/openshift/origin/pkg/authorization/generated/internalclientset/typed/authorization/internalversion"
	testutil "github.com/openshift/origin/test/util"
	testserver "github.com/openshift/origin/test/util/server"
)

func TestAccessRestrictionEscalationCheck(t *testing.T) {
	masterConfig, clusterAdminKubeConfig, err := testserver.StartTestMasterAPI()
	if err != nil {
		t.Fatal(err)
	}
	defer testserver.CleanupMasterEtcd(t, masterConfig)
	clusterAdminClientConfig, err := testutil.GetClusterAdminClientConfig(clusterAdminKubeConfig)
	if err != nil {
		t.Fatal(err)
	}
	rbacClient := rbacinternalversion.NewForConfigOrDie(clusterAdminClientConfig)

	clusterRoleName := "almost-cluster-admin" // can do everything except URLs so still not enough for escalation check
	user := "mo"

	if _, err := rbacClient.ClusterRoles().Create(&rbac.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: clusterRoleName},
		Rules: []rbac.PolicyRule{
			rbac.NewRule(rbac.VerbAll).Groups(rbac.APIGroupAll).Resources(rbac.ResourceAll).RuleOrDie(),
		},
	}); err != nil {
		t.Fatal(err)
	}

	clusterRoleBinding := rbac.NewClusterBinding(clusterRoleName).Users(user).BindingOrDie()
	if _, err := rbacClient.ClusterRoleBindings().Create(&clusterRoleBinding); err != nil {
		t.Fatal(err)
	}

	_, userConfig, err := testutil.GetClientForUser(clusterAdminClientConfig, user)
	if err != nil {
		t.Fatal(err)
	}

	// TODO generate + vendor client-go and use the v1alpha1 client here
	gv := v1alpha1.SchemeGroupVersion
	userConfig.GroupVersion = &gv
	accessRestrictionClient := authorizationinternalversion.NewForConfigOrDie(userConfig).AccessRestrictions()

	if err := wait.ExponentialBackoff(
		wait.Backoff{
			Steps:    30,
			Duration: time.Second,
		},
		func() (done bool, err error) {
			if _, err := accessRestrictionClient.List(metav1.ListOptions{}); err != nil {
				if errors.IsUnauthorized(err) {
					return false, nil
				}
				return false, err
			}
			return true, nil
		}); err != nil {
		t.Fatalf("failed to list access restriction as user: %#v", err)
	}

	_, err = accessRestrictionClient.Create(&authorization.AccessRestriction{
		ObjectMeta: metav1.ObjectMeta{
			Name: "does-not-matter",
		},
		Spec: authorization.AccessRestrictionSpec{
			MatchAttributes: []rbac.PolicyRule{
				rbac.NewRule(rbac.VerbAll).Groups(rbac.APIGroupAll).Resources(rbac.ResourceAll).RuleOrDie(),
			},
			DeniedSubjects: []authorization.SubjectMatcher{
				{
					UserRestriction: &authorization.UserRestriction{
						Users: []string{"bad-user"},
					},
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected non-nil create error for access restriction")
	}
	if !errors.IsForbidden(err) || !strings.Contains(err.Error(), "must have cluster-admin privileges to write access restrictions") {
		t.Fatalf("expected forbidden error for access restrction create: %#v", err)
	}
}
