package integration

import (
	"strings"
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/pkg/apis/rbac"
	rbacinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/rbac/internalversion"

	authorizationv1 "github.com/openshift/api/authorization/v1"
	authorizationv1alpha1 "github.com/openshift/api/authorization/v1alpha1"
	authorizationv1alpha1clientset "github.com/openshift/client-go/authorization/clientset/versioned/typed/authorization/v1alpha1"
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
	clusterAdminAccessRestrictionClient := authorizationv1alpha1clientset.NewForConfigOrDie(clusterAdminClientConfig).AccessRestrictions()

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
	userAccessRestrictionClient := authorizationv1alpha1clientset.NewForConfigOrDie(userConfig).AccessRestrictions()

	// wait for rbac to catch up
	if err := wait.ExponentialBackoff(
		wait.Backoff{
			Steps:    30,
			Duration: time.Second,
		},
		func() (done bool, err error) {
			if _, err := userAccessRestrictionClient.List(metav1.ListOptions{}); err != nil {
				if errors.IsForbidden(err) {
					return false, nil
				}
				return false, err
			}
			return true, nil
		}); err != nil {
		t.Fatalf("failed to list access restriction as user: %#v", err)
	}

	accessRestriction := &authorizationv1alpha1.AccessRestriction{
		ObjectMeta: metav1.ObjectMeta{
			Name: "does-not-matter",
		},
		Spec: authorizationv1alpha1.AccessRestrictionSpec{
			MatchAttributes: []rbacv1.PolicyRule{
				{
					Verbs:     []string{rbacv1.VerbAll},
					APIGroups: []string{rbacv1.APIGroupAll},
					Resources: []string{rbacv1.ResourceAll},
				},
			},
			DeniedSubjects: []authorizationv1alpha1.SubjectMatcher{
				{
					UserRestriction: &authorizationv1.UserRestriction{
						Users: []string{"bad-user"},
					},
				},
			},
		},
	}

	_, err = userAccessRestrictionClient.Create(accessRestriction)
	if err == nil {
		t.Fatal("expected non-nil create error for access restriction")
	}
	if !errors.IsForbidden(err) || !strings.Contains(err.Error(), "must have cluster-admin privileges to write access restrictions") {
		t.Fatalf("expected forbidden error for access restrction create: %#v", err)
	}

	if accessRestriction, err = clusterAdminAccessRestrictionClient.Create(accessRestriction); err != nil {
		t.Fatalf("unexpected error for access restrction create as system:masters: %#v", err)
	}

	// delete the permissions of all users so only system:masters can do anything
	if err := rbacClient.ClusterRoleBindings().DeleteCollection(nil, metav1.ListOptions{}); err != nil {
		t.Fatal(err)
	}

	// wait for rbac to catch up
	if err := wait.ExponentialBackoff(
		wait.Backoff{
			Steps:    30,
			Duration: time.Second,
		},
		func() (done bool, err error) {
			_, err = userAccessRestrictionClient.List(metav1.ListOptions{})
			if errors.IsForbidden(err) {
				return true, nil
			}
			return false, err
		}); err != nil {
		t.Fatalf("failed to revoke right for user: %#v", err)
	}

	// make sure system:masters can still pass the escalation check even with no RBAC rules
	expectedDeniedUser := "other-user"
	accessRestriction.Spec.DeniedSubjects[0].UserRestriction.Users[0] = expectedDeniedUser
	if updatedAccessRestriction, err := clusterAdminAccessRestrictionClient.Update(accessRestriction); err != nil {
		t.Fatalf("failed to update access restriction as system:masters: %#v", err)
	} else {
		if actualDeniedUser := updatedAccessRestriction.Spec.DeniedSubjects[0].UserRestriction.Users[0]; expectedDeniedUser != actualDeniedUser {
			t.Fatalf("updated access restriction does not match, expected %s, actual %s", expectedDeniedUser, actualDeniedUser)
		}
	}
}
