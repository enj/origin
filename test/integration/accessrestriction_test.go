package integration

import (
	"strings"
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/kubernetes/pkg/apis/batch"
	kapi "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/rbac"
	kcoreclient "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/core/internalversion"
	rbacinternalversion "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/rbac/internalversion"

	authorizationv1 "github.com/openshift/api/authorization/v1"
	authorizationv1alpha1 "github.com/openshift/api/authorization/v1alpha1"
	userv1 "github.com/openshift/api/user/v1"
	authorizationv1alpha1clientset "github.com/openshift/client-go/authorization/clientset/versioned/typed/authorization/v1alpha1"
	userv1clientset "github.com/openshift/client-go/user/clientset/versioned/typed/user/v1"
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

func TestAccessRestrictionAuthorizer(t *testing.T) {
	masterConfig, clusterAdminKubeConfig, err := testserver.StartTestMasterAPI()
	if err != nil {
		t.Fatal(err)
	}
	defer testserver.CleanupMasterEtcd(t, masterConfig)
	clusterAdminClientConfig, err := testutil.GetClusterAdminClientConfig(clusterAdminKubeConfig)
	if err != nil {
		t.Fatal(err)
	}
	clusterAdminAccessRestrictionClient := authorizationv1alpha1clientset.NewForConfigOrDie(clusterAdminClientConfig).AccessRestrictions()
	clusterAdminUserAPIClient := userv1clientset.NewForConfigOrDie(clusterAdminClientConfig)
	clusterAdminUserClient := clusterAdminUserAPIClient.Users()
	clusterAdminGroupClient := clusterAdminUserAPIClient.Groups()

	accessRestrictionWatch, err := clusterAdminAccessRestrictionClient.Watch(metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer accessRestrictionWatch.Stop()

	userWatch, err := clusterAdminUserClient.Watch(metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer userWatch.Stop()

	groupWatch, err := clusterAdminGroupClient.Watch(metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer groupWatch.Stop()

	jobGroup := "can-write-jobs"

	// make sure none of these restrictions intersect
	accessRestrictions := []*authorizationv1alpha1.AccessRestriction{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "whitelist-write-jobs",
			},
			Spec: authorizationv1alpha1.AccessRestrictionSpec{
				MatchAttributes: []rbacv1.PolicyRule{
					{
						Verbs:     []string{"create", "update", "patch", "delete", "deletecollection"},
						APIGroups: []string{"batch"},
						Resources: []string{"jobs"},
					},
				},
				AllowedSubjects: []authorizationv1alpha1.SubjectMatcher{
					{
						GroupRestriction: &authorizationv1.GroupRestriction{
							Groups: []string{jobGroup},
						},
					},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name: "blacklist-label-user-get-pods",
			},
			Spec: authorizationv1alpha1.AccessRestrictionSpec{
				MatchAttributes: []rbacv1.PolicyRule{
					{
						Verbs:     []string{"list"},
						APIGroups: []string{""},
						Resources: []string{"pods"},
					},
				},
				DeniedSubjects: []authorizationv1alpha1.SubjectMatcher{
					{
						UserRestriction: &authorizationv1.UserRestriction{
							Selectors: []metav1.LabelSelector{
								{
									MatchLabels: map[string]string{
										"bad": "yes",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, accessRestriction := range accessRestrictions {
		if _, err := clusterAdminAccessRestrictionClient.Create(accessRestriction); err != nil {
			t.Fatal(err)
		}
	}

	accessRestrictionEvents := accessRestrictionWatch.ResultChan()
	for range accessRestrictions {
		checkWatch(t, accessRestrictionEvents, watch.Added, func(object runtime.Object) {
			if _, ok := object.(*authorizationv1alpha1.AccessRestriction); !ok {
				t.Fatalf("unexpected object %T", object)
			}
		})
	}

	project := "mo-project"
	user := "mo"

	moClient, _, err := testserver.CreateNewProject(clusterAdminClientConfig, project, user)
	if err != nil {
		t.Fatal(err)
	}
	var moUser *userv1.User
	userWatchEvents := userWatch.ResultChan()
	checkWatch(t, userWatchEvents, watch.Added, func(obj runtime.Object) {
		var ok bool
		if moUser, ok = obj.(*userv1.User); !ok {
			t.Fatalf("unexpected object %T", obj)
		}
	})

	moSelfSar := moClient.Authorization()
	moJobs := moClient.Batch().Jobs(project)

	{
		// read jobs works
		if _, err := moJobs.List(metav1.ListOptions{}); err != nil {
			t.Fatalf("cannot list jobs as normal user: %#v", err)
		}

		if err := testutil.WaitForPolicyUpdate(moSelfSar, project, "create", schema.GroupResource{Group: "batch", Resource: "jobs"}, false); err != nil {
			t.Fatalf("user permissions not updated to reflect access restrictions: %#v", err)
		}

		// write jobs fails
		_, err = moJobs.Create(&batch.Job{})
		checkAccessRestrictionError(t, err)
	}

	{
		// add user to write jobs group
		if _, err := clusterAdminGroupClient.Create(&userv1.Group{
			ObjectMeta: metav1.ObjectMeta{Name: jobGroup},
			Users:      userv1.OptionalNames{user},
		}); err != nil {
			t.Fatal(err)
		}
		groupWatchEvents := groupWatch.ResultChan()
		checkWatch(t, groupWatchEvents, watch.Added, func(object runtime.Object) {
			eventGroup, ok := object.(*userv1.Group)
			if !ok {
				t.Fatalf("unexpected object %T", object)
			}
			if eventGroup.Users[0] != user {
				t.Fatalf("group is missing user: %#v", eventGroup)
			}
			if err := testutil.WaitForPolicyUpdate(moSelfSar, project, "create", schema.GroupResource{Group: "batch", Resource: "jobs"}, true); err != nil {
				t.Fatalf("user permissions not updated to reflect group membership: %#v", err)
			}
		})

		validJob := &batch.Job{
			ObjectMeta: metav1.ObjectMeta{Name: "myjob"},
			Spec: batch.JobSpec{
				Template: kapi.PodTemplateSpec{
					Spec: kapi.PodSpec{
						Containers:    []kapi.Container{{Name: "mycontainer", Image: "myimage"}},
						RestartPolicy: kapi.RestartPolicyNever,
					},
				},
			},
		}

		// write jobs works after being added to correct group
		if _, err := moJobs.Create(validJob); err != nil {
			t.Fatalf("cannot write jobs as grouped user: %#v", err)
		}
	}

	{
		// list works before labeling
		moPods := moClient.Core().Pods(project)
		if _, err := moPods.List(metav1.ListOptions{}); err != nil {
			t.Fatalf("unexpected list error as unlabeled user: %#v", err)
		}

		// label user to match restriction
		moUser.Labels = map[string]string{
			"bad": "yes",
		}
		if _, err := clusterAdminUserClient.Update(moUser); err != nil {
			t.Fatal(err)
		}
		checkWatch(t, userWatchEvents, watch.Modified, func(object runtime.Object) {
			eventUser, ok := object.(*userv1.User)
			if !ok {
				t.Fatalf("unexpected object %T", object)
			}
			if eventUser.Labels["bad"] != "yes" {
				t.Fatalf("user labels do not match: %#v", eventUser)
			}
		})

		if err := testutil.WaitForPolicyUpdate(moSelfSar, project, "list", schema.GroupResource{Group: "", Resource: "pods"}, false); err != nil {
			t.Fatalf("user permissions not updated to reflect group membership: %#v", err)
		}

		// list is forbidden after labeling
		_, err = moPods.List(metav1.ListOptions{})
		checkAccessRestrictionError(t, err)

		// impersonating client is also forbidden
		clusterAdminClientConfigCopy := *clusterAdminClientConfig
		clusterAdminClientConfigCopy.Impersonate.UserName = user
		impersonateMoPods := kcoreclient.NewForConfigOrDie(&clusterAdminClientConfigCopy).Pods(project)
		_, err = impersonateMoPods.List(metav1.ListOptions{})
		checkAccessRestrictionError(t, err)
	}
}

func checkWatch(t *testing.T, c <-chan watch.Event, eventType watch.EventType, check func(runtime.Object)) {
	t.Helper()
	select {
	case event := <-c:
		if eventType != event.Type {
			t.Fatalf("wrong watch event type, expected %v, actual %v", eventType, event.Type)
		}
		check(event.Object)
	case <-time.After(10 * time.Second):
		t.Fatal("failed to see all access restrictions")
	}
}

func checkAccessRestrictionError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !errors.IsForbidden(err) || !strings.Contains(err.Error(), "denied by access restriction") {
		t.Fatalf("expected forbidden error: %#v", err)
	}
}
