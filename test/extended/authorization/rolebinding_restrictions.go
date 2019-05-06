package authorization

import (
	"context"
	"fmt"
	"time"

	g "github.com/onsi/ginkgo"
	o "github.com/onsi/gomega"

	rbacv1 "k8s.io/api/rbac/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
	kapi "k8s.io/kubernetes/pkg/apis/core"

	authorizationapi "github.com/openshift/origin/pkg/authorization/apis/authorization"
	exutil "github.com/openshift/origin/test/extended/util"
)

var _ = g.Describe("[Feature: RoleBinding Restrictions] RoleBindingRestrictions should be functional", func() {
	defer g.GinkgoRecover()
	oc := exutil.NewCLI("rolebinding-restrictions", exutil.KubeConfigPath())
	g.Context("", func() {
		g.Describe("Create a rolebinding when there are no restrictions", func() {
			g.It(fmt.Sprintf("should succeed"), func() {
				ns := oc.Namespace()
				user := "alice"
				_, err := oc.AdminAuthorizationClient().Authorization().RoleBindings(ns).Create(generateRolebinding(ns, user, "rb1"))
				o.Expect(err).NotTo(o.HaveOccurred())
			})
		})

		g.Describe("Create a rolebinding when subject is permitted by RBR", func() {
			g.It(fmt.Sprintf("should succeed"), func() {
				ns := oc.Namespace()
				user := "bob"
				rbr, err := oc.AdminAuthorizationClient().Authorization().RoleBindingRestrictions(ns).Create(generateAllowUserRolebindingRestriction(ns, user))
				o.Expect(err).NotTo(o.HaveOccurred())
				err = waitForRBR(ns, rbr, oc)
				o.Expect(err).NotTo(o.HaveOccurred())
				_, err = oc.AdminAuthorizationClient().Authorization().RoleBindings(ns).Create(generateRolebinding(ns, user, "rb1"))
				o.Expect(err).NotTo(o.HaveOccurred())
			})
		})

		g.Describe("Create a rolebinding when subject is already bound", func() {
			g.It(fmt.Sprintf("should succeed"), func() {
				user := "cindy"
				ns := oc.Namespace()
				_, err := oc.AdminAuthorizationClient().Authorization().RoleBindings(ns).Create(generateRolebinding(ns, user, "rb1"))
				o.Expect(err).NotTo(o.HaveOccurred())
				rbr, err := oc.AdminAuthorizationClient().Authorization().RoleBindingRestrictions(ns).Create(generateAllowUserRolebindingRestriction(ns, user))
				o.Expect(err).NotTo(o.HaveOccurred())
				err = waitForRBR(ns, rbr, oc)
				o.Expect(err).NotTo(o.HaveOccurred())
				_, err = oc.AdminAuthorizationClient().Authorization().RoleBindings(ns).Create(generateRolebinding(ns, user, "rb2"))
				o.Expect(err).NotTo(o.HaveOccurred())
			})
		})

		g.Describe("Create a rolebinding when subject is not already bound and is not permitted by any RBR", func() {
			g.It(fmt.Sprintf("should fail"), func() {
				ns := oc.Namespace()
				user1 := "dave"
				user2 := "eve"
				_, err := oc.AdminAuthorizationClient().Authorization().RoleBindings(ns).Create(generateRolebinding(ns, user1, "rb1"))
				o.Expect(err).NotTo(o.HaveOccurred())
				rbr, err := oc.AdminAuthorizationClient().Authorization().RoleBindingRestrictions(ns).Create(generateAllowUserRolebindingRestriction(ns, user1))
				o.Expect(err).NotTo(o.HaveOccurred())
				err = waitForRBR(ns, rbr, oc)
				o.Expect(err).NotTo(o.HaveOccurred())
				_, err = oc.AdminAuthorizationClient().Authorization().RoleBindings(ns).Create(generateRolebinding(ns, user2, "rb2"))
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(kerrors.IsForbidden(err)).To(o.BeTrue())
				expectedErrorString := fmt.Sprintf("rolebindings to User \"%s\" are not allowed in project", user2)
				o.Expect(err.Error()).Should(o.ContainSubstring(expectedErrorString))
			})
		})

		g.Describe("Create a RBAC rolebinding when subject is not already bound and is not permitted by any RBR", func() {
			g.It(fmt.Sprintf("should fail"), func() {
				ns := oc.Namespace()
				user1 := "frank"
				user2 := "george"
				_, err := oc.AdminAuthorizationClient().Authorization().RoleBindings(ns).Create(generateRolebinding(ns, user1, "rb1"))
				o.Expect(err).NotTo(o.HaveOccurred())
				rbr, err := oc.AdminAuthorizationClient().Authorization().RoleBindingRestrictions(ns).Create(generateAllowUserRolebindingRestriction(ns, user1))
				o.Expect(err).NotTo(o.HaveOccurred())
				err = waitForRBR(ns, rbr, oc)
				o.Expect(err).NotTo(o.HaveOccurred())
				_, err = oc.AdminKubeClient().RbacV1().RoleBindings(ns).Create(generateRbacUserRolebinding(ns, user2, "rb2"))
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(kerrors.IsForbidden(err)).To(o.BeTrue())
				expectedErrorString := fmt.Sprintf("rolebindings to User \"%s\" are not allowed in project", user2)
				o.Expect(err.Error()).Should(o.ContainSubstring(expectedErrorString))
			})
		})

		g.Describe("Create a rolebinding that also contains system:non-existing users", func() {
			g.It(fmt.Sprintf("should succeed"), func() {
				ns := oc.Namespace()
				user := "harry"
				rbr, err := oc.AdminAuthorizationClient().Authorization().RoleBindingRestrictions(ns).Create(generateRBRnonExist(ns, user))
				o.Expect(err).NotTo(o.HaveOccurred())
				err = waitForRBR(ns, rbr, oc)
				o.Expect(err).NotTo(o.HaveOccurred())
				_, err = oc.AdminAuthorizationClient().Authorization().RoleBindings(ns).Create(generateRolebinding(ns, user, "rb1"))
				o.Expect(err).NotTo(o.HaveOccurred())
				_, err = oc.AdminAuthorizationClient().Authorization().RoleBindings(ns).Create(generateRolebindingNonExisting(ns, "rb2"))
				o.Expect(err).NotTo(o.HaveOccurred())
			})
		})

		g.Describe("Rolebinding restrictions tests single project", func() {
			g.It(fmt.Sprintf("should succeed"), func() {
				ns := oc.Namespace()
				user1 := "zed"
				user2 := "yvette"
				user3 := "xavier"
				// No restrictions, rolebinding should succeed
				_, err := oc.AdminAuthorizationClient().Authorization().RoleBindings(ns).Create(generateRolebinding(ns, user1, "rb1"))
				o.Expect(err).NotTo(o.HaveOccurred())
				// Subject bound, rolebinding restriction should succeed
				rbr, err := oc.AdminAuthorizationClient().Authorization().RoleBindingRestrictions(ns).Create(generateAllowUserRolebindingRestriction(ns, user1))
				o.Expect(err).NotTo(o.HaveOccurred())
				err = waitForRBR(ns, rbr, oc)
				o.Expect(err).NotTo(o.HaveOccurred())
				// Duplicate should succeed
				_, err = oc.AdminAuthorizationClient().Authorization().RoleBindings(ns).Create(generateRolebinding(ns, user1, "rb2"))
				o.Expect(err).NotTo(o.HaveOccurred())
				// Subject not bound, not permitted by any RBR, rolebinding should fail
				_, err = oc.AdminAuthorizationClient().Authorization().RoleBindings(ns).Create(generateRolebinding(ns, user2, "rb3"))
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(kerrors.IsForbidden(err)).To(o.BeTrue())
				expectedErrorString := fmt.Sprintf("rolebindings to User \"%s\" are not allowed in project", user2)
				o.Expect(err.Error()).Should(o.ContainSubstring(expectedErrorString))
				// Subject not bound, not permitted by any RBR, RBAC rolebinding should fail
				_, err = oc.AdminKubeClient().RbacV1().RoleBindings(ns).Create(generateRbacUserRolebinding(ns, user2, "rb3"))
				o.Expect(err).To(o.HaveOccurred())
				o.Expect(kerrors.IsForbidden(err)).To(o.BeTrue())
				o.Expect(err.Error()).Should(o.ContainSubstring(expectedErrorString))
				// Create a rolebinding that also contains system:non-existing users should succeed
				_, err = oc.AdminAuthorizationClient().Authorization().RoleBindingRestrictions(ns).Create(generateRBRnonExist(ns, user3))
				o.Expect(err).NotTo(o.HaveOccurred())
				_, err = oc.AdminAuthorizationClient().Authorization().RoleBindings(ns).Create(generateRolebinding(ns, user3, "rb4"))
				o.Expect(err).NotTo(o.HaveOccurred())
				_, err = oc.AdminAuthorizationClient().Authorization().RoleBindings(ns).Create(generateRolebindingNonExisting(ns, "rb5"))
				o.Expect(err).NotTo(o.HaveOccurred())
			})
		})
	})
})

func generateAllowUserRolebindingRestriction(ns, user string) *authorizationapi.RoleBindingRestriction {
	return &authorizationapi.RoleBindingRestriction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("match-users-%s", user),
			Namespace: ns,
		},
		Spec: authorizationapi.RoleBindingRestrictionSpec{
			UserRestriction: &authorizationapi.UserRestriction{
				Users: []string{user},
			},
		},
	}
}

func generateRBRnonExist(ns, user string) *authorizationapi.RoleBindingRestriction {
	return &authorizationapi.RoleBindingRestriction{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("match-users-%s-and-non-existing", user),
			Namespace: ns,
		},
		Spec: authorizationapi.RoleBindingRestrictionSpec{
			UserRestriction: &authorizationapi.UserRestriction{
				Users: []string{user, "system:non-existing"},
			},
		},
	}
}

func generateRolebinding(ns, user, rb string) *authorizationapi.RoleBinding {
	return &authorizationapi.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      rb,
		},
		Subjects: []kapi.ObjectReference{
			{
				Kind:      authorizationapi.UserKind,
				Namespace: ns,
				Name:      user,
			},
		},
		RoleRef: kapi.ObjectReference{Name: "role", Namespace: ns},
	}
}

func generateRbacUserRolebinding(ns, user, rb string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      rb,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.UserKind,
				Namespace: ns,
				Name:      user,
			},
		},
		RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "role"},
	}
}

func generateRolebindingNonExisting(ns, rb string) *authorizationapi.RoleBinding {
	return &authorizationapi.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      rb,
		},
		Subjects: []kapi.ObjectReference{
			{
				Kind:      authorizationapi.UserKind,
				Namespace: ns,
				Name:      "system:non-existing",
			},
		},
		RoleRef: kapi.ObjectReference{Name: "role", Namespace: ns},
	}
}

func waitForRBR(ns string, rbr *authorizationapi.RoleBindingRestriction, oc *exutil.CLI) error {
	var ctx context.Context
	cancel := func() {}
	defer cancel()
	ctx, cancel = watchtools.ContextWithOptionalTimeout(context.Background(), 3*time.Minute)

	fieldSelector := fields.OneTermEqualSelector("metadata.name", rbr.Name).String()
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = fieldSelector
			return oc.AdminAuthorizationClient().Authorization().RoleBindingRestrictions(ns).List(options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = fieldSelector
			return oc.AdminAuthorizationClient().Authorization().RoleBindingRestrictions(ns).Watch(options)
		},
	}
	_, err := watchtools.UntilWithSync(ctx, lw, rbr, nil, func(event watch.Event) (b bool, e error) {
		switch t := event.Type; t {
		case watch.Added, watch.Modified:
			return true, nil

		case watch.Deleted:
			return true, fmt.Errorf("object has been deleted")

		default:
			return true, fmt.Errorf("internal error: unexpected event %#v", e)
		}
	})
	return err
}
