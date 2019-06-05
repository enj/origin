package rbac

import (
	"context"
	"strings"
	"time"

	g "github.com/onsi/ginkgo"
	o "github.com/onsi/gomega"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	kuser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/apis/apps"
	kauthenticationapi "k8s.io/kubernetes/pkg/apis/authentication"
	kauthorizationapi "k8s.io/kubernetes/pkg/apis/authorization"
	"k8s.io/kubernetes/pkg/apis/autoscaling"
	"k8s.io/kubernetes/pkg/apis/batch"
	"k8s.io/kubernetes/pkg/apis/certificates"
	"k8s.io/kubernetes/pkg/apis/coordination"
	kapi "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/apis/policy"
	"k8s.io/kubernetes/pkg/apis/rbac"
	rbacv1helpers "k8s.io/kubernetes/pkg/apis/rbac/v1"
	"k8s.io/kubernetes/pkg/apis/settings"
	"k8s.io/kubernetes/pkg/apis/storage"
	rbacutil "k8s.io/kubernetes/pkg/kubectl/util/rbac"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
	e2e "k8s.io/kubernetes/test/e2e/framework"

	oapps "github.com/openshift/api/apps"
	"github.com/openshift/api/authorization"
	"github.com/openshift/api/build"
	"github.com/openshift/api/config"
	"github.com/openshift/api/image"
	"github.com/openshift/api/network"
	"github.com/openshift/api/oauth"
	"github.com/openshift/api/project"
	"github.com/openshift/api/quota"
	"github.com/openshift/api/route"
	"github.com/openshift/api/security"
	"github.com/openshift/api/template"
	"github.com/openshift/api/user"
	"github.com/openshift/origin/pkg/api/legacy"
	"github.com/openshift/origin/pkg/cmd/openshift-apiserver/openshiftapiserver"
	"github.com/openshift/origin/pkg/cmd/server/bootstrappolicy"
	exutil "github.com/openshift/origin/test/extended/util"
)

var (
	readWrite = []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}
	read      = []string{"get", "list", "watch"}

	kapiGroup                  = kapi.GroupName
	admissionRegistrationGroup = "admissionregistration.k8s.io"
	appsGroup                  = apps.GroupName
	autoscalingGroup           = autoscaling.GroupName
	apiExtensionsGroup         = "apiextensions.k8s.io"
	eventsGroup                = "events.k8s.io"
	apiRegistrationGroup       = "apiregistration.k8s.io"
	batchGroup                 = batch.GroupName
	certificatesGroup          = certificates.GroupName
	coordinationGroup          = coordination.GroupName
	extensionsGroup            = extensions.GroupName
	networkingGroup            = "networking.k8s.io"
	nodeGroup                  = "node.k8s.io"
	policyGroup                = policy.GroupName
	rbacGroup                  = rbac.GroupName
	storageGroup               = storage.GroupName
	settingsGroup              = settings.GroupName
	schedulingGroup            = "scheduling.k8s.io"
	kAuthzGroup                = kauthorizationapi.GroupName
	kAuthnGroup                = kauthenticationapi.GroupName

	deployGroup         = oapps.GroupName
	authzGroup          = authorization.GroupName
	buildGroup          = build.GroupName
	configGroup         = config.GroupName
	imageGroup          = image.GroupName
	networkGroup        = network.GroupName
	oauthGroup          = oauth.GroupName
	projectGroup        = project.GroupName
	quotaGroup          = quota.GroupName
	routeGroup          = route.GroupName
	securityGroup       = security.GroupName
	templateGroup       = template.GroupName
	userGroup           = user.GroupName
	legacyAuthzGroup    = legacy.GroupName
	legacyBuildGroup    = legacy.GroupName
	legacyDeployGroup   = legacy.GroupName
	legacyImageGroup    = legacy.GroupName
	legacyProjectGroup  = legacy.GroupName
	legacyQuotaGroup    = legacy.GroupName
	legacyRouteGroup    = legacy.GroupName
	legacyTemplateGroup = legacy.GroupName
	legacyUserGroup     = legacy.GroupName
	legacyOauthGroup    = legacy.GroupName
	legacyNetworkGroup  = legacy.GroupName
	legacySecurityGroup = legacy.GroupName
)

var allAuthenticatedRules = []rbacv1.PolicyRule{
	rbacv1helpers.NewRule("get", "create").Groups(buildGroup, legacyBuildGroup).Resources("buildconfigs/webhooks").RuleOrDie(),

	rbacv1helpers.NewRule("create").Groups(buildGroup, legacyBuildGroup).Resources(bootstrappolicy.DockerBuildResource, bootstrappolicy.OptimizedDockerBuildResource).RuleOrDie(),
	rbacv1helpers.NewRule("create").Groups(buildGroup, legacyBuildGroup).Resources(bootstrappolicy.JenkinsPipelineBuildResource).RuleOrDie(),
	rbacv1helpers.NewRule("create").Groups(buildGroup, legacyBuildGroup).Resources(bootstrappolicy.SourceBuildResource).RuleOrDie(),

	rbacv1helpers.NewRule("impersonate").Groups(kAuthnGroup).Resources("userextras/scopes.authorization.openshift.io").RuleOrDie(),

	rbacv1helpers.NewRule("get").Groups(userGroup, legacyUserGroup).Resources("users").Names("~").RuleOrDie(),
	rbacv1helpers.NewRule("list").Groups(projectGroup, legacyProjectGroup).Resources("projectrequests").RuleOrDie(),
	rbacv1helpers.NewRule("get", "list").Groups(authzGroup, legacyAuthzGroup).Resources("clusterroles").RuleOrDie(),
	rbacv1helpers.NewRule(read...).Groups(rbacGroup).Resources("clusterroles").RuleOrDie(),
	rbacv1helpers.NewRule("get", "list").Groups(storageGroup).Resources("storageclasses").RuleOrDie(),
	rbacv1helpers.NewRule("list", "watch").Groups(projectGroup, legacyProjectGroup).Resources("projects").RuleOrDie(),
	rbacv1helpers.NewRule("create").Groups(authzGroup, legacyAuthzGroup).Resources("selfsubjectrulesreviews").RuleOrDie(),
	rbacv1helpers.NewRule("create").Groups(kAuthzGroup).Resources("selfsubjectaccessreviews").RuleOrDie(),

	rbacv1helpers.NewRule("delete").Groups(oauthGroup, legacyOauthGroup).Resources("oauthaccesstokens", "oauthauthorizetokens").RuleOrDie(),

	rbacv1helpers.NewRule("get").URLs(
		"/healthz/",
		"/version/*",
		"/oapi", "/oapi/*",
		"/openapi/v2",
		"/swaggerapi", "/swaggerapi/*", "/swagger.json", "/swagger-2.0.0.pb-v1",
		"/osapi", "/osapi/",
		"/.well-known", "/.well-known/*",
		"/",
	).RuleOrDie(),

	rbacv1helpers.NewRule("get").URLs(
		"/healthz", "/version", "/version/",
		"/openapi", "/openapi/*",
		"/api", "/api/*",
		"/apis", "/apis/*",
	).RuleOrDie(),

	rbacv1helpers.NewRule("get").URLs(
		"/readyz",
	).RuleOrDie(),

	rbacv1helpers.NewRule("create").Groups(kAuthzGroup).Resources("selfsubjectaccessreviews", "selfsubjectrulesreviews").RuleOrDie(),
}

var _ = g.Describe("The default cluster RBAC policy", func() {
	defer g.GinkgoRecover()

	oc := exutil.NewCLI("default-rbac-policy", exutil.KubeConfigPath())

	g.It("aa should only allow the system:authenticated group to access certain policy rules cluster wide", func() {
		crbs, err := oc.AdminKubeClient().RbacV1().ClusterRoleBindings().List(metav1.ListOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		crs, err := oc.AdminKubeClient().RbacV1().ClusterRoles().List(metav1.ListOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		refs := getMatchingCRBRefs(crbs.Items, authenticatedGroup)

		rules := getRules(crs.Items, refs)

		_ = rules

	})

	g.It("should only allow the system:authenticated group to access certain policy rules cluster wide", func() {
		kubeInformers := informers.NewSharedInformerFactory(oc.AdminKubeClient(), 20*time.Minute)
		ruleResolver := openshiftapiserver.NewRuleResolver(kubeInformers.Rbac().V1()) // signal what informers we want to use early

		stopCh := make(chan struct{})
		defer func() { close(stopCh) }()
		kubeInformers.Start(stopCh)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if ok := cache.WaitForCacheSync(ctx.Done(),
			kubeInformers.Rbac().V1().ClusterRoles().Informer().HasSynced,
			kubeInformers.Rbac().V1().ClusterRoleBindings().Informer().HasSynced,
			kubeInformers.Rbac().V1().Roles().Informer().HasSynced,
			kubeInformers.Rbac().V1().RoleBindings().Informer().HasSynced,
		); !ok {
			exutil.FatalErr("todo1")
		}

		servantRules, err := ruleResolver.RulesFor(&kuser.DefaultInfo{Groups: []string{kuser.AllAuthenticated}}, metav1.NamespaceNone)
		o.Expect(err).NotTo(o.HaveOccurred()) // our default RBAC policy should never have rule resolution errors

		if ownerRightsCover, missingRights := validation.Covers(allAuthenticatedRules, servantRules); !ownerRightsCover {
			compactMissingRights := missingRights
			if compact, err := validation.CompactRules(missingRights); err == nil {
				compactMissingRights = compact
			}

			missingDescriptions := sets.NewString()
			for _, missing := range compactMissingRights {
				missingDescriptions.Insert(rbacv1helpers.CompactString(missing))
			}

			exutil.FatalErr("todo2:\n" + strings.Join(missingDescriptions.List(), "\n"))
		}

		if ownerRightsCover, missingRights := validation.Covers(servantRules, allAuthenticatedRules); !ownerRightsCover {
			compactMissingRights := missingRights
			if compact, err := validation.CompactRules(missingRights); err == nil {
				compactMissingRights = compact
			}

			missingDescriptions := sets.NewString()
			for _, missing := range compactMissingRights {
				missingDescriptions.Insert(rbacv1helpers.CompactString(missing))
			}

			exutil.FatalErr("todo3:\n%s" + strings.Join(missingDescriptions.List(), "\n"))
		}
	})
})

var authenticatedGroup = rbacv1.Subject{
	Kind:      rbacv1.GroupKind,
	APIGroup:  rbacv1.GroupName,
	Name:      kuser.AllAuthenticated,
	Namespace: "",
}

func getMatchingCRBRefs(crbs []rbacv1.ClusterRoleBinding, target rbacv1.Subject) []string {
	var refs []string

	for _, crb := range crbs {
		for _, subject := range crb.Subjects {
			if subject == target {
				refs = append(refs, crb.RoleRef.Name)
			}
		}
	}

	return refs
}

func getRules(crs []rbacv1.ClusterRole, refs []string) []rbacv1.PolicyRule {
	var rules []rbacv1.PolicyRule

	names := sets.NewString(refs...)

	for _, cr := range crs {
		if names.Has(cr.Name) {
			rules = append(rules, cr.Rules...)
		}
		names.Delete(cr.Name)
	}

	if len(names) != 0 {
		e2e.Failf("failed to get complete list of policy rules for cluster roles: %v", names.List())
	}

	_, _ = rbacutil.CompactRules(nil)
	_, _ = validation.CompactRules(nil)

	return rules
}
