package util

import (
	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/pkg/util/sets"

	"github.com/openshift/origin/pkg/authorization/api"
)

func ConvertOriginClusterRole(in *api.ClusterRole) *rbac.ClusterRole {
	return &rbac.ClusterRole{
		ObjectMeta: in.ObjectMeta,
		Rules:      convertOriginPolicyRule(in.Rules),
	}
}

func ConvertOriginRole(in *api.Role) *rbac.Role {
	return &rbac.Role{
		ObjectMeta: in.ObjectMeta,
		Rules:      convertOriginPolicyRule(in.Rules),
	}
}

func ConvertOriginClusterRoleBinding(in *api.ClusterRoleBinding) *rbac.ClusterRoleBinding {
	return &rbac.ClusterRoleBinding{
		ObjectMeta: in.ObjectMeta,
		Subjects:   convertOriginSubjects(in.Subjects),
		RoleRef:    convertOriginRoleRef(&in.RoleRef),
	}
}

func ConvertOriginRoleBinding(in *api.RoleBinding) *rbac.RoleBinding {
	return &rbac.RoleBinding{
		ObjectMeta: in.ObjectMeta,
		Subjects:   convertOriginSubjects(in.Subjects),
		RoleRef:    convertOriginRoleRef(&in.RoleRef),
	}
}

func convertOriginPolicyRule(in []api.PolicyRule) []rbac.PolicyRule {
	rules := make([]rbac.PolicyRule, 0, len(in))
	for _, rule := range in {
		r := rbac.PolicyRule{
			APIGroups:       rule.APIGroups,
			Verbs:           rule.Verbs.List(),
			Resources:       rule.Resources.List(),
			ResourceNames:   rule.ResourceNames.List(),
			NonResourceURLs: rule.NonResourceURLs.List(),
		}
		rules = append(rules, r)
	}
	return rules
}

func convertOriginSubjects(in []kapi.ObjectReference) []rbac.Subject {
	subjects := make([]rbac.Subject, 0, len(in))
	for _, subject := range in {
		s := rbac.Subject{
			Kind:       subject.Kind,
			APIVersion: subject.APIVersion,
			Name:       subject.Name,
			Namespace:  subject.Namespace,
		}
		subjects = append(subjects, s)
	}
	return subjects
}

func convertOriginRoleRef(in *kapi.ObjectReference) rbac.RoleRef {
	return rbac.RoleRef{
		APIGroup: in.APIVersion,
		Kind:     in.Kind,
		Name:     in.Name,
	}
}

func ConvertRBACClusterRole(in *rbac.ClusterRole) *api.ClusterRole {
	return &api.ClusterRole{
		ObjectMeta: in.ObjectMeta,
		Rules:      convertRBACPolicyRules(in.Rules),
	}
}

func ConvertRBACRole(in *rbac.Role) *api.Role {
	return &api.Role{
		ObjectMeta: in.ObjectMeta,
		Rules:      convertRBACPolicyRules(in.Rules),
	}
}

func ConvertRBACClusterRoleBinding(in *rbac.ClusterRoleBinding) *api.ClusterRoleBinding {
	return &api.ClusterRoleBinding{
		ObjectMeta: in.ObjectMeta,
		Subjects:   convertRBACSubjects(in.Subjects),
		RoleRef:    convertRBACRoleRef(&in.RoleRef),
	}
}

func ConvertRBACRoleBinding(in *rbac.RoleBinding) *api.RoleBinding {
	return &api.RoleBinding{
		ObjectMeta: in.ObjectMeta,
		Subjects:   convertRBACSubjects(in.Subjects),
		RoleRef:    convertRBACRoleRef(&in.RoleRef),
	}
}

func convertRBACSubjects(in []rbac.Subject) []kapi.ObjectReference {
	subjects := make([]kapi.ObjectReference, 0, len(in))
	for _, subject := range in {
		s := kapi.ObjectReference{
			Kind:       subject.Kind,
			APIVersion: subject.APIVersion,
			Name:       subject.Name,
			Namespace:  subject.Namespace,
		}
		subjects = append(subjects, s)
	}
	return subjects
}

func convertRBACRoleRef(in *rbac.RoleRef) kapi.ObjectReference {
	return kapi.ObjectReference{
		APIVersion: in.APIGroup,
		Kind:       in.Kind,
		Name:       in.Name,
	}
}

func convertRBACPolicyRules(in []rbac.PolicyRule) []api.PolicyRule {
	rules := make([]api.PolicyRule, 0, len(in))
	for _, rule := range in {
		r := api.PolicyRule{
			APIGroups:       rule.APIGroups,
			Verbs:           sets.NewString(rule.Verbs...),
			Resources:       sets.NewString(rule.Resources...),
			ResourceNames:   sets.NewString(rule.ResourceNames...),
			NonResourceURLs: sets.NewString(rule.NonResourceURLs...),
		}
		rules = append(rules, r)
	}
	return rules
}
