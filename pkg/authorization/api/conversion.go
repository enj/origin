package api

import (
	"fmt"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/pkg/conversion"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/sets"

	"github.com/openshift/origin/pkg/user/api/validation"
)

func addConversionFuncs(scheme *runtime.Scheme) error {
	if err := scheme.AddConversionFuncs(
		Convert_api_ClusterRole_To_rbac_ClusterRole,
		Convert_api_Role_To_rbac_Role,
		Convert_api_ClusterRoleBinding_To_rbac_ClusterRoleBinding,
		Convert_api_RoleBinding_To_rbac_RoleBinding,
		Convert_rbac_ClusterRole_To_api_ClusterRole,
		Convert_rbac_Role_To_api_Role,
		Convert_rbac_ClusterRoleBinding_To_api_ClusterRoleBinding,
		Convert_rbac_RoleBinding_To_api_RoleBinding,
	); err != nil { // If one of the conversion functions is malformed, detect it immediately.
		return err
	}
	return nil
}

func Convert_api_ClusterRole_To_rbac_ClusterRole(in *ClusterRole, out *rbac.ClusterRole, _ conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.Rules = convertOriginPolicyRule(in.Rules)
	return nil
}

func Convert_api_Role_To_rbac_Role(in *Role, out *rbac.Role, _ conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.Rules = convertOriginPolicyRule(in.Rules)
	return nil
}

func Convert_api_ClusterRoleBinding_To_rbac_ClusterRoleBinding(in *ClusterRoleBinding, out *rbac.ClusterRoleBinding, _ conversion.Scope) error {
	var err error
	if out.Subjects, err = convertOriginSubjects(in.Subjects); err != nil {
		return err
	}
	out.RoleRef = convertOriginRoleRef(&in.RoleRef)
	out.ObjectMeta = in.ObjectMeta
	return nil
}

func Convert_api_RoleBinding_To_rbac_RoleBinding(in *RoleBinding, out *rbac.RoleBinding, _ conversion.Scope) error {
	if len(in.RoleRef.Namespace) != 0 && in.RoleRef.Namespace != in.Namespace {
		return fmt.Errorf("invalid origin role binding %s: attempts to reference role in namespace %q instead of current namespace %q", in.Name, in.RoleRef.Namespace, in.Namespace)
	}
	var err error
	if out.Subjects, err = convertOriginSubjects(in.Subjects); err != nil {
		return err
	}
	out.RoleRef = convertOriginRoleRef(&in.RoleRef)
	out.ObjectMeta = in.ObjectMeta
	return nil
}

func convertOriginPolicyRule(in []PolicyRule) []rbac.PolicyRule {
	rules := make([]rbac.PolicyRule, 0, len(in))
	for _, rule := range in {
		r := rbac.PolicyRule{ // AttributeRestrictions is lost, but our authorizor ignores that field now
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

func convertOriginSubjects(in []api.ObjectReference) ([]rbac.Subject, error) {
	subjects := make([]rbac.Subject, 0, len(in))
	for _, subject := range in {
		s := rbac.Subject{
			Name:       subject.Name,
			APIVersion: rbac.GroupName, // TODO what to use here?
		}

		switch subject.Kind {
		case ServiceAccountKind:
			s.Kind = rbac.ServiceAccountKind
			s.Namespace = subject.Namespace
		case UserKind, SystemUserKind:
			s.Kind = rbac.UserKind
		case GroupKind, SystemGroupKind:
			s.Kind = rbac.GroupKind
		default:
			return nil, fmt.Errorf("invalid kind for origin subject: %q", subject.Kind)
		}

		subjects = append(subjects, s)
	}
	return subjects, nil
}

func convertOriginRoleRef(in *api.ObjectReference) rbac.RoleRef {
	return rbac.RoleRef{
		APIGroup: in.APIVersion,
		Kind:     in.Kind, // TODO leave empty?
		Name:     in.Name,
	}
}

func Convert_rbac_ClusterRole_To_api_ClusterRole(in *rbac.ClusterRole, out *ClusterRole, _ conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.Rules = convertRBACPolicyRules(in.Rules)
	return nil
}

func Convert_rbac_Role_To_api_Role(in *rbac.Role, out *Role, _ conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.Rules = convertRBACPolicyRules(in.Rules)
	return nil
}

func Convert_rbac_ClusterRoleBinding_To_api_ClusterRoleBinding(in *rbac.ClusterRoleBinding, out *ClusterRoleBinding, _ conversion.Scope) error {
	var err error
	if out.Subjects, err = convertRBACSubjects(in.Subjects); err != nil {
		return err
	}
	out.RoleRef = convertRBACRoleRef(&in.RoleRef, "")
	out.ObjectMeta = in.ObjectMeta
	return nil
}

func Convert_rbac_RoleBinding_To_api_RoleBinding(in *rbac.RoleBinding, out *RoleBinding, _ conversion.Scope) error {
	var err error
	if out.Subjects, err = convertRBACSubjects(in.Subjects); err != nil {
		return err
	}
	out.RoleRef = convertRBACRoleRef(&in.RoleRef, in.Namespace)
	out.ObjectMeta = in.ObjectMeta
	return nil
}

func convertRBACSubjects(in []rbac.Subject) ([]api.ObjectReference, error) {
	subjects := make([]api.ObjectReference, 0, len(in))
	for _, subject := range in {
		s := api.ObjectReference{
			APIVersion: rbac.GroupName, // TODO what do we want here?
			Name:       subject.Name,
		}

		switch subject.Kind {
		case rbac.ServiceAccountKind:
			s.Namespace = subject.Namespace
		case rbac.UserKind:
			s.Kind = determineUserKind(subject.Name, validation.ValidateUserName)
		case rbac.GroupKind:
			s.Kind = determineGroupKind(subject.Name, validation.ValidateGroupName)
		default:
			return nil, fmt.Errorf("invalid kind for rbac subject: %q", subject.Kind)
		}

		subjects = append(subjects, s)
	}
	return subjects, nil
}

func convertRBACRoleRef(in *rbac.RoleRef, namespace string) api.ObjectReference {
	return api.ObjectReference{
		APIVersion: in.APIGroup,
		Kind:       in.Kind, // TODO leave empty?
		Name:       in.Name,
		Namespace:  namespace,
	}
}

func convertRBACPolicyRules(in []rbac.PolicyRule) []PolicyRule {
	rules := make([]PolicyRule, 0, len(in))
	for _, rule := range in {
		r := PolicyRule{
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
