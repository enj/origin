package api

import (
	"fmt"
	"reflect"
	"testing"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/api/validation"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/diff"
	"k8s.io/kubernetes/pkg/util/sets"

	uservalidation "github.com/openshift/origin/pkg/user/api/validation"

	"github.com/google/gofuzz"
)

// make sure rbac <-> origin round trip does not lose any data

func TestOriginClusterRoleFidelity(t *testing.T) {
	for i := 0; i < 100; i++ {
		ocr := &ClusterRole{}
		ocr2 := &ClusterRole{}
		rcr := &rbac.ClusterRole{}
		fuzzer.Fuzz(ocr)
		if err := Convert_api_ClusterRole_To_rbac_ClusterRole(ocr, rcr, nil); err != nil {
			t.Fatal(err)
		}
		if err := Convert_rbac_ClusterRole_To_api_ClusterRole(rcr, ocr2, nil); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(ocr, ocr2) {
			t.Errorf("origin cluster data not preserved; the diff is %s", diff.ObjectDiff(ocr, ocr2))
		}
	}
}

func TestOriginRoleFidelity(t *testing.T) {
	for i := 0; i < 100; i++ {
		or := &Role{}
		or2 := &Role{}
		rr := &rbac.Role{}
		fuzzer.Fuzz(or)
		if err := Convert_api_Role_To_rbac_Role(or, rr, nil); err != nil {
			t.Fatal(err)
		}
		if err := Convert_rbac_Role_To_api_Role(rr, or2, nil); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(or, or2) {
			t.Errorf("origin local data not preserved; the diff is %s", diff.ObjectDiff(or, or2))
		}
	}
}

func TestOriginClusterRoleBindingFidelity(t *testing.T) {
	for i := 0; i < 100; i++ {
		ocrb := &ClusterRoleBinding{}
		ocrb2 := &ClusterRoleBinding{}
		rcrb := &rbac.ClusterRoleBinding{}
		fuzzer.Fuzz(ocrb)
		if err := Convert_api_ClusterRoleBinding_To_rbac_ClusterRoleBinding(ocrb, rcrb, nil); err != nil {
			t.Fatal(err)
		}
		if err := Convert_rbac_ClusterRoleBinding_To_api_ClusterRoleBinding(rcrb, ocrb2, nil); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(ocrb, ocrb2) {
			t.Errorf("origin cluster binding data not preserved; the diff is %s", diff.ObjectDiff(ocrb, ocrb2))
		}
	}
}

func TestOriginRoleBindingFidelity(t *testing.T) {
	for i := 0; i < 100; i++ {
		orb := &RoleBinding{}
		orb2 := &RoleBinding{}
		rrb := &rbac.RoleBinding{}
		fuzzer.Fuzz(orb)
		if err := Convert_api_RoleBinding_To_rbac_RoleBinding(orb, rrb, nil); err != nil {
			t.Fatal(err)
		}
		if err := Convert_rbac_RoleBinding_To_api_RoleBinding(rrb, orb2, nil); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(orb, orb2) {
			t.Errorf("origin local binding data not preserved; the diff is %s", diff.ObjectDiff(orb, orb2))
		}
	}
}

func TestRBACClusterRoleFidelity(t *testing.T) {
	for i := 0; i < 100; i++ {
		rcr := &rbac.ClusterRole{}
		rcr2 := &rbac.ClusterRole{}
		ocr := &ClusterRole{}
		fuzzer.Fuzz(rcr)
		if err := Convert_rbac_ClusterRole_To_api_ClusterRole(rcr, ocr, nil); err != nil {
			t.Fatal(err)
		}
		if err := Convert_api_ClusterRole_To_rbac_ClusterRole(ocr, rcr2, nil); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(rcr, rcr2) {
			t.Errorf("rbac cluster data not preserved; the diff is %s", diff.ObjectDiff(rcr, rcr2))
		}
	}
}

func TestRBACRoleFidelity(t *testing.T) {
	for i := 0; i < 100; i++ {
		rr := &rbac.Role{}
		rr2 := &rbac.Role{}
		or := &Role{}
		fuzzer.Fuzz(rr)
		if err := Convert_rbac_Role_To_api_Role(rr, or, nil); err != nil {
			t.Fatal(err)
		}
		if err := Convert_api_Role_To_rbac_Role(or, rr2, nil); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(rr, rr2) {
			t.Errorf("rbac local data not preserved; the diff is %s", diff.ObjectDiff(rr, rr2))
		}
	}
}

func TestRBACClusterRoleBindingFidelity(t *testing.T) {
	for i := 0; i < 100; i++ {
		rcrb := &rbac.ClusterRoleBinding{}
		rcrb2 := &rbac.ClusterRoleBinding{}
		ocrb := &ClusterRoleBinding{}
		fuzzer.Fuzz(rcrb)
		if err := Convert_rbac_ClusterRoleBinding_To_api_ClusterRoleBinding(rcrb, ocrb, nil); err != nil {
			t.Fatal(err)
		}
		if err := Convert_api_ClusterRoleBinding_To_rbac_ClusterRoleBinding(ocrb, rcrb2, nil); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(rcrb, rcrb2) {
			t.Errorf("rbac cluster binding data not preserved; the diff is %s", diff.ObjectDiff(rcrb, rcrb2))
		}
	}
}

func TestRBACRoleBindingFidelity(t *testing.T) {
	for i := 0; i < 100; i++ {
		rrb := &rbac.RoleBinding{}
		rrb2 := &rbac.RoleBinding{}
		orb := &RoleBinding{}
		fuzzer.Fuzz(rrb)
		if err := Convert_rbac_RoleBinding_To_api_RoleBinding(rrb, orb, nil); err != nil {
			t.Fatal(err)
		}
		if err := Convert_api_RoleBinding_To_rbac_RoleBinding(orb, rrb2, nil); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(rrb, rrb2) {
			t.Errorf("rbac local binding data not preserved; the diff is %s", diff.ObjectDiff(rrb, rrb2))
		}
	}
}

var fuzzer = fuzz.New().NilChance(0).Funcs(
	func(*unversioned.TypeMeta, fuzz.Continue) {}, // Ignore TypeMeta
	func(*runtime.Object, fuzz.Continue) {},       // Ignore AttributeRestrictions since they are deprecated
	func(ocrb *ClusterRoleBinding, c fuzz.Continue) {
		c.FuzzNoCustom(ocrb)
		setRandomOriginRoleBindingData(ocrb.Subjects, &ocrb.RoleRef, "", c)
	},
	func(orb *RoleBinding, c fuzz.Continue) {
		c.FuzzNoCustom(orb)
		setRandomOriginRoleBindingData(orb.Subjects, &orb.RoleRef, orb.Namespace, c)
	},
	func(rcrb *rbac.ClusterRoleBinding, c fuzz.Continue) {
		c.FuzzNoCustom(rcrb)
		setRandomRBACRoleBindingData(rcrb.Subjects, &rcrb.RoleRef, "", c)
	},
	func(rrb *rbac.RoleBinding, c fuzz.Continue) {
		c.FuzzNoCustom(rrb)
		setRandomRBACRoleBindingData(rrb.Subjects, &rrb.RoleRef, rrb.Namespace, c)
	},
	func(rr *rbac.Role, c fuzz.Continue) {
		c.FuzzNoCustom(rr)
		sortAndDeduplicateRBACRulesFields(rr.Rules) // []string <-> sets.String
	},
	func(rcr *rbac.ClusterRole, c fuzz.Continue) {
		c.FuzzNoCustom(rcr)
		sortAndDeduplicateRBACRulesFields(rcr.Rules) // []string <-> sets.String
	},
)

func setRandomRBACRoleBindingData(subjects []rbac.Subject, roleRef *rbac.RoleRef, namespace string, c fuzz.Continue) {
	for i := range subjects {
		subject := &subjects[i]
		subject.APIVersion = rbac.GroupName
		setValidRBACKindAndNamespace(subject, i, c)
	}
	roleRef.APIGroup = rbac.GroupName
	roleRef.Kind = getKind(namespace)
}

func setValidRBACKindAndNamespace(subject *rbac.Subject, i int, c fuzz.Continue) {
	kinds := []string{rbac.UserKind, rbac.GroupKind, rbac.ServiceAccountKind}
	kind := kinds[c.Intn(len(kinds))]
	subject.Kind = kind

	if subject.Kind != rbac.ServiceAccountKind {
		subject.Namespace = ""
	}

	switch subject.Kind {

	case rbac.UserKind:
		if len(uservalidation.ValidateUserName(subject.Name, false)) != 0 {
			subject.Name = fmt.Sprintf("validusername%d", i)
		}

	case rbac.GroupKind:
		if len(uservalidation.ValidateGroupName(subject.Name, false)) != 0 {
			subject.Name = fmt.Sprintf("validgroupname%d", i)
		}

	case rbac.ServiceAccountKind:
		if len(validation.ValidateNamespaceName(subject.Namespace, false)) != 0 {
			subject.Namespace = fmt.Sprintf("sanamespacehere%d", i)
		}
		if len(validation.ValidateServiceAccountName(subject.Name, false)) != 0 {
			subject.Name = fmt.Sprintf("sanamehere%d", i)
		}

	default:
		panic("invalid kind")
	}
}

func setRandomOriginRoleBindingData(subjects []api.ObjectReference, roleRef *api.ObjectReference, namespace string, c fuzz.Continue) {
	for i := range subjects {
		subject := &subjects[i]
		unsetUnpreservedOriginFields(subject)
		setValidOriginKindAndNamespace(subject, i, c)
	}
	unsetUnpreservedOriginFields(roleRef)
	roleRef.Kind = getKind(namespace)
	roleRef.Namespace = namespace
}

func setValidOriginKindAndNamespace(subject *api.ObjectReference, i int, c fuzz.Continue) {
	kinds := []string{UserKind, SystemUserKind, GroupKind, SystemGroupKind, ServiceAccountKind}
	kind := kinds[c.Intn(len(kinds))]
	subject.Kind = kind

	if subject.Kind != ServiceAccountKind {
		subject.Namespace = ""
	}

	switch subject.Kind {

	case UserKind:
		if len(uservalidation.ValidateUserName(subject.Name, false)) != 0 {
			subject.Name = fmt.Sprintf("validusername%d", i)
		}

	case GroupKind:
		if len(uservalidation.ValidateGroupName(subject.Name, false)) != 0 {
			subject.Name = fmt.Sprintf("validgroupname%d", i)
		}

	case SystemUserKind, SystemGroupKind:
		subject.Name = ":" + subject.Name

	case ServiceAccountKind:
		if len(validation.ValidateNamespaceName(subject.Namespace, false)) != 0 {
			subject.Namespace = fmt.Sprintf("sanamespacehere%d", i)
		}
		if len(validation.ValidateServiceAccountName(subject.Name, false)) != 0 {
			subject.Name = fmt.Sprintf("sanamehere%d", i)
		}

	default:
		panic("invalid kind")
	}
}

func unsetUnpreservedOriginFields(ref *api.ObjectReference) {
	ref.UID = ""
	ref.ResourceVersion = ""
	ref.FieldPath = ""
	ref.APIVersion = ""
}

func sortAndDeduplicateRBACRulesFields(in []rbac.PolicyRule) {
	for i := range in {
		rule := reflect.ValueOf(&in[i]).Elem()
		for f := 0; f < rule.NumField(); f++ {
			field := rule.Field(f)
			if field.Kind() == reflect.Slice && field.Len() > 0 {
				s := field.Interface().([]string)
				vs := sets.NewString(s...).List()
				field.Set(reflect.ValueOf(vs))
			}
		}
	}
}
