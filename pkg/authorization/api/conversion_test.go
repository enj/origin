package api

import (
	"reflect"
	"testing"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/diff"
	"k8s.io/kubernetes/pkg/util/sets"

	"github.com/google/gofuzz"
)

// make sure rbac <-> origin round trip does not lose any data

func TestOriginClusterRoleFidelity(t *testing.T) {
	f := fuzz.New().NilChance(0).Funcs(func(*runtime.Object, fuzz.Continue) {}) // Ignore AttributeRestrictions since they are deprecated
	for i := 0; i < 100; i++ {
		ocr := &ClusterRole{}
		ocr2 := &ClusterRole{}
		rcr := &rbac.ClusterRole{}
		f.Fuzz(ocr)
		ocr.TypeMeta = unversioned.TypeMeta{} // Ignore TypeMeta
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
	f := fuzz.New().NilChance(0).Funcs(func(*runtime.Object, fuzz.Continue) {}) // Ignore AttributeRestrictions since they are deprecated
	for i := 0; i < 100; i++ {
		or := &Role{}
		or2 := &Role{}
		rr := &rbac.Role{}
		f.Fuzz(or)
		or.TypeMeta = unversioned.TypeMeta{} // Ignore TypeMeta
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
	f := fuzz.New().NilChance(0)
	for i := 0; i < 100; i++ {
		ocrb := &ClusterRoleBinding{}
		ocrb2 := &ClusterRoleBinding{}
		rcrb := &rbac.ClusterRoleBinding{}
		f.Fuzz(ocrb)
		ocrb.TypeMeta = unversioned.TypeMeta{}               // Ignore TypeMeta
		unsetUnpreservedFields(ocrb.Subjects, &ocrb.RoleRef) // RBAC is missing these fields
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
	f := fuzz.New().NilChance(0)
	for i := 0; i < 100; i++ {
		orb := &RoleBinding{}
		orb2 := &RoleBinding{}
		rrb := &rbac.RoleBinding{}
		f.Fuzz(orb)
		orb.TypeMeta = unversioned.TypeMeta{}              // Ignore TypeMeta
		unsetUnpreservedFields(orb.Subjects, &orb.RoleRef) // RBAC is missing these fields
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
	f := fuzz.New().NilChance(0).Funcs(func(*runtime.Object, fuzz.Continue) {}) // TODO remove func after 1.6 rebase removes AttributeRestrictions
	for i := 0; i < 100; i++ {
		rcr := &rbac.ClusterRole{}
		rcr2 := &rbac.ClusterRole{}
		ocr := &ClusterRole{}
		f.Fuzz(rcr)
		rcr.TypeMeta = unversioned.TypeMeta{}    // Ignore TypeMeta
		sortAndDeduplicateRulesFields(rcr.Rules) // []string <-> sets.String
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
	f := fuzz.New().NilChance(0).Funcs(func(*runtime.Object, fuzz.Continue) {}) // TODO remove func after 1.6 rebase removes AttributeRestrictions
	for i := 0; i < 100; i++ {
		rr := &rbac.Role{}
		rr2 := &rbac.Role{}
		or := &Role{}
		f.Fuzz(rr)
		rr.TypeMeta = unversioned.TypeMeta{}    // Ignore TypeMeta
		sortAndDeduplicateRulesFields(rr.Rules) // []string <-> sets.String
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
	f := fuzz.New().NilChance(0)
	for i := 0; i < 100; i++ {
		rcrb := &rbac.ClusterRoleBinding{}
		rcrb2 := &rbac.ClusterRoleBinding{}
		ocrb := &ClusterRoleBinding{}
		f.Fuzz(rcrb)
		rcrb.TypeMeta = unversioned.TypeMeta{} // Ignore TypeMeta
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
	f := fuzz.New().NilChance(0)
	for i := 0; i < 100; i++ {
		rrb := &rbac.RoleBinding{}
		rrb2 := &rbac.RoleBinding{}
		orb := &RoleBinding{}
		f.Fuzz(rrb)
		rrb.TypeMeta = unversioned.TypeMeta{} // Ignore TypeMeta
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

func unsetUnpreservedFields(subjects []api.ObjectReference, roleRef *api.ObjectReference) {
	for i := range subjects {
		subject := &subjects[i]
		subject.UID = ""
		subject.ResourceVersion = ""
		subject.FieldPath = ""
	}
	roleRef.Namespace = ""
	roleRef.UID = ""
	roleRef.ResourceVersion = ""
	roleRef.FieldPath = ""
}

func sortAndDeduplicateRulesFields(in []rbac.PolicyRule) {
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
