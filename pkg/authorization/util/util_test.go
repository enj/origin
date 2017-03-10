package util

import (
	"reflect"
	"testing"

	kapi "k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/api/unversioned"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/pkg/runtime"
	"k8s.io/kubernetes/pkg/util/diff"
	"k8s.io/kubernetes/pkg/util/sets"

	"github.com/openshift/origin/pkg/authorization/api"

	"github.com/google/gofuzz"
)

// make sure rbac <-> origin round trip does not lose any data

func TestOriginClusterRoleFidelity(t *testing.T) {
	f := fuzz.New().NilChance(0).Funcs(func(*runtime.Object, fuzz.Continue) {}) // Ignore AttributeRestrictions since they are deprecated
	ocr := &api.ClusterRole{}
	for i := 0; i < 100; i++ {
		f.Fuzz(ocr)
		ocr.TypeMeta = unversioned.TypeMeta{} // Ignore TypeMeta
		rcr := ConvertOriginClusterRole(ocr)
		ocr2 := ConvertRBACClusterRole(rcr)
		if !reflect.DeepEqual(ocr, ocr2) {
			t.Errorf("origin cluster data not preserved; the diff is %s", diff.ObjectDiff(ocr, ocr2))
		}
	}
}

func TestOriginRoleFidelity(t *testing.T) {
	f := fuzz.New().NilChance(0).Funcs(func(*runtime.Object, fuzz.Continue) {}) // Ignore AttributeRestrictions since they are deprecated
	or := &api.Role{}
	for i := 0; i < 100; i++ {
		f.Fuzz(or)
		or.TypeMeta = unversioned.TypeMeta{} // Ignore TypeMeta
		rr := ConvertOriginRole(or)
		or2 := ConvertRBACRole(rr)
		if !reflect.DeepEqual(or, or2) {
			t.Errorf("origin local data not preserved; the diff is %s", diff.ObjectDiff(or, or2))
		}
	}
}
func TestOriginClusterRoleBindingFidelity(t *testing.T) {
	f := fuzz.New().NilChance(0)
	ocrb := &api.ClusterRoleBinding{}
	for i := 0; i < 100; i++ {
		f.Fuzz(ocrb)
		ocrb.TypeMeta = unversioned.TypeMeta{}               // Ignore TypeMeta
		unsetUnpreservedFields(ocrb.Subjects, &ocrb.RoleRef) // RBAC is missing these fields
		rcrb := ConvertOriginClusterRoleBinding(ocrb)
		ocrb2 := ConvertRBACClusterRoleBinding(rcrb)
		if !reflect.DeepEqual(ocrb, ocrb2) {
			t.Errorf("origin cluster binding data not preserved; the diff is %s", diff.ObjectDiff(ocrb, ocrb2))
		}
	}
}

func TestOriginRoleBindingFidelity(t *testing.T) {
	f := fuzz.New().NilChance(0)
	orb := &api.RoleBinding{}
	for i := 0; i < 100; i++ {
		f.Fuzz(orb)
		orb.TypeMeta = unversioned.TypeMeta{}              // Ignore TypeMeta
		unsetUnpreservedFields(orb.Subjects, &orb.RoleRef) // RBAC is missing these fields
		rrb := ConvertOriginRoleBinding(orb)
		orb2 := ConvertRBACRoleBinding(rrb)
		if !reflect.DeepEqual(orb, orb2) {
			t.Errorf("origin local binding data not preserved; the diff is %s", diff.ObjectDiff(orb, orb2))
		}
	}
}

func TestRBACClusterRoleFidelity(t *testing.T) {
	f := fuzz.New().NilChance(0).Funcs(func(*runtime.Object, fuzz.Continue) {}) // TODO remove func after 1.6 rebase removes AttributeRestrictions
	rcr := &rbac.ClusterRole{}
	for i := 0; i < 100; i++ {
		f.Fuzz(rcr)
		rcr.TypeMeta = unversioned.TypeMeta{}    // Ignore TypeMeta
		sortAndDeduplicateRulesFields(rcr.Rules) // []string <-> sets.String
		ocr := ConvertRBACClusterRole(rcr)
		rcr2 := ConvertOriginClusterRole(ocr)
		if !reflect.DeepEqual(rcr, rcr2) {
			t.Errorf("rbac cluster data not preserved; the diff is %s", diff.ObjectDiff(rcr, rcr2))
		}
	}
}

func TestRBACRoleFidelity(t *testing.T) {
	f := fuzz.New().NilChance(0).Funcs(func(*runtime.Object, fuzz.Continue) {}) // TODO remove func after 1.6 rebase removes AttributeRestrictions
	rr := &rbac.Role{}
	for i := 0; i < 100; i++ {
		f.Fuzz(rr)
		rr.TypeMeta = unversioned.TypeMeta{}    // Ignore TypeMeta
		sortAndDeduplicateRulesFields(rr.Rules) // []string <-> sets.String
		or := ConvertRBACRole(rr)
		rr2 := ConvertOriginRole(or)
		if !reflect.DeepEqual(rr, rr2) {
			t.Errorf("rbac local data not preserved; the diff is %s", diff.ObjectDiff(rr, rr2))
		}
	}
}

func TestRBACClusterRoleBindingFidelity(t *testing.T) {
	f := fuzz.New().NilChance(0)
	rcrb := &rbac.ClusterRoleBinding{}
	for i := 0; i < 100; i++ {
		f.Fuzz(rcrb)
		rcrb.TypeMeta = unversioned.TypeMeta{} // Ignore TypeMeta
		ocrb := ConvertRBACClusterRoleBinding(rcrb)
		rcrb2 := ConvertOriginClusterRoleBinding(ocrb)
		if !reflect.DeepEqual(rcrb, rcrb2) {
			t.Errorf("rbac cluster binding data not preserved; the diff is %s", diff.ObjectDiff(rcrb, rcrb2))
		}
	}
}

func TestRBACRoleBindingFidelity(t *testing.T) {
	f := fuzz.New().NilChance(0)
	rrb := &rbac.RoleBinding{}
	for i := 0; i < 100; i++ {
		f.Fuzz(rrb)
		rrb.TypeMeta = unversioned.TypeMeta{} // Ignore TypeMeta
		orb := ConvertRBACRoleBinding(rrb)
		rrb2 := ConvertOriginRoleBinding(orb)
		if !reflect.DeepEqual(rrb, rrb2) {
			t.Errorf("rbac local binding data not preserved; the diff is %s", diff.ObjectDiff(rrb, rrb2))
		}
	}
}

func unsetUnpreservedFields(subjects []kapi.ObjectReference, roleRef *kapi.ObjectReference) {
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
