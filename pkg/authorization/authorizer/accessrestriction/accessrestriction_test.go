package accessrestriction

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/apis/rbac"
	"k8s.io/kubernetes/pkg/serviceaccount"

	userapiv1 "github.com/openshift/api/user/v1"
	userlisterv1 "github.com/openshift/client-go/user/listers/user/v1"
	"github.com/openshift/origin/pkg/authorization/apis/authorization"
	authorizationlister "github.com/openshift/origin/pkg/authorization/generated/listers/authorization/internalversion"
)

func Test_accessRestrictionAuthorizer_Authorize(t *testing.T) {
	podWhitelistGroup := &authorization.AccessRestriction{
		Spec: authorization.AccessRestrictionSpec{
			MatchAttributes: []rbac.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{""},
					Resources: []string{"pods"},
				},
			},
			AllowedSubjects: []authorization.SubjectMatcher{
				{
					GroupRestriction: &authorization.GroupRestriction{
						Groups: []string{"admins", "system:serviceaccounts"},
					},
				},
			},
		},
	}
	secretWhitelistGroup := &authorization.AccessRestriction{
		Spec: authorization.AccessRestrictionSpec{
			MatchAttributes: []rbac.PolicyRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{""},
					Resources: []string{"secrets"},
				},
			},
			AllowedSubjects: []authorization.SubjectMatcher{
				{
					GroupRestriction: &authorization.GroupRestriction{
						Groups: []string{"system:serviceaccounts:ns2"},
						Selectors: []v1.LabelSelector{
							{
								MatchLabels: map[string]string{
									"can": "secret",
								},
							},
						},
					},
				},
			},
		},
	}
	secretLabelGroup := &userapiv1.Group{
		ObjectMeta: v1.ObjectMeta{
			Labels: map[string]string{
				"can": "secret",
			},
		},
		Users: userapiv1.OptionalNames{
			"bob",
		},
	}
	secretLabelGroupNoUsers := &userapiv1.Group{
		ObjectMeta: v1.ObjectMeta{
			Name: "sgroup",
			Labels: map[string]string{
				"can": "secret",
			},
		},
	}
	configmapWhitelistUser := &authorization.AccessRestriction{
		Spec: authorization.AccessRestrictionSpec{
			MatchAttributes: []rbac.PolicyRule{
				{
					Verbs:     []string{"list"},
					APIGroups: []string{""},
					Resources: []string{"configmaps"},
				},
			},
			AllowedSubjects: []authorization.SubjectMatcher{
				{
					UserRestriction: &authorization.UserRestriction{
						Users: []string{"nancy"},
					},
				},
			},
		},
	}
	identityWhitelistSA := &authorization.AccessRestriction{
		Spec: authorization.AccessRestrictionSpec{
			MatchAttributes: []rbac.PolicyRule{
				{
					Verbs:     []string{"update"},
					APIGroups: []string{"user.openshift.io"},
					Resources: []string{"identities"},
				},
			},
			AllowedSubjects: []authorization.SubjectMatcher{
				{
					UserRestriction: &authorization.UserRestriction{
						Users:  []string{"system:serviceaccount:ns3:sa3"},
						Groups: []string{"system:serviceaccounts:ns4"},
						Selectors: []v1.LabelSelector{
							{
								MatchLabels: map[string]string{
									"not": "stable",
								},
							},
						},
					},
				},
			},
		},
	}
	labeledUserEric := &userapiv1.User{
		ObjectMeta: v1.ObjectMeta{
			Name: "eric",
			Labels: map[string]string{
				"not": "stable",
			},
		},
	}
	groupedLabeledUserRandy := &userapiv1.User{
		ObjectMeta: v1.ObjectMeta{
			Name: "randy",
			Labels: map[string]string{
				"not": "stable",
			},
		},
		Groups: []string{"sharks"},
	}
	saBlacklistUser := &authorization.AccessRestriction{
		Spec: authorization.AccessRestrictionSpec{
			MatchAttributes: []rbac.PolicyRule{
				{
					Verbs:     []string{"delete"},
					APIGroups: []string{""},
					Resources: []string{"serviceaccounts"},
				},
			},
			DeniedSubjects: []authorization.SubjectMatcher{
				{
					UserRestriction: &authorization.UserRestriction{
						Users:  []string{"gopher"},
						Groups: []string{"pythons"},
						Selectors: []v1.LabelSelector{
							{
								MatchLabels: map[string]string{
									"pandas": "rock",
								},
							},
						},
					},
				},
			},
		},
	}
	groupedLabeledUserFrank := &userapiv1.User{
		ObjectMeta: v1.ObjectMeta{
			Name: "frank",
			Labels: map[string]string{
				"pandas": "rock",
			},
		},
		Groups: []string{"danger-zone"},
	}
	oauthURLBlacklistUser := &authorization.AccessRestriction{
		Spec: authorization.AccessRestrictionSpec{
			MatchAttributes: []rbac.PolicyRule{
				{
					Verbs:           []string{"GET"},
					NonResourceURLs: []string{"/oauth/*"},
				},
			},
			DeniedSubjects: []authorization.SubjectMatcher{
				{
					UserRestriction: &authorization.UserRestriction{
						Users: []string{"oauth-man"},
					},
				},
			},
		},
	}

	type fields struct {
		accessRestrictionLister authorizationlister.AccessRestrictionLister
		userLister              userlisterv1.UserLister
		groupLister             userlisterv1.GroupLister
	}
	type args struct {
		requestAttributes authorizer.Attributes
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    authorizer.Decision
		want1   string
		wantErr bool
	}{
		{
			name: "access restriction list error",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					1, // invalid data
				),
			},
			want:    authorizer.DecisionDeny,
			want1:   "cannot determine access restrictions",
			wantErr: true,
		},
		{
			name: "simple whitelist deny",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					podWhitelistGroup,
					secretWhitelistGroup, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name:   "bob",
						Groups: []string{},
					},
					Verb:            "get",
					APIGroup:        "",
					Resource:        "pods",
					Subresource:     "",
					Name:            "mysql",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionDeny,
			want1:   "denied by access restriction",
			wantErr: false,
		},
		{
			name: "simple whitelist not deny",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					podWhitelistGroup,
					secretWhitelistGroup, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name:   "bob",
						Groups: []string{"admins"},
					},
					Verb:            "get",
					APIGroup:        "",
					Resource:        "pods",
					Subresource:     "",
					Name:            "mysql",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionNoOpinion,
			want1:   "",
			wantErr: false,
		},
		{
			name: "simple whitelist deny not match",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					podWhitelistGroup,
					secretWhitelistGroup, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name:   "bob",
						Groups: []string{},
					},
					Verb:            "get",
					APIGroup:        "",
					Resource:        "node",
					Subresource:     "",
					Name:            "foo",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionNoOpinion,
			want1:   "",
			wantErr: false,
		},
		{
			name: "whitelist group label deny",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					secretWhitelistGroup,
					podWhitelistGroup, // not important for this test, just there to make sure it is ignored
				),
				groupLister: testGroupLister(),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name:   "bob",
						Groups: []string{},
					},
					Verb:            "get",
					APIGroup:        "",
					Resource:        "secrets",
					Subresource:     "",
					Name:            "ssh",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionDeny,
			want1:   "denied by access restriction",
			wantErr: false,
		},
		{
			name: "whitelist group label not deny group object only",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					secretWhitelistGroup,
					podWhitelistGroup, // not important for this test, just there to make sure it is ignored
				),
				groupLister: testGroupLister(
					secretLabelGroup,
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name:   "bob",
						Groups: []string{}, // works when only the group object has the user
					},
					Verb:            "get",
					APIGroup:        "",
					Resource:        "secrets",
					Subresource:     "",
					Name:            "ssh",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionNoOpinion,
			want1:   "",
			wantErr: false,
		},
		{
			name: "whitelist group label not deny virtual user group only",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					secretWhitelistGroup,
					podWhitelistGroup, // not important for this test, just there to make sure it is ignored
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers,
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name:   "bob",
						Groups: []string{"sgroup"}, // works when only the virtual user has the group
					},
					Verb:            "get",
					APIGroup:        "",
					Resource:        "secrets",
					Subresource:     "",
					Name:            "ssh",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionNoOpinion,
			want1:   "",
			wantErr: false,
		},
		{
			name: "whitelist user deny",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					configmapWhitelistUser,
					// the rest are not important for this test, just there to make sure it is ignored
					secretWhitelistGroup,
					podWhitelistGroup,
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name:   "bob",
						Groups: []string{},
					},
					Verb:            "list",
					APIGroup:        "",
					Resource:        "configmaps",
					Subresource:     "",
					Name:            "console",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionDeny,
			want1:   "denied by access restriction",
			wantErr: false,
		},
		{
			name: "whitelist user not deny",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					configmapWhitelistUser,
					// the rest are not important for this test, just there to make sure it is ignored
					secretWhitelistGroup,
					podWhitelistGroup,
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name:   "nancy",
						Groups: []string{},
					},
					Verb:            "list",
					APIGroup:        "",
					Resource:        "configmaps",
					Subresource:     "",
					Name:            "console",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionNoOpinion,
			want1:   "",
			wantErr: false,
		},
		{
			name: "whitelist not deny SA global group",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					podWhitelistGroup,
					// the rest are not important for this test, just there to make sure it is ignored
					configmapWhitelistUser,
					secretWhitelistGroup,
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User:            serviceaccount.UserInfo("ns1", "sa1", "007"),
					Verb:            "get",
					APIGroup:        "",
					Resource:        "pods",
					Subresource:     "",
					Name:            "api",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionNoOpinion,
			want1:   "",
			wantErr: false,
		},
		{
			name: "whitelist not deny SA ns group",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					secretWhitelistGroup,
					// the rest are not important for this test, just there to make sure it is ignored
					configmapWhitelistUser,
					podWhitelistGroup,
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User:            serviceaccount.UserInfo("ns2", "sa2", "008"),
					Verb:            "get",
					APIGroup:        "",
					Resource:        "secrets",
					Subresource:     "",
					Name:            "dbpass",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionNoOpinion,
			want1:   "",
			wantErr: false,
		},
		{
			name: "whitelist not deny SA user",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					identityWhitelistSA,
					// the rest are not important for this test, just there to make sure it is ignored
					secretWhitelistGroup,
					configmapWhitelistUser,
					podWhitelistGroup,
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User:            serviceaccount.UserInfo("ns3", "sa3", "009"),
					Verb:            "update",
					APIGroup:        "user.openshift.io",
					Resource:        "identities",
					Subresource:     "",
					Name:            "github:bob",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionNoOpinion,
			want1:   "",
			wantErr: false,
		},
		{
			name: "whitelist deny SA user",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					identityWhitelistSA,
					// the rest are not important for this test, just there to make sure it is ignored
					secretWhitelistGroup,
					configmapWhitelistUser,
					podWhitelistGroup,
				),
				userLister: testUserLister(),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User:            serviceaccount.UserInfo("ns3", "sa3.1", "009.1"),
					Verb:            "update",
					APIGroup:        "user.openshift.io",
					Resource:        "identities",
					Subresource:     "",
					Name:            "github:adam",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionDeny,
			want1:   "denied by access restriction",
			wantErr: false,
		},
		{
			name: "whitelist not deny SA user via group",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					identityWhitelistSA,
					// the rest are not important for this test, just there to make sure it is ignored
					secretWhitelistGroup,
					configmapWhitelistUser,
					podWhitelistGroup,
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User:            serviceaccount.UserInfo("ns4", "sa4", "010"),
					Verb:            "update",
					APIGroup:        "user.openshift.io",
					Resource:        "identities",
					Subresource:     "",
					Name:            "github:alice",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionNoOpinion,
			want1:   "",
			wantErr: false,
		},
		{
			name: "whitelist deny SA user",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					identityWhitelistSA,
					// the rest are not important for this test, just there to make sure it is ignored
					secretWhitelistGroup,
					configmapWhitelistUser,
					podWhitelistGroup,
				),
				userLister: testUserLister(),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User:            serviceaccount.UserInfo("ns5", "sa5", "011"),
					Verb:            "update",
					APIGroup:        "user.openshift.io",
					Resource:        "identities",
					Subresource:     "",
					Name:            "github:tom",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionDeny,
			want1:   "denied by access restriction",
			wantErr: false,
		},
		{
			name: "whitelist not deny user via label",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					identityWhitelistSA,
					// the rest are not important for this test, just there to make sure it is ignored
					secretWhitelistGroup,
					configmapWhitelistUser,
					podWhitelistGroup,
				),
				userLister: testUserLister(
					labeledUserEric,
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name: "eric",
					},
					Verb:            "update",
					APIGroup:        "user.openshift.io",
					Resource:        "identities",
					Subresource:     "",
					Name:            "github:derek",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionNoOpinion,
			want1:   "",
			wantErr: false,
		},
		{
			name: "whitelist not deny user via embedded group of other labeled user",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					identityWhitelistSA,
					// the rest are not important for this test, just there to make sure it is ignored
					secretWhitelistGroup,
					configmapWhitelistUser,
					podWhitelistGroup,
				),
				userLister: testUserLister(
					groupedLabeledUserRandy, // this matches the label selector for the AR and makes the group allowed
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name:   "some-random-name-ignored",
						Groups: []string{"sharks"}, // this is weird because it is the randy user's label matching that allows it
					},
					Verb:            "update",
					APIGroup:        "user.openshift.io",
					Resource:        "identities",
					Subresource:     "",
					Name:            "github:phantom",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionNoOpinion,
			want1:   "",
			wantErr: false,
		},
		{
			name: "simple blacklist user deny",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					saBlacklistUser,
					// the rest are not important for this test, just there to make sure it is ignored
					identityWhitelistSA,
					secretWhitelistGroup,
					configmapWhitelistUser,
					podWhitelistGroup,
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name: "gopher",
					},
					Verb:            "delete",
					APIGroup:        "",
					Resource:        "serviceaccounts",
					Subresource:     "",
					Name:            "builder",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionDeny,
			want1:   "denied by access restriction",
			wantErr: false,
		},
		{
			name: "simple blacklist user not deny",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					saBlacklistUser,
					// the rest are not important for this test, just there to make sure it is ignored
					identityWhitelistSA,
					secretWhitelistGroup,
					configmapWhitelistUser,
					podWhitelistGroup,
				),
				userLister: testUserLister(
					groupedLabeledUserRandy, // not important for this test, just there to make sure it is ignored
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name: "not-gopher",
					},
					Verb:            "delete",
					APIGroup:        "",
					Resource:        "serviceaccounts",
					Subresource:     "",
					Name:            "builder",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionNoOpinion,
			want1:   "",
			wantErr: false,
		},
		{
			name: "simple blacklist group deny",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					saBlacklistUser,
					// the rest are not important for this test, just there to make sure it is ignored
					identityWhitelistSA,
					secretWhitelistGroup,
					configmapWhitelistUser,
					podWhitelistGroup,
				),
				userLister: testUserLister(
					groupedLabeledUserRandy, // not important for this test, just there to make sure it is ignored
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name:   "not-gopher",
						Groups: []string{"pythons"},
					},
					Verb:            "delete",
					APIGroup:        "",
					Resource:        "serviceaccounts",
					Subresource:     "",
					Name:            "builder",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionDeny,
			want1:   "denied by access restriction",
			wantErr: false,
		},
		{
			name: "simple blacklist group not deny",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					saBlacklistUser,
					// the rest are not important for this test, just there to make sure it is ignored
					identityWhitelistSA,
					secretWhitelistGroup,
					configmapWhitelistUser,
					podWhitelistGroup,
				),
				userLister: testUserLister(
					groupedLabeledUserRandy, // not important for this test, just there to make sure it is ignored
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name:   "not-gopher",
						Groups: []string{"not-pythons"},
					},
					Verb:            "delete",
					APIGroup:        "",
					Resource:        "serviceaccounts",
					Subresource:     "",
					Name:            "builder",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionNoOpinion,
			want1:   "",
			wantErr: false,
		},
		{
			name: "simple blacklist label deny",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					saBlacklistUser,
					// the rest are not important for this test, just there to make sure it is ignored
					identityWhitelistSA,
					secretWhitelistGroup,
					configmapWhitelistUser,
					podWhitelistGroup,
				),
				userLister: testUserLister(
					groupedLabeledUserFrank,
					groupedLabeledUserRandy, // not important for this test, just there to make sure it is ignored
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name:   "frank",
						Groups: []string{"not-pythons"},
					},
					Verb:            "delete",
					APIGroup:        "",
					Resource:        "serviceaccounts",
					Subresource:     "",
					Name:            "builder",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionDeny,
			want1:   "denied by access restriction",
			wantErr: false,
		},
		{
			name: "blacklist deny user via embedded group of other labeled user",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					saBlacklistUser,
					// the rest are not important for this test, just there to make sure it is ignored
					identityWhitelistSA,
					secretWhitelistGroup,
					configmapWhitelistUser,
					podWhitelistGroup,
				),
				userLister: testUserLister(
					groupedLabeledUserFrank,
					groupedLabeledUserRandy, // not important for this test, just there to make sure it is ignored
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name:   "not-used",
						Groups: []string{"danger-zone"}, // this is weird because it is the frank user's label matching that denies it
					},
					Verb:            "delete",
					APIGroup:        "",
					Resource:        "serviceaccounts",
					Subresource:     "",
					Name:            "builder",
					ResourceRequest: true,
					Path:            "",
				},
			},
			want:    authorizer.DecisionDeny,
			want1:   "denied by access restriction",
			wantErr: false,
		},
		{
			name: "blacklist deny user path",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					oauthURLBlacklistUser,
					// the rest are not important for this test, just there to make sure it is ignored
					saBlacklistUser,
					identityWhitelistSA,
					secretWhitelistGroup,
					configmapWhitelistUser,
					podWhitelistGroup,
				),
				userLister: testUserLister(
					// the rest are not important for this test, just there to make sure it is ignored
					groupedLabeledUserFrank,
					groupedLabeledUserRandy,
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name: "oauth-man",
					},
					Verb:            "GET",
					ResourceRequest: false,
					Path:            "/oauth/token",
				},
			},
			want:    authorizer.DecisionDeny,
			want1:   "denied by access restriction",
			wantErr: false,
		},
		{
			name: "blacklist not deny user path",
			fields: fields{
				accessRestrictionLister: testAccessRestrictionLister(
					oauthURLBlacklistUser,
					// the rest are not important for this test, just there to make sure it is ignored
					saBlacklistUser,
					identityWhitelistSA,
					secretWhitelistGroup,
					configmapWhitelistUser,
					podWhitelistGroup,
				),
				userLister: testUserLister(
					// the rest are not important for this test, just there to make sure it is ignored
					groupedLabeledUserFrank,
					groupedLabeledUserRandy,
				),
				groupLister: testGroupLister(
					secretLabelGroupNoUsers, // not important for this test, just there to make sure it is ignored
				),
			},
			args: args{
				requestAttributes: &authorizer.AttributesRecord{
					User: &user.DefaultInfo{
						Name: "not-oauth-man",
					},
					Verb:            "GET",
					ResourceRequest: false,
					Path:            "/oauth/token",
				},
			},
			want:    authorizer.DecisionNoOpinion,
			want1:   "",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &accessRestrictionAuthorizer{
				accessRestrictionLister: tt.fields.accessRestrictionLister,
				userLister:              tt.fields.userLister,
				groupLister:             tt.fields.groupLister,
			}
			got, got1, err := a.Authorize(tt.args.requestAttributes)
			if (err != nil) != tt.wantErr {
				t.Errorf("accessRestrictionAuthorizer.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("accessRestrictionAuthorizer.Authorize() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("accessRestrictionAuthorizer.Authorize() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

type testIndexer struct {
	data          []interface{} // this destroys type safety but allows a simple way to reuse the lister logic
	cache.Indexer               // embed this so we pretend to implement the whole interface, it will panic if anything other than List is called
}

func (i *testIndexer) List() []interface{} {
	return i.data
}

func testAccessRestrictionLister(accessRestrictions ...interface{}) authorizationlister.AccessRestrictionLister {
	return authorizationlister.NewAccessRestrictionLister(&testIndexer{data: accessRestrictions})
}

func testUserLister(users ...interface{}) userlisterv1.UserLister {
	return userlisterv1.NewUserLister(&testIndexer{data: users})
}

func testGroupLister(groups ...interface{}) userlisterv1.GroupLister {
	return userlisterv1.NewGroupLister(&testIndexer{data: groups})
}
