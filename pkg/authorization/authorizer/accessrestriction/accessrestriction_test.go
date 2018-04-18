package accessrestriction

import (
	"flag"
	"reflect"
	"testing"

	"github.com/golang/glog"
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

func init() {
	flag.CommandLine.Lookup("v").Value.Set("2")
	flag.CommandLine.Lookup("stderrthreshold").Value.Set("INFO")
	glog.Flush()
}

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
				userLister: testUserLister(),
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
