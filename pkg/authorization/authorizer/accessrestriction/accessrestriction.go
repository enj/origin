package accessrestriction

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"

	userapiv1 "github.com/openshift/api/user/v1"
	userlisterv1 "github.com/openshift/client-go/user/listers/user/v1"
	"github.com/openshift/origin/pkg/authorization/apis/authorization"
	authorizationlister "github.com/openshift/origin/pkg/authorization/generated/listers/authorization/internalversion"

	"github.com/golang/glog"
)

func NewAuthorizer(accessRestrictionLister authorizationlister.AccessRestrictionLister, userLister userlisterv1.UserLister, groupLister userlisterv1.GroupLister) authorizer.Authorizer {
	return &accessRestrictionAuthorizer{
		accessRestrictionLister: accessRestrictionLister,
		userLister:              userLister,
		groupLister:             groupLister,
	}
}

type accessRestrictionAuthorizer struct {
	accessRestrictionLister authorizationlister.AccessRestrictionLister
	userLister              userlisterv1.UserLister
	groupLister             userlisterv1.GroupLister
}

func (a *accessRestrictionAuthorizer) Authorize(requestAttributes authorizer.Attributes) (authorizer.Decision, string, error) {
	accessRestrictions, err := a.accessRestrictionLister.List(labels.Everything())
	if err != nil {
		// fail closed (but this should never happen because it means some static generated code is broken)
		return authorizer.DecisionDeny, "cannot determine access restrictions", err
	}

	// check all access restrictions and only short circuit on affirmative deny
	for _, accessRestriction := range accessRestrictions {
		// does this access restriction match the given request attributes
		if matches(accessRestriction, requestAttributes) {
			// it does match, meaning we need to check if it denies the request
			if !a.allowed(accessRestriction, requestAttributes.GetUser()) {
				// deny the request because it is not allowed by the current access restriction
				// the reason is opaque because normal users have no visibility into access restriction objects
				glog.V(2).Infof("access restriction %#v denied request attributes %#v for user %#v", accessRestriction, requestAttributes, requestAttributes.GetUser())
				return authorizer.DecisionDeny, "denied by access restriction", nil
			}
			glog.V(4).Infof("access restriction %#v matched but did not deny request attributes %#v for user %#v", accessRestriction, requestAttributes, requestAttributes.GetUser())
		}
	}

	// no access restriction matched or denied this request, so we state that we have no opinion
	// the reason must be blank, otherwise we would spam all RBAC denies with it (which is generally not useful)
	return authorizer.DecisionNoOpinion, "", nil
}

func matches(accessRestriction *authorization.AccessRestriction, requestAttributes authorizer.Attributes) bool {
	if len(accessRestriction.Spec.MatchAttributes) == 0 {
		return true // fail closed (but validation prevents this)
	}
	return rbac.RulesAllow(requestAttributes, accessRestriction.Spec.MatchAttributes...)
}

func (a *accessRestrictionAuthorizer) allowed(accessRestriction *authorization.AccessRestriction, user user.Info) bool {
	s := accessRestriction.Spec
	isWhitelist := len(s.AllowedSubjects) != 0 && len(s.DeniedSubjects) == 0
	isBlacklist := len(s.DeniedSubjects) != 0 && len(s.AllowedSubjects) == 0

	switch {
	case isWhitelist:
		return a.subjectsMatch(s.AllowedSubjects, user)
	case isBlacklist:
		return !a.subjectsMatch(s.DeniedSubjects, user)
	}

	return false // fail closed (but validation prevents this)
}

func (a *accessRestrictionAuthorizer) subjectsMatch(subjects []authorization.SubjectMatcher, user user.Info) bool {
	for _, subject := range subjects {
		if a.subjectMatches(subject, user) {
			return true
		}
	}
	return false
}

func (a *accessRestrictionAuthorizer) subjectMatches(subject authorization.SubjectMatcher, user user.Info) bool {
	switch {
	case subject.UserRestriction != nil && subject.GroupRestriction == nil:
		return a.userMatches(subject.UserRestriction, user)
	case subject.GroupRestriction != nil && subject.UserRestriction == nil:
		return a.groupMatches(subject.GroupRestriction, user)
	}
	return false // fail closed on whitelist, fail open on blacklist (but validation prevents this)
}

func (a *accessRestrictionAuthorizer) userMatches(userRestriction *authorization.UserRestriction, user user.Info) bool {
	if has(userRestriction.Users, user.GetName()) {
		return true
	}
	if hasAny(userRestriction.Groups, user.GetGroups()) {
		return true
	}
	for _, labelSelector := range userRestriction.Selectors {
		for _, u := range a.labelSelectorToUsers(labelSelector) {
			if u.Name == user.GetName() || hasAny(u.Groups, user.GetGroups()) { // TODO not sure if we should check groups here
				return true
			}
		}
	}
	return false
}

func (a *accessRestrictionAuthorizer) labelSelectorToUsers(labelSelector v1.LabelSelector) []*userapiv1.User {
	users, err := a.userLister.List(labelSelectorAsSelector(labelSelector))
	if err != nil {
		runtime.HandleError(err) // this should never happen because it means some static generated code is broken
	}
	// it is safe to return this even when err != nil
	return users
}

func (a *accessRestrictionAuthorizer) groupMatches(groupRestriction *authorization.GroupRestriction, user user.Info) bool {
	if hasAny(groupRestriction.Groups, user.GetGroups()) {
		return true
	}
	for _, labelSelector := range groupRestriction.Selectors {
		for _, group := range a.labelSelectorToGroups(labelSelector) {
			if has(user.GetGroups(), group.Name) || has(group.Users, user.GetName()) {
				return true
			}
		}
	}
	return false
}

func (a *accessRestrictionAuthorizer) labelSelectorToGroups(labelSelector v1.LabelSelector) []*userapiv1.Group {
	groups, err := a.groupLister.List(labelSelectorAsSelector(labelSelector))
	if err != nil {
		runtime.HandleError(err) // this should never happen because it means some static generated code is broken
	}
	// it is safe to return this even when err != nil
	return groups
}

func has(set []string, ele string) bool {
	for _, s := range set {
		if s == ele {
			return true
		}
	}
	return false
}

func hasAny(set, any []string) bool {
	for _, a := range any {
		if has(set, a) {
			return true
		}
	}
	return false
}

func labelSelectorAsSelector(labelSelector v1.LabelSelector) labels.Selector {
	selector, err := v1.LabelSelectorAsSelector(&labelSelector)
	if err != nil {
		runtime.HandleError(err) // validation prevents this from occurring
		return labels.Nothing()  // fail closed on whitelist, fail open on blacklist
	}
	return selector
}
