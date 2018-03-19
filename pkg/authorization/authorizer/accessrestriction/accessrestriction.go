package accessrestriction

import (
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/kubernetes/plugin/pkg/auth/authorizer/rbac"

	"github.com/openshift/origin/pkg/authorization/apis/authorization"
	"github.com/openshift/origin/pkg/authorization/generated/listers/authorization/internalversion"
)

func NewAuthorizer(accessRestrictionLister internalversion.AccessRestrictionLister) authorizer.Authorizer {
	return &accessRestrictionAuthorizer{accessRestrictionLister: accessRestrictionLister}
}

type accessRestrictionAuthorizer struct {
	accessRestrictionLister internalversion.AccessRestrictionLister
}

func (a *accessRestrictionAuthorizer) Authorize(requestAttributes authorizer.Attributes) (authorizer.Decision, string, error) {
	accessRestrictions, err := a.accessRestrictionLister.List(labels.Everything())
	if err != nil {
		// TODO safe?
		return authorizer.DecisionDeny, "cannot determine access restrictions", err
	}

	for _, accessRestriction := range accessRestrictions {
		// does this access restriction match the given request attributes
		if matches(accessRestriction, requestAttributes) {
			// it does match, meaning we need to check if it denies the request
			if !allowed(accessRestriction, requestAttributes.GetUser()) {
				return authorizer.DecisionDeny, "denied by access restriction", nil // TODO better reason?
			}
		}
	}

	return authorizer.DecisionNoOpinion, "", nil
}

func matches(accessRestriction *authorization.AccessRestriction, requestAttributes authorizer.Attributes) bool {
	return rbac.RulesAllow(requestAttributes, accessRestriction.Spec.MatchAttributes...)
}

func allowed(accessRestriction *authorization.AccessRestriction, user user.Info) bool {
	s := accessRestriction.Spec
	isWhitelist := len(s.AllowedSubjects) != 0 && len(s.DeniedSubjects) == 0
	isBlacklist := len(s.DeniedSubjects) != 0 && len(s.AllowedSubjects) == 0

	switch {
	case isWhitelist:
		return subjectsMatch(s.AllowedSubjects, user)
	case isBlacklist:
		return !subjectsMatch(s.DeniedSubjects, user)
	}

	return false // fail closed
}

func subjectsMatch(subjects []authorization.SubjectMatcher, user user.Info) bool {
	for _, subject := range subjects {
		if subjectMatches(subject, user) {
			return true
		}
	}
	return false
}

func subjectMatches(subject authorization.SubjectMatcher, user user.Info) bool {
	switch {
	case len(subject.Names) != 0 && len(subject.Groups) == 0:
		return has(subject.Names, user.GetName())
	case len(subject.Groups) != 0 && len(subject.Names) == 0:
		return hasAny(subject.Groups, user.GetGroups())
	}
	return false // fail closed
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
