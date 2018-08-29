package identitymapper

import (
	kuser "k8s.io/apiserver/pkg/authentication/user"

	authapi "github.com/openshift/origin/pkg/oauthserver/api"
)

type groupsMapper struct {
	delegate authapi.UserIdentityMapper
}

func (p *groupsMapper) UserFor(identityInfo authapi.UserIdentityInfo) (kuser.Info, error) {
	user, err := p.delegate.UserFor(identityInfo)
	if err != nil {
		return nil, err
	}
	// if there are no groups we do not need to waste resources on identity metadata objects
	// this does mean that flows that use the cookie session must always store the user and UID
	// in the cookie as they cannot rely on there always being an identity metadata object
	groups := identityInfo.GetProviderGroups()
	if len(groups) == 0 {
		return user, nil
	}
	return authapi.NewDefaultUserIdentityMetadata(user, identityInfo.GetProviderName(), groups), nil
}
