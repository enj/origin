package identitymapper

import (
	kuser "k8s.io/apiserver/pkg/authentication/user"

	authapi "github.com/openshift/origin/pkg/oauthserver/api"
)

type groupsMapper struct {
	delegate authapi.UserIdentityMapper
	// TODO add identity metadata API client
}

func (p *groupsMapper) UserFor(identityInfo authapi.UserIdentityInfo) (kuser.Info, error) {
	user, err := p.delegate.UserFor(identityInfo)
	if err != nil {
		return nil, err
	}
	// always create identity metadata even if there are no groups (for use in cookie session)
	groups := identityInfo.GetProviderGroups()
	_ = groups // TODO remove
	// TODO use identity metadata API client to store groups, needs to handle conflicts/already exists like provision.go
	identityMetadataName := "<hash>"
	return authapi.NewDefaultUserIdentityMetadata(user, identityMetadataName), nil
}
