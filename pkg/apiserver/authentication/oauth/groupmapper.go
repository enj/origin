package oauth

import (
	"fmt"

	oauthv1 "github.com/openshift/api/oauth/v1"
	userapi "github.com/openshift/api/user/v1"
	"github.com/openshift/origin/pkg/cmd/server/apis/config"
	"github.com/openshift/origin/pkg/user/apis/user/validation"
	usercache "github.com/openshift/origin/pkg/user/cache"
)

func NewGroupMapper(groupCache *usercache.GroupCache, identityProviders []config.IdentityProvider) GroupMapper {
	idpGroupsPrefix := map[string]string{
		"": "", // prevents having to special case tokens that have no groups (and thus no provider name / prefix)
	}
	for _, identityProvider := range identityProviders {
		providerName := identityProvider.Name
		if identityProvider.LocalGroups {
			idpGroupsPrefix[providerName] = "" // no prefix since we are told not to "scope" these groups
		} else {
			// build a prefix based on the name of the IDP (IDP names are unique)
			// we use a / so that we are guaranteed to never conflict with builtin
			// groups like system:masters and group+user API objects
			idpGroupsPrefix[providerName] = providerName + "/"
		}
	}
	return &groupMapper{
		groupCache:      groupCache,
		idpGroupsPrefix: idpGroupsPrefix,
	}
}

type groupMapper struct {
	idpGroupsPrefix map[string]string // IDP Name -> group prefix
	groupCache      *usercache.GroupCache
}

func (g *groupMapper) GroupsFor(token *oauthv1.OAuthAccessToken, user *userapi.User) ([]string, error) {
	// groups from the token have an optional prefix so that groups from different IDPs can be distinguished
	prefix, err := g.getPrefix(token)
	if err != nil {
		// this should only ever error if someone changes the name of an IDP, which breaks all associated identities+users
		return nil, err
	}

	groups, err := g.groupCache.GroupsFor(user.Name)
	if err != nil {
		// this should only ever error if the index is not set up correctly (which means someone broke the wiring of the server)
		return nil, err
	}

	groupNames := make([]string, 0, len(groups)+len(user.Groups)+len(token.ProviderGroups))
	for _, group := range groups {
		groupNames = append(groupNames, group.Name)
	}
	groupNames = append(groupNames, user.Groups...)

	// groups from the cache (backed by group API object) and the user API object are guaranteed to be valid
	// groups from the token do not have such guarantees
	// we do this to make it easier for IDPs to send us group data without having to do large amounts of preprocessing
	// thus we need to drop invalid groups here
	// since we do not drop any group data that we receive from the IDP,
	// we could relax our requirements here if needed in the future
	for _, group := range token.ProviderGroups {
		// TODO possibly support mappings:
		// map group -> other group name based on some configuration
		// any such mapping should occur before our validation so an admin could say foo:bar means foo_bar
		// it is unclear if such a mapping should be global or per IDP, either way it feels messy and complex
		if !isValidGroupName(group) {
			continue
		}
		groupNames = append(groupNames, prefix+group)
	}

	return groupNames, nil
}

func (g *groupMapper) getPrefix(token *oauthv1.OAuthAccessToken) (string, error) {
	providerName := token.ProviderName
	prefix, ok := g.idpGroupsPrefix[providerName]
	if !ok {
		// do not leak any information about the token's metadata.name field
		return "", fmt.Errorf("token for user %q has unknown provider %q", token.UserName, providerName)
	}
	return prefix, nil
}

func isValidGroupName(name string) bool {
	// TODO we may need to copy the validation logic here based on import restrictions
	return len(name) > 0 && len(validation.ValidateGroupName(name, false)) == 0
}
