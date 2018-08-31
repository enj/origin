package oauth

import (
	oauthv1 "github.com/openshift/api/oauth/v1"
	userapi "github.com/openshift/api/user/v1"
	"github.com/openshift/origin/pkg/cmd/server/apis/config"
	"github.com/openshift/origin/pkg/user/apis/user/validation"
	usercache "github.com/openshift/origin/pkg/user/cache"
)

func NewGroupMapper(groupCache *usercache.GroupCache, identityProviders []config.IdentityProvider) GroupMapper {
	idpGroupsPrefix := map[string]string{}
	for _, identityProvider := range identityProviders {
		if groupsPrefix := identityProvider.GroupsPrefix; groupsPrefix != nil {
			idpGroupsPrefix[identityProvider.Name] = *groupsPrefix
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
	// these groups also have an optional prefix to allow easily distinguishing groups from different IDPs
	prefix := g.getPrefix(token)
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

func (g *groupMapper) getPrefix(token *oauthv1.OAuthAccessToken) string {
	providerName := token.ProviderName
	prefix, ok := g.idpGroupsPrefix[providerName]
	if !ok {
		// if there is no provider specific override, we provide a default one.
		// we do the defaulting here instead of NewGroupMapper since the IDP config
		// is not guaranteed to be consistent over the lifetime of a token.
		// we use a / so that we are guaranteed to never conflict with builtin
		// groups like system:masters and group+user API objects
		return providerName + "/"
	}
	return prefix
}

func isValidGroupName(name string) bool {
	// TODO probably need to copy the validation logic here
	return len(name) > 0 && len(validation.ValidateGroupName(name, false)) == 0
}
