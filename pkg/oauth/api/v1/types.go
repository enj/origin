package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OAuthAccessToken describes an OAuth access token
type OAuthAccessToken struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// ClientName references the client that created this token.
	ClientName string `json:"clientName,omitempty" protobuf:"bytes,2,opt,name=clientName"`

	// ExpiresIn is the seconds from CreationTime before this token expires.
	ExpiresIn int64 `json:"expiresIn,omitempty" protobuf:"varint,3,opt,name=expiresIn"`

	// Scopes is an array of the requested scopes.
	Scopes []string `json:"scopes,omitempty" protobuf:"bytes,4,rep,name=scopes"`

	// RedirectURI is the redirection associated with the token.
	RedirectURI string `json:"redirectURI,omitempty" protobuf:"bytes,5,opt,name=redirectURI"`

	// UserName is the user name associated with this token
	UserName string `json:"userName,omitempty" protobuf:"bytes,6,opt,name=userName"`

	// UserUID is the unique UID associated with this token
	UserUID string `json:"userUID,omitempty" protobuf:"bytes,7,opt,name=userUID"`

	// AuthorizeToken contains the token that authorized this token
	AuthorizeToken string `json:"authorizeToken,omitempty" protobuf:"bytes,8,opt,name=authorizeToken"`

	// RefreshToken is the value by which this token can be renewed. Can be blank.
	RefreshToken string `json:"refreshToken,omitempty" protobuf:"bytes,9,opt,name=refreshToken"`
}

// OAuthAuthorizeToken describes an OAuth authorization token
type OAuthAuthorizeToken struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// ClientName references the client that created this token.
	ClientName string `json:"clientName,omitempty" protobuf:"bytes,2,opt,name=clientName"`

	// ExpiresIn is the seconds from CreationTime before this token expires.
	ExpiresIn int64 `json:"expiresIn,omitempty" protobuf:"varint,3,opt,name=expiresIn"`

	// Scopes is an array of the requested scopes.
	Scopes []string `json:"scopes,omitempty" protobuf:"bytes,4,rep,name=scopes"`

	// RedirectURI is the redirection associated with the token.
	RedirectURI string `json:"redirectURI,omitempty" protobuf:"bytes,5,opt,name=redirectURI"`

	// State data from request
	State string `json:"state,omitempty" protobuf:"bytes,6,opt,name=state"`

	// UserName is the user name associated with this token
	UserName string `json:"userName,omitempty" protobuf:"bytes,7,opt,name=userName"`

	// UserUID is the unique UID associated with this token. UserUID and UserName must both match
	// for this token to be valid.
	UserUID string `json:"userUID,omitempty" protobuf:"bytes,8,opt,name=userUID"`

	// CodeChallenge is the optional code_challenge associated with this authorization code, as described in rfc7636
	CodeChallenge string `json:"codeChallenge,omitempty" protobuf:"bytes,9,opt,name=codeChallenge"`

	// CodeChallengeMethod is the optional code_challenge_method associated with this authorization code, as described in rfc7636
	CodeChallengeMethod string `json:"codeChallengeMethod,omitempty" protobuf:"bytes,10,opt,name=codeChallengeMethod"`
}

// +genclient=true

// OAuthClient describes an OAuth client
type OAuthClient struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// Secret is the unique secret associated with a client
	Secret string `json:"secret,omitempty" protobuf:"bytes,2,opt,name=secret"`

	// AdditionalSecrets holds other secrets that may be used to identify the client.  This is useful for rotation
	// and for service account token validation
	AdditionalSecrets []string `json:"additionalSecrets,omitempty" protobuf:"bytes,3,rep,name=additionalSecrets"`

	// RespondWithChallenges indicates whether the client wants authentication needed responses made in the form of challenges instead of redirects
	RespondWithChallenges bool `json:"respondWithChallenges,omitempty" protobuf:"varint,4,opt,name=respondWithChallenges"`

	// RedirectURIs is the valid redirection URIs associated with a client
	RedirectURIs []string `json:"redirectURIs,omitempty" patchStrategy:"merge" protobuf:"bytes,5,rep,name=redirectURIs"`

	// GrantMethod determines how to handle grants for this client. If no method is provided, the
	// cluster default grant handling method will be used. Valid grant handling methods are:
	//  - auto:   always approves grant requests, useful for trusted clients
	//  - prompt: prompts the end user for approval of grant requests, useful for third-party clients
	//  - deny:   always denies grant requests, useful for black-listed clients
	GrantMethod GrantHandlerType `json:"grantMethod,omitempty" protobuf:"bytes,6,opt,name=grantMethod,casttype=GrantHandlerType"`

	// ScopeRestrictions describes which scopes this client can request.  Each requested scope
	// is checked against each restriction.  If any restriction matches, then the scope is allowed.
	// If no restriction matches, then the scope is denied.
	ScopeRestrictions []ScopeRestriction `json:"scopeRestrictions,omitempty" protobuf:"bytes,7,rep,name=scopeRestrictions"`
}

type GrantHandlerType string

const (
	// GrantHandlerAuto auto-approves client authorization grant requests
	GrantHandlerAuto GrantHandlerType = "auto"
	// GrantHandlerPrompt prompts the user to approve new client authorization grant requests
	GrantHandlerPrompt GrantHandlerType = "prompt"
	// GrantHandlerDeny auto-denies client authorization grant requests
	GrantHandlerDeny GrantHandlerType = "deny"
)

// ScopeRestriction describe one restriction on scopes.  Exactly one option must be non-nil.
type ScopeRestriction struct {
	// ExactValues means the scope has to match a particular set of strings exactly
	ExactValues []string `json:"literals,omitempty" protobuf:"bytes,1,rep,name=literals"`

	// ClusterRole describes a set of restrictions for cluster role scoping.
	ClusterRole *ClusterRoleScopeRestriction `json:"clusterRole,omitempty" protobuf:"bytes,2,opt,name=clusterRole"`
}

// ClusterRoleScopeRestriction describes restrictions on cluster role scopes
type ClusterRoleScopeRestriction struct {
	// RoleNames is the list of cluster roles that can referenced.  * means anything
	RoleNames []string `json:"roleNames" protobuf:"bytes,1,rep,name=roleNames"`
	// Namespaces is the list of namespaces that can be referenced.  * means any of them (including *)
	Namespaces []string `json:"namespaces" protobuf:"bytes,2,rep,name=namespaces"`
	// AllowEscalation indicates whether you can request roles and their escalating resources
	AllowEscalation bool `json:"allowEscalation" protobuf:"varint,3,opt,name=allowEscalation"`
}

// OAuthClientAuthorization describes an authorization created by an OAuth client
type OAuthClientAuthorization struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

	// ClientName references the client that created this authorization
	ClientName string `json:"clientName,omitempty" protobuf:"bytes,2,opt,name=clientName"`

	// UserName is the user name that authorized this client
	UserName string `json:"userName,omitempty" protobuf:"bytes,3,opt,name=userName"`

	// UserUID is the unique UID associated with this authorization. UserUID and UserName
	// must both match for this authorization to be valid.
	UserUID string `json:"userUID,omitempty" protobuf:"bytes,4,opt,name=userUID"`

	// Scopes is an array of the granted scopes.
	Scopes []string `json:"scopes,omitempty" protobuf:"bytes,5,rep,name=scopes"`
}

// OAuthAccessTokenList is a collection of OAuth access tokens
type OAuthAccessTokenList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// Items is the list of OAuth access tokens
	Items []OAuthAccessToken `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// OAuthAuthorizeTokenList is a collection of OAuth authorization tokens
type OAuthAuthorizeTokenList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// Items is the list of OAuth authorization tokens
	Items []OAuthAuthorizeToken `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// OAuthClientList is a collection of OAuth clients
type OAuthClientList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// Items is the list of OAuth clients
	Items []OAuthClient `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// OAuthClientAuthorizationList is a collection of OAuth client authorizations
type OAuthClientAuthorizationList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// Items is the list of OAuth client authorizations
	Items []OAuthClientAuthorization `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// OAuthRedirectReference is a reference to an OAuth redirect object.
type OAuthRedirectReference struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// The reference to an redirect object in the current namespace.
	Reference RedirectReference `json:"reference,omitempty" protobuf:"bytes,2,opt,name=reference"`
}

// RedirectReference specifies the target in the current namespace that resolves into redirect URIs.  Only the 'Route' kind is currently allowed.
type RedirectReference struct {
	// The group of the target that is being referred to.
	Group string `json:"group" protobuf:"bytes,1,opt,name=group"`

	// The kind of the target that is being referred to.  Currently, only 'Route' is allowed.
	Kind string `json:"kind" protobuf:"bytes,2,opt,name=kind"`

	// The name of the target that is being referred to. e.g. name of the Route.
	Name string `json:"name" protobuf:"bytes,3,opt,name=name"`
}

// StringSource allows specifying a string inline, or externally via env var or file.
// When it contains only a string value, it marshals to a simple JSON string.
type StringSource struct {
	// StringSourceSpec specifies the string value, or external location
	StringSourceSpec `json:",inline" protobuf:"bytes,1,opt,name=stringSourceSpec"`
}

// StringSourceSpec specifies a string value, or external location
type StringSourceSpec struct {
	// Value specifies the cleartext value, or an encrypted value if keyFile is specified.
	Value string `json:"value" protobuf:"bytes,1,opt,name=value"`

	// Env specifies an envvar containing the cleartext value, or an encrypted value if the keyFile is specified.
	Env string `json:"env" protobuf:"bytes,2,opt,name=env"`

	// File references a file containing the cleartext value, or an encrypted value if a keyFile is specified.
	File string `json:"file" protobuf:"bytes,3,opt,name=file"`

	// KeyFile references a file containing the key to use to decrypt the value.
	KeyFile string `json:"keyFile" protobuf:"bytes,4,opt,name=keyFile"`
}

// LDAPSyncConfigList us cool
type LDAPSyncConfigList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	metav1.ListMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	// Items is the list of LDAPSyncConfig
	Items []LDAPSyncConfig `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// LDAPSyncConfig holds the necessary configuration options to define an LDAP group sync
type LDAPSyncConfig struct {
	metav1.TypeMeta `json:",inline"`
	// Host is the scheme, host and port of the LDAP server to connect to:
	// scheme://host:port
	URL string `json:"url" protobuf:"bytes,1,opt,name=url"`
	// BindDN is an optional DN to bind to the LDAP server with
	BindDN string `json:"bindDN" protobuf:"bytes,2,opt,name=bindDN"`
	// BindPassword is an optional password to bind with during the search phase.
	BindPassword StringSource `json:"bindPassword" protobuf:"bytes,3,opt,name=bindPassword"`

	// Insecure, if true, indicates the connection should not use TLS.
	// Cannot be set to true with a URL scheme of "ldaps://"
	// If false, "ldaps://" URLs connect using TLS, and "ldap://" URLs are upgraded to a TLS connection using StartTLS as specified in https://tools.ietf.org/html/rfc2830
	Insecure bool `json:"insecure" protobuf:"varint,4,opt,name=insecure"`
	// CA is the optional trusted certificate authority bundle to use when making requests to the server
	// If empty, the default system roots are used
	CA string `json:"ca" protobuf:"bytes,5,opt,name=ca"`

	// LDAPGroupUIDToOpenShiftGroupNameMapping is an optional direct mapping of LDAP group UIDs to
	// OpenShift Group names
	LDAPGroupUIDToOpenShiftGroupNameMapping map[string]string `json:"groupUIDNameMapping" protobuf:"bytes,6,rep,name=groupUIDNameMapping"`

	// RFC2307Config holds the configuration for extracting data from an LDAP server set up in a fashion
	// similar to RFC2307: first-class group and user entries, with group membership determined by a
	// multi-valued attribute on the group entry listing its members
	RFC2307Config *RFC2307Config `json:"rfc2307,omitempty" protobuf:"bytes,7,opt,name=rfc2307"`

	// ActiveDirectoryConfig holds the configuration for extracting data from an LDAP server set up in a
	// fashion similar to that used in Active Directory: first-class user entries, with group membership
	// determined by a multi-valued attribute on members listing groups they are a member of
	ActiveDirectoryConfig *ActiveDirectoryConfig `json:"activeDirectory,omitempty" protobuf:"bytes,8,opt,name=activeDirectory"`

	// AugmentedActiveDirectoryConfig holds the configuration for extracting data from an LDAP server
	// set up in a fashion similar to that used in Active Directory as described above, with one addition:
	// first-class group entries exist and are used to hold metadata but not group membership
	AugmentedActiveDirectoryConfig *AugmentedActiveDirectoryConfig `json:"augmentedActiveDirectory,omitempty" protobuf:"bytes,9,opt,name=augmentedActiveDirectory"`
}

// RFC2307Config holds the necessary configuration options to define how an LDAP group sync interacts with an LDAP
// server using the RFC2307 schema
type RFC2307Config struct {
	// AllGroupsQuery holds the template for an LDAP query that returns group entries.
	AllGroupsQuery LDAPQuery `json:"groupsQuery" protobuf:"bytes,1,opt,name=groupsQuery"`

	// GroupUIDAttributes defines which attribute on an LDAP group entry will be interpreted as its unique identifier.
	// (ldapGroupUID)
	GroupUIDAttribute string `json:"groupUIDAttribute" protobuf:"bytes,2,opt,name=groupUIDAttribute"`

	// GroupNameAttributes defines which attributes on an LDAP group entry will be interpreted as its name to use for
	// an OpenShift group
	GroupNameAttributes []string `json:"groupNameAttributes" protobuf:"bytes,3,rep,name=groupNameAttributes"`

	// GroupMembershipAttributes defines which attributes on an LDAP group entry will be interpreted  as its members.
	// The values contained in those attributes must be queryable by your UserUIDAttribute
	GroupMembershipAttributes []string `json:"groupMembershipAttributes" protobuf:"bytes,4,rep,name=groupMembershipAttributes"`

	// AllUsersQuery holds the template for an LDAP query that returns user entries.
	AllUsersQuery LDAPQuery `json:"usersQuery" protobuf:"bytes,5,opt,name=usersQuery"`

	// UserUIDAttribute defines which attribute on an LDAP user entry will be interpreted as its unique identifier.
	// It must correspond to values that will be found from the GroupMembershipAttributes
	UserUIDAttribute string `json:"userUIDAttribute" protobuf:"bytes,6,opt,name=userUIDAttribute"`

	// UserNameAttributes defines which attributes on an LDAP user entry will be used, in order, as its OpenShift user name.
	// The first attribute with a non-empty value is used. This should match your PreferredUsername setting for your LDAPPasswordIdentityProvider
	UserNameAttributes []string `json:"userNameAttributes" protobuf:"bytes,7,rep,name=userNameAttributes"`

	// TolerateMemberNotFoundErrors determines the behavior of the LDAP sync job when missing user entries are
	// encountered. If 'true', an LDAP query for users that doesn't find any will be tolerated and an only
	// and error will be logged. If 'false', the LDAP sync job will fail if a query for users doesn't find
	// any. The default value is 'false'. Misconfigured LDAP sync jobs with this flag set to 'true' can cause
	// group membership to be removed, so it is recommended to use this flag with caution.
	TolerateMemberNotFoundErrors bool `json:"tolerateMemberNotFoundErrors" protobuf:"varint,8,opt,name=tolerateMemberNotFoundErrors"`

	// TolerateMemberOutOfScopeErrors determines the behavior of the LDAP sync job when out-of-scope user entries
	// are encountered. If 'true', an LDAP query for a user that falls outside of the base DN given for the all
	// user query will be tolerated and only an error will be logged. If 'false', the LDAP sync job will fail
	// if a user query would search outside of the base DN specified by the all user query. Misconfigured LDAP
	// sync jobs with this flag set to 'true' can result in groups missing users, so it is recommended to use
	// this flag with caution.
	TolerateMemberOutOfScopeErrors bool `json:"tolerateMemberOutOfScopeErrors" protobuf:"varint,9,opt,name=tolerateMemberOutOfScopeErrors"`
}

// ActiveDirectoryConfig holds the necessary configuration options to define how an LDAP group sync interacts with an LDAP
// server using the Active Directory schema
type ActiveDirectoryConfig struct {
	// AllUsersQuery holds the template for an LDAP query that returns user entries.
	AllUsersQuery LDAPQuery `json:"usersQuery" protobuf:"bytes,1,opt,name=usersQuery"`

	// UserNameAttributes defines which attributes on an LDAP user entry will be interpreted as its OpenShift user name.
	UserNameAttributes []string `json:"userNameAttributes" protobuf:"bytes,2,rep,name=userNameAttributes"`

	// GroupMembershipAttributes defines which attributes on an LDAP user entry will be interpreted
	// as the groups it is a member of
	GroupMembershipAttributes []string `json:"groupMembershipAttributes" protobuf:"bytes,3,rep,name=groupMembershipAttributes"`
}

// AugmentedActiveDirectoryConfig holds the necessary configuration options to define how an LDAP group sync interacts with an LDAP
// server using the augmented Active Directory schema
type AugmentedActiveDirectoryConfig struct {
	// AllUsersQuery holds the template for an LDAP query that returns user entries.
	AllUsersQuery LDAPQuery `json:"usersQuery" protobuf:"bytes,1,opt,name=usersQuery"`

	// UserNameAttributes defines which attributes on an LDAP user entry will be interpreted as its OpenShift user name.
	UserNameAttributes []string `json:"userNameAttributes" protobuf:"bytes,2,rep,name=userNameAttributes"`

	// GroupMembershipAttributes defines which attributes on an LDAP user entry will be interpreted
	// as the groups it is a member of
	GroupMembershipAttributes []string `json:"groupMembershipAttributes" protobuf:"bytes,3,rep,name=groupMembershipAttributes"`

	// AllGroupsQuery holds the template for an LDAP query that returns group entries.
	AllGroupsQuery LDAPQuery `json:"groupsQuery" protobuf:"bytes,4,opt,name=groupsQuery"`

	// GroupUIDAttributes defines which attribute on an LDAP group entry will be interpreted as its unique identifier.
	// (ldapGroupUID)
	GroupUIDAttribute string `json:"groupUIDAttribute" protobuf:"bytes,5,opt,name=groupUIDAttribute"`

	// GroupNameAttributes defines which attributes on an LDAP group entry will be interpreted as its name to use for
	// an OpenShift group
	GroupNameAttributes []string `json:"groupNameAttributes" protobuf:"bytes,6,rep,name=groupNameAttributes"`
}

// LDAPQuery holds the options necessary to build an LDAP query
type LDAPQuery struct {
	// The DN of the branch of the directory where all searches should start from
	BaseDN string `json:"baseDN" protobuf:"bytes,1,opt,name=baseDN"`

	// The (optional) scope of the search. Can be:
	// base: only the base object,
	// one:  all object on the base level,
	// sub:  the entire subtree
	// Defaults to the entire subtree if not set
	Scope string `json:"scope" protobuf:"bytes,2,opt,name=scope"`

	// The (optional) behavior of the search with regards to alisases. Can be:
	// never:  never dereference aliases,
	// search: only dereference in searching,
	// base:   only dereference in finding the base object,
	// always: always dereference
	// Defaults to always dereferencing if not set
	DerefAliases string `json:"derefAliases" protobuf:"bytes,3,opt,name=derefAliases"`

	// TimeLimit holds the limit of time in seconds that any request to the server can remain outstanding
	// before the wait for a response is given up. If this is 0, no client-side limit is imposed
	TimeLimit int64 `json:"timeout" protobuf:"varint,4,opt,name=timeout"`

	// Filter is a valid LDAP search filter that retrieves all relevant entries from the LDAP server with the base DN
	Filter string `json:"filter" protobuf:"bytes,5,opt,name=filter"`

	// PageSize is the maximum preferred page size, measured in LDAP entries. A page size of 0 means no paging will be done.
	PageSize int64 `json:"pageSize" protobuf:"varint,6,opt,name=pageSize"`
}
