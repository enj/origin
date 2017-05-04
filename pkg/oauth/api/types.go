package api

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OAuthAccessToken struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	// ClientName references the client that created this token.
	ClientName string

	// ExpiresIn is the seconds from CreationTime before this token expires.
	ExpiresIn int64

	// Scopes is an array of the requested scopes.
	Scopes []string

	// RedirectURI is the redirection associated with the token.
	RedirectURI string

	// UserName is the user name associated with this token
	UserName string

	// UserUID is the unique UID associated with this token
	UserUID string

	// AuthorizeToken contains the token that authorized this token
	AuthorizeToken string

	// RefreshToken is the value by which this token can be renewed. Can be blank.
	RefreshToken string
}

type OAuthAuthorizeToken struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	// ClientName references the client that created this token.
	ClientName string

	// ExpiresIn is the seconds from CreationTime before this token expires.
	ExpiresIn int64

	// Scopes is an array of the requested scopes.
	Scopes []string

	// RedirectURI is the redirection associated with the token.
	RedirectURI string

	// State data from request
	State string

	// UserName is the user name associated with this token
	UserName string

	// UserUID is the unique UID associated with this token. UserUID and UserName must both match
	// for this token to be valid.
	UserUID string

	// CodeChallenge is the optional code_challenge associated with this authorization code, as described in rfc7636
	CodeChallenge string

	// CodeChallengeMethod is the optional code_challenge_method associated with this authorization code, as described in rfc7636
	CodeChallengeMethod string
}

// +genclient=true

type OAuthClient struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	// Secret is the unique secret associated with a client
	Secret string

	// AdditionalSecrets holds other secrets that may be used to identify the client.  This is useful for rotation
	// and for service account token validation
	AdditionalSecrets []string

	// RespondWithChallenges indicates whether the client wants authentication needed responses made in the form of challenges instead of redirects
	RespondWithChallenges bool

	// RedirectURIs is the valid redirection URIs associated with a client
	RedirectURIs []string

	// GrantMethod determines how to handle grants for this client. If no method is provided, the
	// cluster default grant handling method will be used
	GrantMethod GrantHandlerType

	// ScopeRestrictions describes which scopes this client can request.  Each requested scope
	// is checked against each restriction.  If any restriction matches, then the scope is allowed.
	// If no restriction matches, then the scope is denied.
	ScopeRestrictions []ScopeRestriction
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
	ExactValues []string

	// ClusterRole describes a set of restrictions for cluster role scoping.
	ClusterRole *ClusterRoleScopeRestriction
}

// ClusterRoleScopeRestriction describes restrictions on cluster role scopes
type ClusterRoleScopeRestriction struct {
	// RoleNames is the list of cluster roles that can referenced.  * means anything
	RoleNames []string
	// Namespaces is the list of namespaces that can be referenced.  * means any of them (including *)
	Namespaces []string
	// AllowEscalation indicates whether you can request roles and their escalating resources
	AllowEscalation bool
}

type OAuthClientAuthorization struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	// ClientName references the client that created this authorization
	ClientName string

	// UserName is the user name that authorized this client
	UserName string

	// UserUID is the unique UID associated with this authorization. UserUID and UserName
	// must both match for this authorization to be valid.
	UserUID string

	// Scopes is an array of the granted scopes.
	Scopes []string
}

type OAuthAccessTokenList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []OAuthAccessToken
}

type OAuthAuthorizeTokenList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []OAuthAuthorizeToken
}

type OAuthClientList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []OAuthClient
}

type OAuthClientAuthorizationList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []OAuthClientAuthorization
}

type OAuthRedirectReference struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Reference RedirectReference
}

type RedirectReference struct {
	Group string
	Kind  string
	Name  string
}

// StringSource allows specifying a string inline, or externally via env var or file.
// When it contains only a string value, it marshals to a simple JSON string.
type StringSource struct {
	// StringSourceSpec specifies the string value, or external location
	StringSourceSpec `json:",inline"`
}

// StringSourceSpec specifies a string value, or external location
type StringSourceSpec struct {
	// Value specifies the cleartext value, or an encrypted value if keyFile is specified.
	Value string `json:"value"`

	// Env specifies an envvar containing the cleartext value, or an encrypted value if the keyFile is specified.
	Env string `json:"env"`

	// File references a file containing the cleartext value, or an encrypted value if a keyFile is specified.
	File string `json:"file"`

	// KeyFile references a file containing the key to use to decrypt the value.
	KeyFile string `json:"keyFile"`
}

type LDAPSyncConfigList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []LDAPSyncConfig
}

// LDAPSyncConfig holds the necessary configuration options to define an LDAP group sync
type LDAPSyncConfig struct {
	metav1.TypeMeta `json:",inline"`
	// Host is the scheme, host and port of the LDAP server to connect to:
	// scheme://host:port
	URL string `json:"url"`
	// BindDN is an optional DN to bind to the LDAP server with
	BindDN string `json:"bindDN"`
	// BindPassword is an optional password to bind with during the search phase.
	BindPassword StringSource `json:"bindPassword"`

	// Insecure, if true, indicates the connection should not use TLS.
	// Cannot be set to true with a URL scheme of "ldaps://"
	// If false, "ldaps://" URLs connect using TLS, and "ldap://" URLs are upgraded to a TLS connection using StartTLS as specified in https://tools.ietf.org/html/rfc2830
	Insecure bool `json:"insecure"`
	// CA is the optional trusted certificate authority bundle to use when making requests to the server
	// If empty, the default system roots are used
	CA string `json:"ca"`

	// LDAPGroupUIDToOpenShiftGroupNameMapping is an optional direct mapping of LDAP group UIDs to
	// OpenShift Group names
	LDAPGroupUIDToOpenShiftGroupNameMapping map[string]string `json:"groupUIDNameMapping"`

	// RFC2307Config holds the configuration for extracting data from an LDAP server set up in a fashion
	// similar to RFC2307: first-class group and user entries, with group membership determined by a
	// multi-valued attribute on the group entry listing its members
	RFC2307Config *RFC2307Config `json:"rfc2307,omitempty"`

	// ActiveDirectoryConfig holds the configuration for extracting data from an LDAP server set up in a
	// fashion similar to that used in Active Directory: first-class user entries, with group membership
	// determined by a multi-valued attribute on members listing groups they are a member of
	ActiveDirectoryConfig *ActiveDirectoryConfig `json:"activeDirectory,omitempty"`

	// AugmentedActiveDirectoryConfig holds the configuration for extracting data from an LDAP server
	// set up in a fashion similar to that used in Active Directory as described above, with one addition:
	// first-class group entries exist and are used to hold metadata but not group membership
	AugmentedActiveDirectoryConfig *AugmentedActiveDirectoryConfig `json:"augmentedActiveDirectory,omitempty"`
}

// RFC2307Config holds the necessary configuration options to define how an LDAP group sync interacts with an LDAP
// server using the RFC2307 schema
type RFC2307Config struct {
	// AllGroupsQuery holds the template for an LDAP query that returns group entries.
	AllGroupsQuery LDAPQuery `json:"groupsQuery"`

	// GroupUIDAttributes defines which attribute on an LDAP group entry will be interpreted as its unique identifier.
	// (ldapGroupUID)
	GroupUIDAttribute string `json:"groupUIDAttribute"`

	// GroupNameAttributes defines which attributes on an LDAP group entry will be interpreted as its name to use for
	// an OpenShift group
	GroupNameAttributes []string `json:"groupNameAttributes"`

	// GroupMembershipAttributes defines which attributes on an LDAP group entry will be interpreted  as its members.
	// The values contained in those attributes must be queryable by your UserUIDAttribute
	GroupMembershipAttributes []string `json:"groupMembershipAttributes"`

	// AllUsersQuery holds the template for an LDAP query that returns user entries.
	AllUsersQuery LDAPQuery `json:"usersQuery"`

	// UserUIDAttribute defines which attribute on an LDAP user entry will be interpreted as its unique identifier.
	// It must correspond to values that will be found from the GroupMembershipAttributes
	UserUIDAttribute string `json:"userUIDAttribute"`

	// UserNameAttributes defines which attributes on an LDAP user entry will be used, in order, as its OpenShift user name.
	// The first attribute with a non-empty value is used. This should match your PreferredUsername setting for your LDAPPasswordIdentityProvider
	UserNameAttributes []string `json:"userNameAttributes"`

	// TolerateMemberNotFoundErrors determines the behavior of the LDAP sync job when missing user entries are
	// encountered. If 'true', an LDAP query for users that doesn't find any will be tolerated and an only
	// and error will be logged. If 'false', the LDAP sync job will fail if a query for users doesn't find
	// any. The default value is 'false'. Misconfigured LDAP sync jobs with this flag set to 'true' can cause
	// group membership to be removed, so it is recommended to use this flag with caution.
	TolerateMemberNotFoundErrors bool `json:"tolerateMemberNotFoundErrors"`

	// TolerateMemberOutOfScopeErrors determines the behavior of the LDAP sync job when out-of-scope user entries
	// are encountered. If 'true', an LDAP query for a user that falls outside of the base DN given for the all
	// user query will be tolerated and only an error will be logged. If 'false', the LDAP sync job will fail
	// if a user query would search outside of the base DN specified by the all user query. Misconfigured LDAP
	// sync jobs with this flag set to 'true' can result in groups missing users, so it is recommended to use
	// this flag with caution.
	TolerateMemberOutOfScopeErrors bool `json:"tolerateMemberOutOfScopeErrors"`
}

// ActiveDirectoryConfig holds the necessary configuration options to define how an LDAP group sync interacts with an LDAP
// server using the Active Directory schema
type ActiveDirectoryConfig struct {
	// AllUsersQuery holds the template for an LDAP query that returns user entries.
	AllUsersQuery LDAPQuery `json:"usersQuery"`

	// UserNameAttributes defines which attributes on an LDAP user entry will be interpreted as its OpenShift user name.
	UserNameAttributes []string `json:"userNameAttributes"`

	// GroupMembershipAttributes defines which attributes on an LDAP user entry will be interpreted
	// as the groups it is a member of
	GroupMembershipAttributes []string `json:"groupMembershipAttributes"`
}

// AugmentedActiveDirectoryConfig holds the necessary configuration options to define how an LDAP group sync interacts with an LDAP
// server using the augmented Active Directory schema
type AugmentedActiveDirectoryConfig struct {
	// AllUsersQuery holds the template for an LDAP query that returns user entries.
	AllUsersQuery LDAPQuery `json:"usersQuery"`

	// UserNameAttributes defines which attributes on an LDAP user entry will be interpreted as its OpenShift user name.
	UserNameAttributes []string `json:"userNameAttributes"`

	// GroupMembershipAttributes defines which attributes on an LDAP user entry will be interpreted
	// as the groups it is a member of
	GroupMembershipAttributes []string `json:"groupMembershipAttributes"`

	// AllGroupsQuery holds the template for an LDAP query that returns group entries.
	AllGroupsQuery LDAPQuery `json:"groupsQuery"`

	// GroupUIDAttributes defines which attribute on an LDAP group entry will be interpreted as its unique identifier.
	// (ldapGroupUID)
	GroupUIDAttribute string `json:"groupUIDAttribute"`

	// GroupNameAttributes defines which attributes on an LDAP group entry will be interpreted as its name to use for
	// an OpenShift group
	GroupNameAttributes []string `json:"groupNameAttributes"`
}

// LDAPQuery holds the options necessary to build an LDAP query
type LDAPQuery struct {
	// The DN of the branch of the directory where all searches should start from
	BaseDN string `json:"baseDN"`

	// The (optional) scope of the search. Can be:
	// base: only the base object,
	// one:  all object on the base level,
	// sub:  the entire subtree
	// Defaults to the entire subtree if not set
	Scope string `json:"scope"`

	// The (optional) behavior of the search with regards to alisases. Can be:
	// never:  never dereference aliases,
	// search: only dereference in searching,
	// base:   only dereference in finding the base object,
	// always: always dereference
	// Defaults to always dereferencing if not set
	DerefAliases string `json:"derefAliases"`

	// TimeLimit holds the limit of time in seconds that any request to the server can remain outstanding
	// before the wait for a response is given up. If this is 0, no client-side limit is imposed
	TimeLimit int64 `json:"timeout"`

	// Filter is a valid LDAP search filter that retrieves all relevant entries from the LDAP server with the base DN
	Filter string `json:"filter"`

	// PageSize is the maximum preferred page size, measured in LDAP entries. A page size of 0 means no paging will be done.
	PageSize int64 `json:"pageSize"`
}
