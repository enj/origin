// +build !ignore_autogenerated_openshift

// This file was autogenerated by conversion-gen. Do not edit it manually!

package v1

import (
	v1 "github.com/openshift/api/oauth/v1"
	oauth "github.com/openshift/origin/pkg/oauth/apis/oauth"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
	unsafe "unsafe"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(scheme *runtime.Scheme) error {
	return scheme.AddGeneratedConversionFuncs(
		Convert_v1_ClusterRoleScopeRestriction_To_oauth_ClusterRoleScopeRestriction,
		Convert_oauth_ClusterRoleScopeRestriction_To_v1_ClusterRoleScopeRestriction,
		Convert_v1_OAuthAccessToken_To_oauth_OAuthAccessToken,
		Convert_oauth_OAuthAccessToken_To_v1_OAuthAccessToken,
		Convert_v1_OAuthAccessTokenList_To_oauth_OAuthAccessTokenList,
		Convert_oauth_OAuthAccessTokenList_To_v1_OAuthAccessTokenList,
		Convert_v1_OAuthAccessTokenRequest_To_oauth_OAuthAccessTokenRequest,
		Convert_oauth_OAuthAccessTokenRequest_To_v1_OAuthAccessTokenRequest,
		Convert_v1_OAuthAuthorizeToken_To_oauth_OAuthAuthorizeToken,
		Convert_oauth_OAuthAuthorizeToken_To_v1_OAuthAuthorizeToken,
		Convert_v1_OAuthAuthorizeTokenList_To_oauth_OAuthAuthorizeTokenList,
		Convert_oauth_OAuthAuthorizeTokenList_To_v1_OAuthAuthorizeTokenList,
		Convert_v1_OAuthClient_To_oauth_OAuthClient,
		Convert_oauth_OAuthClient_To_v1_OAuthClient,
		Convert_v1_OAuthClientAuthorization_To_oauth_OAuthClientAuthorization,
		Convert_oauth_OAuthClientAuthorization_To_v1_OAuthClientAuthorization,
		Convert_v1_OAuthClientAuthorizationList_To_oauth_OAuthClientAuthorizationList,
		Convert_oauth_OAuthClientAuthorizationList_To_v1_OAuthClientAuthorizationList,
		Convert_v1_OAuthClientList_To_oauth_OAuthClientList,
		Convert_oauth_OAuthClientList_To_v1_OAuthClientList,
		Convert_v1_OAuthRedirectReference_To_oauth_OAuthRedirectReference,
		Convert_oauth_OAuthRedirectReference_To_v1_OAuthRedirectReference,
		Convert_v1_RedirectReference_To_oauth_RedirectReference,
		Convert_oauth_RedirectReference_To_v1_RedirectReference,
		Convert_v1_ScopeRestriction_To_oauth_ScopeRestriction,
		Convert_oauth_ScopeRestriction_To_v1_ScopeRestriction,
	)
}

func autoConvert_v1_ClusterRoleScopeRestriction_To_oauth_ClusterRoleScopeRestriction(in *v1.ClusterRoleScopeRestriction, out *oauth.ClusterRoleScopeRestriction, s conversion.Scope) error {
	out.RoleNames = *(*[]string)(unsafe.Pointer(&in.RoleNames))
	out.Namespaces = *(*[]string)(unsafe.Pointer(&in.Namespaces))
	out.AllowEscalation = in.AllowEscalation
	return nil
}

// Convert_v1_ClusterRoleScopeRestriction_To_oauth_ClusterRoleScopeRestriction is an autogenerated conversion function.
func Convert_v1_ClusterRoleScopeRestriction_To_oauth_ClusterRoleScopeRestriction(in *v1.ClusterRoleScopeRestriction, out *oauth.ClusterRoleScopeRestriction, s conversion.Scope) error {
	return autoConvert_v1_ClusterRoleScopeRestriction_To_oauth_ClusterRoleScopeRestriction(in, out, s)
}

func autoConvert_oauth_ClusterRoleScopeRestriction_To_v1_ClusterRoleScopeRestriction(in *oauth.ClusterRoleScopeRestriction, out *v1.ClusterRoleScopeRestriction, s conversion.Scope) error {
	out.RoleNames = *(*[]string)(unsafe.Pointer(&in.RoleNames))
	out.Namespaces = *(*[]string)(unsafe.Pointer(&in.Namespaces))
	out.AllowEscalation = in.AllowEscalation
	return nil
}

// Convert_oauth_ClusterRoleScopeRestriction_To_v1_ClusterRoleScopeRestriction is an autogenerated conversion function.
func Convert_oauth_ClusterRoleScopeRestriction_To_v1_ClusterRoleScopeRestriction(in *oauth.ClusterRoleScopeRestriction, out *v1.ClusterRoleScopeRestriction, s conversion.Scope) error {
	return autoConvert_oauth_ClusterRoleScopeRestriction_To_v1_ClusterRoleScopeRestriction(in, out, s)
}

func autoConvert_v1_OAuthAccessToken_To_oauth_OAuthAccessToken(in *v1.OAuthAccessToken, out *oauth.OAuthAccessToken, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.ClientName = in.ClientName
	out.ExpiresIn = in.ExpiresIn
	out.Scopes = *(*[]string)(unsafe.Pointer(&in.Scopes))
	out.RedirectURI = in.RedirectURI
	out.UserName = in.UserName
	out.UserUID = in.UserUID
	out.AuthorizeToken = in.AuthorizeToken
	out.RefreshToken = in.RefreshToken
	out.InactivityTimeoutSeconds = in.InactivityTimeoutSeconds
	return nil
}

// Convert_v1_OAuthAccessToken_To_oauth_OAuthAccessToken is an autogenerated conversion function.
func Convert_v1_OAuthAccessToken_To_oauth_OAuthAccessToken(in *v1.OAuthAccessToken, out *oauth.OAuthAccessToken, s conversion.Scope) error {
	return autoConvert_v1_OAuthAccessToken_To_oauth_OAuthAccessToken(in, out, s)
}

func autoConvert_oauth_OAuthAccessToken_To_v1_OAuthAccessToken(in *oauth.OAuthAccessToken, out *v1.OAuthAccessToken, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.ClientName = in.ClientName
	out.ExpiresIn = in.ExpiresIn
	out.Scopes = *(*[]string)(unsafe.Pointer(&in.Scopes))
	out.RedirectURI = in.RedirectURI
	out.UserName = in.UserName
	out.UserUID = in.UserUID
	out.AuthorizeToken = in.AuthorizeToken
	out.RefreshToken = in.RefreshToken
	out.InactivityTimeoutSeconds = in.InactivityTimeoutSeconds
	return nil
}

// Convert_oauth_OAuthAccessToken_To_v1_OAuthAccessToken is an autogenerated conversion function.
func Convert_oauth_OAuthAccessToken_To_v1_OAuthAccessToken(in *oauth.OAuthAccessToken, out *v1.OAuthAccessToken, s conversion.Scope) error {
	return autoConvert_oauth_OAuthAccessToken_To_v1_OAuthAccessToken(in, out, s)
}

func autoConvert_v1_OAuthAccessTokenList_To_oauth_OAuthAccessTokenList(in *v1.OAuthAccessTokenList, out *oauth.OAuthAccessTokenList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]oauth.OAuthAccessToken)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_v1_OAuthAccessTokenList_To_oauth_OAuthAccessTokenList is an autogenerated conversion function.
func Convert_v1_OAuthAccessTokenList_To_oauth_OAuthAccessTokenList(in *v1.OAuthAccessTokenList, out *oauth.OAuthAccessTokenList, s conversion.Scope) error {
	return autoConvert_v1_OAuthAccessTokenList_To_oauth_OAuthAccessTokenList(in, out, s)
}

func autoConvert_oauth_OAuthAccessTokenList_To_v1_OAuthAccessTokenList(in *oauth.OAuthAccessTokenList, out *v1.OAuthAccessTokenList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]v1.OAuthAccessToken)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_oauth_OAuthAccessTokenList_To_v1_OAuthAccessTokenList is an autogenerated conversion function.
func Convert_oauth_OAuthAccessTokenList_To_v1_OAuthAccessTokenList(in *oauth.OAuthAccessTokenList, out *v1.OAuthAccessTokenList, s conversion.Scope) error {
	return autoConvert_oauth_OAuthAccessTokenList_To_v1_OAuthAccessTokenList(in, out, s)
}

func autoConvert_v1_OAuthAccessTokenRequest_To_oauth_OAuthAccessTokenRequest(in *v1.OAuthAccessTokenRequest, out *oauth.OAuthAccessTokenRequest, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.UserName = in.UserName
	out.Token = in.Token
	return nil
}

// Convert_v1_OAuthAccessTokenRequest_To_oauth_OAuthAccessTokenRequest is an autogenerated conversion function.
func Convert_v1_OAuthAccessTokenRequest_To_oauth_OAuthAccessTokenRequest(in *v1.OAuthAccessTokenRequest, out *oauth.OAuthAccessTokenRequest, s conversion.Scope) error {
	return autoConvert_v1_OAuthAccessTokenRequest_To_oauth_OAuthAccessTokenRequest(in, out, s)
}

func autoConvert_oauth_OAuthAccessTokenRequest_To_v1_OAuthAccessTokenRequest(in *oauth.OAuthAccessTokenRequest, out *v1.OAuthAccessTokenRequest, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.UserName = in.UserName
	out.Token = in.Token
	return nil
}

// Convert_oauth_OAuthAccessTokenRequest_To_v1_OAuthAccessTokenRequest is an autogenerated conversion function.
func Convert_oauth_OAuthAccessTokenRequest_To_v1_OAuthAccessTokenRequest(in *oauth.OAuthAccessTokenRequest, out *v1.OAuthAccessTokenRequest, s conversion.Scope) error {
	return autoConvert_oauth_OAuthAccessTokenRequest_To_v1_OAuthAccessTokenRequest(in, out, s)
}

func autoConvert_v1_OAuthAuthorizeToken_To_oauth_OAuthAuthorizeToken(in *v1.OAuthAuthorizeToken, out *oauth.OAuthAuthorizeToken, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.ClientName = in.ClientName
	out.ExpiresIn = in.ExpiresIn
	out.Scopes = *(*[]string)(unsafe.Pointer(&in.Scopes))
	out.RedirectURI = in.RedirectURI
	out.State = in.State
	out.UserName = in.UserName
	out.UserUID = in.UserUID
	out.CodeChallenge = in.CodeChallenge
	out.CodeChallengeMethod = in.CodeChallengeMethod
	return nil
}

// Convert_v1_OAuthAuthorizeToken_To_oauth_OAuthAuthorizeToken is an autogenerated conversion function.
func Convert_v1_OAuthAuthorizeToken_To_oauth_OAuthAuthorizeToken(in *v1.OAuthAuthorizeToken, out *oauth.OAuthAuthorizeToken, s conversion.Scope) error {
	return autoConvert_v1_OAuthAuthorizeToken_To_oauth_OAuthAuthorizeToken(in, out, s)
}

func autoConvert_oauth_OAuthAuthorizeToken_To_v1_OAuthAuthorizeToken(in *oauth.OAuthAuthorizeToken, out *v1.OAuthAuthorizeToken, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.ClientName = in.ClientName
	out.ExpiresIn = in.ExpiresIn
	out.Scopes = *(*[]string)(unsafe.Pointer(&in.Scopes))
	out.RedirectURI = in.RedirectURI
	out.State = in.State
	out.UserName = in.UserName
	out.UserUID = in.UserUID
	out.CodeChallenge = in.CodeChallenge
	out.CodeChallengeMethod = in.CodeChallengeMethod
	return nil
}

// Convert_oauth_OAuthAuthorizeToken_To_v1_OAuthAuthorizeToken is an autogenerated conversion function.
func Convert_oauth_OAuthAuthorizeToken_To_v1_OAuthAuthorizeToken(in *oauth.OAuthAuthorizeToken, out *v1.OAuthAuthorizeToken, s conversion.Scope) error {
	return autoConvert_oauth_OAuthAuthorizeToken_To_v1_OAuthAuthorizeToken(in, out, s)
}

func autoConvert_v1_OAuthAuthorizeTokenList_To_oauth_OAuthAuthorizeTokenList(in *v1.OAuthAuthorizeTokenList, out *oauth.OAuthAuthorizeTokenList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]oauth.OAuthAuthorizeToken)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_v1_OAuthAuthorizeTokenList_To_oauth_OAuthAuthorizeTokenList is an autogenerated conversion function.
func Convert_v1_OAuthAuthorizeTokenList_To_oauth_OAuthAuthorizeTokenList(in *v1.OAuthAuthorizeTokenList, out *oauth.OAuthAuthorizeTokenList, s conversion.Scope) error {
	return autoConvert_v1_OAuthAuthorizeTokenList_To_oauth_OAuthAuthorizeTokenList(in, out, s)
}

func autoConvert_oauth_OAuthAuthorizeTokenList_To_v1_OAuthAuthorizeTokenList(in *oauth.OAuthAuthorizeTokenList, out *v1.OAuthAuthorizeTokenList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]v1.OAuthAuthorizeToken)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_oauth_OAuthAuthorizeTokenList_To_v1_OAuthAuthorizeTokenList is an autogenerated conversion function.
func Convert_oauth_OAuthAuthorizeTokenList_To_v1_OAuthAuthorizeTokenList(in *oauth.OAuthAuthorizeTokenList, out *v1.OAuthAuthorizeTokenList, s conversion.Scope) error {
	return autoConvert_oauth_OAuthAuthorizeTokenList_To_v1_OAuthAuthorizeTokenList(in, out, s)
}

func autoConvert_v1_OAuthClient_To_oauth_OAuthClient(in *v1.OAuthClient, out *oauth.OAuthClient, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.Secret = in.Secret
	out.AdditionalSecrets = *(*[]string)(unsafe.Pointer(&in.AdditionalSecrets))
	out.RespondWithChallenges = in.RespondWithChallenges
	out.RedirectURIs = *(*[]string)(unsafe.Pointer(&in.RedirectURIs))
	out.GrantMethod = oauth.GrantHandlerType(in.GrantMethod)
	out.ScopeRestrictions = *(*[]oauth.ScopeRestriction)(unsafe.Pointer(&in.ScopeRestrictions))
	out.AccessTokenMaxAgeSeconds = (*int32)(unsafe.Pointer(in.AccessTokenMaxAgeSeconds))
	out.AccessTokenInactivityTimeoutSeconds = (*int32)(unsafe.Pointer(in.AccessTokenInactivityTimeoutSeconds))
	return nil
}

// Convert_v1_OAuthClient_To_oauth_OAuthClient is an autogenerated conversion function.
func Convert_v1_OAuthClient_To_oauth_OAuthClient(in *v1.OAuthClient, out *oauth.OAuthClient, s conversion.Scope) error {
	return autoConvert_v1_OAuthClient_To_oauth_OAuthClient(in, out, s)
}

func autoConvert_oauth_OAuthClient_To_v1_OAuthClient(in *oauth.OAuthClient, out *v1.OAuthClient, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.Secret = in.Secret
	out.AdditionalSecrets = *(*[]string)(unsafe.Pointer(&in.AdditionalSecrets))
	out.RespondWithChallenges = in.RespondWithChallenges
	out.RedirectURIs = *(*[]string)(unsafe.Pointer(&in.RedirectURIs))
	out.GrantMethod = v1.GrantHandlerType(in.GrantMethod)
	out.ScopeRestrictions = *(*[]v1.ScopeRestriction)(unsafe.Pointer(&in.ScopeRestrictions))
	out.AccessTokenMaxAgeSeconds = (*int32)(unsafe.Pointer(in.AccessTokenMaxAgeSeconds))
	out.AccessTokenInactivityTimeoutSeconds = (*int32)(unsafe.Pointer(in.AccessTokenInactivityTimeoutSeconds))
	return nil
}

// Convert_oauth_OAuthClient_To_v1_OAuthClient is an autogenerated conversion function.
func Convert_oauth_OAuthClient_To_v1_OAuthClient(in *oauth.OAuthClient, out *v1.OAuthClient, s conversion.Scope) error {
	return autoConvert_oauth_OAuthClient_To_v1_OAuthClient(in, out, s)
}

func autoConvert_v1_OAuthClientAuthorization_To_oauth_OAuthClientAuthorization(in *v1.OAuthClientAuthorization, out *oauth.OAuthClientAuthorization, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.ClientName = in.ClientName
	out.UserName = in.UserName
	out.UserUID = in.UserUID
	out.Scopes = *(*[]string)(unsafe.Pointer(&in.Scopes))
	return nil
}

// Convert_v1_OAuthClientAuthorization_To_oauth_OAuthClientAuthorization is an autogenerated conversion function.
func Convert_v1_OAuthClientAuthorization_To_oauth_OAuthClientAuthorization(in *v1.OAuthClientAuthorization, out *oauth.OAuthClientAuthorization, s conversion.Scope) error {
	return autoConvert_v1_OAuthClientAuthorization_To_oauth_OAuthClientAuthorization(in, out, s)
}

func autoConvert_oauth_OAuthClientAuthorization_To_v1_OAuthClientAuthorization(in *oauth.OAuthClientAuthorization, out *v1.OAuthClientAuthorization, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	out.ClientName = in.ClientName
	out.UserName = in.UserName
	out.UserUID = in.UserUID
	out.Scopes = *(*[]string)(unsafe.Pointer(&in.Scopes))
	return nil
}

// Convert_oauth_OAuthClientAuthorization_To_v1_OAuthClientAuthorization is an autogenerated conversion function.
func Convert_oauth_OAuthClientAuthorization_To_v1_OAuthClientAuthorization(in *oauth.OAuthClientAuthorization, out *v1.OAuthClientAuthorization, s conversion.Scope) error {
	return autoConvert_oauth_OAuthClientAuthorization_To_v1_OAuthClientAuthorization(in, out, s)
}

func autoConvert_v1_OAuthClientAuthorizationList_To_oauth_OAuthClientAuthorizationList(in *v1.OAuthClientAuthorizationList, out *oauth.OAuthClientAuthorizationList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]oauth.OAuthClientAuthorization)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_v1_OAuthClientAuthorizationList_To_oauth_OAuthClientAuthorizationList is an autogenerated conversion function.
func Convert_v1_OAuthClientAuthorizationList_To_oauth_OAuthClientAuthorizationList(in *v1.OAuthClientAuthorizationList, out *oauth.OAuthClientAuthorizationList, s conversion.Scope) error {
	return autoConvert_v1_OAuthClientAuthorizationList_To_oauth_OAuthClientAuthorizationList(in, out, s)
}

func autoConvert_oauth_OAuthClientAuthorizationList_To_v1_OAuthClientAuthorizationList(in *oauth.OAuthClientAuthorizationList, out *v1.OAuthClientAuthorizationList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]v1.OAuthClientAuthorization)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_oauth_OAuthClientAuthorizationList_To_v1_OAuthClientAuthorizationList is an autogenerated conversion function.
func Convert_oauth_OAuthClientAuthorizationList_To_v1_OAuthClientAuthorizationList(in *oauth.OAuthClientAuthorizationList, out *v1.OAuthClientAuthorizationList, s conversion.Scope) error {
	return autoConvert_oauth_OAuthClientAuthorizationList_To_v1_OAuthClientAuthorizationList(in, out, s)
}

func autoConvert_v1_OAuthClientList_To_oauth_OAuthClientList(in *v1.OAuthClientList, out *oauth.OAuthClientList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]oauth.OAuthClient)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_v1_OAuthClientList_To_oauth_OAuthClientList is an autogenerated conversion function.
func Convert_v1_OAuthClientList_To_oauth_OAuthClientList(in *v1.OAuthClientList, out *oauth.OAuthClientList, s conversion.Scope) error {
	return autoConvert_v1_OAuthClientList_To_oauth_OAuthClientList(in, out, s)
}

func autoConvert_oauth_OAuthClientList_To_v1_OAuthClientList(in *oauth.OAuthClientList, out *v1.OAuthClientList, s conversion.Scope) error {
	out.ListMeta = in.ListMeta
	out.Items = *(*[]v1.OAuthClient)(unsafe.Pointer(&in.Items))
	return nil
}

// Convert_oauth_OAuthClientList_To_v1_OAuthClientList is an autogenerated conversion function.
func Convert_oauth_OAuthClientList_To_v1_OAuthClientList(in *oauth.OAuthClientList, out *v1.OAuthClientList, s conversion.Scope) error {
	return autoConvert_oauth_OAuthClientList_To_v1_OAuthClientList(in, out, s)
}

func autoConvert_v1_OAuthRedirectReference_To_oauth_OAuthRedirectReference(in *v1.OAuthRedirectReference, out *oauth.OAuthRedirectReference, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_v1_RedirectReference_To_oauth_RedirectReference(&in.Reference, &out.Reference, s); err != nil {
		return err
	}
	return nil
}

// Convert_v1_OAuthRedirectReference_To_oauth_OAuthRedirectReference is an autogenerated conversion function.
func Convert_v1_OAuthRedirectReference_To_oauth_OAuthRedirectReference(in *v1.OAuthRedirectReference, out *oauth.OAuthRedirectReference, s conversion.Scope) error {
	return autoConvert_v1_OAuthRedirectReference_To_oauth_OAuthRedirectReference(in, out, s)
}

func autoConvert_oauth_OAuthRedirectReference_To_v1_OAuthRedirectReference(in *oauth.OAuthRedirectReference, out *v1.OAuthRedirectReference, s conversion.Scope) error {
	out.ObjectMeta = in.ObjectMeta
	if err := Convert_oauth_RedirectReference_To_v1_RedirectReference(&in.Reference, &out.Reference, s); err != nil {
		return err
	}
	return nil
}

// Convert_oauth_OAuthRedirectReference_To_v1_OAuthRedirectReference is an autogenerated conversion function.
func Convert_oauth_OAuthRedirectReference_To_v1_OAuthRedirectReference(in *oauth.OAuthRedirectReference, out *v1.OAuthRedirectReference, s conversion.Scope) error {
	return autoConvert_oauth_OAuthRedirectReference_To_v1_OAuthRedirectReference(in, out, s)
}

func autoConvert_v1_RedirectReference_To_oauth_RedirectReference(in *v1.RedirectReference, out *oauth.RedirectReference, s conversion.Scope) error {
	out.Group = in.Group
	out.Kind = in.Kind
	out.Name = in.Name
	return nil
}

// Convert_v1_RedirectReference_To_oauth_RedirectReference is an autogenerated conversion function.
func Convert_v1_RedirectReference_To_oauth_RedirectReference(in *v1.RedirectReference, out *oauth.RedirectReference, s conversion.Scope) error {
	return autoConvert_v1_RedirectReference_To_oauth_RedirectReference(in, out, s)
}

func autoConvert_oauth_RedirectReference_To_v1_RedirectReference(in *oauth.RedirectReference, out *v1.RedirectReference, s conversion.Scope) error {
	out.Group = in.Group
	out.Kind = in.Kind
	out.Name = in.Name
	return nil
}

// Convert_oauth_RedirectReference_To_v1_RedirectReference is an autogenerated conversion function.
func Convert_oauth_RedirectReference_To_v1_RedirectReference(in *oauth.RedirectReference, out *v1.RedirectReference, s conversion.Scope) error {
	return autoConvert_oauth_RedirectReference_To_v1_RedirectReference(in, out, s)
}

func autoConvert_v1_ScopeRestriction_To_oauth_ScopeRestriction(in *v1.ScopeRestriction, out *oauth.ScopeRestriction, s conversion.Scope) error {
	out.ExactValues = *(*[]string)(unsafe.Pointer(&in.ExactValues))
	out.ClusterRole = (*oauth.ClusterRoleScopeRestriction)(unsafe.Pointer(in.ClusterRole))
	return nil
}

// Convert_v1_ScopeRestriction_To_oauth_ScopeRestriction is an autogenerated conversion function.
func Convert_v1_ScopeRestriction_To_oauth_ScopeRestriction(in *v1.ScopeRestriction, out *oauth.ScopeRestriction, s conversion.Scope) error {
	return autoConvert_v1_ScopeRestriction_To_oauth_ScopeRestriction(in, out, s)
}

func autoConvert_oauth_ScopeRestriction_To_v1_ScopeRestriction(in *oauth.ScopeRestriction, out *v1.ScopeRestriction, s conversion.Scope) error {
	out.ExactValues = *(*[]string)(unsafe.Pointer(&in.ExactValues))
	out.ClusterRole = (*v1.ClusterRoleScopeRestriction)(unsafe.Pointer(in.ClusterRole))
	return nil
}

// Convert_oauth_ScopeRestriction_To_v1_ScopeRestriction is an autogenerated conversion function.
func Convert_oauth_ScopeRestriction_To_v1_ScopeRestriction(in *oauth.ScopeRestriction, out *v1.ScopeRestriction, s conversion.Scope) error {
	return autoConvert_oauth_ScopeRestriction_To_v1_ScopeRestriction(in, out, s)
}
