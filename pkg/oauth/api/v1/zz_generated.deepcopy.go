// +build !ignore_autogenerated_openshift

// This file was autogenerated by deepcopy-gen. Do not edit it manually!

package v1

import (
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
	reflect "reflect"
)

func init() {
	SchemeBuilder.Register(RegisterDeepCopies)
}

// RegisterDeepCopies adds deep-copy functions to the given scheme. Public
// to allow building arbitrary schemes.
func RegisterDeepCopies(scheme *runtime.Scheme) error {
	return scheme.AddGeneratedDeepCopyFuncs(
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_ActiveDirectoryConfig, InType: reflect.TypeOf(&ActiveDirectoryConfig{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_AugmentedActiveDirectoryConfig, InType: reflect.TypeOf(&AugmentedActiveDirectoryConfig{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_ClusterRoleScopeRestriction, InType: reflect.TypeOf(&ClusterRoleScopeRestriction{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_LDAPQuery, InType: reflect.TypeOf(&LDAPQuery{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_LDAPSyncConfig, InType: reflect.TypeOf(&LDAPSyncConfig{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_LDAPSyncConfigList, InType: reflect.TypeOf(&LDAPSyncConfigList{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_OAuthAccessToken, InType: reflect.TypeOf(&OAuthAccessToken{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_OAuthAccessTokenList, InType: reflect.TypeOf(&OAuthAccessTokenList{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_OAuthAuthorizeToken, InType: reflect.TypeOf(&OAuthAuthorizeToken{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_OAuthAuthorizeTokenList, InType: reflect.TypeOf(&OAuthAuthorizeTokenList{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_OAuthClient, InType: reflect.TypeOf(&OAuthClient{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_OAuthClientAuthorization, InType: reflect.TypeOf(&OAuthClientAuthorization{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_OAuthClientAuthorizationList, InType: reflect.TypeOf(&OAuthClientAuthorizationList{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_OAuthClientList, InType: reflect.TypeOf(&OAuthClientList{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_OAuthRedirectReference, InType: reflect.TypeOf(&OAuthRedirectReference{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_RFC2307Config, InType: reflect.TypeOf(&RFC2307Config{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_RedirectReference, InType: reflect.TypeOf(&RedirectReference{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_ScopeRestriction, InType: reflect.TypeOf(&ScopeRestriction{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_StringSource, InType: reflect.TypeOf(&StringSource{})},
		conversion.GeneratedDeepCopyFunc{Fn: DeepCopy_v1_StringSourceSpec, InType: reflect.TypeOf(&StringSourceSpec{})},
	)
}

func DeepCopy_v1_ActiveDirectoryConfig(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*ActiveDirectoryConfig)
		out := out.(*ActiveDirectoryConfig)
		*out = *in
		if in.UserNameAttributes != nil {
			in, out := &in.UserNameAttributes, &out.UserNameAttributes
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		if in.GroupMembershipAttributes != nil {
			in, out := &in.GroupMembershipAttributes, &out.GroupMembershipAttributes
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		return nil
	}
}

func DeepCopy_v1_AugmentedActiveDirectoryConfig(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*AugmentedActiveDirectoryConfig)
		out := out.(*AugmentedActiveDirectoryConfig)
		*out = *in
		if in.UserNameAttributes != nil {
			in, out := &in.UserNameAttributes, &out.UserNameAttributes
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		if in.GroupMembershipAttributes != nil {
			in, out := &in.GroupMembershipAttributes, &out.GroupMembershipAttributes
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		if in.GroupNameAttributes != nil {
			in, out := &in.GroupNameAttributes, &out.GroupNameAttributes
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		return nil
	}
}

func DeepCopy_v1_ClusterRoleScopeRestriction(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*ClusterRoleScopeRestriction)
		out := out.(*ClusterRoleScopeRestriction)
		*out = *in
		if in.RoleNames != nil {
			in, out := &in.RoleNames, &out.RoleNames
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		if in.Namespaces != nil {
			in, out := &in.Namespaces, &out.Namespaces
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		return nil
	}
}

func DeepCopy_v1_LDAPQuery(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*LDAPQuery)
		out := out.(*LDAPQuery)
		*out = *in
		return nil
	}
}

func DeepCopy_v1_LDAPSyncConfig(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*LDAPSyncConfig)
		out := out.(*LDAPSyncConfig)
		*out = *in
		if in.LDAPGroupUIDToOpenShiftGroupNameMapping != nil {
			in, out := &in.LDAPGroupUIDToOpenShiftGroupNameMapping, &out.LDAPGroupUIDToOpenShiftGroupNameMapping
			*out = make(map[string]string)
			for key, val := range *in {
				(*out)[key] = val
			}
		}
		if in.RFC2307Config != nil {
			in, out := &in.RFC2307Config, &out.RFC2307Config
			*out = new(RFC2307Config)
			if err := DeepCopy_v1_RFC2307Config(*in, *out, c); err != nil {
				return err
			}
		}
		if in.ActiveDirectoryConfig != nil {
			in, out := &in.ActiveDirectoryConfig, &out.ActiveDirectoryConfig
			*out = new(ActiveDirectoryConfig)
			if err := DeepCopy_v1_ActiveDirectoryConfig(*in, *out, c); err != nil {
				return err
			}
		}
		if in.AugmentedActiveDirectoryConfig != nil {
			in, out := &in.AugmentedActiveDirectoryConfig, &out.AugmentedActiveDirectoryConfig
			*out = new(AugmentedActiveDirectoryConfig)
			if err := DeepCopy_v1_AugmentedActiveDirectoryConfig(*in, *out, c); err != nil {
				return err
			}
		}
		return nil
	}
}

func DeepCopy_v1_LDAPSyncConfigList(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*LDAPSyncConfigList)
		out := out.(*LDAPSyncConfigList)
		*out = *in
		if in.Items != nil {
			in, out := &in.Items, &out.Items
			*out = make([]LDAPSyncConfig, len(*in))
			for i := range *in {
				if err := DeepCopy_v1_LDAPSyncConfig(&(*in)[i], &(*out)[i], c); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func DeepCopy_v1_OAuthAccessToken(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*OAuthAccessToken)
		out := out.(*OAuthAccessToken)
		*out = *in
		if newVal, err := c.DeepCopy(&in.ObjectMeta); err != nil {
			return err
		} else {
			out.ObjectMeta = *newVal.(*meta_v1.ObjectMeta)
		}
		if in.Scopes != nil {
			in, out := &in.Scopes, &out.Scopes
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		return nil
	}
}

func DeepCopy_v1_OAuthAccessTokenList(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*OAuthAccessTokenList)
		out := out.(*OAuthAccessTokenList)
		*out = *in
		if in.Items != nil {
			in, out := &in.Items, &out.Items
			*out = make([]OAuthAccessToken, len(*in))
			for i := range *in {
				if err := DeepCopy_v1_OAuthAccessToken(&(*in)[i], &(*out)[i], c); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func DeepCopy_v1_OAuthAuthorizeToken(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*OAuthAuthorizeToken)
		out := out.(*OAuthAuthorizeToken)
		*out = *in
		if newVal, err := c.DeepCopy(&in.ObjectMeta); err != nil {
			return err
		} else {
			out.ObjectMeta = *newVal.(*meta_v1.ObjectMeta)
		}
		if in.Scopes != nil {
			in, out := &in.Scopes, &out.Scopes
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		return nil
	}
}

func DeepCopy_v1_OAuthAuthorizeTokenList(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*OAuthAuthorizeTokenList)
		out := out.(*OAuthAuthorizeTokenList)
		*out = *in
		if in.Items != nil {
			in, out := &in.Items, &out.Items
			*out = make([]OAuthAuthorizeToken, len(*in))
			for i := range *in {
				if err := DeepCopy_v1_OAuthAuthorizeToken(&(*in)[i], &(*out)[i], c); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func DeepCopy_v1_OAuthClient(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*OAuthClient)
		out := out.(*OAuthClient)
		*out = *in
		if newVal, err := c.DeepCopy(&in.ObjectMeta); err != nil {
			return err
		} else {
			out.ObjectMeta = *newVal.(*meta_v1.ObjectMeta)
		}
		if in.AdditionalSecrets != nil {
			in, out := &in.AdditionalSecrets, &out.AdditionalSecrets
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		if in.RedirectURIs != nil {
			in, out := &in.RedirectURIs, &out.RedirectURIs
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		if in.ScopeRestrictions != nil {
			in, out := &in.ScopeRestrictions, &out.ScopeRestrictions
			*out = make([]ScopeRestriction, len(*in))
			for i := range *in {
				if err := DeepCopy_v1_ScopeRestriction(&(*in)[i], &(*out)[i], c); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func DeepCopy_v1_OAuthClientAuthorization(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*OAuthClientAuthorization)
		out := out.(*OAuthClientAuthorization)
		*out = *in
		if newVal, err := c.DeepCopy(&in.ObjectMeta); err != nil {
			return err
		} else {
			out.ObjectMeta = *newVal.(*meta_v1.ObjectMeta)
		}
		if in.Scopes != nil {
			in, out := &in.Scopes, &out.Scopes
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		return nil
	}
}

func DeepCopy_v1_OAuthClientAuthorizationList(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*OAuthClientAuthorizationList)
		out := out.(*OAuthClientAuthorizationList)
		*out = *in
		if in.Items != nil {
			in, out := &in.Items, &out.Items
			*out = make([]OAuthClientAuthorization, len(*in))
			for i := range *in {
				if err := DeepCopy_v1_OAuthClientAuthorization(&(*in)[i], &(*out)[i], c); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func DeepCopy_v1_OAuthClientList(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*OAuthClientList)
		out := out.(*OAuthClientList)
		*out = *in
		if in.Items != nil {
			in, out := &in.Items, &out.Items
			*out = make([]OAuthClient, len(*in))
			for i := range *in {
				if err := DeepCopy_v1_OAuthClient(&(*in)[i], &(*out)[i], c); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

func DeepCopy_v1_OAuthRedirectReference(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*OAuthRedirectReference)
		out := out.(*OAuthRedirectReference)
		*out = *in
		if newVal, err := c.DeepCopy(&in.ObjectMeta); err != nil {
			return err
		} else {
			out.ObjectMeta = *newVal.(*meta_v1.ObjectMeta)
		}
		return nil
	}
}

func DeepCopy_v1_RFC2307Config(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*RFC2307Config)
		out := out.(*RFC2307Config)
		*out = *in
		if in.GroupNameAttributes != nil {
			in, out := &in.GroupNameAttributes, &out.GroupNameAttributes
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		if in.GroupMembershipAttributes != nil {
			in, out := &in.GroupMembershipAttributes, &out.GroupMembershipAttributes
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		if in.UserNameAttributes != nil {
			in, out := &in.UserNameAttributes, &out.UserNameAttributes
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		return nil
	}
}

func DeepCopy_v1_RedirectReference(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*RedirectReference)
		out := out.(*RedirectReference)
		*out = *in
		return nil
	}
}

func DeepCopy_v1_ScopeRestriction(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*ScopeRestriction)
		out := out.(*ScopeRestriction)
		*out = *in
		if in.ExactValues != nil {
			in, out := &in.ExactValues, &out.ExactValues
			*out = make([]string, len(*in))
			copy(*out, *in)
		}
		if in.ClusterRole != nil {
			in, out := &in.ClusterRole, &out.ClusterRole
			*out = new(ClusterRoleScopeRestriction)
			if err := DeepCopy_v1_ClusterRoleScopeRestriction(*in, *out, c); err != nil {
				return err
			}
		}
		return nil
	}
}

func DeepCopy_v1_StringSource(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*StringSource)
		out := out.(*StringSource)
		*out = *in
		return nil
	}
}

func DeepCopy_v1_StringSourceSpec(in interface{}, out interface{}, c *conversion.Cloner) error {
	{
		in := in.(*StringSourceSpec)
		out := out.(*StringSourceSpec)
		*out = *in
		return nil
	}
}
