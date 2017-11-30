package registry

import (
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/openshift/origin/pkg/auth/api"
	oauthclient "github.com/openshift/origin/pkg/oauth/generated/internalclientset/typed/oauth/internalversion"
	"github.com/openshift/origin/pkg/oauth/registry/oauthclientauthorization"
	"github.com/openshift/origin/pkg/oauth/scope"

	"github.com/golang/glog"
)

type ClientAuthorizationGrantChecker struct {
	client oauthclient.OAuthClientAuthorizationInterface
}

func NewClientAuthorizationGrantChecker(client oauthclient.OAuthClientAuthorizationInterface) *ClientAuthorizationGrantChecker {
	return &ClientAuthorizationGrantChecker{client}
}

func (c *ClientAuthorizationGrantChecker) HasAuthorizedClient(user user.Info, grant *api.Grant) (approved bool, err error) {
	id := oauthclientauthorization.ClientAuthorizationName(user.GetName(), grant.Client.GetId())
	authorization, err := c.client.Get(id, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	// Validation prevents authorization.UserUID from being empty (and always has).
	// However, user.GetUID() is empty during impersonation, meaning this flow does not work for impersonation.
	// This is fine because no OAuth / grant flow works with impersonation in general.
	if user.GetUID() != authorization.UserUID {
		glog.Infof("%#v does not match stored client authorization %#v, attempting to delete stale authorization", user, authorization)
		if err := c.client.Delete(id, nil); err != nil && !errors.IsNotFound(err) {
			return false, err
		}
		return false, nil
	}

	// TODO: improve this to allow the scope implementation to determine overlap
	if !scope.Covers(authorization.Scopes, scope.Split(grant.Scope)) {
		return false, nil
	}

	return true, nil
}
