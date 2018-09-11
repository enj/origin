package keystonepassword

import (
	"net/http"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	authapi "github.com/openshift/origin/pkg/oauthserver/api"
	"github.com/openshift/origin/pkg/oauthserver/authenticator/identitymapper"
)

// keystonePasswordAuthenticator uses OpenStack keystone to authenticate a user by password
type keystonePasswordAuthenticator struct {
	providerName        string
	url                 string
	domainName          string
	client              *gophercloud.ServiceClient
	identityMapper      authapi.UserIdentityMapper
	useKeystoneIdentity bool
}

// New creates a new password authenticator that uses OpenStack keystone to authenticate a user by password
func New(providerName, url, domainName string, transport http.RoundTripper, identityMapper authapi.UserIdentityMapper, useKeystoneIdentity bool) (authenticator.Password, error) {
	// Call NewClient instead of AuthenticatedClient to pass in a custom transport
	providerClient, err := openstack.NewClient(url)
	if err != nil {
		// should be impossible since validation catches these errors early
		return nil, err
	}
	providerClient.HTTPClient = http.Client{Transport: transport}

	// Override the generated service endpoint with the one returned by the version endpoint.
	serviceClient, err := openstack.NewIdentityV3(providerClient, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}

	return &keystonePasswordAuthenticator{
		providerName:        providerName,
		url:                 url,
		domainName:          domainName,
		client:              serviceClient,
		identityMapper:      identityMapper,
		useKeystoneIdentity: useKeystoneIdentity,
	}, nil
}

// AuthenticatePassword approves any login attempt which is successfully validated with Keystone
func (a *keystonePasswordAuthenticator) AuthenticatePassword(username, password string) (user.Info, bool, error) {
	defer utilruntime.HandleCrash()

	// if password is missing, fail authentication immediately
	if len(password) == 0 {
		return nil, false, nil
	}

	user, err := a.getUser(username, password)
	if err != nil {
		if _, ok := err.(gophercloud.ErrDefault401); ok {
			return nil, false, nil
		}
		return nil, false, err
	}

	// TODO this should probably be user.Name, relying on user input sounds like a terrible idea
	providerUserID := username
	if a.useKeystoneIdentity {
		providerUserID = user.ID
	}

	identity := authapi.NewDefaultUserIdentityInfo(a.providerName, providerUserID)

	// TODO this should probably be user.Name, relying on user input sounds like a terrible idea
	identity.Extra[authapi.IdentityPreferredUsernameKey] = username

	return identitymapper.UserFor(a.identityMapper, identity)
}

func (a *keystonePasswordAuthenticator) getUser(username, password string) (*tokens.User, error) {
	opts := &gophercloud.AuthOptions{
		IdentityEndpoint: a.url,
		Username:         username,
		Password:         password,
		DomainName:       a.domainName,
	}

	// issue new unscoped token
	result := tokens.Create(a.client, opts)
	if err := result.Err; err != nil {
		return nil, err
	}

	return result.ExtractUser()
}
