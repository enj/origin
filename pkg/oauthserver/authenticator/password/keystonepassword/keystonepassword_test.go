package keystonepassword

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"

	th "github.com/gophercloud/gophercloud/testhelper"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/openshift/origin/pkg/oauthserver/api"
)

// This type emulates a mapper with "claim" provisioning strategy
type testUserIdentityMapperClaim struct {
	idnts  map[string]string
	groups map[string][]string
}

func (m *testUserIdentityMapperClaim) UserFor(identityInfo api.UserIdentityInfo) (user.Info, error) {
	userName := identityInfo.GetProviderUserName()
	if login, ok := identityInfo.GetExtra()[api.IdentityPreferredUsernameKey]; ok && len(login) > 0 {
		userName = login
	}
	claimedIdentityName := identityInfo.GetProviderName() + ":" + identityInfo.GetProviderUserName()

	if identityName, ok := m.idnts[userName]; ok && identityName != claimedIdentityName {
		// A user with that user name is already mapped to another identity
		return nil, fmt.Errorf("invalid user %s, expected identity %s, got %s", userName, identityName, claimedIdentityName)
	}
	// Map the user with new identity
	m.idnts[userName] = claimedIdentityName

	// Record groups
	m.groups[userName] = identityInfo.GetProviderGroups()

	return &user.DefaultInfo{Name: userName}, nil
}

func (m *testUserIdentityMapperClaim) getGroupsOnce(userName string) []string {
	groups := m.groups[userName]
	delete(m.groups, userName)
	return groups
}

var keystoneID string

func TestKeystoneLogin(t *testing.T) {
	th.SetupHTTP()
	defer th.TeardownHTTP()

	const ID = "0123456789"

	th.Mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("X-Subject-Token", ID)
		type AuthRequest struct {
			Auth struct {
				Identity struct {
					Password struct {
						User struct {
							Domain   struct{ Name string }
							Name     string
							Password string
						}
					}
				}
			}
		}
		var x AuthRequest
		body, _ := ioutil.ReadAll(r.Body)
		json.Unmarshal(body, &x)
		domainName := x.Auth.Identity.Password.User.Domain.Name
		userName := x.Auth.Identity.Password.User.Name
		password := x.Auth.Identity.Password.User.Password
		if domainName == "default" && userName == "testuser" && password == "testpw" {
			w.WriteHeader(http.StatusCreated)
			resp := `{"token": {
							"methods": [
								"password"
							],
							"expires_at": "2015-11-09T01:42:57.527363Z",
							"user": {
								"domain": {
									"id": "default",
									"name": "Default"
								},
								"id": "` + keystoneID + `",
								"name": "admin",
								"password_expires_at": null
							},
							"audit_ids": [
								"lC2Wj1jbQe-dLjLyOx4qPQ"
							],
							"issued_at": "2015-11-09T00:42:57.527404Z"
						}
					}`
			fmt.Fprintf(w, resp)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	})

	initialGroups := `
{
    "groups": [
        {
            "description": "Developers cleared for work on all general projects",
            "domain_id": "1789d1",
            "id": "ea167b",
            "links": {
                "self": "https://example.com/identity/v3/groups/ea167b"
            },
            "building": "Hilltop A",
            "name": "Developers"
        },
        {
            "description": "Developers cleared for work on secret projects",
            "domain_id": "1789d1",
            "id": "a62db1",
            "links": {
                "self": "https://example.com/identity/v3/groups/a62db1"
            },
            "name": "Secure Developers"
        }
    ],
    "links": {
        "self": "http://example.com/identity/v3/users/initial_keystone_id/groups",
        "previous": null,
        "next": null
    }
}
`

	newGroups := `
{
    "groups": [
        {
            "description": "Greatest animal evvvaaarrrr",
            "domain_id": "1789d2",
            "id": "a62db2",
            "links": {
                "self": "https://example.com/identity/v3/groups/a62db2"
            },
            "building": "Zoo",
            "name": "Pandas"
        }
    ],
    "links": {
        "self": "http://example.com/identity/v3/users/new_keystone_id/groups",
        "previous": null,
        "next": null
    }
}
`

	th.Mux.HandleFunc("/v3/users/initial_keystone_id/groups", getGroupHandler(t, initialGroups))
	th.Mux.HandleFunc("/v3/users/new_keystone_id/groups", getGroupHandler(t, newGroups))

	// -----Test Claim strategy with enabled Keystone identity-----
	mapperClaim := testUserIdentityMapperClaim{idnts: map[string]string{}, groups: map[string][]string{}}
	keystoneID = "initial_keystone_id"
	keystoneAuth, err := New("keystone_auth", th.Endpoint(), "default", http.DefaultTransport, &mapperClaim, true)
	th.AssertNoErr(t, err)

	// 1. User authenticates for the first time, new identity is created
	_, ok, err := keystoneAuth.AuthenticatePassword("testuser", "testpw")
	th.AssertNoErr(t, err)
	th.CheckEquals(t, true, ok)
	th.CheckEquals(t, "keystone_auth:initial_keystone_id", mapperClaim.idnts["testuser"])
	th.CheckDeepEquals(t, []string{"Developers", "Secure Developers"}, mapperClaim.getGroupsOnce("testuser"))

	// 2. Authentication with wrong or empty password fails
	_, ok, err = keystoneAuth.AuthenticatePassword("testuser", "badpw")
	th.AssertNoErr(t, err)
	th.CheckEquals(t, false, ok)
	_, ok, err = keystoneAuth.AuthenticatePassword("testuser", "")
	th.AssertNoErr(t, err)
	th.CheckEquals(t, false, ok)

	// 3. Id of "testuser" has changed, authentication will fail
	keystoneID = "new_keystone_id"
	_, ok, err = keystoneAuth.AuthenticatePassword("testuser", "testpw")
	th.CheckEquals(t, false, ok)
	th.CheckEquals(t, "invalid user testuser, expected identity keystone_auth:initial_keystone_id, got keystone_auth:new_keystone_id", err.Error())
	th.CheckDeepEquals(t, []string(nil), mapperClaim.getGroupsOnce("testuser"))

	// -----Test Claim strategy with disabled Keystone identity-----
	mapperClaim = testUserIdentityMapperClaim{idnts: map[string]string{}, groups: map[string][]string{}}
	keystoneID = "initial_keystone_id"
	keystoneAuth, err = New("keystone_auth", th.Endpoint(), "default", http.DefaultTransport, &mapperClaim, false)
	th.AssertNoErr(t, err)

	// 1. User authenticates for the first time, new identity is created
	_, ok, err = keystoneAuth.AuthenticatePassword("testuser", "testpw")
	th.AssertNoErr(t, err)
	th.CheckEquals(t, true, ok)
	th.CheckEquals(t, "keystone_auth:testuser", mapperClaim.idnts["testuser"])
	th.CheckDeepEquals(t, []string{"Developers", "Secure Developers"}, mapperClaim.getGroupsOnce("testuser"))

	// 2. Authentication with wrong or empty password fails
	_, ok, err = keystoneAuth.AuthenticatePassword("testuser", "badpw")
	th.AssertNoErr(t, err)
	th.CheckEquals(t, false, ok)
	_, ok, err = keystoneAuth.AuthenticatePassword("testuser", "")
	th.AssertNoErr(t, err)
	th.CheckEquals(t, false, ok)

	// 3. Id of "testuser" has changed, authentication will work as before
	keystoneID = "new_keystone_id"
	_, ok, err = keystoneAuth.AuthenticatePassword("testuser", "testpw")
	th.CheckEquals(t, true, ok)
	th.AssertNoErr(t, err)
	th.CheckDeepEquals(t, []string{"Pandas"}, mapperClaim.getGroupsOnce("testuser"))
}

func getGroupHandler(t *testing.T, groupData string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		th.TestMethod(t, r, "GET")
		th.TestHeader(t, r, "Accept", "application/json")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, groupData)
	}
}
