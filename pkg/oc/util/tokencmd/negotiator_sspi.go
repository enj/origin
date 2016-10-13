// +build windows

package tokencmd

import (
	"errors"
	"os"
	"os/user"
	"strings"

	utilerrors "k8s.io/kubernetes/pkg/util/errors"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"

	"github.com/golang/glog"
)

func SSPIEnabled() bool {
	return true
}

type sspiNegotiater struct {
	principalName string
	password      string

	cred     *sspi.Credentials
	ctx      *negotiate.ClientContext
	complete bool
}

func NewSSPINegotiator(principalName, password string) Negotiater {
	return &sspiNegotiater{principalName: principalName, password: password}
}

func (s *sspiNegotiater) Load() error {
	glog.V(5).Info("Attempt to load SSPI")
	return nil
}

func (s *sspiNegotiater) InitSecContext(requestURL string, challengeToken []byte) ([]byte, error) {
	if s.cred == nil || s.ctx == nil {
		cred, err := s.getUserCredentials()
		if err != nil {
			glog.V(5).Infof("getUserCredentials returned error: %v", err)
			return nil, err
		}
		s.cred = cred

		hostname, err := getHostname(requestURL)
		if err != nil {
			return nil, err
		}

		serviceName := "HTTP/" + hostname // TODO refactor these together if they are the same
		glog.V(5).Infof("importing service name %s", serviceName)
		ctx, token, err := negotiate.NewClientContext(s.cred, serviceName)
		if err != nil {
			glog.V(5).Infof("NewClientContext returned error: %v", err)
			return nil, err
		}
		s.ctx = ctx
		return token, nil
	}

	complete, token, err := s.ctx.Update(challengeToken)
	if err != nil {
		glog.V(5).Infof("Update returned error: %v", err)
		return nil, err
	}
	s.complete = complete
	return token, nil
}

func (s *sspiNegotiater) IsComplete() bool {
	return s.complete
}

func (s *sspiNegotiater) Release() error {
	glog.V(5).Info("Attempt to release SSPI")
	var errs []error // TODO make sure these errors and the ones in InitSecContext are safe to use => I think they are
	if s.ctx != nil {
		if err := s.ctx.Release(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.cred != nil {
		if err := s.cred.Release(); err != nil {
			errs = append(errs, err)
		}
	}
	return utilerrors.NewAggregate(errs)
}

func (s *sspiNegotiater) getUserCredentials() (*sspi.Credentials, error) {
	// Try to use principalName if possible
	// Fallback to the current user if principalName referred to the same user or was unspecified
	if len(s.principalName) != 0 {
		username, domain, err := s.splitDomainAndUsername()
		if err != nil {
			return nil, err
		}
		glog.V(5).Info("Using AcquireUserCredentials because principalName is not empty")
		cred, err := negotiate.AcquireUserCredentials(domain, username, s.password)
		if err != nil {
			if u, uerr := user.Current(); uerr == nil && u.Username == username && domain == getCurrentUserDomain() {
				glog.V(5).Info("Using AcquireCurrentUserCredentials because AcquireUserCredentials failed and principalName is probably the current user")
				return negotiate.AcquireCurrentUserCredentials()
			}
			glog.V(5).Info("AcquireUserCredentials failed and not falling back to AcquireCurrentUserCredentials because principalName is not the current user")
			return nil, err
		}
		glog.V(5).Info("AcquireUserCredentials successful")
		return cred, nil
	}
	glog.V(5).Info("Using AcquireCurrentUserCredentials because principalName is empty")
	return negotiate.AcquireCurrentUserCredentials()
}

const upnSeparator = "@"

func (s *sspiNegotiater) splitDomainAndUsername() (string, string, error) {
	if strings.Contains(s.principalName, upnSeparator) {
		data := strings.Split(s.principalName, upnSeparator)
		if len(data) != 2 {
			return "", "", errors.New("Invalid principalName: " + s.principalName)
		}
		username := data[0]
		domain := data[1]
		if len(domain) == 0 {
			domain = getCurrentUserDomain()
		}
		return username, domain, nil
	}
	return s.principalName, getCurrentUserDomain(), nil
}

func getCurrentUserDomain() string {
	for _, env := range []string{"USERDNSDOMAIN", "USERDOMAIN"} {
		domain, ok := os.LookupEnv(env) // TODO there has to be a better way to do this => use syscall or sys/x/
		if ok {
			return domain
		}
	}
	return ""
}
