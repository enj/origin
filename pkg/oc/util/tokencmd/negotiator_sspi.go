// +build windows

package tokencmd

import (
	"fmt"
	"strings"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/runtime"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
	"github.com/golang/glog"
)

func SSPIEnabled() bool {
	return true
}

type sspiNegotiator struct {
	principalName string
	password      string

	cred     *sspi.Credentials
	ctx      *negotiate.ClientContext
	complete bool
}

func NewSSPINegotiator(principalName, password string) Negotiator {
	return &sspiNegotiator{principalName: principalName, password: password}
}

func (s *sspiNegotiator) Load() error {
	glog.V(5).Info("Attempt to load SSPI")
	return nil
}

func (s *sspiNegotiator) InitSecContext(requestURL string, challengeToken []byte) ([]byte, error) {
	defer runtime.HandleCrash()
	if s.cred == nil || s.ctx == nil {
		glog.V(5).Infof("Start SSPI flow: %s", requestURL)

		cred, err := s.getUserCredentials()
		if err != nil {
			glog.V(5).Infof("getUserCredentials returned error: %v", err)
			return nil, err
		}
		s.cred = cred
		glog.V(5).Info("getUserCredentials successful")

		serviceName, err := getServiceName('/', requestURL)
		if err != nil {
			return nil, err
		}

		glog.V(5).Infof("importing service name %s", serviceName)
		ctx, outputToken, err := negotiate.NewClientContext(s.cred, serviceName)
		if err != nil {
			glog.V(5).Infof("NewClientContext returned error: %v", err)
			return nil, err
		}
		s.ctx = ctx
		glog.V(5).Info("NewClientContext successful")
		return outputToken, nil
	}

	glog.V(5).Info("Continue SSPI flow")

	complete, outputToken, err := s.ctx.Update(challengeToken)
	if err != nil {
		glog.V(5).Infof("Update returned error: %v", err)
		return nil, err
	}
	s.complete = complete
	glog.V(5).Infof("Update successful, complete=%v", s.complete)
	return outputToken, nil
}

func (s *sspiNegotiator) IsComplete() bool {
	return s.complete
}

func (s *sspiNegotiator) Release() error {
	defer runtime.HandleCrash()
	glog.V(5).Info("Attempt to release SSPI")
	var errs []error
	if s.ctx != nil {
		if err := s.ctx.Release(); err != nil {
			glog.V(5).Infof("SSPI context release failed: %v", err)
			errs = append(errs, err)
		}
	}
	if s.cred != nil {
		if err := s.cred.Release(); err != nil {
			glog.V(5).Infof("SSPI credential release failed: %v", err)
			errs = append(errs, err)
		}
	}
	if len(errs) == 1 {
		return errs[0]
	}
	return utilerrors.NewAggregate(errs)
}

func (s *sspiNegotiator) getUserCredentials() (*sspi.Credentials, error) {
	// Try to use principalName if specified
	if len(s.principalName) > 0 {
		domain, username, err := s.splitDomainAndUsername()
		if err != nil {
			return nil, err
		}
		glog.V(5).Infof("Using AcquireUserCredentials because principalName is not empty, principalName=%s, username=%s, domain=%s",
			s.principalName, username, domain)
		cred, err := negotiate.AcquireUserCredentials(domain, username, s.password)
		if err != nil {
			glog.V(5).Infof("AcquireUserCredentials failed: %v", err)
			return nil, err
		}
		glog.V(5).Info("AcquireUserCredentials successful")
		return cred, nil
	}
	glog.V(5).Info("Using AcquireCurrentUserCredentials because principalName is empty")
	return negotiate.AcquireCurrentUserCredentials()
}

const domainSeparator = `\`

func (s *sspiNegotiator) splitDomainAndUsername() (string, string, error) {
	data := strings.Split(s.principalName, domainSeparator)
	if len(data) != 2 {
		return "", "", fmt.Errorf(`invalid principalName %s, must be in format DOMAIN\username`, s.principalName)
	}
	domain := data[0]
	username := data[1]
	return domain, username, nil
}
