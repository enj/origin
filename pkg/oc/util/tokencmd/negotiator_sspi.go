// +build windows

package tokencmd

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/runtime"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/negotiate"
	"github.com/golang/glog"
)

const (
	// sane set of default flags, see sspiNegotiator.flags
	// TODO make configurable?
	flags = sspi.ISC_REQ_CONFIDENTIALITY |
		sspi.ISC_REQ_INTEGRITY |
		sspi.ISC_REQ_MUTUAL_AUTH |
		sspi.ISC_REQ_REPLAY_DETECT |
		sspi.ISC_REQ_SEQUENCE_DETECT

	// separator used in fully qualified user name format
	domainSeparator = `\`
)

func SSPIEnabled() bool {
	return true
}

// sspiNegotiator handles negotiate flows on windows via SSPI
// It expects sspiNegotiator.InitSecContext to be called until sspiNegotiator.IsComplete returns true
type sspiNegotiator struct {
	// optional DOMAIN\Username and password
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa374714(v=vs.85).aspx
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa380131(v=vs.85).aspx
	// pAuthData [in]: If credentials are supplied, they are passed via a pointer to a sspi.SEC_WINNT_AUTH_IDENTITY
	// structure that includes those credentials.
	// When using the Negotiate package, the maximum character lengths for user name, password, and domain are
	// 256, 256, and 15, respectively.
	// TODO should we validate the lengths?
	principalName string
	password      string

	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721572(v=vs.85).aspx#_security_credentials_gly
	// phCredential [in, optional]: A handle to the credentials returned by AcquireCredentialsHandle (Negotiate).
	// This handle is used to build the security context.  sspi.SECPKG_CRED_OUTBOUND is used to request OUTBOUND credentials.
	cred *sspi.Credentials
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms721625(v=vs.85).aspx#_security_security_context_gly
	// Manages all steps of the Negotiate negotiation.
	ctx *negotiate.ClientContext
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa375509(v=vs.85).aspx
	// fContextReq [in]: Bit flags that indicate requests for the context.
	flags uint32
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa375509(v=vs.85).aspx
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa374764(v=vs.85).aspx
	// Set to true once InitializeSecurityContext or CompleteAuthToken return sspi.SEC_E_OK
	complete bool
}

func NewSSPINegotiator(principalName, password string) Negotiator {
	return &sspiNegotiator{principalName: principalName, password: password, flags: flags}
}

func (s *sspiNegotiator) Load() error {
	glog.V(5).Info("Attempt to load SSPI")
	// do nothing since SSPI uses lazy DLL loading
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
		ctx, outputToken, err := negotiate.NewClientContext(s.cred, serviceName) // TODO send s.flags
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
		glog.V(5).Infof("context Update returned error: %v", err)
		return nil, err
	}
	// TODO we need a way to verify s.ctx.sctxt.EstablishedFlags matches s.ctx.sctxt.RequestedFlags (s.flags)
	// we will need to update upstream to add the verification or use reflection hacks here
	s.complete = complete
	glog.V(5).Infof("context Update successful, complete=%v", s.complete)
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
	return errors.NewAggregate(errs)
}

func (s *sspiNegotiator) getUserCredentials() (*sspi.Credentials, error) {
	// Try to use principalName if specified
	if len(s.principalName) > 0 {
		domain, username, err := s.splitDomainAndUsername()
		if err != nil {
			return nil, err
		}
		glog.V(5).Infof(
			"Using AcquireUserCredentials because principalName is not empty, principalName=%s, username=%s, domain=%s",
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

func (s *sspiNegotiator) splitDomainAndUsername() (string, string, error) {
	data := strings.Split(s.principalName, domainSeparator)
	if len(data) != 2 {
		return "", "", fmt.Errorf(`invalid username %s, must be in Fully Qualified User Name format (ex: DOMAIN\Username)`,
			s.principalName)
	}
	domain := data[0]
	username := data[1]
	return domain, username, nil
}
