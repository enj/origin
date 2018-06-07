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
	// sane set of default flags, see sspiNegotiator.desiredFlags
	// TODO make configurable?
	desiredFlags = sspi.ISC_REQ_CONFIDENTIALITY |
		sspi.ISC_REQ_INTEGRITY |
		sspi.ISC_REQ_MUTUAL_AUTH |
		sspi.ISC_REQ_REPLAY_DETECT |
		sspi.ISC_REQ_SEQUENCE_DETECT
	// subset of desiredFlags that must be set, see sspiNegotiator.requiredFlags
	// TODO make configurable?
	requiredFlags = sspi.ISC_REQ_CONFIDENTIALITY |
		sspi.ISC_REQ_INTEGRITY |
		sspi.ISC_REQ_MUTUAL_AUTH

	// separator used in fully qualified user name format
	domainSeparator = `\`

	// max lengths for various fields, see sspiNegotiator.principalName
	maxUsername = 256
	maxPassword = 256
	maxDomain   = 15
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
	desiredFlags uint32
	// requiredFlags is the subset of desiredFlags that must be set for flag verification to succeed
	requiredFlags uint32
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa375509(v=vs.85).aspx
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa374764(v=vs.85).aspx
	// Set to true once InitializeSecurityContext or CompleteAuthToken return sspi.SEC_E_OK
	complete bool
}

func NewSSPINegotiator(principalName, password string) Negotiator {
	return &sspiNegotiator{principalName: principalName, password: password, desiredFlags: desiredFlags, requiredFlags: requiredFlags}
}

func (s *sspiNegotiator) Load() error {
	glog.V(5).Info("Attempt to load SSPI")
	// do nothing since SSPI uses lazy DLL loading
	return nil
}

func (s *sspiNegotiator) InitSecContext(requestURL string, challengeToken []byte) (tokenToSend []byte, err error) {
	defer runtime.HandleCrash()

	if needsInit := s.cred == nil || s.ctx == nil; needsInit {
		glog.V(5).Infof("Start SSPI flow: %s", requestURL)
		return s.initContext(requestURL)
	}

	glog.V(5).Info("Continue SSPI flow")
	return s.updateContext(challengeToken)
}

func (s *sspiNegotiator) initContext(requestURL string) (outputToken []byte, err error) {
	cred, err := s.getUserCredentials()
	if err != nil {
		glog.V(5).Infof("getUserCredentials failed: %v", err)
		return nil, err
	}
	s.cred = cred
	glog.V(5).Info("getUserCredentials successful")

	serviceName, err := getServiceName('/', requestURL)
	if err != nil {
		return nil, err
	}

	glog.V(5).Infof("importing service name %s", serviceName)
	ctx, outputToken, err := negotiate.NewClientContextWithFlags(s.cred, serviceName, s.desiredFlags)
	if err != nil {
		glog.V(5).Infof("NewClientContextWithFlags failed: %v", err)
		return nil, err
	}
	s.ctx = ctx
	glog.V(5).Info("NewClientContextWithFlags successful")
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

func (s *sspiNegotiator) splitDomainAndUsername() (domain, username string, err error) {
	data := strings.Split(s.principalName, domainSeparator)
	if len(data) != 2 {
		return "", "", fmt.Errorf(`invalid username %s, must be in Fully Qualified User Name format (ex: DOMAIN\Username)`,
			s.principalName)
	}
	domain = data[0]
	username = data[1]
	if domainLen,
		usernameLen,
		passwordLen := len(domain),
		len(username),
		len(s.password); domainLen > maxDomain || usernameLen > maxUsername || passwordLen > maxPassword {
		return "", "", fmt.Errorf(
			"the maximum character lengths for user name, password, and domain are 256, 256, and 15, respectively:\n"+
				"fully qualifed username=%s username=%s,len=%d domain=%s,len=%d password=<redacted>,len=%d",
			s.principalName, username, usernameLen, domain, domainLen, passwordLen)
	}
	return domain, username, nil
}

func (s *sspiNegotiator) updateContext(challengeToken []byte) (outputToken []byte, err error) {
	// ClientContext.Update does not return errors for success codes:
	// 1. sspi.SEC_E_OK (complete=true and err=nil)
	// 2. sspi.SEC_I_CONTINUE_NEEDED (complete=false and err=nil)
	// 3. sspi.SEC_I_COMPLETE_AND_CONTINUE and sspi.SEC_I_COMPLETE_NEEDED
	// complete=false and err=nil as long as sspi.CompleteAuthToken returns sspi.SEC_E_OK
	// Thus we can safely assume that any error returned here is an error code
	authCompleted, outputToken, err := s.ctx.Update(challengeToken)
	if err != nil {
		glog.V(5).Infof("ClientContext.Update failed: %v", err)
		return nil, err
	}
	s.complete = authCompleted
	glog.V(5).Infof("ClientContext.Update successful, complete=%v", s.complete)

	// TODO should we skip the flag check if complete = true?
	if nonFatalErr := s.ctx.VerifyFlags(); nonFatalErr == nil {
		glog.V(5).Infof("ClientContext.VerifyFlags successful, flags=%b", s.desiredFlags)
	} else {
		glog.V(5).Infof("ClientContext.VerifyFlags failed: %v", nonFatalErr)
		if fatalErr := s.ctx.VerifySelectiveFlags(s.requiredFlags); fatalErr != nil {
			glog.V(5).Infof("ClientContext.VerifySelectiveFlags failed: %v", fatalErr)
			return nil, fatalErr
		}
		glog.V(5).Infof("ClientContext.VerifySelectiveFlags successful, flags=%b", s.requiredFlags)
	}

	return outputToken, nil
}
