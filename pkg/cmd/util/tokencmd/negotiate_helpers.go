package tokencmd

import (
	"errors"
	"net"
	"net/url"
)

func getHostname(requestURL string) (string, error) {
	u, err := url.Parse(requestURL)
	if err != nil {
		return "", err
	}

	hostname := u.Host
	if h, _, err := net.SplitHostPort(u.Host); err == nil {
		hostname = h
	}

	return hostname, nil
}

type negotiateUnsupported struct {
	error
}

func newUnsupportedNegotiator(name string) Negotiater {
	return &negotiateUnsupported{errors.New(name + " support is not enabled")}
}

func (n *negotiateUnsupported) Load() error {
	return n
}

func (n *negotiateUnsupported) InitSecContext(requestURL string, challengeToken []byte) ([]byte, error) {
	return nil, n
}

func (*negotiateUnsupported) IsComplete() bool {
	return false
}

func (n *negotiateUnsupported) Release() error {
	return n
}
