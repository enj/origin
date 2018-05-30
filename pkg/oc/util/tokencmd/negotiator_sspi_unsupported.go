// +build !windows

package tokencmd

func SSPIEnabled() bool {
	return false
}

func NewSSPINegotiator(string, string) Negotiator {
	return newUnsupportedNegotiator("SSPI")
}
