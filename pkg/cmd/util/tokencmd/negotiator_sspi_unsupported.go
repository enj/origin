// +build !windows

package tokencmd

func SSPIEnabled() bool {
	return false
}

func NewSSPINegotiator(string, string) Negotiater {
	return newUnsupportedNegotiator("SSPI")
}
