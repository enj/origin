// +build !gssapi

package tokencmd

func GSSAPIEnabled() bool {
	return false
}

func NewGSSAPINegotiator(string) Negotiater {
	return newUnsupportedNegotiator("GSSAPI")
}
