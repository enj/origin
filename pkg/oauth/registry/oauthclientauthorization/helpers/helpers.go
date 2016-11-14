package oauthclientauthorization

const NameSeparator = "::"

func getClientAuthorizationName(userName, clientName string) string {
	return userName + NameSeparator + clientName
}
