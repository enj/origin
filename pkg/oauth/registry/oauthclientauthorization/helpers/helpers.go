package helpers

const UserSpaceSeparator = "::"

func GetClientAuthorizationName(userName, clientName string) string {
	return userName + UserSpaceSeparator + clientName
}
