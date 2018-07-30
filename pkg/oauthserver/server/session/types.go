package session

import (
	"fmt"
	"net/http"
)

type Store interface {
	Get(*http.Request) (Values, error)
	Save(http.ResponseWriter, *http.Request) error
	Clear(*http.Request)
}

type Values map[interface{}]interface{}

func (v Values) Get(key string) (string, bool, error) {
	obj, ok := v[key]
	if !ok {
		return "", false, nil
	}
	str, ok := obj.(string)
	if !ok {
		return "", false, fmt.Errorf("%s on session is not a string", key)
	}
	return str, len(str) != 0, nil
}
