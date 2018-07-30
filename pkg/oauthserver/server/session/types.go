package session

import (
	"fmt"
	"net/http"
)

// Store abstracts HTTP session storage of Values
type Store interface {
	// Get the Values associated with the given request
	Get(r *http.Request) (Values, error)
	// Put writes the given Values to the response
	Put(w http.ResponseWriter, v Values) error
}

type Values map[interface{}]interface{}

func (v Values) Get(key string) (string, bool, error) {
	obj, ok := v[key]
	if !ok {
		return "", false, nil
	}
	str, ok := obj.(string)
	if !ok {
		return "", false, fmt.Errorf("%s on store is not a string", key)
	}
	return str, len(str) != 0, nil
}

// TODO: GetInt
