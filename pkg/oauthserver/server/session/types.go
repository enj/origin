package session

import (
	"fmt"
	"net/http"
)

// Store abstracts HTTP session storage of Values
type Store interface {
	// Get and decode the Values associated with the given request
	Get(r *http.Request) Values
	// Put encodes and writes the given Values to the response
	Put(w http.ResponseWriter, v Values) error
}

type Values map[interface{}]interface{}

func (v Values) GetString(key string) (string, bool, error) {
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

func (v Values) GetInt64(key string) (int64, bool, error) {
	obj, ok := v[key]
	if !ok {
		return -1, false, nil // zero is used to unset these values so return something different
	}
	i, ok := obj.(int64)
	if !ok {
		return 0, false, fmt.Errorf("%s on store is not an int64", key)
	}
	return i, i != 0, nil
}
