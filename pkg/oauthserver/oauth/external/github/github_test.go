package github

import (
	"reflect"
	"testing"
)

// TestGitHubAddNewAPI makes sure we update URL endpoints for both standard GitHub and GitHub Enterprise
func TestGitHubAddNewAPI(t *testing.T) {
	// set up the provider structs in a way that all config string values are different
	standard := NewProvider("a", "b", "c", "", nil, nil, nil)
	enterprise := NewProvider("d", "e", "f", "g", nil, nil, nil)

	// get the raw structs using reflection
	standardValue := reflect.ValueOf(standard).Elem()
	enterpriseValue := reflect.ValueOf(enterprise).Elem()

	// check to make sure all string fields are different
	// any fields that are the same at this point are likely to be API endpoints we forgot to update
	for i := 0; i < standardValue.NumField(); i++ {
		fieldValue := standardValue.Field(i)
		if fieldValue.Type().Kind() != reflect.String { // we only care about strings (i.e. API endpoints)
			continue
		}
		if s, e := fieldValue.String(), enterpriseValue.Field(i).String(); s == e {
			t.Errorf("Invalid matching value for field %s: %s", standardValue.Type().Field(i).Name, s)
		}
	}
}
