package oauthserver

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	osinv1 "github.com/openshift/api/osin/v1"
)

func TestGetDefaultSessionSecrets(t *testing.T) {
	secrets, err := getSessionSecrets("")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(secrets) != 2 {
		t.Errorf("Unexpected 2 secrets, got: %#v", secrets)
	}
}

func TestGetMissingSessionSecretsFile(t *testing.T) {
	_, err := getSessionSecrets("missing")
	if err == nil {
		t.Errorf("Expected error, got none")
	}
}

func TestGetInvalidSessionSecretsFile(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "invalid.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if err := ioutil.WriteFile(tmpfile.Name(), []byte("invalid content"), os.FileMode(0600)); err != nil {
		t.Fatal(err)
	}

	_, err = getSessionSecrets(tmpfile.Name())
	if err == nil {
		t.Errorf("Expected error, got none")
	}
}

func TestGetEmptySessionSecretsFile(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "empty.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	secrets := &osinv1.SessionSecrets{
		Secrets: []osinv1.SessionSecret{},
	}

	yamlData, err := writeYAML(secrets)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if err := ioutil.WriteFile(tmpfile.Name(), []byte(yamlData), os.FileMode(0600)); err != nil {
		t.Fatal(err)
	}

	_, err = getSessionSecrets(tmpfile.Name())
	if err == nil {
		t.Errorf("Expected error, got none")
	}
}

func TestGetValidSessionSecretsFile(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "valid.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	secrets := &osinv1.SessionSecrets{
		Secrets: []osinv1.SessionSecret{
			{Authentication: "a1", Encryption: "e1"},
			{Authentication: "a2", Encryption: "e2"},
		},
	}
	expectedSecrets := [][]byte{[]byte("a1"), []byte("e1"), []byte("a2"), []byte("e2")}

	yamlData, err := writeYAML(secrets)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if err := ioutil.WriteFile(tmpfile.Name(), []byte(yamlData), os.FileMode(0600)); err != nil {
		t.Fatal(err)
	}

	readSecrets, err := getSessionSecrets(tmpfile.Name())
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !reflect.DeepEqual(readSecrets, expectedSecrets) {
		t.Errorf("Unexpected %v, got %v", expectedSecrets, readSecrets)
	}
}

func TestGetValidSessionSecretsFileJSON(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "valid.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	secrets := &osinv1.SessionSecrets{
		Secrets: []osinv1.SessionSecret{
			{Authentication: "a3", Encryption: "e5"},
			{Authentication: "a4", Encryption: "e6"},
		},
	}
	expectedSecrets := [][]byte{[]byte("a3"), []byte("e5"), []byte("a4"), []byte("e6")}

	jsonData, err := json.Marshal(secrets)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if err := ioutil.WriteFile(tmpfile.Name(), []byte(jsonData), os.FileMode(0600)); err != nil {
		t.Fatal(err)
	}

	readSecrets, err := getSessionSecrets(tmpfile.Name())
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !reflect.DeepEqual(readSecrets, expectedSecrets) {
		t.Errorf("Unexpected %v, got %v", expectedSecrets, readSecrets)
	}
}

func writeYAML(obj runtime.Object) ([]byte, error) {
	jsonData, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	return yaml.JSONToYAML(jsonData)
}
