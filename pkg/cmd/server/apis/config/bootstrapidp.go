package config

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type BootstrapIdentityProvider struct {
	v1.TypeMeta
}

func (b *BootstrapIdentityProvider) DeepCopyObject() runtime.Object {
	return &BootstrapIdentityProvider{
		TypeMeta: b.TypeMeta,
	}
}
