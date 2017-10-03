package browsersafeproxy

import (
	"fmt"
	"io"

	"k8s.io/apiserver/pkg/admission"
	kclientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	authorizationclient "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/typed/authorization/internalversion"
	kadmission "k8s.io/kubernetes/pkg/kubeapiserver/admission"
)

const PluginName = "openshift.io/BrowserSafeProxy"

func Register(plugins *admission.Plugins) {
	plugins.Register(PluginName, func(_ io.Reader) (admission.Interface, error) {
		return NewBrowserSafeProxyAdmission()
	})
}

var _ = kadmission.WantsInternalKubeClientSet(&browserSafeProxy{})

func NewBrowserSafeProxyAdmission() (admission.Interface, error) {
	return &browserSafeProxy{
		Handler: admission.NewHandler(admission.Create, admission.Update), // TODO fix methods
	}, nil
}

type browserSafeProxy struct {
	*admission.Handler

	sar authorizationclient.SubjectAccessReviewInterface
}

func (b *browserSafeProxy) SetInternalKubeClientSet(c kclientset.Interface) {
	b.sar = c.Authorization().SubjectAccessReviews()
}

func (b *browserSafeProxy) Validate() error {
	if b.sar == nil {
		return fmt.Errorf("%s plugin requires a SAR client", PluginName)
	}
	return nil
}

func (b *browserSafeProxy) Admit(a admission.Attributes) (err error) {
	panic("implement me")
}
