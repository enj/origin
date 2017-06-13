package controller

import (
	"time"

	osclient "github.com/openshift/origin/pkg/client"
	"github.com/openshift/origin/pkg/cmd/server/bootstrappolicy"
	deployclient "github.com/openshift/origin/pkg/deploy/generated/internalclientset/typed/apps/internalversion"
	unidlingcontroller "github.com/openshift/origin/pkg/unidling/controller"
)

type UnidlingControllerConfig struct {
	ResyncPeriod time.Duration
}

func (c *UnidlingControllerConfig) RunController(ctx ControllerContext) (bool, error) {
	// oc, kc, extensionsClient := c.UnidlingControllerClients()
	scaleNamespacer := osclient.NewDelegatingScaleNamespacer(
		ctx.ClientBuilder.DeprecatedOpenshiftClientOrDie(bootstrappolicy.InfraUnidlingControllerServiceAccountName),
		ctx.ClientBuilder.ClientOrDie(bootstrappolicy.InfraUnidlingControllerServiceAccountName).Extensions(),
	)
	controller := unidlingcontroller.NewUnidlingController(
		scaleNamespacer,
		ctx.ClientBuilder.KubeInternalClientOrDie(bootstrappolicy.InfraUnidlingControllerServiceAccountName).Core(),
		ctx.ClientBuilder.KubeInternalClientOrDie(bootstrappolicy.InfraUnidlingControllerServiceAccountName).Core(),
		deployclient.NewForConfigOrDie(ctx.ClientBuilder.ConfigOrDie(bootstrappolicy.InfraUnidlingControllerServiceAccountName)),
		ctx.ClientBuilder.KubeInternalClientOrDie(bootstrappolicy.InfraUnidlingControllerServiceAccountName).Core(),
		c.ResyncPeriod,
	)

	go controller.Run(ctx.Stop)

	return true, nil
}
