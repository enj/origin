package master

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	kv1core "k8s.io/client-go/kubernetes/typed/core/v1"
	kclientv1 "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/record"
	kctrlmgr "k8s.io/kubernetes/cmd/kube-controller-manager/app"
	kubecontroller "k8s.io/kubernetes/cmd/kube-controller-manager/app"
	kapi "k8s.io/kubernetes/pkg/api"
	kapiv1 "k8s.io/kubernetes/pkg/api/v1"
	"k8s.io/kubernetes/pkg/apis/componentconfig"
	kclientset "k8s.io/kubernetes/pkg/client/clientset_generated/clientset"
	"k8s.io/kubernetes/pkg/cloudprovider"
	nodecontroller "k8s.io/kubernetes/pkg/controller/node"
	servicecontroller "k8s.io/kubernetes/pkg/controller/service"
	attachdetachcontroller "k8s.io/kubernetes/pkg/controller/volume/attachdetach"
	persistentvolumecontroller "k8s.io/kubernetes/pkg/controller/volume/persistentvolume"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/volume"
	"k8s.io/kubernetes/pkg/volume/aws_ebs"
	"k8s.io/kubernetes/pkg/volume/azure_dd"
	"k8s.io/kubernetes/pkg/volume/cinder"
	"k8s.io/kubernetes/pkg/volume/flexvolume"
	"k8s.io/kubernetes/pkg/volume/gce_pd"
	"k8s.io/kubernetes/pkg/volume/glusterfs"
	"k8s.io/kubernetes/pkg/volume/host_path"
	"k8s.io/kubernetes/pkg/volume/nfs"
	"k8s.io/kubernetes/pkg/volume/rbd"
	"k8s.io/kubernetes/pkg/volume/vsphere_volume"
	"k8s.io/kubernetes/plugin/pkg/scheduler"
	_ "k8s.io/kubernetes/plugin/pkg/scheduler/algorithmprovider"
	schedulerapi "k8s.io/kubernetes/plugin/pkg/scheduler/api"
	latestschedulerapi "k8s.io/kubernetes/plugin/pkg/scheduler/api/latest"
	"k8s.io/kubernetes/plugin/pkg/scheduler/factory"

	"github.com/golang/glog"
	"github.com/openshift/origin/pkg/cmd/server/bootstrappolicy"
)

type PersistentVolumeControllerConfig struct {
	OpenShiftInfrastructureNamespace string
	RecyclerImage                    string
	CloudProvider                    cloudprovider.Interface
}

func (c *PersistentVolumeControllerConfig) RunController(ctx kubecontroller.ControllerContext) (bool, error) {
	alphaProvisioner, err := kctrlmgr.NewAlphaVolumeProvisioner(c.CloudProvider, ctx.Options.VolumeConfiguration)
	if err != nil {
		return false, fmt.Errorf("A backward-compatible provisioner could not be created: %v, but one was expected. Provisioning will not work. This functionality is considered an early Alpha version.", err)
	}

	eventcast := record.NewBroadcaster()
	recorder := eventcast.NewRecorder(kapi.Scheme, kclientv1.EventSource{Component: bootstrappolicy.InfraPersistentVolumeControllerServiceAccountName})
	eventcast.StartRecordingToSink(
		&kv1core.EventSinkImpl{
			Interface: ctx.ClientBuilder.ClientGoClientOrDie(bootstrappolicy.InfraPersistentVolumeControllerServiceAccountName).CoreV1().Events(""),
		},
	)
	recyclerSA := bootstrappolicy.InfraPersistentVolumeRecyclerControllerServiceAccountName
	plugins, err := probeRecyclableVolumePlugins(ctx.Options.VolumeConfiguration, c.OpenShiftInfrastructureNamespace, c.RecyclerImage, recyclerSA)
	if err != nil {
		return false, err
	}

	volumeController := persistentvolumecontroller.NewController(
		persistentvolumecontroller.ControllerParameters{
			KubeClient:                ctx.ClientBuilder.ClientOrDie(bootstrappolicy.InfraPersistentVolumeControllerServiceAccountName),
			SyncPeriod:                ctx.Options.PVClaimBinderSyncPeriod.Duration,
			AlphaProvisioner:          alphaProvisioner,
			VolumePlugins:             plugins,
			Cloud:                     c.CloudProvider,
			ClusterName:               ctx.Options.ClusterName,
			VolumeInformer:            ctx.InformerFactory.Core().V1().PersistentVolumes(),
			ClaimInformer:             ctx.InformerFactory.Core().V1().PersistentVolumeClaims(),
			ClassInformer:             ctx.InformerFactory.Storage().V1beta1().StorageClasses(),
			EventRecorder:             recorder,
			EnableDynamicProvisioning: ctx.Options.VolumeConfiguration.EnableDynamicProvisioning,
		})

	go volumeController.Run(ctx.Stop)

	return true, nil
}

type PersistentVolumeAttachDetachControllerConfig struct {
	CloudProvider cloudprovider.Interface
}

func (c *PersistentVolumeAttachDetachControllerConfig) RunController(ctx kubecontroller.ControllerContext) (bool, error) {
	attachDetachController, err := attachdetachcontroller.NewAttachDetachController(
		ctx.ClientBuilder.ClientOrDie(bootstrappolicy.InfraPersistentVolumeAttachDetachControllerServiceAccountName),
		ctx.InformerFactory.Core().V1().Pods(),
		ctx.InformerFactory.Core().V1().Nodes(),
		ctx.InformerFactory.Core().V1().PersistentVolumeClaims(),
		ctx.InformerFactory.Core().V1().PersistentVolumes(),
		c.CloudProvider,
		kctrlmgr.ProbeAttachableVolumePlugins(ctx.Options.VolumeConfiguration),
		ctx.Options.DisableAttachDetachReconcilerSync,
		ctx.Options.ReconcilerSyncLoopPeriod.Duration,
	)
	if err != nil {
		return false, fmt.Errorf("failed to start attach/detach persistent volume controller: %v", err)
	}

	go attachDetachController.Run(ctx.Stop)

	return true, nil
}

type SchedulerControllerConfig struct {
	PrivilegedClient               kclientset.Interface
	SchedulerName                  string
	HardPodAffinitySymmetricWeight int
	PolicyConfigFile               string
	SchedulerConfigFile            string
}

func (c *SchedulerControllerConfig) RunController(ctx kubecontroller.ControllerContext) (bool, error) {
	var (
		policy     schedulerapi.Policy
		configData []byte
		config     *scheduler.Config
	)

	// TODO make the rate limiter configurable
	configFactory := factory.NewConfigFactory(
		c.SchedulerName,
		c.PrivilegedClient,
		ctx.InformerFactory.Core().V1().Nodes(),
		ctx.InformerFactory.Core().V1().Pods(),
		ctx.InformerFactory.Core().V1().PersistentVolumes(),
		ctx.InformerFactory.Core().V1().PersistentVolumeClaims(),
		ctx.InformerFactory.Core().V1().ReplicationControllers(),
		ctx.InformerFactory.Extensions().V1beta1().ReplicaSets(),
		ctx.InformerFactory.Apps().V1beta1().StatefulSets(),
		ctx.InformerFactory.Core().V1().Services(),
		c.HardPodAffinitySymmetricWeight,
	)

	if _, err := os.Stat(c.SchedulerConfigFile); err == nil {
		//configData, err = ioutil.ReadFile(c.SchedulerServer.PolicyConfigFile)
		configData, err = ioutil.ReadFile(c.PolicyConfigFile)
		if err != nil {
			return false, fmt.Errorf("unable to read scheduler config: %v", err)
		}
		err = runtime.DecodeInto(latestschedulerapi.Codec, configData, &policy)
		if err != nil {
			return true, fmt.Errorf("invalid scheduler configuration: %v", err)
		}

		config, err = configFactory.CreateFromConfig(policy)
		if err != nil {
			return true, fmt.Errorf("failed to create scheduler config from policy: %v", err)
		}
	} else {
		config, err = configFactory.CreateFromProvider(factory.DefaultProvider)
		if err != nil {
			return true, fmt.Errorf("failed to create scheduler config: %v", err)
		}
	}

	eventcast := record.NewBroadcaster()
	config.Recorder = eventcast.NewRecorder(kapi.Scheme, kclientv1.EventSource{Component: bootstrappolicy.InfraSchedulerServiceAccountName})
	eventcast.StartRecordingToSink(
		&kv1core.EventSinkImpl{
			Interface: ctx.ClientBuilder.ClientGoClientOrDie(bootstrappolicy.InfraSchedulerServiceAccountName).CoreV1().Events(""),
		},
	)

	s := scheduler.New(config)
	go s.Run()

	return true, nil
}

type NodeControllerConfig struct {
	CloudProvider cloudprovider.Interface
}

func (c *NodeControllerConfig) RunController(ctx kubecontroller.ControllerContext) (bool, error) {
	_, clusterCIDR, err := net.ParseCIDR(ctx.Options.ClusterCIDR)
	if err != nil {
		glog.Warningf("NodeController failed parsing cluster CIDR %v: %v", ctx.Options.ClusterCIDR, err)
	}

	_, serviceCIDR, err := net.ParseCIDR(ctx.Options.ServiceCIDR)
	if err != nil {
		glog.Warning("NodeController failed parsing service CIDR %v: %v", ctx.Options.ServiceCIDR, err)
	}

	controller, err := nodecontroller.NewNodeController(
		ctx.InformerFactory.Core().V1().Pods(),
		ctx.InformerFactory.Core().V1().Nodes(),
		ctx.InformerFactory.Extensions().V1beta1().DaemonSets(),
		c.CloudProvider,
		// TODO: Do we need openshift service account here?
		ctx.ClientBuilder.ClientOrDie("node-controller"),

		ctx.Options.PodEvictionTimeout.Duration,
		ctx.Options.NodeEvictionRate,
		ctx.Options.SecondaryNodeEvictionRate,
		ctx.Options.LargeClusterSizeThreshold,
		ctx.Options.UnhealthyZoneThreshold,
		ctx.Options.NodeMonitorGracePeriod.Duration,
		ctx.Options.NodeStartupGracePeriod.Duration,
		ctx.Options.NodeMonitorPeriod.Duration,

		clusterCIDR,
		serviceCIDR,

		int(ctx.Options.NodeCIDRMaskSize),
		ctx.Options.AllocateNodeCIDRs,
		ctx.Options.EnableTaintManager,
		utilfeature.DefaultFeatureGate.Enabled(features.TaintBasedEvictions),
	)
	if err != nil {
		return false, fmt.Errorf("unable to start node controller: %v", err)
	}

	go controller.Run()

	return true, nil
}

type ServiceLoadBalancerControllerConfig struct {
	CloudProvider cloudprovider.Interface
}

func (c *ServiceLoadBalancerControllerConfig) RunController(ctx kubecontroller.ControllerContext) (bool, error) {
	if c.CloudProvider == nil {
		glog.Warningf("ServiceLoadBalancer controller will not start - no cloud provider configured")
		return false, nil
	}
	serviceController, err := servicecontroller.New(
		c.CloudProvider,
		ctx.ClientBuilder.ClientOrDie(bootstrappolicy.InfraServiceLoadBalancerControllerServiceAccountName),
		ctx.InformerFactory.Core().V1().Services(),
		ctx.InformerFactory.Core().V1().Nodes(),
		ctx.Options.ClusterName,
	)
	if err != nil {
		return false, fmt.Errorf("unable to start service load balancer controller: %v", err)
	}

	go serviceController.Run(ctx.Stop, int(ctx.Options.ConcurrentServiceSyncs))
	return true, nil
}

// probeRecyclableVolumePlugins collects all persistent volume plugins into an easy to use list.
// TODO: Move this into some helper package?
func probeRecyclableVolumePlugins(config componentconfig.VolumeConfiguration, namespace, recyclerImageName, recyclerServiceAccountName string) ([]volume.VolumePlugin, error) {
	uid := int64(0)
	defaultScrubPod := volume.NewPersistentVolumeRecyclerPodTemplate()
	defaultScrubPod.Namespace = namespace
	defaultScrubPod.Spec.ServiceAccountName = recyclerServiceAccountName
	defaultScrubPod.Spec.Containers[0].Image = recyclerImageName
	defaultScrubPod.Spec.Containers[0].Command = []string{"/usr/bin/openshift-recycle"}
	defaultScrubPod.Spec.Containers[0].Args = []string{"/scrub"}
	defaultScrubPod.Spec.Containers[0].SecurityContext = &kapiv1.SecurityContext{RunAsUser: &uid}
	defaultScrubPod.Spec.Containers[0].ImagePullPolicy = kapiv1.PullIfNotPresent

	allPlugins := []volume.VolumePlugin{}

	// The list of plugins to probe is decided by this binary, not
	// by dynamic linking or other "magic".  Plugins will be analyzed and
	// initialized later.

	// Each plugin can make use of VolumeConfig.  The single arg to this func contains *all* enumerated
	// options meant to configure volume plugins.  From that single config, create an instance of volume.VolumeConfig
	// for a specific plugin and pass that instance to the plugin's ProbeVolumePlugins(config) func.

	// HostPath recycling is for testing and development purposes only!
	hostPathConfig := volume.VolumeConfig{
		RecyclerMinimumTimeout:   int(config.PersistentVolumeRecyclerConfiguration.MinimumTimeoutHostPath),
		RecyclerTimeoutIncrement: int(config.PersistentVolumeRecyclerConfiguration.IncrementTimeoutHostPath),
		RecyclerPodTemplate:      defaultScrubPod,
		ProvisioningEnabled:      config.EnableHostPathProvisioning,
	}
	if err := kctrlmgr.AttemptToLoadRecycler(config.PersistentVolumeRecyclerConfiguration.PodTemplateFilePathHostPath, &hostPathConfig); err != nil {
		return nil, fmt.Errorf("could not create hostpath recycler pod from file %s: %+v", config.PersistentVolumeRecyclerConfiguration.PodTemplateFilePathHostPath, err)
	}
	allPlugins = append(allPlugins, host_path.ProbeVolumePlugins(hostPathConfig)...)

	nfsConfig := volume.VolumeConfig{
		RecyclerMinimumTimeout:   int(config.PersistentVolumeRecyclerConfiguration.MinimumTimeoutNFS),
		RecyclerTimeoutIncrement: int(config.PersistentVolumeRecyclerConfiguration.IncrementTimeoutNFS),
		RecyclerPodTemplate:      defaultScrubPod,
	}
	if err := kctrlmgr.AttemptToLoadRecycler(config.PersistentVolumeRecyclerConfiguration.PodTemplateFilePathNFS, &nfsConfig); err != nil {
		return nil, fmt.Errorf("could not create NFS recycler pod from file %s: %+v", config.PersistentVolumeRecyclerConfiguration.PodTemplateFilePathNFS, err)
	}
	allPlugins = append(allPlugins, nfs.ProbeVolumePlugins(nfsConfig)...)

	allPlugins = append(allPlugins, aws_ebs.ProbeVolumePlugins()...)
	allPlugins = append(allPlugins, gce_pd.ProbeVolumePlugins()...)
	allPlugins = append(allPlugins, cinder.ProbeVolumePlugins()...)
	allPlugins = append(allPlugins, flexvolume.ProbeVolumePlugins(config.FlexVolumePluginDir)...)
	allPlugins = append(allPlugins, vsphere_volume.ProbeVolumePlugins()...)
	allPlugins = append(allPlugins, glusterfs.ProbeVolumePlugins()...)
	allPlugins = append(allPlugins, rbd.ProbeVolumePlugins()...)
	allPlugins = append(allPlugins, azure_dd.ProbeVolumePlugins()...)

	return allPlugins, nil
}
