package etcd

import (
	"time"

	"github.com/coreos/etcd/clientv3"
	g "github.com/onsi/ginkgo"
	o "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	restclient "k8s.io/client-go/rest"

	routev1 "github.com/openshift/api/route/v1"
	exutil "github.com/openshift/origin/test/extended/util"
)

var _ = g.Describe("API data in etcd", func() {
	defer g.GinkgoRecover()

	oc := exutil.NewCLI("etcd-storage-path", exutil.KubeConfigPath())

	_ = g.It("should be stored at the correct location and version for all resources", func() {
		const (
			name            = "etcd"
			etcdNamespace   = "openshift-etcd"
			configNamespace = "openshift-config"
		)

		routes := oc.AdminRouteClient().RouteV1().Routes(etcdNamespace)
		defer func() {
			o.Expect(routes.Delete(name, nil)).NotTo(o.HaveOccurred())
		}()

		_, err := routes.Create(&routev1.Route{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: etcdNamespace,
			},
			Spec: routev1.RouteSpec{
				To: routev1.RouteTargetReference{
					Kind: "Service",
					Name: name,
				},
				Port: &routev1.RoutePort{
					TargetPort: intstr.FromInt(2379),
				},
				TLS: &routev1.TLSConfig{
					Termination: routev1.TLSTerminationPassthrough,
				},
			},
		})
		o.Expect(err).NotTo(o.HaveOccurred())

		var etcdHost string
		err = wait.PollImmediate(time.Second, wait.ForeverTestTimeout, func() (done bool, err error) {
			route, err := routes.Get(name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			etcdHost = getHost(route)
			return len(etcdHost) > 0, nil
		})
		o.Expect(err).NotTo(o.HaveOccurred())

		coreV1 := oc.AdminKubeClient().CoreV1()
		etcdConfigMap, err := coreV1.ConfigMaps(configNamespace).Get("etcd-ca-bundle", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
		etcdSecret, err := coreV1.Secrets(configNamespace).Get("etcd-client", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
		etcdEndpoint, err := coreV1.Endpoints(etcdNamespace).Get("host-etcd", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())
		infrastructure, err := oc.AdminConfigClient().ConfigV1().Infrastructures().Get("cluster", metav1.GetOptions{})
		o.Expect(err).NotTo(o.HaveOccurred())

		tlsConfig, err := restclient.TLSConfigFor(&restclient.Config{
			TLSClientConfig: restclient.TLSClientConfig{
				ServerName: getHostName(etcdEndpoint) + "." + infrastructure.Status.EtcdDiscoveryDomain,
				CertData:   etcdSecret.Data[corev1.TLSCertKey],
				KeyData:    etcdSecret.Data[corev1.TLSPrivateKeyKey],
				CAData:     []byte(etcdConfigMap.Data["ca-bundle.crt"]),
			},
		})
		o.Expect(err).NotTo(o.HaveOccurred())

		etcdClient3, err := clientv3.New(clientv3.Config{
			Endpoints:   []string{"https://" + etcdHost + ":443"},
			DialTimeout: 30 * time.Second,
			TLS:         tlsConfig,
		})
		o.Expect(err).NotTo(o.HaveOccurred())

		testEtcd3StoragePath(g.GinkgoT(), oc.AdminConfig(), etcdClient3.KV)
	})
})

func getHost(route *routev1.Route) string {
	for _, ingress := range route.Status.Ingress {
		if !isIngressAdmitted(ingress) {
			continue
		}
		return ingress.Host
	}
	return ""
}

func isIngressAdmitted(ingress routev1.RouteIngress) bool {
	for _, condition := range ingress.Conditions {
		if condition.Type == routev1.RouteAdmitted && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func getHostName(ep *corev1.Endpoints) string {
	for _, s := range ep.Subsets {
		for _, a := range s.Addresses {
			if len(a.Hostname) > 0 {
				return a.Hostname
			}
		}
	}
	return "not a valid hostname!"
}
