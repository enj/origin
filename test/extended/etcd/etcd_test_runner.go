package etcd

import (
	"time"

	"github.com/coreos/etcd/clientv3"
	g "github.com/onsi/ginkgo"
	o "github.com/onsi/gomega"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	restclient "k8s.io/client-go/rest"

	routev1 "github.com/openshift/api/route/v1"
	exutil "github.com/openshift/origin/test/extended/util"
)

var _ = g.Describe("API data in etcd", func() {
	defer g.GinkgoRecover()

	oc := exutil.NewCLI("etcd-storage-path", exutil.KubeConfigPath())

	g.It("should be stored at the correct location and version for all resources", func() {
		const (
			name      = "etcd"
			namespace = "openshift-etcd"
			port      = 2379
		)

		routes := oc.AdminRouteClient().RouteV1().Routes(namespace)
		defer func() {
			o.Expect(routes.Delete(name, nil)).NotTo(o.HaveOccurred())
		}()

		_, err := routes.Create(&routev1.Route{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Spec: routev1.RouteSpec{
				To: routev1.RouteTargetReference{
					Kind: "Service",
					Name: name,
				},
				Port: &routev1.RoutePort{
					TargetPort: intstr.FromInt(port),
				},
				TLS: &routev1.TLSConfig{
					Termination: routev1.TLSTerminationPassthrough,
				},
			},
		})
		o.Expect(err).NotTo(o.HaveOccurred())

		// get route host name

		tlsConfig, err := restclient.TLSConfigFor(&restclient.Config{
			TLSClientConfig: restclient.TLSClientConfig{
				ServerName: "",
				CertData:   nil,
				KeyData:    nil,
				CAData:     nil,
			},
		})
		o.Expect(err).NotTo(o.HaveOccurred())

		etcdConfig := clientv3.Config{
			Endpoints:   []string{"TODO"},
			DialTimeout: 30 * time.Second,
			TLS:         tlsConfig,
		}
		etcdClient3, err := clientv3.New(etcdConfig)
		o.Expect(err).NotTo(o.HaveOccurred())

		testEtcd3StoragePath(g.GinkgoT(), oc.AdminConfig(), etcdClient3.KV)
	})
})
