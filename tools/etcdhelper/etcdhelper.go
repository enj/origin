package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	jsonserializer "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/kubernetes/pkg/api"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/pkg/transport"

	// try really hard to install all APIs
	_ "github.com/openshift/origin/pkg/api/install"
	_ "github.com/openshift/origin/pkg/authorization/apis/authorization/install"
	_ "github.com/openshift/origin/pkg/build/apis/build/install"
	_ "github.com/openshift/origin/pkg/build/controller/build/defaults/api/install"
	_ "github.com/openshift/origin/pkg/build/controller/build/overrides/api/install"
	_ "github.com/openshift/origin/pkg/cmd/server/api/install"
	_ "github.com/openshift/origin/pkg/deploy/apis/apps/install"
	_ "github.com/openshift/origin/pkg/image/admission/imagepolicy/api/install"
	_ "github.com/openshift/origin/pkg/image/apis/image/install"
	_ "github.com/openshift/origin/pkg/ingress/admission/api/install"
	_ "github.com/openshift/origin/pkg/oauth/apis/oauth/install"
	_ "github.com/openshift/origin/pkg/project/admission/requestlimit/api/install"
	_ "github.com/openshift/origin/pkg/project/apis/project/install"
	_ "github.com/openshift/origin/pkg/quota/admission/clusterresourceoverride/api/install"
	_ "github.com/openshift/origin/pkg/quota/admission/runonceduration/api/install"
	_ "github.com/openshift/origin/pkg/quota/apis/quota/install"
	_ "github.com/openshift/origin/pkg/route/apis/route/install"
	_ "github.com/openshift/origin/pkg/scheduler/admission/podnodeconstraints/api/install"
	_ "github.com/openshift/origin/pkg/sdn/apis/network/install"
	_ "github.com/openshift/origin/pkg/security/apis/security/install"
	_ "github.com/openshift/origin/pkg/template/apis/template/install"
	_ "github.com/openshift/origin/pkg/user/apis/user/install"
	_ "k8s.io/apiserver/pkg/apis/apiserver/install"
	_ "k8s.io/kube-aggregator/pkg/apis/apiregistration/install"
	_ "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm/install"
	_ "k8s.io/kubernetes/federation/apis/core/install"
	_ "k8s.io/kubernetes/federation/apis/federation/install"
	_ "k8s.io/kubernetes/pkg/api/install"
	_ "k8s.io/kubernetes/pkg/apis/admission/install"
	_ "k8s.io/kubernetes/pkg/apis/admissionregistration/install"
	_ "k8s.io/kubernetes/pkg/apis/apps/install"
	_ "k8s.io/kubernetes/pkg/apis/authentication/install"
	_ "k8s.io/kubernetes/pkg/apis/authorization/install"
	_ "k8s.io/kubernetes/pkg/apis/autoscaling/install"
	_ "k8s.io/kubernetes/pkg/apis/batch/install"
	_ "k8s.io/kubernetes/pkg/apis/certificates/install"
	_ "k8s.io/kubernetes/pkg/apis/componentconfig/install"
	_ "k8s.io/kubernetes/pkg/apis/extensions/install"
	_ "k8s.io/kubernetes/pkg/apis/imagepolicy/install"
	_ "k8s.io/kubernetes/pkg/apis/networking/install"
	_ "k8s.io/kubernetes/pkg/apis/policy/install"
	_ "k8s.io/kubernetes/pkg/apis/rbac/install"
	_ "k8s.io/kubernetes/pkg/apis/settings/install"
	_ "k8s.io/kubernetes/pkg/apis/storage/install"
	_ "k8s.io/metrics/pkg/apis/custom_metrics/install"
	_ "k8s.io/metrics/pkg/apis/metrics/install"
)

func main() {
	var endpoint, keyFile, certFile, caFile string
	flag.StringVar(&endpoint, "endpoint", "https://127.0.0.1:4001", "Etcd endpoint.")
	flag.StringVar(&keyFile, "key", "", "TLS client key.")
	flag.StringVar(&certFile, "cert", "", "TLS client certificate.")
	flag.StringVar(&caFile, "cacert", "", "Server TLS CA certificate.")
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprint(os.Stderr, "ERROR: you need to specify action: dump or ls [<key>] or get <key>\n")
		os.Exit(1)
	}
	if flag.Arg(0) == "get" && flag.NArg() == 1 {
		fmt.Fprint(os.Stderr, "ERROR: you need to specify <key> for get operation\n")
		os.Exit(1)
	}
	if flag.Arg(0) == "dump" && flag.NArg() != 1 {
		fmt.Fprint(os.Stderr, "ERROR: you cannot specify positional arguments with dump\n")
		os.Exit(1)
	}
	action := flag.Arg(0)
	key := ""
	if flag.NArg() > 1 {
		key = flag.Arg(1)
	}

	var tlsConfig *tls.Config
	if len(certFile) != 0 || len(keyFile) != 0 || len(caFile) != 0 {
		tlsInfo := transport.TLSInfo{
			CertFile: certFile,
			KeyFile:  keyFile,
			CAFile:   caFile,
		}
		var err error
		tlsConfig, err = tlsInfo.ClientConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: unable to create client config: %v\n", err)
			os.Exit(1)
		}
	}

	config := clientv3.Config{
		Endpoints:   []string{endpoint},
		TLS:         tlsConfig,
		DialTimeout: 5 * time.Second,
	}
	client, err := clientv3.New(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: unable to connect to etcd: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	switch action {
	case "ls":
		err = listKeys(client, key)
	case "get":
		err = getKey(client, key)
	case "dump":
		err = dump(client)
	default:
		fmt.Fprintf(os.Stderr, "ERROR: invalid action: %s\n", action)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s-ing %s: %v\n", action, key, err)
		os.Exit(1)
	}
}

func listKeys(client *clientv3.Client, key string) error {
	var resp *clientv3.GetResponse
	var err error
	if len(key) == 0 {
		resp, err = clientv3.NewKV(client).Get(context.Background(), "/", clientv3.WithFromKey(), clientv3.WithKeysOnly())
	} else {
		resp, err = clientv3.NewKV(client).Get(context.Background(), key, clientv3.WithPrefix(), clientv3.WithKeysOnly())
	}
	if err != nil {
		return err
	}

	for _, kv := range resp.Kvs {
		fmt.Println(string(kv.Key))
	}

	return nil
}

func getKey(client *clientv3.Client, key string) error {
	resp, err := clientv3.NewKV(client).Get(context.Background(), key)
	if err != nil {
		return err
	}

	decoder := api.Codecs.UniversalDeserializer()
	encoder := jsonserializer.NewSerializer(jsonserializer.DefaultMetaFactory, api.Scheme, api.Scheme, true)

	for _, kv := range resp.Kvs {
		obj, gvk, err := decoder.Decode(kv.Value, nil, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: unable to decode %s: %v\n", kv.Key, err)
			continue
		}
		fmt.Println(gvk)
		err = encoder.Encode(obj, os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: unable to decode %s: %v\n", kv.Key, err)
			continue
		}
	}

	return nil
}

func dump(client *clientv3.Client) error {
	response, err := clientv3.NewKV(client).Get(context.Background(), "/", clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return err
	}

	kvData := []etcd3kv{}
	decoder := api.Codecs.UniversalDeserializer()
	encoder := jsonserializer.NewSerializer(jsonserializer.DefaultMetaFactory, api.Scheme, api.Scheme, false)
	objJSON := &bytes.Buffer{}

	for _, kv := range response.Kvs {
		obj, _, err := decoder.Decode(kv.Value, nil, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARN: error decoding value %s: %v\n", string(kv.Value), err)
			continue
		}
		objJSON.Reset()
		if err := encoder.Encode(obj, objJSON); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: error encoding object %#v as JSON: %v", obj, err)
			continue
		}
		kvData = append(
			kvData,
			etcd3kv{
				Key:            string(kv.Key),
				Value:          string(objJSON.Bytes()),
				CreateRevision: kv.CreateRevision,
				ModRevision:    kv.ModRevision,
				Version:        kv.Version,
				Lease:          kv.Lease,
			},
		)
	}

	jsonData, err := json.MarshalIndent(kvData, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(jsonData))

	return nil
}

type etcd3kv struct {
	Key            string `json:"key,omitempty"`
	Value          string `json:"value,omitempty"`
	CreateRevision int64  `json:"create_revision,omitempty"`
	ModRevision    int64  `json:"mod_revision,omitempty"`
	Version        int64  `json:"version,omitempty"`
	Lease          int64  `json:"lease,omitempty"`
}
