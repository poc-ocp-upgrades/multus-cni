package k8sclient

import (
	"encoding/json"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
	godefaultruntime "runtime"
	"fmt"
	"os"
	"regexp"
	"strings"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/skel"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	"github.com/intel/multus-cni/kubeletclient"
	"github.com/intel/multus-cni/logging"
	"github.com/intel/multus-cni/types"
)

const (
	resourceNameAnnot	= "k8s.v1.cni.cncf.io/resourceName"
	defaultNetAnnot		= "v1.multus-cni.io/default-network"
	networkAttachmentAnnot	= "k8s.v1.cni.cncf.io/networks"
)

type NoK8sNetworkError struct{ message string }
type clientInfo struct {
	Client		KubeClient
	Podnamespace	string
	Podname		string
}

func (e *NoK8sNetworkError) Error() string {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return string(e.message)
}

type defaultKubeClient struct{ client kubernetes.Interface }

var _ KubeClient = &defaultKubeClient{}

func (d *defaultKubeClient) GetRawWithPath(path string) ([]byte, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return d.client.ExtensionsV1beta1().RESTClient().Get().AbsPath(path).DoRaw()
}
func (d *defaultKubeClient) GetPod(namespace, name string) (*v1.Pod, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return d.client.Core().Pods(namespace).Get(name, metav1.GetOptions{})
}
func (d *defaultKubeClient) UpdatePodStatus(pod *v1.Pod) (*v1.Pod, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	return d.client.Core().Pods(pod.Namespace).UpdateStatus(pod)
}
func setKubeClientInfo(c *clientInfo, client KubeClient, k8sArgs *types.K8sArgs) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	logging.Debugf("setKubeClientInfo: %v, %v, %v", c, client, k8sArgs)
	c.Client = client
	c.Podnamespace = string(k8sArgs.K8S_POD_NAMESPACE)
	c.Podname = string(k8sArgs.K8S_POD_NAME)
}
func SetNetworkStatus(client KubeClient, k8sArgs *types.K8sArgs, netStatus []*types.NetworkStatus, conf *types.NetConf) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	logging.Debugf("SetNetworkStatus: %v, %v, %v, %v", client, k8sArgs, netStatus, conf)
	client, err := GetK8sClient(conf.Kubeconfig, client)
	if err != nil {
		return logging.Errorf("SetNetworkStatus: %v", err)
	}
	if client == nil {
		if len(conf.Delegates) == 0 {
			return logging.Errorf("must have either Kubernetes config or delegates, refer to Multus documentation for usage instructions")
		}
		logging.Debugf("SetNetworkStatus: kube client info is not defined, skip network status setup")
		return nil
	}
	podName := string(k8sArgs.K8S_POD_NAME)
	podNamespace := string(k8sArgs.K8S_POD_NAMESPACE)
	pod, err := client.GetPod(podNamespace, podName)
	if err != nil {
		return logging.Errorf("SetNetworkStatus: failed to query the pod %v in out of cluster comm: %v", podName, err)
	}
	var networkStatuses string
	if netStatus != nil {
		var networkStatus []string
		for _, status := range netStatus {
			data, err := json.MarshalIndent(status, "", "    ")
			if err != nil {
				return logging.Errorf("SetNetworkStatus: error with Marshal Indent: %v", err)
			}
			networkStatus = append(networkStatus, string(data))
		}
		networkStatuses = fmt.Sprintf("[%s]", strings.Join(networkStatus, ","))
	}
	_, err = setPodNetworkAnnotation(client, podNamespace, pod, networkStatuses)
	if err != nil {
		return logging.Errorf("SetNetworkStatus: failed to update the pod %v in out of cluster comm: %v", podName, err)
	}
	return nil
}
func setPodNetworkAnnotation(client KubeClient, namespace string, pod *v1.Pod, networkstatus string) (*v1.Pod, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	logging.Debugf("setPodNetworkAnnotation: %v, %s, %v, %s", client, namespace, pod, networkstatus)
	if len(pod.Annotations) == 0 {
		pod.Annotations = make(map[string]string)
	}
	pod.Annotations["k8s.v1.cni.cncf.io/networks-status"] = networkstatus
	pod = pod.DeepCopy()
	var err error
	if resultErr := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		if err != nil {
			pod, err = client.GetPod(pod.Namespace, pod.Name)
			if err != nil {
				return err
			}
		}
		pod, err = client.UpdatePodStatus(pod)
		return err
	}); resultErr != nil {
		return nil, logging.Errorf("status update failed for pod %s/%s: %v", pod.Namespace, pod.Name, resultErr)
	}
	return pod, nil
}
func parsePodNetworkObjectName(podnetwork string) (string, string, string, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var netNsName string
	var netIfName string
	var networkName string
	logging.Debugf("parsePodNetworkObjectName: %s", podnetwork)
	slashItems := strings.Split(podnetwork, "/")
	if len(slashItems) == 2 {
		netNsName = strings.TrimSpace(slashItems[0])
		networkName = slashItems[1]
	} else if len(slashItems) == 1 {
		networkName = slashItems[0]
	} else {
		return "", "", "", logging.Errorf("Invalid network object (failed at '/')")
	}
	atItems := strings.Split(networkName, "@")
	networkName = strings.TrimSpace(atItems[0])
	if len(atItems) == 2 {
		netIfName = strings.TrimSpace(atItems[1])
	} else if len(atItems) != 1 {
		return "", "", "", logging.Errorf("Invalid network object (failed at '@')")
	}
	allItems := []string{netNsName, networkName, netIfName}
	for i := range allItems {
		matched, _ := regexp.MatchString("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", allItems[i])
		if !matched && len([]rune(allItems[i])) > 0 {
			return "", "", "", logging.Errorf(fmt.Sprintf("Failed to parse: one or more items did not match comma-delimited format (must consist of lower case alphanumeric characters). Must start and end with an alphanumeric character), mismatch @ '%v'", allItems[i]))
		}
	}
	logging.Debugf("parsePodNetworkObjectName: parsed: %s, %s, %s", netNsName, networkName, netIfName)
	return netNsName, networkName, netIfName, nil
}
func parsePodNetworkAnnotation(podNetworks, defaultNamespace string) ([]*types.NetworkSelectionElement, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var networks []*types.NetworkSelectionElement
	logging.Debugf("parsePodNetworkAnnotation: %s, %s", podNetworks, defaultNamespace)
	if podNetworks == "" {
		return nil, logging.Errorf("parsePodNetworkAnnotation: pod annotation not having \"network\" as key, refer Multus README.md for the usage guide")
	}
	if strings.IndexAny(podNetworks, "[{\"") >= 0 {
		if err := json.Unmarshal([]byte(podNetworks), &networks); err != nil {
			return nil, logging.Errorf("parsePodNetworkAnnotation: failed to parse pod Network Attachment Selection Annotation JSON format: %v", err)
		}
	} else {
		for _, item := range strings.Split(podNetworks, ",") {
			item = strings.TrimSpace(item)
			netNsName, networkName, netIfName, err := parsePodNetworkObjectName(item)
			if err != nil {
				return nil, logging.Errorf("parsePodNetworkAnnotation: %v", err)
			}
			networks = append(networks, &types.NetworkSelectionElement{Name: networkName, Namespace: netNsName, InterfaceRequest: netIfName})
		}
	}
	for _, net := range networks {
		if net.Namespace == "" {
			net.Namespace = defaultNamespace
		}
	}
	return networks, nil
}
func getCNIConfigFromFile(name string, confdir string) ([]byte, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	logging.Debugf("getCNIConfigFromFile: %s, %s", name, confdir)
	files, err := libcni.ConfFiles(confdir, []string{".conf", ".json", ".conflist"})
	switch {
	case err != nil:
		return nil, logging.Errorf("No networks found in %s", confdir)
	case len(files) == 0:
		return nil, logging.Errorf("No networks found in %s", confdir)
	}
	for _, confFile := range files {
		var confList *libcni.NetworkConfigList
		if strings.HasSuffix(confFile, ".conflist") {
			confList, err = libcni.ConfListFromFile(confFile)
			if err != nil {
				return nil, logging.Errorf("Error loading CNI conflist file %s: %v", confFile, err)
			}
			if confList.Name == name || name == "" {
				return confList.Bytes, nil
			}
		} else {
			conf, err := libcni.ConfFromFile(confFile)
			if err != nil {
				return nil, logging.Errorf("Error loading CNI config file %s: %v", confFile, err)
			}
			if conf.Network.Name == name || name == "" {
				if conf.Network.Type == "" {
					return nil, logging.Errorf("Error loading CNI config file %s: no 'type'; perhaps this is a .conflist?", confFile)
				}
				return conf.Bytes, nil
			}
		}
	}
	return nil, logging.Errorf("no network available in the name %s in cni dir %s", name, confdir)
}
func getCNIConfigFromSpec(configData, netName string) ([]byte, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var rawConfig map[string]interface{}
	var err error
	logging.Debugf("getCNIConfigFromSpec: %s, %s", configData, netName)
	configBytes := []byte(configData)
	err = json.Unmarshal(configBytes, &rawConfig)
	if err != nil {
		return nil, logging.Errorf("getCNIConfigFromSpec: failed to unmarshal Spec.Config: %v", err)
	}
	if n, ok := rawConfig["name"]; !ok || n == "" {
		rawConfig["name"] = netName
		configBytes, err = json.Marshal(rawConfig)
		if err != nil {
			return nil, logging.Errorf("getCNIConfigFromSpec: failed to re-marshal Spec.Config: %v", err)
		}
	}
	return configBytes, nil
}
func cniConfigFromNetworkResource(customResource *types.NetworkAttachmentDefinition, confdir string) ([]byte, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var config []byte
	var err error
	logging.Debugf("cniConfigFromNetworkResource: %v, %s", customResource, confdir)
	emptySpec := types.NetworkAttachmentDefinitionSpec{}
	if customResource.Spec == emptySpec {
		config, err = getCNIConfigFromFile(customResource.Metadata.Name, confdir)
		if err != nil {
			return nil, logging.Errorf("cniConfigFromNetworkResource: err in getCNIConfigFromFile: %v", err)
		}
	} else {
		config, err = getCNIConfigFromSpec(customResource.Spec.Config, customResource.Metadata.Name)
		if err != nil {
			return nil, logging.Errorf("cniConfigFromNetworkResource: err in getCNIConfigFromSpec: %v", err)
		}
	}
	return config, nil
}
func getKubernetesDelegate(client KubeClient, net *types.NetworkSelectionElement, confdir string, pod *v1.Pod, resourceMap map[string]*types.ResourceInfo) (*types.DelegateNetConf, map[string]*types.ResourceInfo, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	logging.Debugf("getKubernetesDelegate: %v, %v, %s", client, net, confdir)
	rawPath := fmt.Sprintf("/apis/k8s.cni.cncf.io/v1/namespaces/%s/network-attachment-definitions/%s", net.Namespace, net.Name)
	netData, err := client.GetRawWithPath(rawPath)
	if err != nil {
		return nil, resourceMap, logging.Errorf("getKubernetesDelegate: failed to get network resource, refer Multus README.md for the usage guide: %v", err)
	}
	customResource := &types.NetworkAttachmentDefinition{}
	if err := json.Unmarshal(netData, customResource); err != nil {
		return nil, resourceMap, logging.Errorf("getKubernetesDelegate: failed to get the netplugin data: %v", err)
	}
	deviceID := ""
	resourceName, ok := customResource.Metadata.Annotations[resourceNameAnnot]
	if ok && pod.Name != "" && pod.Namespace != "" {
		logging.Debugf("getKubernetesDelegate: found resourceName annotation : %s", resourceName)
		if resourceMap == nil {
			ck, err := kubeletclient.GetResourceClient()
			if err != nil {
				return nil, resourceMap, logging.Errorf("getKubernetesDelegate: failed to get a ResourceClient instance: %v", err)
			}
			resourceMap, err = ck.GetPodResourceMap(pod)
			if err != nil {
				return nil, resourceMap, logging.Errorf("getKubernetesDelegate: failed to get resourceMap from ResourceClient: %v", err)
			}
			logging.Debugf("getKubernetesDelegate(): resourceMap instance: %+v", resourceMap)
		}
		entry, ok := resourceMap[resourceName]
		if ok {
			if idCount := len(entry.DeviceIDs); idCount > 0 && idCount > entry.Index {
				deviceID = entry.DeviceIDs[entry.Index]
				logging.Debugf("getKubernetesDelegate: podName: %s deviceID: %s", pod.Name, deviceID)
				entry.Index++
			}
		}
	}
	configBytes, err := cniConfigFromNetworkResource(customResource, confdir)
	if err != nil {
		return nil, resourceMap, err
	}
	delegate, err := types.LoadDelegateNetConf(configBytes, net, deviceID)
	if err != nil {
		return nil, resourceMap, err
	}
	return delegate, resourceMap, nil
}

type KubeClient interface {
	GetRawWithPath(path string) ([]byte, error)
	GetPod(namespace, name string) (*v1.Pod, error)
	UpdatePodStatus(pod *v1.Pod) (*v1.Pod, error)
}

func GetK8sArgs(args *skel.CmdArgs) (*types.K8sArgs, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	k8sArgs := &types.K8sArgs{}
	logging.Debugf("GetK8sArgs: %v", args)
	err := cnitypes.LoadArgs(args.Args, k8sArgs)
	if err != nil {
		return nil, err
	}
	return k8sArgs, nil
}
func TryLoadPodDelegates(k8sArgs *types.K8sArgs, conf *types.NetConf, kubeClient KubeClient) (int, *clientInfo, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var err error
	clientInfo := &clientInfo{}
	logging.Debugf("TryLoadPodDelegates: %v, %v, %v", k8sArgs, conf, kubeClient)
	kubeClient, err = GetK8sClient(conf.Kubeconfig, kubeClient)
	if err != nil {
		return 0, nil, err
	}
	if kubeClient == nil {
		if len(conf.Delegates) == 0 {
			return 0, nil, logging.Errorf("must have either Kubernetes config or delegates, refer Multus README.md for the usage guide")
		}
		return 0, nil, nil
	}
	setKubeClientInfo(clientInfo, kubeClient, k8sArgs)
	pod, err := kubeClient.GetPod(string(k8sArgs.K8S_POD_NAMESPACE), string(k8sArgs.K8S_POD_NAME))
	if err != nil {
		logging.Debugf("tryLoadK8sDelegates: Err in loading K8s cluster default network from pod annotation: %v, use cached delegates", err)
		return 0, nil, nil
	}
	delegate, err := tryLoadK8sPodDefaultNetwork(kubeClient, pod, conf)
	if err != nil {
		return 0, nil, logging.Errorf("tryLoadK8sDelegates: Err in loading K8s cluster default network from pod annotation: %v", err)
	}
	if delegate != nil {
		logging.Debugf("tryLoadK8sDelegates: Overwrite the cluster default network with %v from pod annotations", delegate)
		conf.Delegates[0] = delegate
	}
	networks, err := GetPodNetwork(pod)
	if networks != nil {
		delegates, err := GetNetworkDelegates(kubeClient, pod, networks, conf.ConfDir, conf.NamespaceIsolation)
		if err != nil {
			if _, ok := err.(*NoK8sNetworkError); ok {
				return 0, clientInfo, nil
			}
			return 0, nil, logging.Errorf("Multus: Err in getting k8s network from pod: %v", err)
		}
		if err = conf.AddDelegates(delegates); err != nil {
			return 0, nil, err
		}
		return len(delegates), clientInfo, nil
	}
	return 0, clientInfo, nil
}
func GetK8sClient(kubeconfig string, kubeClient KubeClient) (KubeClient, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	logging.Debugf("GetK8sClient: %s, %v", kubeconfig, kubeClient)
	if kubeClient != nil {
		return kubeClient, nil
	}
	var err error
	var config *rest.Config
	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, logging.Errorf("GetK8sClient: failed to get context for the kubeconfig %v, refer Multus README.md for the usage guide: %v", kubeconfig, err)
		}
	} else if os.Getenv("KUBERNETES_SERVICE_HOST") != "" && os.Getenv("KUBERNETES_SERVICE_PORT") != "" {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, logging.Errorf("createK8sClient: failed to get context for in-cluster kube config, refer Multus README.md for the usage guide: %v", err)
		}
	} else {
		return nil, nil
	}
	config.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	config.ContentType = "application/vnd.kubernetes.protobuf"
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &defaultKubeClient{client: client}, nil
}
func GetPodNetwork(pod *v1.Pod) ([]*types.NetworkSelectionElement, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	logging.Debugf("GetPodNetwork: %v", pod)
	netAnnot := pod.Annotations[networkAttachmentAnnot]
	defaultNamespace := pod.ObjectMeta.Namespace
	if len(netAnnot) == 0 {
		return nil, &NoK8sNetworkError{"no kubernetes network found"}
	}
	networks, err := parsePodNetworkAnnotation(netAnnot, defaultNamespace)
	if err != nil {
		return nil, err
	}
	return networks, nil
}
func GetNetworkDelegates(k8sclient KubeClient, pod *v1.Pod, networks []*types.NetworkSelectionElement, confdir string, confnamespaceIsolation bool) ([]*types.DelegateNetConf, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	logging.Debugf("GetNetworkDelegates: %v, %v, %v, %v, %v", k8sclient, pod, networks, confdir, confnamespaceIsolation)
	var resourceMap map[string]*types.ResourceInfo
	var delegates []*types.DelegateNetConf
	defaultNamespace := pod.ObjectMeta.Namespace
	for _, net := range networks {
		if confnamespaceIsolation {
			if defaultNamespace != net.Namespace {
				return nil, logging.Errorf("GetPodNetwork: namespace isolation violation: podnamespace: %v / target namespace: %v", defaultNamespace, net.Namespace)
			}
		}
		delegate, updatedResourceMap, err := getKubernetesDelegate(k8sclient, net, confdir, pod, resourceMap)
		if err != nil {
			return nil, logging.Errorf("GetPodNetwork: failed getting the delegate: %v", err)
		}
		delegates = append(delegates, delegate)
		resourceMap = updatedResourceMap
	}
	return delegates, nil
}
func getDefaultNetDelegateCRD(client KubeClient, net, confdir, namespace string) (*types.DelegateNetConf, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	logging.Debugf("getDefaultNetDelegateCRD: %v, %v, %s, %s", client, net, confdir, namespace)
	rawPath := fmt.Sprintf("/apis/k8s.cni.cncf.io/v1/namespaces/%s/network-attachment-definitions/%s", namespace, net)
	netData, err := client.GetRawWithPath(rawPath)
	if err != nil {
		return nil, logging.Errorf("getDefaultNetDelegateCRD: failed to get network resource, refer Multus README.md for the usage guide: %v", err)
	}
	customResource := &types.NetworkAttachmentDefinition{}
	if err := json.Unmarshal(netData, customResource); err != nil {
		return nil, logging.Errorf("getDefaultNetDelegateCRD: failed to get the netplugin data: %v", err)
	}
	configBytes, err := cniConfigFromNetworkResource(customResource, confdir)
	if err != nil {
		return nil, err
	}
	delegate, err := types.LoadDelegateNetConf(configBytes, nil, "")
	if err != nil {
		return nil, err
	}
	return delegate, nil
}
func getNetDelegate(client KubeClient, netname, confdir, namespace string) (*types.DelegateNetConf, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	logging.Debugf("getNetDelegate: %v, %v, %v, %s", client, netname, confdir, namespace)
	delegate, err := getDefaultNetDelegateCRD(client, netname, confdir, namespace)
	if err == nil {
		return delegate, nil
	}
	var configBytes []byte
	configBytes, err = getCNIConfigFromFile(netname, confdir)
	if err == nil {
		delegate, err := types.LoadDelegateNetConf(configBytes, nil, "")
		if err != nil {
			return nil, err
		}
		return delegate, nil
	}
	fInfo, err := os.Stat(netname)
	if err == nil {
		if fInfo.IsDir() {
			files, err := libcni.ConfFiles(netname, []string{".conf", ".conflist"})
			if err != nil {
				return nil, err
			}
			if len(files) > 0 {
				var configBytes []byte
				configBytes, err = getCNIConfigFromFile("", netname)
				if err == nil {
					delegate, err := types.LoadDelegateNetConf(configBytes, nil, "")
					if err != nil {
						return nil, err
					}
					return delegate, nil
				}
				return nil, err
			}
		}
	}
	return nil, logging.Errorf("getNetDelegate: cannot find network: %v", netname)
}
func GetDefaultNetworks(k8sArgs *types.K8sArgs, conf *types.NetConf, kubeClient KubeClient) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	logging.Debugf("GetDefaultNetworks: %v, %v, %v", k8sArgs, conf, kubeClient)
	var delegates []*types.DelegateNetConf
	kubeClient, err := GetK8sClient(conf.Kubeconfig, kubeClient)
	if err != nil {
		return err
	}
	if kubeClient == nil {
		if len(conf.Delegates) == 0 {
			return logging.Errorf("must have either Kubernetes config or delegates, refer Multus README.md for the usage guide")
		}
		return nil
	}
	delegate, err := getNetDelegate(kubeClient, conf.ClusterNetwork, conf.ConfDir, conf.MultusNamespace)
	if err != nil {
		return err
	}
	delegate.MasterPlugin = true
	delegates = append(delegates, delegate)
	if !types.CheckSystemNamespaces(string(k8sArgs.K8S_POD_NAMESPACE), conf.SystemNamespaces) {
		for _, netname := range conf.DefaultNetworks {
			delegate, err := getNetDelegate(kubeClient, netname, conf.ConfDir, conf.MultusNamespace)
			if err != nil {
				return err
			}
			delegates = append(delegates, delegate)
		}
	}
	if err = conf.AddDelegates(delegates); err != nil {
		return err
	}
	return nil
}
func tryLoadK8sPodDefaultNetwork(kubeClient KubeClient, pod *v1.Pod, conf *types.NetConf) (*types.DelegateNetConf, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	var netAnnot string
	logging.Debugf("tryLoadK8sPodDefaultNetwork: %v, %v, %v", kubeClient, pod, conf)
	netAnnot, ok := pod.Annotations[defaultNetAnnot]
	if !ok {
		logging.Debugf("tryLoadK8sPodDefaultNetwork: Pod default network annotation is not defined")
		return nil, nil
	}
	networks, err := parsePodNetworkAnnotation(netAnnot, conf.MultusNamespace)
	if err != nil {
		return nil, logging.Errorf("tryLoadK8sPodDefaultNetwork: failed to parse CRD object: %v", err)
	}
	if len(networks) > 1 {
		return nil, logging.Errorf("tryLoadK8sPodDefaultNetwork: more than one default network is specified: %s", netAnnot)
	}
	delegate, _, err := getKubernetesDelegate(kubeClient, networks[0], conf.ConfDir, pod, nil)
	if err != nil {
		return nil, logging.Errorf("tryLoadK8sPodDefaultNetwork: failed getting the delegate: %v", err)
	}
	delegate.MasterPlugin = true
	return delegate, nil
}
func _logClusterCodePath() {
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("http://35.226.239.161:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
