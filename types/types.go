package types

import (
	"net"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NetConf struct {
	types.NetConf
	RawPrevResult			*map[string]interface{}		`json:"prevResult"`
	PrevResult				*current.Result				`json:"-"`
	ConfDir					string						`json:"confDir"`
	CNIDir					string						`json:"cniDir"`
	BinDir					string						`json:"binDir"`
	RawDelegates			[]map[string]interface{}	`json:"delegates"`
	Delegates				[]*DelegateNetConf			`json:"-"`
	NetStatus				[]*NetworkStatus			`json:"-"`
	Kubeconfig				string						`json:"kubeconfig"`
	ClusterNetwork			string						`json:"clusterNetwork"`
	DefaultNetworks			[]string					`json:"defaultNetworks"`
	LogFile					string						`json:"logFile"`
	LogLevel				string						`json:"logLevel"`
	RuntimeConfig			*RuntimeConfig				`json:"runtimeConfig,omitempty"`
	ReadinessIndicatorFile	string						`json:"readinessindicatorfile"`
	NamespaceIsolation		bool						`json:"namespaceIsolation"`
	SystemNamespaces		[]string					`json:"systemNamespaces"`
	MultusNamespace			string						`json:"multusNamespace"`
}
type RuntimeConfig struct {
	PortMaps []PortMapEntry `json:"portMappings,omitempty"`
}
type PortMapEntry struct {
	HostPort		int		`json:"hostPort"`
	ContainerPort	int		`json:"containerPort"`
	Protocol		string	`json:"protocol"`
	HostIP			string	`json:"hostIP,omitempty"`
}
type NetworkStatus struct {
	Name		string		`json:"name"`
	Interface	string		`json:"interface,omitempty"`
	IPs			[]string	`json:"ips,omitempty"`
	Mac			string		`json:"mac,omitempty"`
	Default		bool		`json:"default,omitempty"`
	DNS			types.DNS	`json:"dns,omitempty"`
}
type DelegateNetConf struct {
	Conf			types.NetConf
	ConfList		types.NetConfList
	IfnameRequest	string	`json:"ifnameRequest,omitempty"`
	MacRequest		string	`json:"macRequest,omitempty"`
	IPRequest		string	`json:"ipRequest,omitempty"`
	MasterPlugin	bool	`json:"-"`
	ConfListPlugin	bool	`json:"-"`
	Bytes			[]byte
}
type NetworkAttachmentDefinition struct {
	metav1.TypeMeta	`json:",inline"`
	Metadata		metav1.ObjectMeta				`json:"metadata,omitempty" description:"standard object metadata"`
	Spec			NetworkAttachmentDefinitionSpec	`json:"spec"`
}
type NetworkAttachmentDefinitionSpec struct {
	Config string `json:"config"`
}
type NetworkSelectionElement struct {
	Name				string	`json:"name"`
	Namespace			string	`json:"namespace,omitempty"`
	IPRequest			string	`json:"ips,omitempty"`
	MacRequest			string	`json:"mac,omitempty"`
	InterfaceRequest	string	`json:"interface,omitempty"`
}
type K8sArgs struct {
	types.CommonArgs
	IP							net.IP
	K8S_POD_NAME				types.UnmarshallableString
	K8S_POD_NAMESPACE			types.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID	types.UnmarshallableString
}
type ResourceInfo struct {
	Index		int
	DeviceIDs	[]string
}
type ResourceClient interface {
	GetPodResourceMap(*v1.Pod) (map[string]*ResourceInfo, error)
}
