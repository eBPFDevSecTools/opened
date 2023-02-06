package main

import (
    "fmt"
    "flag"
    "time"
    "path/filepath"
    "net"
    "errors"
    "encoding/binary"

    "k8s.io/api/core/v1"
    "k8s.io/apimachinery/pkg/util/wait"
    "k8s.io/apimachinery/pkg/labels"
    "k8s.io/client-go/informers"
    client_go_v1 "k8s.io/client-go/informers/core/v1"
    "k8s.io/client-go/kubernetes"
    "k8s.io/client-go/tools/clientcmd"
    "k8s.io/client-go/tools/cache"
    "k8s.io/client-go/util/homedir"
    "k8s.io/client-go/rest"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/rlimit"
)

type map_key struct {
    IP [4]byte
    Port int32
}

type map_value struct {
    IP [4]byte
    Port int32
}

func monitorEndpoints(informerFactory informers.SharedInformerFactory, endpoints map[string]*v1.Endpoints) {

    // Starts serviceInformer so we can query services more efficiently
    serviceInformer := informerFactory.Core().V1().Services()
    serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc: func(new interface{}) {
        },
        UpdateFunc: func(old, new interface{}) {
        },
        DeleteFunc: func(obj interface{}) {
        },
    })

    // Starts endpointInformer so we can handle endpoint events
    endpointInformer := informerFactory.Core().V1().Endpoints()
    endpointInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
        AddFunc: func(new interface{}) {
            //fmt.Println("Addfunc")
            endpoint := new.(*v1.Endpoints)
            namespace := endpoint.ObjectMeta.Namespace
            name := endpoint.ObjectMeta.Name
            key := namespace + ":" + name
            if _, ok := endpoints[key]; ok {
                // This endpoint already exists
                //fmt.Printf("Adding an endpoint %s that already exists\n", key)
                return
            }
            endpoints[key] = endpoint
            // This call usually returns as endpoint.Subsets is usually empty at this time
            addEndpointToMap(endpoint, serviceInformer)
        },
        UpdateFunc: func(old, new interface{}) {
            //fmt.Println("Updatefunc")
            o := old.(*v1.Endpoints)
            n := new.(*v1.Endpoints)
            if (len(o.Subsets) != len(n.Subsets)) {
                //fmt.Printf("old: %s\n", o)
                //fmt.Printf("new: %s\n", n)
                key := o.ObjectMeta.Namespace + ":" + o.ObjectMeta.Name
                endpoints[key] = n
                deleteEndpointFromMap(o, serviceInformer)
                addEndpointToMap(n, serviceInformer)
            }
        },
        DeleteFunc: func(obj interface{}) {
            //fmt.Println("Deletefunc")
            // This is not very useful as endpoint.Subsets is empty at this point
            endpoint := obj.(*v1.Endpoints)
            namespace := endpoint.ObjectMeta.Namespace
            name := endpoint.ObjectMeta.Name
            key := namespace + ":" + name
            delete(endpoints, key)
            deleteEndpointFromMap(endpoint, serviceInformer)
        },
    })

    informerFactory.Start(wait.NeverStop)
    informerFactory.WaitForCacheSync(wait.NeverStop)

    current, err := endpointInformer.Lister().Endpoints("").List(labels.Everything())
    if (err == nil) {
        for _, c := range current {
            namespace := c.ObjectMeta.Namespace
            name := c.ObjectMeta.Name
            key := namespace + ":" + name
            endpoints[key] = c
            addEndpointToMap(c, serviceInformer)
        }
    } else {
        panic(err.Error())
    }
}

func ntohl(i uint32) uint32 {
    b := make([]byte, 4)
    binary.BigEndian.PutUint32(b, i)
    return binary.LittleEndian.Uint32(b)
}

func htonl(i uint32) uint32 {
    b := make([]byte, 4)
    binary.LittleEndian.PutUint32(b, i)
    return binary.BigEndian.Uint32(b)
}

func htons(i uint16) uint16 {
    b := make([]byte, 2)
    binary.LittleEndian.PutUint16(b, i)
    return binary.BigEndian.Uint16(b)
}

func addEndpointToMap(endpoint *v1.Endpoints, serviceInformer client_go_v1.ServiceInformer) {
    //fmt.Println("addEndpointToMap")
    service, err := serviceInformer.Lister().Services(endpoint.ObjectMeta.Namespace).Get(endpoint.ObjectMeta.Name)
    if (err != nil) {
        return
    }

    servicePorts := service.Spec.Ports
    if (len(servicePorts) == 0) {
        return
    }

    serviceIP := net.ParseIP(service.Spec.ClusterIP)
    if (serviceIP == nil) {
        return
    }

    subsets := endpoint.Subsets
    if (subsets == nil) {
        return
    }

    path := filepath.Join("/sys/fs/bpf", "endpoints_to_service_map")
    m, err := ebpf.LoadPinnedMap(path, nil)
    if (err != nil) {
        panic(err.Error())
    }
    defer m.Close()

    // Populate endpoints_to_service_map
    for _, subset := range subsets {
        addresses := subset.Addresses
        if (addresses == nil) {
            continue
        }

        for _, address := range addresses {
            podIP := net.ParseIP(address.IP)

            for _, port := range servicePorts {
                // We only handle TCP and TCP is default if the Protocol field is not specified
                if (port.Protocol != "" && port.Protocol != "TCP") {
                    continue
                }

                servicePort := port.Port
                // TODO: TargetPort could be an name, for now we assume it is a number
                podPort := int32(port.TargetPort.IntValue())

                var podIPKey [4]byte
                // Pod IP is already in network byte order
                copy(podIPKey[:], podIP.To4())
                // Convert pod port to network byte order
                q := htons(uint16(podPort))

                key := map_key{IP: podIPKey, Port: int32(q)}
                var value map_value;
                err := m.Lookup(key, &value)
                var serviceIPKey [4]byte
                // Service IP is already in network byte order
                copy(serviceIPKey[:], serviceIP.To4())
                if errors.Is(err, ebpf.ErrKeyNotExist) {
                    // Convert service port to network order
                    p := htons(uint16(servicePort))

                    value := map_value{IP: serviceIPKey, Port: int32(p)}
                    err = m.Put(key, value)
                    if (err != nil) {
                        panic(err.Error())
                    }
                    fmt.Printf("(+) %s:%d -> %s:%d\n", podIP, podPort, serviceIP, servicePort)
                } else {
                    fmt.Printf("(.) key already exists and cannot be added: %s:%d\n", podIP, podPort)
                }
            }
        }
    }
    return
}

func deleteEndpointFromMap(endpoint *v1.Endpoints, serviceInformer client_go_v1.ServiceInformer) {
    //fmt.Println("deleteEndpointFromMap")
    service, err := serviceInformer.Lister().Services(endpoint.ObjectMeta.Namespace).Get(endpoint.ObjectMeta.Name)
    if (err != nil) {
        return
    }

    servicePorts := service.Spec.Ports
    if (len(servicePorts) == 0) {
        return
    }

    serviceIP := net.ParseIP(service.Spec.ClusterIP)
    if (serviceIP == nil) {
        return
    }

    subsets := endpoint.Subsets
    if (subsets == nil) {
        return
    }

    path := filepath.Join("/sys/fs/bpf", "endpoints_to_service_map")
    m, err := ebpf.LoadPinnedMap(path, nil)
    if (err != nil) {
        panic(err.Error())
    }
    defer m.Close()

    // Delete from endpoints_to_service_map
    for _, subset := range subsets {
        addresses := subset.Addresses
        if (addresses == nil) {
            continue
        }

        for _, address := range addresses {
            podIP := net.ParseIP(address.IP)
            
            for _, port := range servicePorts {
                // We only handle TCP and TCP is default if the Protocol field is not specified
                if (port.Protocol != "" && port.Protocol != "TCP") {
                    continue
                }

                // TODO: TargetPort could be an name, for now we assume it is a number
                podPort := int32(port.TargetPort.IntValue())
                // Convert pod port to network order
                p := htons(uint16(podPort))

                var podIPKey [4]byte
                copy (podIPKey[:], podIP.To4())
                key := map_key{IP: podIPKey, Port: int32(p)}
                err := m.Delete(key)
                if errors.Is(err, ebpf.ErrKeyNotExist) {
                    fmt.Printf("(.) key doesn't exist and cannot be deleted: %s:%d\n", podIP, podPort)
                } else {
                    fmt.Printf("(-) %s:%d\n", podIP, podPort)
                }
            }
        }
    }
    return
}

func printEndpoints(endpoints map[string]*v1.Endpoints) {
    for {
        for key, value:= range endpoints {
            fmt.Printf("%s: %s\n", key, value)
        }
        time.Sleep(5*time.Second)
    }
}

func StartController() {
    rlimit.RemoveMemlock()
    var kubeconfig *string
    if home := homedir.HomeDir(); home != "" {
        kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
    } else {
        kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file") }
    flag.Parse()

    config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
    if err != nil {
        config, err = rest.InClusterConfig()
        if err != nil {
            panic(err.Error())
        }
    }

    clientset, err := kubernetes.NewForConfig(config)
    if err != nil {
        panic(err.Error())
    }

    informerFactory := informers.NewSharedInformerFactory(clientset, 10*time.Second)

    endpoints := make(map[string]*v1.Endpoints)
    go monitorEndpoints(informerFactory, endpoints)
    //go printEndpoints(endpoints)

    for {
        time.Sleep(time.Duration(1<<63 - 1))
    }
}
