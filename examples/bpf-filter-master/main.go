package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
)

const MAXLEN = 2000

// ifindex,mac address mapping for the interfaces
type entry struct {
	ifIdx uint32
	mac   net.HardwareAddr
	ip    uint32
}

// cntPkt resembles cntPkt in ebpf kernel code
type cntPkt struct {
	drop uint32
	pass uint32
}

type statEntry struct {
	ifIdx uint32
	count cntPkt
}

func Ip2long(ipAddr string) (uint32, error) {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return 0, errors.New("wrong ipAddr format")
	}
	ip = ip.To4()
	return binary.LittleEndian.Uint32(ip), nil
}

func Long2ip(ipLong uint32) string {
	ipByte := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipByte, ipLong)
	ip := net.IP(ipByte)
	return ip.String()
}

func initializeStatsMap(m *ebpf.Map, entries []uint32) error {
	fmt.Printf("initStatsMap : Info: %v keysize: %v valueSize: %v", m.String(), m.KeySize(), m.ValueSize())
	for _, entry := range entries {
		cntPkt := cntPkt{drop: 0, pass: 0}
		err := m.Put(entry, (cntPkt))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return err
		}
	}
	return nil
}

func makeEntry(ifIdx uint32, mac net.HardwareAddr, ip uint32) *entry {
	var en entry
	en.ifIdx = ifIdx
	en.mac = mac
	en.ip = ip
	fmt.Printf("created an entry with id %v, mac %s, ip %v\n", ifIdx, mac, ip)
	return &en
}

func getAllMACs() ([]entry, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	entries := []entry{}
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" {
			fmt.Printf("ifIndex: %v macAddr: %v size_mac: %d\n",
				ifa.Index, ifa.HardwareAddr, int(unsafe.Sizeof(ifa.HardwareAddr)))
			e := makeEntry(uint32(ifa.Index), ifa.HardwareAddr, 0)
			entries = append(entries, *e)
		}
	}
	return entries, nil
}

func getInterface(idx int) (*net.Interface, error) {
	ifa, err := net.InterfaceByIndex(idx)
	if err != nil {
		fmt.Printf("Error: %v", err.Error())
		return nil, err
	}
	return ifa, nil
}

// Returns indices of interfaces
func getAllIfaceIndices() ([]uint32, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	entries := []uint32{}
	for _, ifa := range ifas {
		a := ifa.HardwareAddr.String()
		if a != "" {
			fmt.Printf("ifIndex: %v macAddr: %v size_mac: %d\n",
				ifa.Index, ifa.HardwareAddr, int(unsafe.Sizeof(ifa.HardwareAddr)))
			entries = append(entries, uint32(ifa.Index))
		}
	}
	return entries, nil

}

// This will overwrite previous entry if any
func addEntryMacMap(m *ebpf.Map, entries []entry, rand int) error {
	for _, ifa := range entries {
		err := m.Put(ifa.ifIdx+uint32(rand), []byte(ifa.mac))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return err
		}
	}
	return nil
}

// This will overwrite previous entry if any
func addEntryIpMap(m *ebpf.Map, entries []entry, rand int) error {
	for _, ifa := range entries {
		err := m.Put(ifa.ifIdx+uint32(rand), ifa.ip)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return err
		}
	}
	return nil
}

// This will ignore missing entries and always return success
func delEntryMap(m *ebpf.Map, keys []interface{}) error {
	for _, ifa := range keys {
		var err error
		switch ifa.(type) {
		case uint32:
			err = m.Delete(ifa.(uint32))
		case string:
			err = m.Delete(ifa.(string))
		}
		fmt.Printf("[delMap] ifIdx: %v\n", ifa)
		if err != nil {
			fmt.Printf("[delMap] Warn: %v\n", err)
		}
	}
	return nil
}

func createArray(maxEntries int, keySize int, valueSize int) (*ebpf.Map, error) {
	fmt.Printf("KeySize: %d ValueSize: %d MaxEntries: %d\n", keySize, valueSize, maxEntries)
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(keySize),
		ValueSize:  uint32(valueSize),
		MaxEntries: uint32(maxEntries),
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

func pinMap(m *ebpf.Map, path string) error {
	if err := m.Pin(path); err != nil {
		m.Close()
		//fmt.Printf("[pinMap] Error! pin map: %s\n", err)
		return err
	}
	return nil
}

func closeMap(m *ebpf.Map) error {
	return m.Close()
}

func getMap(path string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(path)
}

func pinOrGetMap(path string, m *ebpf.Map) (*ebpf.Map, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err = pinMap(m, path)
		if err != nil {
			//fmt.Printf("Error! PinOrGetMap map: %s\n", err)
			return m, err
		}
		return m, nil
	} else {
		temp, err := getMap(path)
		if err != nil {
			//fmt.Printf("Error! PinOrGetMap map: %s\n", err)
			return m, err
		}
		return temp, nil
	}
}

// We are not unpinning the map XXX
// We should Freeze() userspace to avoid maniplulation XXX
// Userspace should keep updating interfaces when they come and go down? So dont freeze()?? XXX
func main() {

	var mode string
	var idx int
	var pod_mac string
	var pod_ip uint32
	var arg_ip string

	flag.StringVar(&mode, "mode", "init", "Mode can be init or add")
	flag.IntVar(&idx, "idx", 0, "iface index where tc hook is attached")
	flag.StringVar(&pod_mac, "pod_mac", "invalid", "MAC address which is allowed to pass through idx")
	flag.StringVar(&arg_ip, "pod_ip", "invalid", "IP address of pod which is allowed to pass through idx")

	flag.Parse()
	fmt.Printf("Arguments - mode: %v idx: %v pod_mac: %v pod_ip: %v\n", mode, idx, pod_mac, arg_ip)

	pod_ip, err := Ip2long(arg_ip)
	if err != nil {
		fmt.Printf("Error while converting %s to ip address", arg_ip)
		fmt.Println(err)
		return
	}

	mapPathDir := "/sys/fs/bpf/tc/globals/"
	ifaceMacMapPath := "/sys/fs/bpf/tc/globals/iface_map"
	ifaceIpMapPath := "/sys/fs/bpf/tc/globals/iface_ip_map"
	countMapPath := "/sys/fs/bpf/tc/globals/iface_stat_map"

	var ip_map *ebpf.Map
	var mac_map *ebpf.Map
	var m *ebpf.Map
	var stats_map *ebpf.Map

	var en entry
	var ct cntPkt
	err = os.MkdirAll(mapPathDir, os.ModePerm)
	if err != nil {
		fmt.Printf("Error while creating the directory %s", err)
		return
	}

	mac_map, err = createArray(MAXLEN,
		//len(macArr),
		int(unsafe.Sizeof(en.ifIdx)),
		//int(unsafe.Sizeof(en.mac)))
		6)
	if err != nil {
		fmt.Printf("Create Map returned error %s\n", err)
		return
	}
	mac_map, err = pinOrGetMap(ifaceMacMapPath, mac_map)
	if err != nil {
		fmt.Printf("Error! create map: %s\n", err)
		return
	}

	ip_map, err = createArray(MAXLEN,
		int(unsafe.Sizeof(en.ifIdx)),
		4)
	if err != nil {
		fmt.Printf("Create Map returned error %s\n", err)
		return
	}
	ip_map, err = pinOrGetMap(ifaceIpMapPath, ip_map)
	if err != nil {
		fmt.Printf("Error! create map: %s\n", err)
		return
	}

	stats_map, err = createArray(MAXLEN, int(unsafe.Sizeof(en.ifIdx)), int(unsafe.Sizeof(ct)))
	stats_map, err = pinOrGetMap(countMapPath, stats_map)
	if err != nil {
		fmt.Printf("Error! create map: %s\n", err)
		return
	}

	switch mode {
	case "init":
		macArr, err := getAllMACs()
		if err != nil || len(macArr) == 0 {
			return
		}
		err = addEntryMacMap(mac_map, macArr, 0)
		if err != nil {
			fmt.Printf("Error! populating map: %s\n", err)
			return
		}
		ifaceIndices, err := getAllIfaceIndices()
		initializeStatsMap(stats_map, ifaceIndices)
	case "add":
		ifa, err := getInterface(idx)
		if err != nil {
			fmt.Printf("Could not get interface %v\n", err.Error())
			os.Exit(1)
		}
		entries := []entry{}

		hwa, err := net.ParseMAC(pod_mac)
		if err != nil {
			hwa = ifa.HardwareAddr
		}
		e := makeEntry(uint32(ifa.Index), hwa, pod_ip)
		entries = append(entries, *e)
		err = addEntryMacMap(mac_map, entries, 0)
		if err != nil {
			fmt.Printf("Error! populating map: %s\n", err)
			return
		}
		err = addEntryIpMap(ip_map, entries, 0)
		if err != nil {
			fmt.Printf("Error! populating map: %s\n", err)
			return
		}

		//Initialize stats maps for idx
		cntPkt := cntPkt{drop: 0, pass: 0}
		err = stats_map.Put(uint32(ifa.Index), (cntPkt))
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
	}

	err = closeMap(m)
	if err != nil {
		fmt.Printf("Error! closing map: %s\n", err)
		return
	}

	return
}
