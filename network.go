package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/google/gopacket/pcap"
)

// 网络接口信息结构体
type NetworkInterface struct {
	Name        string // pcap设备名称
	Description string // 网卡描述
	IPAddresses string // IP地址和网段信息
	DisplayName string // 显示名称（用于UI显示）
}

// 获取本地网络接口
func getNetworkInterfaces() []NetworkInterface {
	// 在Windows上使用pcap查找设备
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Printf("查找网络设备错误: %v", err)
		return []NetworkInterface{}
	}

	var interfaces []NetworkInterface
	for _, device := range devices {
		// 过滤掉不活跃
		if device.Description == "" {
			continue
		}

		// 过滤掉回环接口，注意大小写不敏感
		if strings.Contains(strings.ToLower(device.Description), "loopback") {
			continue
		}

		// 获取IP地址信息
		ipInfo := ""
		for _, address := range device.Addresses {
			ipInfo += fmt.Sprintf("%s/%s, ", address.IP.String(), address.Netmask.String())
		}
		if ipInfo != "" {
			ipInfo = ipInfo[:len(ipInfo)-2] // 移除最后的逗号和空格
		}

		// 过滤掉没有IP地址的接口
		if ipInfo == "" {
			continue
		}

		// 创建显示名称
		displayName := fmt.Sprintf("%s [%s]", device.Description, ipInfo)

		interfaces = append(interfaces, NetworkInterface{
			Name:        device.Name,
			Description: device.Description,
			IPAddresses: ipInfo,
			DisplayName: displayName,
		})

	}
	return interfaces
}

// 根据pcap设备名称获取硬件MAC地址（降低嵌套）
func getHardwareAddr(interfaceName string) net.HardwareAddr {
	devices, _ := pcap.FindAllDevs()
	var targetAddrs []string
	for _, device := range devices {
		if device.Name == interfaceName {
			for _, address := range device.Addresses {
				targetAddrs = append(targetAddrs, address.IP.String()+"/"+address.Netmask.String())
			}
			break
		}
	}
	if len(targetAddrs) > 0 {
		interfaces, _ := net.Interfaces()
		for _, iface := range interfaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				for _, ta := range targetAddrs {
					if addr.String() == ta && len(iface.HardwareAddr) > 0 {
						return iface.HardwareAddr
					}
				}
			}
		}
	}
	return net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
}