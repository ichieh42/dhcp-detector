package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// DHCPServer 结构体用于存储DHCP服务器信息
type DHCPServer struct {
	IP        string
	MAC       string
	Interface string
	Timestamp time.Time
}

// 扫描DHCP服务器
func scanDHCPServers(interfaceName string, resultChan chan<- DHCPServer, stopChan <-chan bool) error {
	handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// 设置过滤器只捕获DHCPv4和DHCPv6包
	err = handle.SetBPFFilter("udp and (port 67 or port 68 or port 546 or port 547)")
	if err != nil {
		return err
	}

	// 先发送DHCPv4和DHCPv6请求包
	log.Printf("正在发送DHCPv4发现请求...")
	err = sendDHCPDiscover(interfaceName)
	if err != nil {
		log.Printf("发送DHCPv4发现请求失败: %v", err)
		// 即使发送失败，我们仍然尝试捕获可能存在的DHCP服务器响应
	} else {
		log.Printf("DHCPv4发现请求已发送，等待响应...")
	}

	log.Printf("正在发送DHCPv6 Solicitate 请求...")
	err = sendDHCPv6Solicit(interfaceName)
	if err != nil {
		log.Printf("发送DHCPv6 Solicitate 请求失败: %v", err)
	} else {
		log.Printf("DHCPv6 Solicitate 请求已发送，等待响应...")
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	go func() {
		defer close(resultChan) // 确保在退出时关闭结果通道
		for {
			select {
			case <-stopChan:
				return
			case packet, ok := <-packetSource.Packets():
				// 检查channel是否已关闭或packet是否为nil
				if !ok || packet == nil {
					continue
				}

				// 首先检查是否有UDP层
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer == nil {
					continue
				}
				udp, ok := udpLayer.(*layers.UDP)
				if !ok || udp == nil {
					continue
				}

				log.Printf("收到UDP包，源端口: %v, 目标端口: %v", udp.SrcPort, udp.DstPort)

				// 更平坦的处理逻辑
				if server, ok := processDHCPv4Packet(packet, interfaceName); ok {
					resultChan <- server
					continue
				}
				if server, ok := processDHCPv6Packet(packet, interfaceName); ok {
					resultChan <- server
					continue
				}
				continue
			}
		}
	}()

	log.Printf("开始在接口 %s 上扫描DHCP服务器 (IPv4/IPv6)", interfaceName)

	// 发送DHCPv4发现包
	err = sendDHCPDiscover(interfaceName)
	if err != nil {
		log.Printf("发送DHCPv4发现包错误: %v", err)
	} else {
		log.Printf("已发送DHCPv4发现包")
	}

	// 发送DHCPv6 Solicitate
	err = sendDHCPv6Solicit(interfaceName)
	if err != nil {
		log.Printf("发送DHCPv6 Solicitate 错误: %v", err)
	} else {
		log.Printf("已发送DHCPv6 Solicitate")
	}

	return nil
}

// 发送DHCPv4发现包
func sendDHCPDiscover(interfaceName string) error {
	// 在Windows上，interfaceName已经是pcap设备名称；直接获取MAC地址
	hardwareAddr := getHardwareAddr(interfaceName)

	handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("打开网络适配器错误: %v", err)
	}
	defer handle.Close()

	eth := layers.Ethernet{
		SrcMAC:       hardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(0, 0, 0, 0), DstIP: net.IPv4(255, 255, 255, 255)}
	udp := layers.UDP{SrcPort: 68, DstPort: 67}
	udp.SetNetworkLayerForChecksum(&ip)
	dhcp := layers.DHCPv4{Operation: layers.DHCPOpRequest, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6, ClientHWAddr: hardwareAddr, ClientIP: net.IPv4(0, 0, 0, 0)}
	dhcp.Options = append(dhcp.Options,
		layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}),
		layers.NewDHCPOption(layers.DHCPOptRequestIP, []byte{0, 0, 0, 0}),
		layers.NewDHCPOption(layers.DHCPOptEnd, nil),
	)
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buffer, opts, &eth, &ip, &udp, &dhcp); err != nil {
		return err
	}
	return handle.WritePacketData(buffer.Bytes())
}

// 发送DHCPv6 Solicitate
func sendDHCPv6Solicit(interfaceName string) error {
	hardwareAddr := getHardwareAddr(interfaceName)
	handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("打开网络适配器错误(IPv6): %v", err)
	}
	defer handle.Close()

	eth := layers.Ethernet{SrcMAC: hardwareAddr, DstMAC: net.HardwareAddr{0x33, 0x33, 0x00, 0x01, 0x00, 0x02}, EthernetType: layers.EthernetTypeIPv6}
	ip6 := layers.IPv6{Version: 6, HopLimit: 255, SrcIP: net.ParseIP("::"), DstIP: net.ParseIP("ff02::1:2")}
	udp := layers.UDP{SrcPort: 546, DstPort: 547}
	udp.SetNetworkLayerForChecksum(&ip6)
	txid := make([]byte, 3)
	_, _ = rand.Read(txid)
	dhcp6 := layers.DHCPv6{MsgType: 1, TransactionID: txid}
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buffer, opts, &eth, &ip6, &udp, &dhcp6); err != nil {
		return err
	}
	return handle.WritePacketData(buffer.Bytes())
}

// 从数据包中提取源MAC地址
func findSrcMAC(packet gopacket.Packet) string {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return ""
	}
	ethernet, _ := ethernetLayer.(*layers.Ethernet)
	if ethernet == nil {
		return ""
	}
	return ethernet.SrcMAC.String()
}

// 提取DHCPv4服务器IP
func findDHCPv4ServerIP(packet gopacket.Packet, dhcp *layers.DHCPv4) string {
	for _, opt := range dhcp.Options {
		if opt.Type == layers.DHCPOptServerID {
			return net.IP(opt.Data).String()
		}
	}
	if dhcp.NextServerIP != nil && len(dhcp.NextServerIP) > 0 {
		return dhcp.NextServerIP.String()
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		if ip, ok := ipLayer.(*layers.IPv4); ok && ip != nil {
			return ip.SrcIP.String()
		}
	}
	return ""
}

// 处理DHCPv4数据包
func processDHCPv4Packet(packet gopacket.Packet, interfaceName string) (DHCPServer, bool) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return DHCPServer{}, false
	}
	udp, ok := udpLayer.(*layers.UDP)
	if !ok || udp == nil || !(udp.SrcPort == 67 && udp.DstPort == 68) {
		return DHCPServer{}, false
	}
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer == nil {
		return DHCPServer{}, false
	}
	dhcp, ok := dhcpLayer.(*layers.DHCPv4)
	if !ok || dhcp == nil || dhcp.Operation != layers.DHCPOpReply {
		return DHCPServer{}, false
	}
	serverIP := findDHCPv4ServerIP(packet, dhcp)
	if serverIP == "" {
		return DHCPServer{}, false
	}
	mac := findSrcMAC(packet)
	return DHCPServer{IP: serverIP, MAC: mac, Interface: interfaceName, Timestamp: time.Now()}, true
}

// 处理DHCPv6数据包
func processDHCPv6Packet(packet gopacket.Packet, interfaceName string) (DHCPServer, bool) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return DHCPServer{}, false
	}
	udp, ok := udpLayer.(*layers.UDP)
	if !ok || udp == nil || !(udp.SrcPort == 547 && udp.DstPort == 546) {
		return DHCPServer{}, false
	}
	dhcp6Layer := packet.Layer(layers.LayerTypeDHCPv6)
	if dhcp6Layer == nil {
		return DHCPServer{}, false
	}
	dhcp6, ok := dhcp6Layer.(*layers.DHCPv6)
	if !ok || dhcp6 == nil {
		return DHCPServer{}, false
	}
	// 2: Advertise, 7: Reply
	if dhcp6.MsgType != 2 && dhcp6.MsgType != 7 {
		return DHCPServer{}, false
	}
	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer == nil {
		return DHCPServer{}, false
	}
	ip6, ok := ip6Layer.(*layers.IPv6)
	if !ok || ip6 == nil {
		return DHCPServer{}, false
	}
	mac := findSrcMAC(packet)
	return DHCPServer{IP: ip6.SrcIP.String(), MAC: mac, Interface: interfaceName, Timestamp: time.Now()}, true
}
