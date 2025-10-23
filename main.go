package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
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

// 应用状态管理
type AppState struct {
	dhcpServers   map[string]DHCPServer
	stopScan      chan bool
	isScanRunning bool
	resultTable   *widget.Table
	statusLabel   *widget.Label
}

// 创建新的应用状态
func NewAppState() *AppState {
	return &AppState{
		dhcpServers: make(map[string]DHCPServer),
		stopScan:    make(chan bool, 1), // 使用缓冲通道避免阻塞
	}
}

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
		if device.Description != "" && !strings.Contains(device.Description, "Loopback") {
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
	}
	return interfaces
}

// 扫描DHCP服务器
func scanDHCPServers(interfaceName string, resultChan chan<- DHCPServer, stopChan <-chan bool) error {
	handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// 设置过滤器只捕获DHCP包
	err = handle.SetBPFFilter("udp and (port 67 or port 68)")
	if err != nil {
		return err
	}

	// 先发送DHCP请求包
	log.Printf("正在发送DHCP发现请求...")
	err = sendDHCPDiscover(interfaceName)
	if err != nil {
		log.Printf("发送DHCP发现请求失败: %v", err)
		// 即使发送失败，我们仍然尝试捕获可能存在的DHCP服务器响应
	} else {
		log.Printf("DHCP发现请求已发送，等待响应...")
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

				// 解析DHCP包
				// 首先检查是否有UDP层
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer == nil {
					continue
				}

				udp, ok := udpLayer.(*layers.UDP)
				if !ok || udp == nil {
					continue
				}

				// 打印UDP包信息用于调试
				log.Printf("收到UDP包，源端口: %v, 目标端口: %v", udp.SrcPort, udp.DstPort)

				// 确认是从DHCP服务器端口(67)发出的响应包
				if !(udp.SrcPort == 67 && udp.DstPort == 68) {
					log.Printf("忽略非67-68端口的UDP包")
					continue
				}

				// 尝试解析DHCP层
				dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
				if dhcpLayer == nil {
					// 如果没有直接解析到DHCP层，尝试从应用层数据中解析
					applicationLayer := packet.ApplicationLayer()
					if applicationLayer != nil {
						// 打印调试信息
						log.Printf("收到可能的DHCP包，尝试手动解析")

						// 这里可以添加手动解析DHCP包的逻辑
						// 但为了简单起见，我们先尝试使用标准解析
					}
					log.Printf("无法解析应用层数据为DHCP包")
					continue
				}

				dhcp, ok := dhcpLayer.(*layers.DHCPv4)
				if !ok || dhcp == nil {
					log.Printf("无法解析DHCP层")
					continue
				}

				log.Printf("收到DHCP包，操作: %v, 硬件类型: %v, 硬件地址: %v, 客户端IP: %v",
					dhcp.Operation, dhcp.HardwareType, dhcp.ClientHWAddr, dhcp.ClientIP)

				// 检查是否是DHCP Offer或DHCP ACK
				if dhcp.Operation == layers.DHCPOpReply {
					// 打印调试信息
					log.Printf("检测到DHCP回复")

					// 获取服务器IP地址
					var serverIP string

					// 首先尝试从DHCPOptServerID选项获取
					for _, opt := range dhcp.Options {
						if opt.Type == layers.DHCPOptServerID {
							serverIP = net.IP(opt.Data).String()
							log.Printf("从DHCPOptServerID获取服务器IP: %s", serverIP)
							break
						}
					}

					// 如果没有找到，尝试从NextServerIP字段获取
					if serverIP == "" && dhcp.NextServerIP != nil && len(dhcp.NextServerIP) > 0 {
						serverIP = dhcp.NextServerIP.String()
						log.Printf("从NextServerIP获取服务器IP: %s", serverIP)
					}

					// 如果仍然没有找到，尝试从IP层获取源IP
					if serverIP == "" {
						ipLayer := packet.Layer(layers.LayerTypeIPv4)
						if ipLayer != nil {
							ip, ok := ipLayer.(*layers.IPv4)
							if ok && ip != nil {
								serverIP = ip.SrcIP.String()
								log.Printf("从IP层获取服务器IP: %s", serverIP)
							}
						}
					}

					if serverIP != "" {
						// 获取MAC地址
						ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
						var serverMAC string
						if ethernetLayer != nil {
							ethernet, _ := ethernetLayer.(*layers.Ethernet)
							serverMAC = ethernet.SrcMAC.String()
						}

						// 发送结果
						resultChan <- DHCPServer{
							IP:        serverIP,
							MAC:       serverMAC,
							Interface: interfaceName,
							Timestamp: time.Now(),
						}
					}
				}
			}
		}
	}()

	// 添加调试日志
	log.Printf("开始在接口 %s 上扫描DHCP服务器", interfaceName)

	// 发送DHCP发现包
	err = sendDHCPDiscover(interfaceName)
	if err != nil {
		log.Printf("发送DHCP发现包错误: %v", err)
	} else {
		log.Printf("已发送DHCP发现包")
	}

	return nil
}

// 发送DHCP发现包
func sendDHCPDiscover(interfaceName string) error {
	// 在Windows上，interfaceName已经是pcap设备名称，不需要通过net.InterfaceByName获取
	// 但我们仍需要获取MAC地址，使用pcap获取设备信息
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("查找网络设备错误: %v", err)
	}

	// 查找匹配的设备
	var hardwareAddr net.HardwareAddr
	for _, device := range devices {
		if device.Name == interfaceName {
			// 尝试从设备的地址中获取MAC地址
			for _, address := range device.Addresses {
				// 获取该接口的MAC地址
				interfaces, _ := net.Interfaces()
				for _, iface := range interfaces {
					// 检查IP地址是否匹配
					addrs, _ := iface.Addrs()
					for _, addr := range addrs {
						if addr.String() == address.IP.String()+"/"+address.Netmask.String() {
							hardwareAddr = iface.HardwareAddr
							break
						}
					}
					if hardwareAddr != nil {
						break
					}
				}
				if hardwareAddr != nil {
					break
				}
			}
			break
		}
	}

	// 如果无法获取MAC地址，使用随机MAC
	if len(hardwareAddr) == 0 {
		hardwareAddr = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	}

	handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("打开网络适配器错误: %v", err)
	}
	defer handle.Close()

	// 创建以太网层
	eth := layers.Ethernet{
		SrcMAC:       hardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // 广播
		EthernetType: layers.EthernetTypeIPv4,
	}

	// 创建IP层
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(0, 0, 0, 0),
		DstIP:    net.IPv4(255, 255, 255, 255), // 广播
	}

	// 创建UDP层
	udp := layers.UDP{
		SrcPort: 68,
		DstPort: 67,
	}
	udp.SetNetworkLayerForChecksum(&ip)

	// 创建DHCP层
	dhcp := layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		ClientHWAddr: hardwareAddr,
		ClientIP:     net.IPv4(0, 0, 0, 0),
	}

	// 添加DHCP选项
	dhcp.Options = append(dhcp.Options,
		layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}),
		layers.NewDHCPOption(layers.DHCPOptRequestIP, []byte{0, 0, 0, 0}),
		layers.NewDHCPOption(layers.DHCPOptEnd, nil),
	)

	// 序列化数据包
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err = gopacket.SerializeLayers(buffer, opts, &eth, &ip, &udp, &dhcp)
	if err != nil {
		return err
	}

	// 发送数据包
	return handle.WritePacketData(buffer.Bytes())
}

func main() {
	// 创建应用状态
	appState := NewAppState()

	// 创建Fyne应用
	a := app.New()
	w := a.NewWindow("DHCP服务检测器")
	w.Resize(fyne.NewSize(600, 400))

	// 创建界面元素

	// 获取网络接口信息
	interfaces := getNetworkInterfaces()
	var interfaceNames []string
	var interfaceMap = make(map[string]string) // 显示名称到实际设备名称的映射

	for _, iface := range interfaces {
		interfaceNames = append(interfaceNames, iface.DisplayName)
		interfaceMap[iface.DisplayName] = iface.Name
	}

	// 网络接口选择
	interfaceSelect := widget.NewSelect(interfaceNames, func(value string) {})
	if len(interfaceNames) > 0 {
		interfaceSelect.SetSelected(interfaceNames[0])
	}

	// 状态标签
	appState.statusLabel = widget.NewLabel("就绪")

	// 声明变量
	var scanBtn *widget.Button

	// 结果表格
	appState.resultTable = widget.NewTable(
		func() (int, int) {
			return len(appState.dhcpServers) + 1, 4 // 标题行 + 数据行, 4列
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("数据")
		},
		func(id widget.TableCellID, cell fyne.CanvasObject) {
			label := cell.(*widget.Label)

			// 标题行
			if id.Row == 0 {
				switch id.Col {
				case 0:
					label.SetText("IP地址")
				case 1:
					label.SetText("MAC地址")
				case 2:
					label.SetText("网络接口")
				case 3:
					label.SetText("发现时间")
				}
				label.TextStyle = fyne.TextStyle{Bold: true}
				return
			}

			// 数据行
			row := id.Row - 1
			var keys []string
			for k := range appState.dhcpServers {
				keys = append(keys, k)
			}

			if row < len(keys) {
				server := appState.dhcpServers[keys[row]]
				switch id.Col {
				case 0:
					label.SetText(server.IP)
				case 1:
					label.SetText(server.MAC)
				case 2:
					label.SetText(server.Interface)
				case 3:
					label.SetText(server.Timestamp.Format("15:04:05"))
				}
			} else {
				label.SetText("")
			}
		},
	)

	// 设置表格样式
	appState.resultTable.SetColumnWidth(0, 120)
	appState.resultTable.SetColumnWidth(1, 150)
	appState.resultTable.SetColumnWidth(2, 100)
	appState.resultTable.SetColumnWidth(3, 100)

	// 扫描按钮
	scanBtn = widget.NewButton("开始扫描", func() {
		if appState.isScanRunning {
			// 停止扫描
			select {
			case appState.stopScan <- true:
			default:
				// 通道已满，忽略
			}
			appState.isScanRunning = false
			scanBtn.SetText("开始扫描")
			appState.statusLabel.SetText("扫描已停止")
			return
		}

		// 开始扫描
		selectedDisplayName := interfaceSelect.Selected
		if selectedDisplayName == "" {
			dialog.ShowError(fmt.Errorf("请选择网络接口"), w)
			return
		}

		// 获取实际的设备名称
		selectedInterface := interfaceMap[selectedDisplayName]

		// 清空之前的结果
		appState.dhcpServers = make(map[string]DHCPServer)
		appState.resultTable.Refresh()

		// 创建结果通道
		resultChan := make(chan DHCPServer, 10) // 使用缓冲通道

		// 启动扫描
		err := scanDHCPServers(selectedInterface, resultChan, appState.stopScan)
		if err != nil {
			dialog.ShowError(err, w)
			log.Printf("扫描错误: %v", err)
			return
		}

		appState.isScanRunning = true
		scanBtn.SetText("停止扫描")
		appState.statusLabel.SetText("正在扫描...")

		// 处理扫描结果 - 使用事件驱动的UI更新
		go func() {
			defer func() {
				// 扫描结束时重置状态
				fyne.Do(func() {
					appState.isScanRunning = false
					scanBtn.SetText("开始扫描")
					if len(appState.dhcpServers) == 0 {
						appState.statusLabel.SetText("未发现DHCP服务器")
					}
				})
			}()

			for server := range resultChan {
				// 在主线程中安全地更新数据和UI
				fyne.Do(func() {
					appState.dhcpServers[server.IP] = server
					appState.resultTable.Refresh()
					appState.statusLabel.SetText(fmt.Sprintf("已发现 %d 个DHCP服务器", len(appState.dhcpServers)))
				})
			}
		}()
	})

	// 布局
	topContent := container.NewVBox(
		container.NewGridWithColumns(2,
			widget.NewLabel("选择网络接口:"),
			interfaceSelect,
		),
		scanBtn,
		widget.NewLabel("发现的DHCP服务器:"),
	)

	// 使表格占据窗口的大部分空间
	tableContainer := container.New(layout.NewStackLayout(), appState.resultTable)

	// 底部状态栏
	bottomContent := container.NewHBox(layout.NewSpacer(), appState.statusLabel)

	// 使用BorderLayout让表格自动填充中间区域
	content := container.New(layout.NewBorderLayout(
		topContent, bottomContent, nil, nil),
		topContent, tableContainer, bottomContent,
	)

	w.SetContent(content)
	w.ShowAndRun()
}
