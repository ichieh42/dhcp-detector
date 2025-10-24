package main

import (
	"fmt"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)


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
			return len(appState.dhcpServers) + 1, 3 // 标题行 + 数据行, 3列
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
