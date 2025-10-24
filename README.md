# DHCP Detector

DHCP 服务器探测工具，用于发现网络中的 DHCP 服务器（包括小型路由器）。

## 功能特性

- 自动扫描本地网络接口
- 同时支持 DHCPv4 和 DHCPv6 服务器探测
- 发送 DHCPv4 Discover 和 DHCPv6 Solicit 请求
- 实时显示发现的 DHCP 服务器信息
- 简洁直观的图形用户界面

## 安装要求

- Go 1.16 或更高版本（仅构建需要）

## 使用方法

1. 从 Release 页面下载最新版本
2. 运行 `dhcp-detector.exe`
3. 在下拉菜单中选择网络接口
4. 点击"开始扫描"按钮
5. 在表格中查看发现的 DHCP 服务器

## 构建指南

```bash
# 克隆仓库
cd dhcp-detector

# 构建项目
go build

# 或使用提供的批处理脚本（Windows）
windows.cmd
```

## 项目结构

- `main.go` - 用户界面和应用程序入口
- `network.go` - 网络接口相关功能
- `dhcp.go` - DHCP 协议实现和数据包处理
- `windows.cmd` - Windows 构建脚本
