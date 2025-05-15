# 域名和IP查询工具

## 项目概述

域名和IP查询工具是一个功能强大的命令行工具，用于查询域名信息和IP地址关联数据。该工具可以：

- 查询域名的WHOIS信息、DNS记录、SSL证书状态和关联IP地址
- 反向查询IP地址关联的所有域名
- 自动从URL中提取域名进行查询
- 提供清晰、彩色的结果显示

## 主要功能

- **域名查询**：获取域名的详细信息，包括：
  - WHOIS信息（注册商、创建时间、到期时间等）
  - DNS记录（A、AAAA、MX、NS、TXT、CNAME）
  - SSL证书状态
  - 关联的IP地址（通过VirusTotal API或DNS记录）

- **IP反查**：查询IP地址关联的所有域名（通过VirusTotal API）

## 前置条件

- Python 3.6+
- 以下Python库：
  - whois
  - dnspython
  - requests
  - colorama
  - datetime

## 安装方法

1. 克隆或下载本项目代码
2. 安装所需依赖：

```bash
pip install python-whois dnspython requests colorama
```

## 运行方法

直接运行主脚本：

```bash
python domain_ip_tool.py
```

按照提示输入域名、URL或IP地址进行查询。输入`exit`退出程序。

## 使用示例

### 查询域名信息

输入域名（如`example.com`）或URL（如`https://example.com/page`），工具会自动提取域名并显示其WHOIS信息、DNS记录、SSL状态和关联IP地址。

### 查询IP关联域名

输入IP地址（如`8.8.8.8`），工具会显示与该IP关联的所有域名。

## API密钥

本工具使用VirusTotal API进行部分查询。默认包含一个API密钥，但建议用户替换为自己的API密钥以避免限制。

修改方法：打开`domain_ip_tool.py`文件，找到`self.vt_api_key`变量并替换为您自己的VirusTotal API密钥。

## 注意事项

- 查询结果依赖于VirusTotal API和DNS服务的响应
- 部分查询可能受到API限制或网络条件影响
- 请合理使用，避免频繁查询导致API限制

## 许可证

MIT许可证

## 免责声明

本工具仅供安全研究和网络管理使用，请勿用于非法目的。使用本工具产生的任何后果由用户自行承担。
