# AstrBot WHOIS 插件

使用 `python-whois` 查询域名 WHOIS 信息，并按中文字段名输出结果。

## 安装

AstrBot 会根据 `metadata.yaml` / `requirements.txt` 安装依赖；如果需要手动安装：

```bash
pip install python-whois
```

## 指令

```text
whois 域名
```

例如：

```text
whois example.com
```

部分平台或 AstrBot 配置可能需要使用命令前缀：

```text
/whois example.com
```
