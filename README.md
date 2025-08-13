# WHOIS插件

## 安装步骤

1. 安装插件后，请前往控制台页面安装以下pip扩展:
   ```
   pip install python-whois
   ```
   
   **注意**: 不需要同时安装 `whois` 和 `python-whois`，只需要安装 `python-whois` 即可。

2. 如果使用docker安装的astrbot，请使用以下命令在容器内安装依赖:
   ```
   docker exec -it 你的容器名称 pip install python-whois
   ```
   然后重启容器:
   ```
   docker restart 你的容器名称
   ```

3. 如果安装后仍然遇到错误，请尝试以下命令:
   ```
   pip uninstall python-whois
   pip install python-whois --force-reinstall
   ```

## 常见问题排查

1. 如果遇到 `ModuleNotFoundError: No module named 'whois'` 错误:
   - 确认已经正确安装了 `python-whois` 包
   - 确认安装后已重启 astrbot 或 astrbot 容器
   - 检查 pip 是否安装到了正确的 Python 环境

2. 如果遇到 `TypeError: Cannot read properties of null (reading 'name')` 错误:
   - 这通常是因为查询结果为空或格式不正确
   - 尝试查询其他域名，如 `google.com` 或 `baidu.com`
   - 检查网络连接是否正常

# 指令

/whois 域名

例如

/whois fis.ink

更新请先卸载

好用就点个🌟吧 https://github.com/fishcpy/astrbot_plugin_whois

由克劳德4在2小时内完成主要开发和BUG修复

插件 BY Fishcpy , 翻译 BY AcoFork