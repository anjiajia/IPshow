# IP 批量归属地查询工具

本项目是一个本地可视化脚本，支持：

- 导入 `TXT / CSV / XLS / XLSX` IP 列表
- 批量查询 IP 地址归属地
- 页面中直接预览查询结果
- 导出 `Excel` 或 `CSV`

## 启动方式

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

启动后，浏览器会自动打开本地页面。

## 文件格式

- `TXT`：支持换行、英文逗号、中文逗号、分号分隔
- `CSV / XLS / XLSX`：会读取所有单元格中的非空值并自动识别 IP

## 说明

- 当前版本通过 `ip-api` 进行批量查询
- 应用会自动校验 IP、去重并分批请求
- 如果外网不可用或接口限流，查询会失败，需要稍后重试
