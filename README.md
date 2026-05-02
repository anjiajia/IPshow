# IP 批量归属地查询工具

本项目是一个本地可视化脚本，支持：

- 导入 `TXT / CSV / XLS / XLSX` IP 列表
- 支持 **CIDR 网段**（如 `192.168.1.0/24`）自动展开
- 批量查询 IP 地址归属地
- 切换查询数据源
- 可选接入恶意 IP 风险检测
- 页面中直接预览查询结果
- **数据可视化**：国家/运营商分布、地图展示
- **历史记录**：自动保存查询结果，支持加载和对比
- **配置持久化**：Token 等设置自动保存，重启不丢失
- 导出 `Excel` 或 `CSV`

## 启动方式

### 本地启动

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

启动后，浏览器会自动打开本地页面。

### Docker 启动

```bash
docker build -t ipshow .
docker run -d -p 8501:8501 --name ipshow ipshow
```

然后访问 http://localhost:8501。

## 文件格式

- `TXT`：支持换行、英文逗号、中文逗号、分号分隔
- `CSV / XLS / XLSX`：会读取所有单元格中的非空值并自动识别 IP
- **CIDR**：支持 `192.168.1.0/24` 等网段格式，自动展开为单个 IP（上限 1024 个）

## 查询数据源

- 推荐：`IPIP`
  - 中国厂商，中文字段更完整
  - 更适合中国网络环境
  - 需要 `Token`
- 默认：`自动`
  - 已填写 `IPIP Token` 时优先使用 `IPIP`
  - 如果失败，会自动回退到 `ip-api` 和 `IP.SB`
  - 适合当前这类国内外网络环境不稳定的情况
- 可选：`IP.SB`
  - 使用 `HTTPS`
  - 在部分环境比 `ip-api` 更稳定
  - 结果以英文为主，国家名称会尽量转成中文
  - 免费接口按单个 IP 查询，批量时会逐条请求
- 可选：`ip-api`
  - 免费版仅支持 `HTTP`
  - 支持批量接口
  - 在中国大陆网络环境下可能不稳定

## 恶意 IP 检测

- 应用支持优先接入 `IPIP` 风险画像接口
- 需要你在页面侧边栏填写自己的 `IPIP 风险画像 Token`
- 结果中会直接显示 `恶意IP` 列
- 当前默认规则：
  - `风险分 >= 90` 记为 `恶意IP = 是`
  - `风险分 < 90` 记为 `恶意IP = 否`
- 同时会附加这些字段：
  - `风险等级`
  - `风险分`
  - `风险行为`
  - `IP类型`
- 也保留了 `AbuseIPDB` 作为国际备用方案
- 启用后会附加这些字段：
  - `近90天举报次数`
  - `最近举报时间`
  - `使用类型`
  - `域名`

## 配置持久化

- 在侧边栏填写 Token 和选择数据源后，点击 **"保存当前配置"**
- 配置会保存到本地 `.ipshow_config.json`
- 下次启动应用时会自动加载，无需重新输入

## 查询历史与对比

- 每次查询结果会自动保存到 `.ipshow_history/`
- 最多保留最近 **50 条** 历史记录
- 在侧边栏可加载任意历史记录
- 在结果页面的 **"结果对比"** 中，可与历史记录进行对比：
  - 查看新增/移除/字段变化的 IP

## 数据可视化

查询结果页面提供可视化看板：

- **国家/地区分布**：Top 10 国家柱状图
- **运营商分布**：Top 10 运营商柱状图
- **查询状态分布**：成功/失败统计
- **恶意 IP 分布**：风险统计
- **地理分布地图**：基于经纬度的散点地图

## 测试

项目已集成 `pytest` 单元测试，覆盖核心逻辑和 API mock：

```bash
pytest tests/ -v
```

测试内容包括：
- IP 解析与 CIDR 展开
- IP 校验与去重
- 各数据源的批量查询（mock）
- 配置读写、历史记录、结果对比

## CI/CD

### CI（持续集成）

每次 Push / PR 到 `main` 分支会自动执行：
- Python 3.11 / 3.12 环境下的 pytest 测试
- 代码风格检查（ruff）
- Docker 镜像构建与运行测试

### CD（持续交付）

每次推送以 `v` 开头的 Tag（如 `v1.0.0`）会自动触发发布流程：

1. **自动测试**：先跑完整 CI 测试，确保代码质量
2. **构建多平台镜像**：同时构建 `linux/amd64` 和 `linux/arm64` 镜像
3. **推送到 GitHub Container Registry (ghcr.io)**：
   - `ghcr.io/anjiajia/ipshow:v1.0.0`
   - `ghcr.io/anjiajia/ipshow:latest`
4. **可选推送到 Docker Hub**：在仓库 Secrets 中配置 `DOCKER_USERNAME` 和 `DOCKER_PASSWORD` 后，会自动同时推送
5. **创建 GitHub Release**：自动生成 Release Notes

#### 如何发布新版本

```bash
git tag v1.0.0
git push origin v1.0.0
```

推送 Tag 后，到 [Actions](https://github.com/anjiajia/IPshow/actions) 页面查看发布进度，约 2-3 分钟后镜像和 Release 都会就绪。

#### 从 GHCR 拉取镜像（无需 Docker Hub）

```bash
docker pull ghcr.io/anjiajia/ipshow:latest
docker run -d -p 8501:8501 --name ipshow ghcr.io/anjiajia/ipshow:latest
```

#### 可选：配置 Docker Hub

如果你想同时推送到 Docker Hub：
1. 在 GitHub 仓库 → Settings → Secrets and variables → Actions → New repository secret
2. 添加 `DOCKER_USERNAME`（Docker Hub 用户名）
3. 添加 `DOCKER_PASSWORD`（Docker Hub Access Token，不是登录密码）
4. 下次推送 Tag 时就会自动同时推送到 Docker Hub

## 项目结构

```
.
├── app.py              # Streamlit UI 入口
├── core.py             # 核心逻辑（查询、缓存、历史、配置等）
├── requirements.txt    # Python 依赖
├── Dockerfile          # 容器化打包
├── tests/
│   └── test_core.py    # 单元测试
├── .github/
│   └── workflows/
│       ├── ci.yml      # GitHub Actions CI
│       └── cd.yml      # GitHub Actions CD（自动发布镜像）
├── README.md           # 本文件
```

## 说明

- 应用会自动校验 IP、去重并按所选数据源发起查询
- 如果外网不可用或接口限流，查询会失败，需要稍后重试
- CIDR 展开上限为 1024 个 IP，防止误输入大网段导致程序卡死
