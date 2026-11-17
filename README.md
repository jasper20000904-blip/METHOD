# 经营方法论中枢 · V2.0 多人协作版

这是基于首版「资产结算方法论」离线网页升级的完整后端 + 前端项目，内置原有 **5 个一级章节、资产投放的 5 个小章节、23 张方法卡片及原始手稿**。

## 已实现

- 统一网站登录；管理员分配账户，角色为 `admin`、`editor`、`viewer`
- 所有章节与方法统一保存在 SQLite（本机开发）或 PostgreSQL（线上），跨设备共享
- 编辑自动保存（约 0.5 秒防抖）；有服务器版本号和 409 冲突保护，不会直接用旧版本覆盖他人新内容
- 20 秒检查一次云端是否有新版本；本地无未提交编辑时自动刷新
- 所有提交保存为历史版本，管理员可恢复任一版本
- 方法库搜索、矩阵、策略组合、总分行承接对照、JSON/CSV/Markdown 导出
- 原始 3 张手写稿附在网页里供复核
- HTTP-only Cookie 会话；PBKDF2 密码哈希；修改操作 CSRF 防护

**注意：**策略组合勾选只在个人浏览器本地保存（不是共享项目方案），共享的是整个方法论知识库。若需要多人同时精细修改同一章节，目前采用“整库版本检查”，后提交者要手动备份草稿、刷新，再重新合并，而不是自动逐字段合并。

## 方式 A：部署到 Railway + PostgreSQL

1. 将压缩包解压后的文件（包括根目录的 `Dockerfile`、`railway.json`、`requirements.txt` 和 `app/` 文件夹）上传到**私有** GitHub 仓库根目录（请勿上传包含真实客户信息、内部秘密或密码的文件）。
2. 在 Railway 创建新 Project -> Deploy from GitHub Repo -> 选择该仓库。构建会自动识别根目录 `Dockerfile`。
3. 在同一个 Project 里添加 **PostgreSQL** 数据库服务。
4. 在 Web 服务 **Variables** 配置：

   | 变量名 | 值 |
   |---|---|
   | `DATABASE_URL` | 引用 Railway PostgreSQL 服务的 `DATABASE_URL`（通过变量引用，不要手动分享给他人） |
   | `ADMIN_USERNAME` | 自定管理员账号（例如 `admin`） |
   | `ADMIN_PASSWORD` | 随机生成的至少12位**独立强密码** |
   | `COOKIE_SECURE` | `true` |

5. 部署 Web 服务，在 Railway **Settings / Networking** 生成 `.up.railway.app` 域名或绑定你们的专用域名。Railway 会提供 HTTPS。
6. 打开 `https://<你的域名>/login`，用管理员账号登录。进入 **用户管理** 创建 editor/viewer 账号，并向授权同事分享该网址。
7. 建议在 Railway 设置定期备份 PostgreSQL（以及/或者从网页定期下载 JSON 备份）。部署前请检查所属机构是否允许把此类资料放入第三方云端。

**数据持久化：**线上务必使用 PostgreSQL。不要把生产数据库留在 Railway 容器的临时文件系统中：重新部署可能丢失 SQLite 文件。只有在数据库是同一个 Railway Postgres 实例时，才会跨重部署保存数据。

**权限提醒：**首个管理员只会在首次初始化数据库且 `users` 表为空时，由环境变量创建。以后修改 `ADMIN_PASSWORD` 环境变量 **不会**重置现有管理员密码；请在用户管理中重置。

## 方式 B：本机运行/测试

Python >=3.10。假定当前工作目录是本项目根目录。

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD='使用自己生成的至少12位强密码'
export COOKIE_SECURE=false
export SQLITE_PATH=./data/local.db
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

访问：`http://127.0.0.1:8080`。本机运行默认用 SQLite，适合个人测试，但不适合 Railway 的无持久卷生产部署。

Windows PowerShell 将 `export X=...` 换成 `$env:X='...'`。

## 主要接口与页面

| 路径 | 用途 |
|---|---|
| `/login` | 登录页面 |
| `/` | 协作版知识库 |
| `/history` | 版本历史，管理员可恢复 |
| `/admin` | 成员账号、角色及密码管理 |
| `/api/health` | 健康检测 |
| `/api/bootstrap` | 当前版本、所有章节和登录者角色 |
| `/api/knowledge` | 原子更新全部章节（版本号校验） |
| `/api/users` | 管理员账户维护 |

## 安全与上线注意事项

- **只适合先做内部试点**：独立账号密码+角色不是银行生产级身份认证，尚未集成企业 SSO、公司 VPN、IP 白名单、专职审计平台或数据分级管控。
- **合规优先**：原始手稿已经内嵌在前端页面（登录后可浏览）。如果这些图片、案例、客户名单、信贷策略等属于机构内部资料，上第三方公网云平台之前，应经信息科技与数据安全审批；建议改为银行批准的内网/私有云环境或隔离区域。
- 现有权限仅为粗粒度的查看 / 编辑 / 管理角色，没有章节级和字段级权限控制；单次更新以全库为单位，不适合高并发编辑场景。
- 不要使用真实工作邮箱密码作为系统初始密码；更不要将数据库 URL、管理密码写进源代码。
- 本项目未在 Railway 上实际部署前，不应声称已经上线或具有一个真实公网网址。
