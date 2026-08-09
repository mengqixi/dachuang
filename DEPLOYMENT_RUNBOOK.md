# 部署 Runbook

本文件只描述经过人工确认的部署流程。仓库不会自动连接服务器，也不会自动停止线上进程。旧 `deploy*`、`upload*` 脚本已停用。

## 安全边界

- 先明确项目的绝对部署目录和专属服务名；不要根据模糊文件名猜测。
- 不使用 `pkill -f python`、`killall python`、端口批量清理等宽泛命令。
- 不执行 `git reset --hard`、递归删除或覆盖整个服务器目录。
- 服务器工作区不干净时停止部署，先备份并人工判断每项变化。
- `data/`、`logs/`、数据库、上传归档、密钥和模型属于运行状态，不随代码覆盖。
- 服务器上还有其他项目时，只操作已核对的项目目录和专属 systemd 单元。

## 1. 本地发布前检查

```bash
python validate_project.py
python -m unittest discover tests -v
git status --short
git diff --stat
```

确认代码中没有真实密码、Token、私钥或服务器凭据。已经暴露过的凭据必须轮换，删除当前文件中的字符串不能清除 Git 历史或命令历史。

## 2. 服务器只读审计

以下命令中的目录和服务名必须先替换为人工确认过的值：

```bash
project_dir=/absolute/path/to/dachuang
service_name=dachuang.service

cd "$project_dir"
pwd
git status --short
git diff --stat
git ls-files --others --exclude-standard
systemctl status "$service_name" --no-pager
```

如果目录、服务名或进程归属不能确认，不继续部署。

## 3. 备份运行状态

备份应写入项目目录之外、权限受控的位置。至少保留：

- `data/system.db`
- `data/user_submissions/`
- `data/keys/`
- `data/models/`
- `data/datasets/processed/`
- `data/federated/`
- `logs/` 和 `data/logs/`
- 当前 Git 提交号、工作区 diff 和未跟踪文件清单

不要为了部署而删除这些文件。

## 4. 推荐发布方式

推荐将每个代码版本放入独立 release 目录，并让专属服务指向审核后的 release；运行数据使用明确的持久目录挂载。不要在正在运行的目录中强行覆盖未知修改。

正式入口只有：

```bash
python3 app.py
```

应用默认监听 5000 和 5001。通过反向代理公开服务时，应只暴露需要的入口并启用 HTTPS。

## 5. systemd 专属服务示例

```ini
[Unit]
Description=Dachuang Password Risk Platform
After=network.target

[Service]
Type=simple
User=dachuang
Group=dachuang
WorkingDirectory=/absolute/path/to/dachuang
EnvironmentFile=/etc/dachuang/dachuang.env
ExecStart=/usr/bin/python3 /absolute/path/to/dachuang/app.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

环境文件权限建议为 `0600`，至少配置：

```text
FLASK_SECRET_KEY=<随机强密钥>
ADMIN_USERNAME=<非默认账号>
ADMIN_PASSWORD=<强密码>
SESSION_COOKIE_SECURE=true
CORS_ALLOWED_ORIGINS=https://trusted.example
```

只重启经过核对的专属单元：

```bash
systemctl restart dachuang.service
systemctl status dachuang.service --no-pager
```

## 6. 部署后只读验证

在服务器本机执行：

```bash
python3 scripts/smoke_check.py \
  --user-base http://127.0.0.1:5000 \
  --admin-base http://127.0.0.1:5001
```

另外确认以下敏感路径返回 404：

```text
/.env.example
/.git/HEAD
/app.py
/data/system.db
/src/main.py
```

检查专属服务日志，不按 `python` 关键字扫描或处理其他项目进程。

## 7. 回滚

回滚只切换到已知正常的代码 release，并保持持久数据不动。数据库结构或数据已经迁移时，先评估兼容性；不要直接用旧目录覆盖当前 `data/`。

如果无法确认回滚对运行数据的影响，停止操作并从备份副本进行离线验证。
