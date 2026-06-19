# 部署安全配置清单

本文档用于上线前检查密码攻击检测与隐私训练平台的基础安全配置。它不包含真实服务器密码、Token、密钥或任何生产凭据。

## 1. 必须配置项

上线前必须完成以下配置：

| 检查项 | 要求 | 验证方式 |
| --- | --- | --- |
| `FLASK_SECRET_KEY` | 必须设置为随机强密钥，不能使用默认值 `dachuang-dev-secret-change-me` | `echo $FLASK_SECRET_KEY`，确认非空且不是默认值 |
| `ADMIN_USERNAME` | 必须设置管理端账号 | `echo $ADMIN_USERNAME` |
| `ADMIN_PASSWORD` | 必须设置强密码，不能使用 `admin123` | `echo $ADMIN_PASSWORD`，确认非空且不是默认值 |
| 管理端登录 | 未配置强密码时应禁止公网登录 | 访问 `http://服务器:5001/api/admin/session` |
| 上传限制 | CSV/JSON 文件必须有大小、类型、行列数和空文件校验 | 上传空文件、坏 JSON、非 CSV/JSON 文件验证 |
| 数据目录 | `data/`、`logs/`、上传归档和模型文件不应提交到 Git | `git status --short` |

推荐生成 `FLASK_SECRET_KEY`：

```bash
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
```

示例环境变量：

```bash
export FLASK_SECRET_KEY='请替换为随机强密钥'
export ADMIN_USERNAME='admin'
export ADMIN_PASSWORD='请替换为强密码'
python3 app.py
```

也可以参考仓库中的 [.env.example](.env.example)，复制后填写真实值。真实 `.env` 文件已被 `.gitignore` 忽略，不应提交。

Windows PowerShell 示例：

```powershell
$env:FLASK_SECRET_KEY = "请替换为随机强密钥"
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "请替换为强密码"
python app.py
```

## 2. 建议配置项

| 检查项 | 建议 |
| --- | --- |
| HTTPS | 公网部署建议通过 Nginx / Caddy / 云厂商证书启用 HTTPS |
| Flask debug | 公网环境不要开启 debug 模式 |
| CORS | 当前开发阶段允许 `*`，公网部署建议限制为实际前端域名 |
| Cookie | 反向代理启用 HTTPS 后，建议配置安全 Cookie 策略 |
| 日志轮转 | `logs/`、`data/logs/` 建议使用 logrotate 或定期归档 |
| systemd | 推荐使用 systemd 管理 Flask 进程，而不是长期手动 nohup |
| 最小权限 | 生产环境建议使用专门运行用户，不建议长期使用 root 直接运行服务 |
| 防火墙 | 只开放必要端口，例如 5000/5001 或反向代理后的 80/443 |

## 3. systemd 服务示例

文件路径建议：

```text
/etc/systemd/system/dachuang.service
```

示例内容：

```ini
[Unit]
Description=Dachuang Password Risk Platform
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/dachuang
Environment=PYTHONUNBUFFERED=1
Environment=FLASK_SECRET_KEY=请替换为随机强密钥
Environment=ADMIN_USERNAME=admin
Environment=ADMIN_PASSWORD=请替换为强密码
ExecStart=/usr/bin/python3 /root/dachuang/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

启用命令：

```bash
systemctl daemon-reload
systemctl enable dachuang
systemctl restart dachuang
systemctl status dachuang
```

注意：不要把真实密钥和密码提交到 Git。线上更推荐使用 systemd drop-in、环境变量文件或云平台密钥管理能力。

## 4. CORS 与反向代理建议

当前项目仍以 Flask 原型为主。如果需要公网展示，建议使用 Nginx 或 Caddy 做反向代理：

```text
https://example.com        -> 127.0.0.1:5000 用户端
https://admin.example.com  -> 127.0.0.1:5001 管理端
```

部署后建议把 CORS 从开发模式收紧为允许实际域名。不要在公网管理端长期使用任意来源访问策略。

## 5. 上传安全检查

当前上传链路应满足：

- 只允许 CSV / JSON。
- 空文件返回明确错误。
- 文件大小超过限制返回明确错误。
- CSV 缺少表头或数据行返回明确错误。
- CSV / JSON 字段过多返回明确错误。
- 非 UTF-8 编码或损坏 JSON 返回明确错误。
- 上传失败不应留下半成品索引。
- 用户端和管理端默认不展示明文密码、Token、银行卡、手机号等敏感字段。

手动验证示例：

```bash
curl -X POST http://127.0.0.1:5000/api/user/datasets/upload \
  -F "file=@empty.csv"

curl -X POST http://127.0.0.1:5000/api/user/datasets/upload \
  -F "file=@bad.json"
```

## 6. 部署后冒烟检查

```bash
curl -i http://127.0.0.1:5000/
curl -i http://127.0.0.1:5001/
curl -i http://127.0.0.1:5000/api/system/health
curl -i http://127.0.0.1:5001/api/admin/session
```

如需使用项目脚本：

```bash
python3 scripts/smoke_check.py \
  --user-base http://127.0.0.1:5000 \
  --admin-base http://127.0.0.1:5001
```

## 7. 不应提交到 Git 的内容

以下内容属于运行数据或本地配置，不应提交：

- `data/system.db`
- `data/logs/`
- `data/generated/`
- `data/models/`
- `data/user_submissions/`
- `data/keys/`
- `logs/`
- `.env`
- `.claude/settings.local.json`
- 真实服务器密码、Token、密钥

提交前检查：

```bash
git status --short
git diff --stat
```
