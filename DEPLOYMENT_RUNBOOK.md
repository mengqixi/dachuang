# 部署 Runbook

## 1. 项目部署目录

线上部署目录：

```bash
/root/dachuang
```

当前 Flask 入口：

```bash
python3 app.py
```

当前首页入口：

```python
send_file("index.html")
```

也就是说，线上 `/` 读取的是：

```bash
/root/dachuang/index.html
```

不是 `templates/index.html`。

## 2. 当前线上状态审计结论

最近一次只读审计结果：

- 服务器目录：`/root/dachuang`
- 当前分支：`master`
- 当前服务器 HEAD：`028aa6b`
- 远程 `master`：`1a86beb`
- 当前 Flask 进程：`python3 app.py`
- 当前线上入口：`/root/dachuang/index.html`
- 当前服务器工作区：不干净，不能直接 `git pull`

服务器已修改文件：

```text
app.py
data/federated/bank/X.npy
data/federated/government/X.npy
data/federated/hospital/X.npy
data/federated/insurance/X.npy
data/models/lstm_model.npz
data/system.db
index.html
logs/server.log
logs/system_2026-05-30.log
```

服务器未跟踪文件：

```text
config/security.yaml
data/logs/security.log
data/logs/slow_api.log
index.html.bak-20260610-121751
logs/system_2026-06-09.log
logs/system_2026-06-10.log
src/security/
tests/test_security_events_api.py
tests/test_slow_api.py
tests/test_trace_id.py
```

其中 `src/security/`、`tests/test_*`、`config/security.yaml` 属于后来已纳入本地开发流程的代码/测试内容，应以干净 Git 版本为准；`data/**`、`logs/**`、`*.bak` 属于运行数据或服务器现场文件，应备份保留，不应直接提交到 Git。

## 3. 风险分类

### A 类：必须保留，不应提交到 Git

这些文件通常是运行数据、日志、模型产物或服务器本地状态：

```text
data/system.db
data/logs/
data/generated/
data/models/
data/federated/*/*.npy
logs/
*.log
*.pid
.env
index.html.bak-*
*.bak
```

处理建议：

- 部署前整体备份。
- 不直接删除。
- 不提交到 Git。
- 如需要重建演示数据，应通过脚本或接口重新生成，而不是把服务器运行产物当源码维护。

### B 类：可以归档备份后回退

这些文件可能是服务器手动改动或临时覆盖内容：

```text
index.html
index.html.bak-*
app.py
logs/server.log
logs/system_*.log
```

处理建议：

- 先保存完整备份和 diff。
- 确认本地/远程 master 已包含需要保留的功能后，再用 Git 标准版本覆盖。
- 不在服务器上继续手工编辑前端文件。

### C 类：应该纳入 Git 或已经在本地 master 中存在

这些内容属于项目代码、配置或测试，应该从 Git 标准部署获得：

```text
index.html
app.py
config/security.yaml
src/security/
tests/test_trace_id.py
tests/test_slow_api.py
tests/test_security_events_api.py
CODEX_REVIEW_*.md
DEPLOYMENT_RUNBOOK.md
docs/
```

处理建议：

- 以本地审核通过并推送后的 `origin/master` 为准。
- 服务器不要保留同名未跟踪代码文件。
- 通过备份、清单确认、`git reset --hard origin/master` 进入干净部署状态。

## 4. 标准部署流程

### 4.1 本地发布前检查

在本地项目目录执行：

```bash
git status
git log --oneline -10
python -m py_compile app.py src/**/*.py
git push origin master
```

如果 `git remote -v` 中包含明文访问令牌，应改为安全远程地址，并轮换已暴露的 token：

```bash
git remote set-url origin https://github.com/mengqixi/dachuang.git
```

### 4.2 服务器上线前审计

在服务器执行：

```bash
cd /root/dachuang
pwd
git status
git log --oneline -10
git branch
git remote -v
git diff --stat
git diff --name-status
git ls-files --others --exclude-standard
ps -ef | grep app.py
```

如果 `git status` 不干净，不要直接 `git pull`。

### 4.3 备份服务器现场

在服务器执行：

```bash
cd /root/dachuang
ts=$(date +%Y%m%d-%H%M%S)
tar -czf /root/dachuang-backup-$ts.tar.gz /root/dachuang
git status > /root/dachuang-status-$ts.txt
git diff > /root/dachuang-diff-$ts.patch
git ls-files --others --exclude-standard > /root/dachuang-untracked-$ts.txt
```

确认备份文件存在：

```bash
ls -lh /root/dachuang-backup-$ts.tar.gz /root/dachuang-status-$ts.txt /root/dachuang-diff-$ts.patch /root/dachuang-untracked-$ts.txt
```

### 4.4 标准同步代码

只有在确认服务器本地代码改动不需要保留，且运行数据已经备份后，才执行：

```bash
cd /root/dachuang
git fetch origin
git reset --hard origin/master
```

注意：

- `git reset --hard` 会丢弃已跟踪文件的本地修改。
- 不会删除未跟踪文件，但未跟踪代码文件仍可能干扰运行。
- 对 `src/security/` 这类未跟踪代码目录，应在备份后确认是否与 Git 版本重复，再决定清理。

### 4.5 恢复或保留运行数据

确认以下运行数据仍存在：

```bash
ls -lh data/system.db 2>/dev/null || true
ls -lah data/logs 2>/dev/null || true
ls -lah data/generated 2>/dev/null || true
ls -lah data/models 2>/dev/null || true
```

如果标准化后需要从备份恢复数据，应只恢复数据和本地配置，不恢复旧代码：

```bash
# 示例：按实际备份包路径和需要恢复的文件执行
tar -tzf /root/dachuang-backup-YYYYMMDD-HHMMSS.tar.gz | grep 'data/system.db'
```

不要直接把整个备份包覆盖回 `/root/dachuang`，否则会把旧代码一起恢复。

### 4.6 重启 Flask

当前临时方式：

```bash
cd /root/dachuang
pkill -f "python3 app.py" || true
nohup python3 app.py > app.log 2>&1 &
ps -ef | grep app.py
```

更推荐使用 systemd，见下文。

### 4.7 健康检查

服务器本机检查：

```bash
curl -i http://127.0.0.1:5000/
curl -i http://127.0.0.1:5000/api/system/health
curl -i http://127.0.0.1:5000/api/security/events/recent
```

公网检查：

```bash
curl -i http://47.110.65.93:5000/
```

前端版本检查：

```bash
grep -n 'data-page="report"' /root/dachuang/index.html
grep -n 'id="pg-report"' /root/dachuang/index.html
grep -n 'data-page="sec"' /root/dachuang/index.html
grep -n 'id="pg-sec"' /root/dachuang/index.html
```

## 5. 回滚流程

### 5.1 Git 版本回滚

先查看历史：

```bash
cd /root/dachuang
git log --oneline -10
```

回滚到指定提交：

```bash
git reset --hard <commit_hash>
```

然后重启服务并做健康检查。

### 5.2 从备份恢复单个文件

先查看备份内容：

```bash
tar -tzf /root/dachuang-backup-YYYYMMDD-HHMMSS.tar.gz | grep 'index.html'
```

只恢复必要文件，不恢复整个目录：

```bash
tar -xzf /root/dachuang-backup-YYYYMMDD-HHMMSS.tar.gz -C /tmp root/dachuang/index.html
cp /tmp/root/dachuang/index.html /root/dachuang/index.html
```

恢复后重启服务并检查页面。

## 6. 日志查看

临时 nohup 方式：

```bash
tail -n 100 /root/dachuang/app.log
```

项目日志：

```bash
tail -n 100 /root/dachuang/data/logs/security.log
tail -n 100 /root/dachuang/data/logs/security_events.log
tail -n 100 /root/dachuang/data/logs/slow_api.log
tail -n 100 /root/dachuang/data/logs/rate_limit.log
```

如果使用 systemd：

```bash
journalctl -u dachuang -n 100 --no-pager
journalctl -u dachuang -f
```

## 7. systemd 托管建议

建议新增服务文件：

```ini
# /etc/systemd/system/dachuang.service
[Unit]
Description=Dachuang Flask Application
After=network.target

[Service]
Type=simple
WorkingDirectory=/root/dachuang
ExecStart=/usr/bin/python3 /root/dachuang/app.py
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

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

注意：启用 systemd 前，应先确认依赖安装、端口占用、运行用户和日志路径。

## 8. .gitignore 建议

当前 `.gitignore` 已覆盖：

```text
__pycache__/
*.py[cod]
*.log
/uploads/
.env
.env.local
```

建议补充：

```gitignore
# Runtime data
data/system.db
data/logs/
data/generated/
data/models/
data/federated/**/*.npy

# Local process files
*.pid

# Local assistant settings
.claude/settings.local.json

# Backups
index.html.bak-*
*.bak

# Server logs directory
logs/
```

注意：`.gitignore` 不会自动停止跟踪已经纳入 Git 的文件。对已跟踪的运行日志或数据文件，需要单独评估是否执行 `git rm --cached`，本次不建议直接操作。

## 9. 前端缓存排查

如果本地或服务器代码已更新，但浏览器仍显示旧页面：

```bash
curl -s http://127.0.0.1:5000/ | grep 'data-page="report"'
curl -s http://47.110.65.93:5000/ | grep 'data-page="report"'
```

如果 curl 已经能看到新内容，而浏览器看不到：

- 强制刷新：`Ctrl + F5`
- 清理浏览器缓存
- 使用无痕窗口访问
- 检查是否访问了错误端口或旧代理地址

如果 curl 也看不到新内容：

- 检查服务器 `index.html` 是否更新。
- 检查 Flask 是否已重启。
- 检查运行目录是否是 `/root/dachuang`。
- 检查 `app.py` 是否仍使用 `send_file("index.html")`。

## 10. 常见问题

### 本地改了但线上没变

排查：

```bash
git log --oneline -5
git push origin master
ssh root@47.110.65.93 'cd /root/dachuang && git log --oneline -5'
```

如果服务器落后，按标准部署流程处理，不要手工覆盖单个文件。

### git pull 失败

常见原因：

- 服务器工作区有本地修改。
- 服务器有未跟踪文件与新版本冲突。
- 服务器无法访问 GitHub。
- 远程认证失效。

处理：

```bash
cd /root/dachuang
git status
git diff --stat
git ls-files --others --exclude-standard
```

先备份，再决定是否 `git reset --hard origin/master`。

### Flask 端口被占用

排查：

```bash
ss -lntp | grep ':5000'
ps -ef | grep app.py
```

处理：

```bash
pkill -f "python3 app.py"
nohup python3 app.py > app.log 2>&1 &
```

如果使用 systemd：

```bash
systemctl restart dachuang
systemctl status dachuang
```

### 页面还是旧版

排查：

```bash
cd /root/dachuang
git log --oneline -5
grep -n 'data-page="report"' index.html
curl -s http://127.0.0.1:5000/ | grep 'data-page="report"'
```

如果文件有新内容但 HTTP 没有，重启 Flask。

### API 200 但前端空白

排查：

```bash
curl -i http://127.0.0.1:5000/
tail -n 100 app.log
```

同时在浏览器控制台检查 JS 报错。常见原因：

- `index.html` 中 JS 语法错误。
- API 返回结构变化。
- 页面元素 id 或 JS 函数名被改动。
- 浏览器缓存仍使用旧脚本。

