# 部署安全检查清单

## 凭据与会话

- [ ] `FLASK_SECRET_KEY` 是随机强密钥，通过环境或密钥管理服务提供。
- [ ] `ADMIN_USERNAME`、`ADMIN_PASSWORD` 已配置为非默认强凭据。
- [ ] 已轮换曾经出现在仓库、文档、命令或聊天记录中的服务器凭据。
- [ ] `.env`、数据库、AES 密钥、模型和上传归档未进入镜像或 Git。
- [ ] HTTPS 环境设置 `SESSION_COOKIE_SECURE=true`。

未配置管理密码时，`root / root` 只允许本机 Host 登录；公网 Host 会返回 503。生产环境不应依赖这个开发保护作为长期认证方案。

## HTTP 暴露面

- [ ] `/.git/HEAD`、`/app.py`、`/data/system.db`、`/src/main.py` 均返回 404。
- [ ] 管理 API 和历史写接口未登录时返回 HTTP 401。
- [ ] `CORS_ALLOWED_ORIGINS` 只包含精确可信源，不使用 `*`。
- [ ] 反向代理只开放必要端口，并设置 HTTPS、请求体上限和访问日志。
- [ ] `X-Content-Type-Options`、`X-Frame-Options`、`Referrer-Policy` 响应头存在。

## 上传与数据

- [ ] 仅接受 CSV / JSON，文件大小、行数和列数限制生效。
- [ ] 空文件、损坏 JSON、异常编码和超限文件会被拒绝。
- [ ] password、token 等敏感字段不会以明文进入归档或 API 预览。
- [ ] 新上传只保留 AES-256-GCM 加密归档，临时解密文件会删除。
- [ ] `data/keys/user_archive.key` 有严格文件权限并有独立备份；丢失后无法恢复历史归档。
- [ ] 管理员审核后数据才能进入训练池。

## 数据与模型一致性

- [ ] 准备结果包含 `dataset_revision`、`preparation_id` 和 `preprocessing_version`。
- [ ] 数据源未变化时复用准备结果；变化时按上限全量重建。
- [ ] 四节点来自同一准备版本，X/y 数量一致。
- [ ] 联邦上下文随准备版本变化而重置，不跨数据源继承权重。
- [ ] 运行时融合模型与联邦训练追踪分开，不把 FedAvg 记录冒充用户检测模型。
- [ ] 模型未就绪时返回 503，不产生伪模型分数。

## 进程与服务器隔离

- [ ] 已核对项目绝对目录、运行用户和专属 systemd 服务名。
- [ ] 没有使用宽泛 `pkill`、`killall`、端口批量清理或递归删除。
- [ ] 部署前已检查服务器工作区并备份运行数据。
- [ ] 操作不会触碰同机其他项目目录、数据库、容器或服务。

## 验证命令

```bash
python validate_project.py
python -m unittest discover tests -v
python scripts/smoke_check.py \
  --user-base http://127.0.0.1:5000 \
  --admin-base http://127.0.0.1:5001
```
