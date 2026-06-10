# CODEX Review: Frontend Task H1 - Global JS Guards

## 1. 是否可以合并

结论：可以合并。

Claude 的 H1 改动聚焦在 `index.html`，目标是修复全局 JS 容错、接口业务错误识别和 `.map()` undefined 导致的页面崩溃问题。Codex 审核中做了两个 H1 范围内的小修：

- `buildTable()` 中 `Object.keys(data[0])` 改为先通过 `safeObject(data[0])` 兜底。
- `getData()` 中 `payload.data || payload` 改为显式判断 `payload.data !== undefined`，避免合法 falsy 数据被误替换。

## 2. 本次修改文件清单

Claude 修改：

- `index.html`

Codex 小修：

- `index.html`

Codex 新增审核报告：

- `CODEX_REVIEW_FRONTEND_TASK_H1.md`

未修改：

- `app.py`
- `src/**`
- `config/**`
- `tests/**`
- `data/**`
- `requirements.txt`

## 3. 新增容错函数检查

已确认以下函数存在：

- `safeArray`
- `safeObject`
- `safeGet`
- `getData`
- `showEmpty`
- `escapeHtml`

兼容性检查：

- 原 `esc()` 仍存在。
- `escapeHtml()` 指向 `esc()`，旧逻辑如 `loadSec()` 继续可用。
- 未引入 React、Vue、Angular 或新依赖。

建议优化：

- `showEmpty(el, msg)` 当前允许传入 HTML 字符串并直接写入 `innerHTML`。目前调用点使用内部固定文案，风险可控；后续不要把用户输入直接传给 `showEmpty()`。

## 4. get/post 业务 code 处理检查

已确认 `get()` / `post()` 会解析 JSON 后调用 `getData()`。

当前逻辑：

- `code === 200`：返回 `data`。
- `code !== 200`：返回 `null`，并把 `msg` 作为错误传入回调。
- HTTP 非 200：进入错误回调。
- JSON 解析失败：进入错误回调。

重点场景：

```json
{
  "code": 500,
  "msg": "处理失败",
  "data": {}
}
```

现在不会被当作成功处理。`POST /api/dataset/unsw/process` 返回业务 `code:500` 时，`procDS()` 会走错误提示逻辑，不会继续执行 `d.nodes.map(...)`。

## 5. `.map()` / `.forEach()` / `Object.keys()` 风险检查

已检查当前残余使用点：

- `Object.keys(first)`：`first` 来自 `safeObject(data[0])`，可接受。
- `safeArray(d.nodes).map(...)`：已通过 `safeArray()` 保护。
- `confs.reduce(...)`：执行前检查 `confs.length`，可接受。
- `labs.map(...)`：`labs` 是本地固定数组，安全。

未发现直接对 `undefined` 执行 `.map()`、`.forEach()` 或 `Object.keys()` 的高风险路径。

## 6. 数据集缺失场景验证

本地接口验证：

- `GET /api/dataset/unsw/status`：HTTP 200，业务 `code:200`，`exists:false`。
- `GET /api/federated/nodes`：HTTP 200，业务 `code:200`，返回 hospital / bank / insurance / government 四个 `ready:false` 节点。
- `POST /api/dataset/unsw/process`：HTTP 200，业务 `code:500`，原因是缺少 `data/datasets/UNSW-NB15`。

前端逻辑检查：

- `loadDS()` 使用 `safeArray(d.files)`。
- `loadDS()` 使用 `safeArray(d.nodes)`。
- `procDS()` 在 `err` 存在时直接 toast 并 return。
- `procDS()` 不再直接执行未保护的 `d.nodes.map(...)`。
- 当前数据集缺失场景不会再触发 `Cannot read properties of undefined (reading 'map')`。

说明：

- 当前接口返回四个节点，因此页面仍可显示 hospital / bank / insurance / government。
- 如果未来 `/api/federated/nodes` 返回空数组，当前页面会显示友好说明，但不会生成四张演示节点卡片。这个更适合放到 H3 数据处理页重构中处理。

## 7. 导航点击稳定性验证

静态检查：

- 当前 `data-page` 集合保持：`dash,data,detect,ds,enc,fed,optim,report,sec,train`。
- 当前页面 id 保持：`pg-dash,pg-data,pg-detect,pg-ds,pg-enc,pg-fed,pg-optim,pg-report,pg-sec,pg-train`。
- 导航切换时已为每个懒加载函数包裹 `try/catch`。
- 若单个懒加载函数抛异常，不会阻断其他页面切换逻辑。

浏览器验证：

- 当前本机环境没有可用 Playwright 依赖，也没有暴露 Browser 工具；本次使用静态 DOM 检查、JS 语法检查和 HTTP/API 验证替代。

## 8. 是否影响旧功能

未发现旧功能被破坏：

- 原 JS 函数名保留。
- 原 API URL 集合与 H1 前一致，数量均为 16。
- 原 `data-page` 保留。
- 原 `pg-*` 页面 id 保留。
- 未新增后端接口。
- 未修改后端文件。
- 未新增依赖。

验证命令：

- `python -m py_compile app.py src/**/*.py`：通过。
- 从 `index.html` 抽取 `<script>` 后执行 `node --check`：通过。
- `git diff --check -- index.html`：通过。

本地 HTTP 验证：

- `GET /`：200。
- `GET /api/system/health`：200，业务 `code:200`。
- `GET /api/dataset/unsw/status`：200，业务 `code:200`。
- `GET /api/federated/nodes`：200，业务 `code:200`。
- `POST /api/dataset/unsw/process`：200，业务 `code:500`，用于验证前端业务错误兜底。

## 9. 是否建议进入 H2

建议进入 H2。

H1 已经解决稳定性底座问题。下一步可以开始将“总览”重构为答辩入口，但必须继续保持小步改动：只改 `index.html`，不改后端，不合并其他页面。

## 10. H2 推荐做什么

H2 推荐目标：

- 将“总览”放到主导航第一位。
- 总览页展示项目名称、一句话目标、演示流程、模块状态卡片和推荐演示顺序。
- 接口可用时展示真实状态；接口失败时展示稳定默认状态。
- 不删除旧函数，不修改旧 API URL。
- 不进入 H3，不合并数据处理页面。

