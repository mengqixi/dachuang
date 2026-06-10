# 前端答辩演示版重构方案

## 1. 当前前端问题诊断

当前前端已经完成 Task A-G 的标题和文案整理，但整体仍然是旧功能页面的堆叠式结构。上线后出现空白页、数据集报错和节点未加载，核心原因不是单个文案问题，而是前端缺少统一容错层、接口返回结构判断不足，以及导航仍按旧页面拆分。

主要问题：

- 导航顺序与答辩叙事不一致。当前导航仍包含 `数据处理`、`数据集处理`、`模型训练`、`联邦训练`、`攻击检测`、`加密对比`、`自适应优化`、`总览`、`安全防护`、`实验报告`，入口过多，且“总览”不在第一位。
- 页面切换逻辑没有保护。`document.getElementById('pg-' + pg).style.display = 'block'` 如果找不到页面 id，会直接抛错。
- 懒加载函数没有外层 try/catch。点击导航后触发 `loadDS()`、`loadFed()`、`loadDash()`、`loadSec()`、`loadOpt()`、`updEnc()`，其中任一函数抛错都可能导致页面局部空白或后续逻辑中断。
- `get()` / `post()` 只判断 HTTP 状态码，没有判断业务返回体中的 `code`。例如后端返回 HTTP 200，但 JSON 为 `{code:500,msg:"处理失败",data:{}}` 时，当前前端仍当成成功处理。
- 多处直接读取深层字段，例如 `d.nodes.map(...)`、`d.traditional.encryption_time_ms`、`res.traditional.accuracy`，缺少空值兜底。
- 数据为空时，多数页面只显示空表格或完全不渲染，缺少稳定的“当前未加载 / 演示数据 / 请先处理数据集”状态。
- 部分页面仍使用旧功能表述和旧接口结构，不适合作为答辩演示主线。

## 2. 数据集 `.map()` 报错原因

报错：

```text
Cannot read properties of undefined (reading 'map')
```

定位位置：

```javascript
d.nodes.map(function(n){ return n.name + ':' + n.samples }).join(', ')
```

对应函数：

```javascript
procDS()
```

触发链路：

1. 用户点击“处理数据集 + 训练模型”。
2. 前端请求：

```text
POST /api/dataset/unsw/process
```

3. 当前本地验证中，服务器未检测到 `data/datasets/UNSW-NB15`，后端返回：

```json
{
  "code": 500,
  "msg": "处理失败: [WinError 3] 系统找不到指定的路径。: 'data/datasets/UNSW-NB15'",
  "data": {}
}
```

4. 但 HTTP 状态仍是 200。
5. 当前 `post()` 只判断 `x.status === 200`，并执行：

```javascript
cb(j.data || j, null)
```

6. 因为 `j.data` 是 `{}`，前端收到的 `d` 是空对象 `{}`，`err` 为 `null`。
7. `procDS()` 继续把它当成功结果，执行 `d.nodes.map(...)`。
8. `d.nodes` 为 `undefined`，因此报错。

结论：

这不是单纯的数据集缺失问题，而是前端没有识别业务失败返回，也没有对 `nodes` 做 `safeArray()` 保护。

## 3. 空白页面可能原因

空白页面主要有四类原因：

1. 导航目标缺失或 id 不匹配。
   当前 `data-page` 与 `pg-*` 基本齐全，但后续合并页面时必须维护映射，不允许让 `data-page` 指向不存在的页面。

2. 懒加载函数抛异常。
   例如 `procDS()` 中的 `d.nodes.map()`、`updEnc()` 中的 `d.traditional.encryption_time_ms`、`startTrain()` 中的 `res.traditional.accuracy` 都可能在接口返回空对象时抛异常。

3. 接口失败但页面没有空状态。
   当前 `loadDash()` 如果 `/api/data/system_status` 返回空数组，`renderDashCharts()` 直接 `return`，图表区域没有明确说明；`loadFed()` 如果节点为空，只写入空字符串；`showDetRes()` 如果检测结果为空，表格体为空。

4. 业务 code 失败但 HTTP 200。
   当前接口包装函数没有统一处理 `{code: 非200}`，导致很多失败响应被当作成功数据。

高风险位置：

- `procDS()`：`d.nodes.map(...)`。
- `buildTable()`：已判断空数组，但如果 `data[0]` 不是对象，`Object.keys(data[0])` 仍有风险。
- `startTrain()`：直接访问 `res.traditional`、`res.federated`、`res.comparison`。
- `showDetRes()`：假设 `d` 存在且有 `detections`。
- `updEnc()`：直接访问 `d.traditional` 和 `d.homomorphic`。
- `loadOpt()`：对状态对象容错较少，但相对可控。
- `loadDash()`：依赖 `s.total_gain.toFixed(1)`，如果 `total_gain` 非数字可能报错。
- `loadSec()`：已做 `Array.isArray(d.events)` 判断，是当前相对稳的页面。

## 4. 数据集接口诊断

本地验证结果：

### 4.1 `GET /api/dataset/unsw/status`

HTTP：200

返回结构：

```json
{
  "code": 200,
  "msg": "操作成功",
  "data": {
    "exists": false,
    "files": [],
    "path": "data/datasets/UNSW-NB15"
  }
}
```

前端期待结构：

```javascript
{
  exists: boolean,
  files: []
}
```

当前 `get()` 会解包 `data`，所以 `loadDS()` 可正常读取 `exists` 和 `files`。

### 4.2 `GET /api/federated/nodes`

HTTP：200

返回结构：

```json
{
  "code": 200,
  "msg": "操作成功",
  "data": {
    "nodes": [
      {"name": "hospital", "ready": false, "samples": 0},
      {"name": "bank", "ready": false, "samples": 0},
      {"name": "insurance", "ready": false, "samples": 0},
      {"name": "government", "ready": false, "samples": 0}
    ],
    "total": 4
  }
}
```

前端期待结构：

```javascript
{
  nodes: []
}
```

当前 `get()` 会解包 `data`，所以 `loadDS()` 和 `loadFed()` 可正常读取节点。但节点未准备好时，页面只显示“未加载”，答辩展示不稳定，需要改为“演示节点 / 当前未加载”。

### 4.3 `POST /api/dataset/unsw/process`

HTTP：200

数据集缺失时返回结构：

```json
{
  "code": 500,
  "msg": "处理失败: ... data/datasets/UNSW-NB15",
  "data": {}
}
```

前端期待结构：

```javascript
{
  samples: number,
  features: number,
  nodes: [],
  ensemble_accuracy: number
}
```

字段不匹配：

- 前端期待 `nodes`，失败时没有。
- 前端期待 `samples`、`features`、`ensemble_accuracy`，失败时没有。
- 前端没有检查业务 `code`。

处理原则：

- 不要求本阶段下载 UNSW-NB15。
- 数据集缺失时前端必须显示“当前服务器未检测到 UNSW-NB15 处理结果”。
- 四个模拟节点仍显示为答辩演示节点。
- 处理按钮失败时显示友好提示，不跳转、不崩溃。

## 5. 推荐新导航

答辩演示版建议减少入口，按技术路线组织为 7 个页面：

1. 总览
2. 数据处理
3. 联邦训练
4. 攻击检测
5. 自适应优化
6. 安全防护
7. 实验报告

建议映射：

| 新导航 | 原页面来源 | 用途 |
| --- | --- | --- |
| 总览 | 原 `pg-dash` + 项目流程说明 | 作为答辩入口，先说明项目目标、流程和模块状态 |
| 数据处理 | 原 `pg-data` + `pg-ds` | 展示数据生成、UNSW-NB15 状态、四个模拟节点 |
| 联邦训练 | 原 `pg-train` + `pg-fed` | 展示本地训练、四节点模拟训练、FedAvg 聚合 |
| 攻击检测 | 原 `pg-detect` | 展示样本检测、上传检测和风险评分 |
| 自适应优化 | 原 `pg-enc` + `pg-optim` | 展示 AES/Paillier 指标和 Q-learning 参数调整流程 |
| 安全防护 | 原 `pg-sec` | 展示 TraceId、慢接口、限流、安全事件日志 |
| 实验报告 | 原 `pg-report` | 静态答辩总结 |

不建议继续保留 10 个主导航入口。旧页面块可先隐藏或保留为内部区块，但主导航应服务答辩流程。

## 6. 页面合并方案

### 6.1 总览

目标：变成答辩入口，而不是普通数据看板。

展示内容：

- 项目名称。
- 一句话目标。
- 当前演示流程：

```text
数据处理 → 联邦训练 → 攻击检测 → 自适应优化 → 安全防护 → 实验报告
```

- 模块状态卡片：
  - 数据处理：演示可用
  - 联邦训练：模拟演示
  - 攻击检测：接口演示
  - 自适应优化：参数调优演示
  - 安全防护：事件看板
- 推荐演示顺序。

接口优先级：

- 优先读取 `/api/data/statistics`。
- 失败时使用演示状态卡片，不让页面空白。

### 6.2 数据处理

合并 `pg-data` 和 `pg-ds`。

展示内容：

- 数据生成演示。
- Paillier 密态样本预览。
- UNSW-NB15 状态。
- 四个模拟节点：hospital、bank、insurance、government。
- 数据集缺失说明。

接口优先级：

1. `GET /api/dataset/unsw/status`
2. `GET /api/federated/nodes`
3. `POST /api/generate_dataset`
4. `POST /api/dataset/unsw/process`

默认展示：

- 数据集状态：未加载。
- 四个模拟节点显示“演示节点 / 当前未加载”。
- 明文/密文预览区域显示“请点击生成演示数据”。

### 6.3 联邦训练

合并 `pg-train` 和 `pg-fed`。

展示内容：

- 本地训练演示入口。
- 四节点单机模拟联邦训练。
- FedAvg 聚合说明。
- 训练历史和联邦训练详情。

接口优先级：

1. `GET /api/federated/nodes`
2. `POST /api/train/dual`
3. `GET /api/train/history`
4. `POST /api/federated/round`

默认展示：

- 四个模拟节点。
- “当前未训练，可点击执行一轮演示”。
- 曲线区域显示空状态或演示曲线。

### 6.4 攻击检测

保留 `pg-detect` 主体。

展示内容：

- 内置样本检测。
- CSV/JSON 上传检测。
- 风险分数、风险等级、攻击类型。
- 检测结果表格。

接口优先级：

1. `POST /api/ensemble/detect`
2. `POST /upload`

默认展示：

```text
正常流量：风险 0.18，低风险
可疑登录：风险 0.63，中风险
异常访问：风险 0.87，高风险
```

必须标注：

```text
演示数据，仅用于答辩流程展示。
```

### 6.5 自适应优化

合并 `pg-enc` 和 `pg-optim`。

展示内容：

- AES / Paillier 指标展示。
- 当前风险等级。
- 当前密钥长度和加密轮数。
- Q-learning 参数调整流程说明。
- 优化历史记录。

接口优先级：

1. `POST /api/compare_encryption`
2. `GET /api/optimization/status`
3. `GET /api/optimization/history`
4. `POST /api/optimization/auto`

默认展示：

- 当前风险：中。
- 密钥长度：2048 bit。
- 加密轮数：10。
- 策略说明：演示参数。
- 历史记录：暂无真实记录，可展示演示记录。

### 6.6 安全防护

保留 `pg-sec`，强化空状态。

展示内容：

- TraceId。
- 慢接口日志。
- 限流日志。
- 安全事件日志。
- 最近安全事件表格。

接口优先级：

1. `GET /api/security/events/recent?limit=50`

默认展示：

- 暂无安全事件。
- TraceId / 慢接口 / 限流 / 安全事件日志功能已接入。
- 可通过访问接口或触发限流产生事件。

### 6.7 实验报告

保持静态页，不接后端。

展示内容：

- 项目概述。
- 技术路线。
- 模块说明。
- 实验流程。
- 创新点。
- 系统边界。
- 答辩讲解建议。

## 7. 容错函数设计

### 7.1 `safeArray(value)`

```javascript
function safeArray(value) {
  return Array.isArray(value) ? value : [];
}
```

用途：

- 替代所有直接 `.map()`、`.forEach()` 前的隐式假设。
- 适用于 `nodes`、`events`、`detections`、`records`、`history`。

### 7.2 `safeObject(value)`

```javascript
function safeObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}
```

用途：

- 保护接口返回对象。
- 保护 `traditional`、`homomorphic`、`comparison` 等嵌套字段。

### 7.3 `getData(payload)`

```javascript
function getData(payload) {
  if (Array.isArray(payload)) return payload;
  var p = safeObject(payload);
  if (p.data !== undefined) {
    var d = p.data;
    if (Array.isArray(d)) return d;
    if (d && typeof d === 'object') {
      if (Array.isArray(d.items)) return d.items;
      if (Array.isArray(d.nodes)) return d.nodes;
      if (Array.isArray(d.events)) return d.events;
      if (Array.isArray(d.detections)) return d.detections;
      return d;
    }
    return d;
  }
  if (Array.isArray(p.items)) return p.items;
  if (Array.isArray(p.nodes)) return p.nodes;
  if (Array.isArray(p.events)) return p.events;
  if (Array.isArray(p.detections)) return p.detections;
  return p;
}
```

注意：

- `getData()` 不能替代业务错误判断。
- 必须配合 `apiFetch()` 的 `ok` 字段使用。

### 7.4 `showEmpty(container, message)`

```javascript
function showEmpty(container, message) {
  var el = typeof container === 'string' ? document.getElementById(container) : container;
  if (!el) return;
  el.innerHTML = '<div class="text-muted text-center py-3">' + esc(message || '暂无数据') + '</div>';
}
```

用途：

- 所有空表格、空图表、空卡片统一显示。
- 避免页面整块空白。

### 7.5 `showDemoBadge()`

```javascript
function showDemoBadge() {
  return '<span class="badge bg-warning text-dark ms-2">演示数据</span>';
}
```

用途：

- 所有兜底数据旁边必须标注。
- 避免把演示数据误认为真实实验结果。

### 7.6 `apiFetch(url, options)`

```javascript
function apiFetch(url, options) {
  return fetch(url, options || {})
    .then(function(resp) {
      return resp.text().then(function(text) {
        var json = null;
        try { json = text ? JSON.parse(text) : {}; }
        catch (e) {
          return {ok: false, data: null, error: 'JSON 解析失败'};
        }
        if (!resp.ok) {
          return {ok: false, data: json, error: 'HTTP ' + resp.status};
        }
        if (json && typeof json.code !== 'undefined' && Number(json.code) !== 200) {
          return {ok: false, data: json.data || {}, error: json.msg || ('业务错误 ' + json.code)};
        }
        return {ok: true, data: json.data !== undefined ? json.data : json, error: null};
      });
    })
    .catch(function(err) {
      return {ok: false, data: null, error: err && err.message ? err.message : '网络请求失败'};
    });
}
```

如果需要兼容旧浏览器，也可以继续用 `XMLHttpRequest` 实现同样返回格式。关键不是使用 `fetch`，而是统一返回：

```javascript
{ ok: boolean, data: any, error: string | null }
```

## 8. 页面展示规则

每个页面必须遵守：

1. 顶部有“本模块说明”。
2. 中间有“当前状态”。
3. 下方有“接口返回数据或演示占位数据”。
4. 接口失败时显示友好提示。
5. 数据为空时显示空状态。
6. 不允许整页空白。
7. 不允许用户一进页面就看到 JS 报错。
8. 不允许 `.map()`、`.forEach()`、`Object.keys()` 直接作用于未知值。
9. 演示数据必须标注“演示数据”。
10. 模拟能力不能写成生产级能力。

## 9. 每个页面默认展示数据

### 9.1 总览

默认数据：

```javascript
{
  title: '基于联邦学习与自适应加密的安全检测演示系统',
  goal: '演示数据处理、联邦训练、攻击检测、自适应优化和安全防护的技术闭环',
  modules: [
    {name: '数据处理', status: '演示可用'},
    {name: '联邦训练', status: '模拟演示'},
    {name: '攻击检测', status: '接口演示'},
    {name: '自适应优化', status: '参数调优演示'},
    {name: '安全防护', status: '事件看板'}
  ]
}
```

### 9.2 数据处理

默认节点：

```javascript
[
  {name: 'hospital', ready: false, samples: 0, label: '演示节点'},
  {name: 'bank', ready: false, samples: 0, label: '演示节点'},
  {name: 'insurance', ready: false, samples: 0, label: '演示节点'},
  {name: 'government', ready: false, samples: 0, label: '演示节点'}
]
```

默认说明：

```text
当前服务器未检测到 UNSW-NB15 处理结果，可点击“处理数据集 + 训练模型”尝试处理；如果未配置 Kaggle 数据集，系统仍可使用演示节点展示答辩流程。
```

### 9.3 联邦训练

默认状态：

```javascript
{
  mode: '单机模拟联邦训练流程',
  round: 0,
  avg_accuracy: '--',
  clients: []
}
```

### 9.4 攻击检测

默认演示结果：

```javascript
[
  {id: 1, name: '正常流量', risk_score: 0.18, risk_level: '低风险', attack_type: 'normal', demo: true},
  {id: 2, name: '可疑登录', risk_score: 0.63, risk_level: '中风险', attack_type: 'suspicious_login', demo: true},
  {id: 3, name: '异常访问', risk_score: 0.87, risk_level: '高风险', attack_type: 'abnormal_access', demo: true}
]
```

### 9.5 自适应优化

默认状态：

```javascript
{
  risk_level: 'medium',
  current_key_length: 2048,
  current_rounds: 10,
  performance_gain: 0,
  strategy: '演示参数'
}
```

### 9.6 安全防护

默认状态：

```text
暂无安全事件。TraceId / 慢接口 / 限流 / 安全事件日志功能已接入，可通过访问接口或触发限流产生事件。
```

### 9.7 实验报告

静态内容，不需要默认数据。

## 10. 真实接口数据优先级

原则：

1. 接口成功且结构有效：显示接口数据。
2. 接口成功但数据为空：显示空状态和必要说明。
3. 接口返回业务失败：显示错误提示和演示占位。
4. 网络错误或 JSON 解析失败：显示错误提示和演示占位。

页面优先级：

| 页面 | 真实接口优先级 | 失败兜底 |
| --- | --- | --- |
| 总览 | `/api/data/statistics`、`/api/data/system_status` | 模块状态卡片 |
| 数据处理 | `/api/dataset/unsw/status`、`/api/federated/nodes` | 四个演示节点 |
| 联邦训练 | `/api/federated/nodes`、`/api/train/history`、`/api/federated/round` | 单机模拟说明 |
| 攻击检测 | `/api/ensemble/detect`、`/upload` | 三条演示检测结果 |
| 自适应优化 | `/api/compare_encryption`、`/api/optimization/status`、`/api/optimization/history` | 默认参数状态 |
| 安全防护 | `/api/security/events/recent?limit=50` | 暂无事件说明 |
| 实验报告 | 无 | 静态展示 |

## 11. 分阶段实现任务

### Task H1：修复全局 JS 容错

目标：

- 解决 `.map()` undefined、接口失败导致页面空白、业务 `code != 200` 被当成功的问题。

允许修改文件：

- `index.html`

禁止修改文件：

- `app.py`
- `src/**`
- `config/**`
- `tests/**`
- `data/**`
- `requirements.txt`

是否允许改后端：

- 不允许。

验收标准：

- 新增 `safeArray()`、`safeObject()`、`getData()`、`showEmpty()`、`showDemoBadge()`、`apiFetch()` 或等价工具函数。
- `procDS()` 不再直接执行 `d.nodes.map(...)`。
- 所有 `.map()`、`.forEach()`、`Object.keys()` 前都有空值保护。
- `POST /api/dataset/unsw/process` 返回 `{code:500,data:{}}` 时页面不崩溃。
- 所有导航点击不出现 JS 报错。

回归测试命令：

```bash
python -m py_compile app.py src/**/*.py
python app.py
curl -i http://127.0.0.1:5000/
curl -i http://127.0.0.1:5000/api/system/health
curl -i http://127.0.0.1:5000/api/dataset/unsw/status
curl -i http://127.0.0.1:5000/api/federated/nodes
curl -i -X POST http://127.0.0.1:5000/api/dataset/unsw/process -H "Content-Type: application/json" -d "{}"
```

### Task H2：重构总览页为答辩入口

目标：

- 将总览页调整为答辩入口，而不是普通数据看板。

允许修改文件：

- `index.html`

禁止修改文件：

- 后端和数据文件全部禁止。

是否允许改后端：

- 不允许。

验收标准：

- 总览位于导航第一项。
- 展示项目名称、一句话目标、演示流程、模块状态卡片和推荐演示顺序。
- 接口失败时仍显示稳定默认内容。

回归测试命令：

```bash
curl -i http://127.0.0.1:5000/
curl -i http://127.0.0.1:5000/api/data/statistics
```

### Task H3：合并数据处理 + 数据集处理为稳定数据处理页

目标：

- 合并 `pg-data` 和 `pg-ds` 的展示逻辑。
- 数据集未下载时不报错。

允许修改文件：

- `index.html`

禁止修改文件：

- 后端和数据文件全部禁止。

是否允许改后端：

- 不允许。

验收标准：

- 主导航只保留一个“数据处理”入口。
- 页面显示数据生成、密态样本、UNSW-NB15 状态和四个模拟节点。
- 数据集缺失时显示友好说明。
- 四个节点即使未加载也显示为演示节点。

回归测试命令：

```bash
curl -i http://127.0.0.1:5000/api/dataset/unsw/status
curl -i http://127.0.0.1:5000/api/federated/nodes
```

### Task H4：合并模型训练 + 联邦训练为联邦训练页

目标：

- 合并本地训练和四节点模拟联邦训练展示。

允许修改文件：

- `index.html`

禁止修改文件：

- 后端和数据文件全部禁止。

是否允许改后端：

- 不允许。

验收标准：

- 主导航只保留一个“联邦训练”入口。
- 本地训练、训练历史、四节点模拟、FedAvg 聚合说明均可见。
- 无数据时显示“当前未训练 / 可执行一轮演示”。

回归测试命令：

```bash
curl -i http://127.0.0.1:5000/api/train/history
curl -i http://127.0.0.1:5000/api/federated/nodes
```

### Task H5：整理攻击检测页，增加演示数据兜底

目标：

- 接口可用时显示真实检测结果。
- 接口失败或返回为空时显示三条明确标注的演示结果。

允许修改文件：

- `index.html`

禁止修改文件：

- 后端和数据文件全部禁止。

是否允许改后端：

- 不允许。

验收标准：

- `detSample()`、`detFile()`、`showDetRes()` 保留。
- `POST /api/ensemble/detect` 和 `POST /upload` 保留。
- 空结果时表格不空白。
- 演示结果必须标注“演示数据，仅用于答辩流程展示”。

回归测试命令：

```bash
curl -i http://127.0.0.1:5000/api/ensemble/status
```

### Task H6：合并加密对比 + 自适应优化为自适应优化页

目标：

- 合并 AES/Paillier 指标和 Q-learning 参数调整流程。

允许修改文件：

- `index.html`

禁止修改文件：

- 后端和数据文件全部禁止。

是否允许改后端：

- 不允许。

验收标准：

- 主导航只保留一个“自适应优化”入口。
- `updEnc()`、`loadOpt()`、`toggleAuto()` 保留或通过兼容 wrapper 保留。
- 接口为空时显示默认风险、密钥长度、轮数和演示历史。

回归测试命令：

```bash
curl -i http://127.0.0.1:5000/api/optimization/status
curl -i http://127.0.0.1:5000/api/optimization/history
```

### Task H7：整理安全防护页空状态

目标：

- 安全事件为空时不显得像坏掉。

允许修改文件：

- `index.html`

禁止修改文件：

- 后端和数据文件全部禁止。

是否允许改后端：

- 不允许。

验收标准：

- `loadSec()`、`ensureSecTimer()`、`esc()` 保留。
- 空事件时显示 TraceId / 慢接口 / 限流 / 安全事件日志已接入说明。
- API 失败时显示友好错误，不清空全页。

回归测试命令：

```bash
curl -i http://127.0.0.1:5000/api/security/events/recent?limit=50
```

### Task H8：检查实验报告页和全导航流程

目标：

- 确认最终 7 页导航流程完整。

允许修改文件：

- `index.html`

禁止修改文件：

- 后端和数据文件全部禁止。

是否允许改后端：

- 不允许。

验收标准：

- 主导航为：总览、数据处理、联邦训练、攻击检测、自适应优化、安全防护、实验报告。
- 点击每个导航都不报错。
- 每个页面都有默认展示。
- 实验报告仍为静态页，不接 `/api/export/report`。

回归测试命令：

```bash
curl -i http://127.0.0.1:5000/
curl -i http://127.0.0.1:5000/api/system/health
curl -i http://127.0.0.1:5000/api/security/events/recent
```

## 12. 风险点和回滚方案

### 12.1 风险点

- 一次性重写 `index.html` 容易破坏现有函数和 API 调用。
- 合并页面时如果直接删除旧页面块，可能导致旧函数仍引用不存在的 DOM id。
- 修改导航时如果 `data-page` 与 `pg-*` 不一致，会出现点击空白。
- 改用 `fetch` 时要确认目标浏览器兼容性；如果不确定，可继续用 `XMLHttpRequest` 封装 `apiFetch()`。
- 演示数据必须明确标注，不能被写成真实实验结果。
- 不应为了前端展示去下载数据集、训练模型或新增后端逻辑。

### 12.2 回滚方案

每个 H 任务都应单独提交。

回滚单个任务：

```bash
git revert <task_commit_hash>
```

快速恢复当前线上版本：

```bash
git reset --hard 1b377a5
```

回滚后验证：

```bash
python -m py_compile app.py src/**/*.py
python app.py
curl -i http://127.0.0.1:5000/
curl -i http://127.0.0.1:5000/api/system/health
```

## 13. 推荐实施顺序

必须先做 H1。

原因：

- H1 是稳定性底座。
- 当前 `.map()` 报错和空白页问题必须先解决。
- 没有全局容错层，后续页面合并会继续放大风险。

推荐顺序：

```text
H1 全局容错
H2 总览
H3 数据处理
H4 联邦训练
H5 攻击检测
H6 自适应优化
H7 安全防护
H8 全流程检查
```

每次只做一个任务，每次完成后由 Codex 做代码审查和页面回归。

