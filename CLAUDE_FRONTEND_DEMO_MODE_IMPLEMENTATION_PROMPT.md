# 给 Claude 的前端答辩展示版开发任务

## 背景

当前项目是 Flask + SQLite 的大创演示系统。前端已经经历多轮文案整理，但线上实际展示效果仍不稳定：

1. 多个导航页面点击后出现大面积空白。
2. 数据集未加载时页面容易报错。
3. 数据集处理、联邦节点、训练、检测、优化、安全看板之间缺少清晰答辩主线。
4. 当前导航入口过多，像功能堆叠，不像答辩展示流程。
5. 现在目标不是继续堆功能，而是搭建一个稳定、清晰、可讲解的“答辩演示版前端框架”。

请你只做前端展示框架整理，不要新增后端功能。

## 总目标

把当前前端改成“答辩演示版前端”：

```text
总览
↓
数据处理
↓
联邦训练
↓
攻击检测
↓
自适应优化
↓
安全防护
↓
实验报告
```

每个页面都必须满足：

- 首屏不空白。
- 接口失败不崩溃。
- 数据为空时显示友好占位。
- 后端接口能用就展示真实返回。
- 后端接口不可用时展示“演示数据 / 当前未加载 / 请先处理数据集”。
- 所有演示数据必须明确标注“演示数据，仅用于答辩流程展示”。
- 不把模拟能力写成生产级能力。

## 严格限制

只允许修改：

- `index.html`

禁止修改：

- `app.py`
- `src/**`
- `config/**`
- `tests/**`
- `data/**`
- `requirements.txt`
- 任何后端 API
- 数据库结构
- 模型文件
- 数据集文件

禁止：

- 不要引入 React / Vue / Angular。
- 不要新增复杂依赖。
- 不要下载数据集。
- 不要新增模型训练逻辑。
- 不要新增后端接口。
- 不要删除原有 API 调用。
- 不要把演示数据写成真实实验结果。
- 不要把联邦训练写成真实生产级跨机构部署。
- 不要把 Paillier 写成完整生产级安全聚合。
- 不要把安全防护写成完整企业级安全运营平台。

## 当前页面空白的优先修复原则

当前线上截图显示：顶部导航存在，但内容区域为空白。这说明前端必须先保证：

1. 页面默认打开时一定显示“总览”。
2. 即使 JS 某个加载函数报错，也不能导致主内容区空白。
3. 每个 `data-page` 必须有对应内容容器。
4. 每个页面容器必须有静态兜底内容。
5. 所有接口加载都只能增强页面，不能决定页面是否存在。

请采用“静态框架先显示，接口数据后填充”的方式。

## 新导航结构

请把主导航整理为 7 个入口：

1. 总览
2. 数据处理
3. 联邦训练
4. 攻击检测
5. 自适应优化
6. 安全防护
7. 实验报告

推荐 `data-page`：

```html
data-page="overview"
data-page="data"
data-page="federated"
data-page="detect"
data-page="optimize"
data-page="security"
data-page="report"
```

对应页面容器：

```html
id="pg-overview"
id="pg-data"
id="pg-federated"
id="pg-detect"
id="pg-optimize"
id="pg-security"
id="pg-report"
```

注意：

- 如果为了兼容旧函数，需要保留旧 `pg-ds`、`pg-train`、`pg-fed`、`pg-enc`、`pg-optim`、`pg-dash`，可以隐藏保留。
- 但主导航只展示 7 个入口。
- 不要让导航指向不存在的页面。

## 全局前端框架要求

请在 `index.html` 中建立一个小型前端框架，不要写很多复杂代码。

必须包含以下工具函数：

```javascript
function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function escapeHtml(value) {
  value = value === null || value === undefined ? '' : String(value);
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function showEmpty(target, message) {
  var el = typeof target === 'string' ? document.getElementById(target) : target;
  if (!el) return;
  el.innerHTML = '<div class="empty-state">' + escapeHtml(message || '暂无数据') + '</div>';
}

function demoBadge() {
  return '<span class="demo-badge">演示数据</span>';
}
```

必须有统一请求函数：

```javascript
function apiGet(url, callback) {}
function apiPost(url, body, callback) {}
```

要求：

- 捕获网络错误。
- 捕获 JSON 解析失败。
- HTTP 非 200 返回错误。
- 业务 `code !== 200` 返回错误。
- 返回结构统一为：

```javascript
callback({
  ok: true或false,
  data: 数据对象,
  error: 错误信息
});
```

特别注意：

`POST /api/dataset/unsw/process` 可能返回：

```json
{
  "code": 500,
  "msg": "处理失败",
  "data": {}
}
```

这种情况必须作为失败处理，不能继续执行 `data.nodes.map(...)`。

## 页面切换要求

请实现稳定导航：

```javascript
function showPage(page) {}
```

要求：

- 所有页面先隐藏。
- 目标页面存在才显示。
- 目标页面不存在时显示总览。
- 页面显示后再执行对应加载函数。
- 加载函数必须包 `try/catch`。
- 加载失败不能让页面空白。

伪代码：

```javascript
function runSafe(fn) {
  try {
    if (typeof fn === 'function') fn();
  } catch (e) {
    console.error(e);
  }
}
```

## 页面一：总览

用途：

作为答辩入口，不要做成普通监控页。

必须展示：

1. 项目名称。
2. 一句话目标：

```text
面向隐私保护场景的攻击检测、联邦训练与自适应加密演示系统。
```

3. 技术路线：

```text
数据处理 → 联邦训练 → 攻击检测 → 自适应优化 → 安全防护 → 实验报告
```

4. 模块状态卡片：

- 数据处理：演示可用
- 联邦训练：单机模拟
- 攻击检测：接口演示
- 自适应优化：参数调优演示
- 安全防护：事件看板

5. 推荐演示顺序。

接口增强：

- 可尝试读取 `/api/system/health`
- 可尝试读取 `/api/data/statistics`
- 接口失败时仍显示静态默认内容。

## 页面二：数据处理

合并原：

- 数据处理
- 数据集处理

必须展示：

1. 本模块说明。
2. 数据生成演示区。
3. 明文样本预览。
4. Paillier 密态样本预览。
5. UNSW-NB15 数据集状态。
6. 四个模拟节点：

- hospital
- bank
- insurance
- government

接口：

- `POST /api/generate_dataset`
- `GET /api/dataset/unsw/status`
- `GET /api/federated/nodes`
- `POST /api/dataset/unsw/process`

数据集未加载时必须显示：

```text
数据集状态：未加载
当前服务器未检测到 UNSW-NB15 处理结果。可点击“处理数据集 + 训练模型”尝试处理；如果未配置 Kaggle 数据集，系统仍可使用演示节点展示答辩流程。
```

四个节点即使后端未准备好，也要显示为：

```text
hospital：演示节点，当前未加载
bank：演示节点，当前未加载
insurance：演示节点，当前未加载
government：演示节点，当前未加载
```

禁止：

- 不要因为数据集不存在而白屏。
- 不要因为 `nodes` 不存在而 `.map()` 报错。
- 不要自动下载数据集。

## 页面三：联邦训练

合并原：

- 模型训练
- 联邦训练

必须展示：

1. 本模块说明。
2. 本地训练演示。
3. 四节点模拟联邦训练。
4. FedAvg 聚合说明。
5. 训练历史或空状态。
6. 一轮联邦训练按钮。

接口：

- `POST /api/train/dual`
- `GET /api/train/history`
- `GET /api/federated/nodes`
- `POST /api/federated/round`

默认状态：

```text
当前尚未执行训练，可点击按钮运行演示流程。
如果数据集未处理，联邦训练将以当前后端可用状态为准。
```

文案必须说明：

```text
当前为单机模拟联邦训练流程，不代表真实生产级跨机构部署。
```

## 页面四：攻击检测

保留原：

- 内置样本检测
- 文件上传检测
- 检测结果表格

接口：

- `POST /api/ensemble/detect`
- `POST /upload`

如果接口成功：

- 显示真实返回的 `risk_score`
- 显示 `risk_level`
- 显示 `attack_type`

如果接口失败或返回为空：

显示演示数据：

```text
正常流量：风险 0.18，低风险
可疑登录：风险 0.63，中风险
异常访问：风险 0.87，高风险
```

必须标注：

```text
演示数据，仅用于答辩流程展示。
```

禁止：

- 不要写成真实在线流量检测平台。
- 不要写成生产级三模型系统。

## 页面五：自适应优化

合并原：

- 加密对比
- 自适应优化

必须展示：

1. AES / Paillier 指标展示。
2. 当前风险等级。
3. 密钥长度。
4. 加密轮数。
5. Q-learning 参数调整流程说明。
6. 优化历史或空状态。

接口：

- `POST /api/compare_encryption`
- `GET /api/optimization/status`
- `GET /api/optimization/history`
- `POST /api/optimization/auto`

接口为空时默认显示：

```text
当前风险：中
密钥长度：2048 bit
加密轮数：10
策略说明：演示参数
历史记录：暂无真实记录
```

文案必须说明：

```text
当前页面用于展示参数调整流程，不代表完整生产级密码学评测或智能安全策略平台。
```

## 页面六：安全防护

保留原安全事件看板，但空状态要更清楚。

接口：

- `GET /api/security/events/recent?limit=50`

必须展示：

- TraceId 请求链路追踪
- 慢接口日志
- 限流日志
- 安全事件日志
- 最近事件表格

如果事件为空，显示：

```text
暂无安全事件。
TraceId / 慢接口 / 限流 / 安全事件日志功能已接入。
可通过访问接口或触发限流产生事件。
```

禁止：

- 不要写成完整 WAF。
- 不要写成企业级安全运营平台。
- 不要写成已经实现防重放、签名验签、IP 黑白名单。

## 页面七：实验报告

静态页面即可。

必须包含：

1. 项目概述。
2. 技术路线。
3. 模块说明。
4. 实验流程。
5. 创新点。
6. 当前系统边界。
7. 答辩讲解建议。

禁止：

- 不要调用 `/api/export/report`。
- 不要新增报告导出功能。

## 必须保留的原 API

不要删除或改名这些字符串：

```text
/api/system/health
/api/generate_dataset
/api/dataset/unsw/status
/api/federated/nodes
/api/dataset/unsw/process
/api/train/dual
/api/train/history
/api/federated/round
/api/ensemble/detect
/upload
/api/compare_encryption
/api/optimization/status
/api/optimization/history
/api/optimization/auto
/api/security/events/recent?limit=50
```

## 必须解决的问题

1. 页面默认打开不能空白。
2. 点击任意导航不能空白。
3. 数据集未下载不能报错。
4. `POST /api/dataset/unsw/process` 返回业务 `code:500` 时不能继续当成功处理。
5. 不允许再出现：

```text
Cannot read properties of undefined (reading 'map')
```

6. 不允许 `.map()`、`.forEach()`、`Object.keys()` 直接作用于未知值。
7. 接口失败时显示友好提示和演示占位。
8. 所有演示数据必须标注“演示数据”。

## 建议实现方式

不要一次性写复杂功能。

优先实现最小稳定框架：

1. 重写主导航为 7 项。
2. 每个页面先放静态兜底内容。
3. 再逐个接入现有 API。
4. API 失败不影响静态内容。
5. 数据为空只更新局部区域，不清空整页。

## 验收标准

完成后必须满足：

1. `/` 返回 200。
2. 首页默认显示“总览”，不是空白。
3. 点击 7 个导航都能显示内容。
4. 数据处理页在数据集不存在时仍能显示四个演示节点。
5. 点击“处理数据集 + 训练模型”失败时只提示错误，不白屏。
6. 攻击检测页有演示兜底结果。
7. 自适应优化页有默认参数状态。
8. 安全防护页空事件时有说明。
9. 实验报告页可打开。
10. 浏览器控制台没有明显 JS 报错。
11. 不修改任何后端文件。

## 建议测试命令

```bash
python -m py_compile app.py src/**/*.py
python app.py
curl -i http://127.0.0.1:5000/
curl -i http://127.0.0.1:5000/api/system/health
curl -i http://127.0.0.1:5000/api/dataset/unsw/status
curl -i http://127.0.0.1:5000/api/federated/nodes
curl -i -X POST http://127.0.0.1:5000/api/dataset/unsw/process -H "Content-Type: application/json" -d "{}"
curl -i http://127.0.0.1:5000/api/security/events/recent?limit=50
```

浏览器检查：

1. 打开 `/`。
2. 确认默认显示总览。
3. 依次点击：
   - 总览
   - 数据处理
   - 联邦训练
   - 攻击检测
   - 自适应优化
   - 安全防护
   - 实验报告
4. 点击数据处理页的处理按钮。
5. 确认页面不白屏。
6. 确认控制台没有 `.map()` undefined 报错。

## 最终输出给 Codex 审核

完成后请告诉 Codex：

1. 修改了哪些文件。
2. 是否只修改 `index.html`。
3. 是否新增后端功能。
4. 是否保留所有旧 API 字符串。
5. 是否解决页面空白。
6. 是否解决数据集 `.map()` 报错。
7. 数据集未加载时页面如何展示。
8. 是否所有演示数据都标注为演示数据。
9. 是否可以进入 Codex 审核。

