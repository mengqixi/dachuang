# CODEX_REVIEW_PRACTICAL_TASK3_4_RISK_PIPELINE

## 审核结论

Task 3 / Task 4 增量通过。当前用户端风险检测已经以统一风险字段输出，前端使用“风险排名”，且没有继续保留独立风险详情模块或 Top 20 文案。

## 本次修改

- 新增 `tests/test_practical_platform.py`。
- 修复 `src/user_submission_manager.py` 中 AES 归档读取文件未关闭句柄的问题。

## 覆盖要求

1. 用户端仍包含上传数据、风险检测、分析报告三页。
2. 前端包含风险排名和风险排名摘要。
3. 前端不包含 `Top 20` 文案。
4. 前端不包含“风险详情模块”或“展开详情按钮”文案。
5. 上传登录安全 CSV 后，分析接口返回统一检测字段：
   - is_risk
   - risk_score
   - risk_level
   - attack_type
   - confidence
   - action_suggestion
   - detection_time_ms
   - trigger_features
   - score_breakdown
   - reason
   - suggestion
   - source_dataset
   - model_version
6. `risk_ranking` 按 `risk_score` 降序。
7. `risk_ranking_limit` 和统计字段存在。

## 验证结果

- `python -m compileall -q app.py src tests\test_practical_platform.py`：通过。
- `python -W error::ResourceWarning -m unittest tests.test_practical_platform -v`：2 个测试通过，无 ResourceWarning。

## 未提交内容

- `data/system.db`：运行数据库，不应提交。
- `data/user_submissions/`：测试/运行提交数据，不应提交。

## 后续建议

继续维护这组回归测试。后续修改用户端检测页、报告页或上传分析接口时，必须保持统一风险字段和风险排名语义不回退。
