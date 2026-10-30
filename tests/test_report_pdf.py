import copy
import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from pypdf import PdfReader

import app as a
from src.report_export import build_report_pdf, report_rows


def payload(n=125):
    rows = [{"id": i+1, "ip": "198.51.100.%s" % (i+1), "risk_score": .8,
             "risk_level": "high", "reason": "短时间内连续失败，需核实是否本人重试。",
             "suggestion": "联系账号使用者核实，排除本人操作后启用二次验证。"} for i in range(n)]
    return {"submission": {"id": "pdf-unit", "filename": "登录事件.csv", "upload_time": "2026-10-30 10:00:00", "encrypted": True},
            "analysis": {"total": n, "risk_summary": {"high": n}, "detections": rows,
                         "risk_ranking": rows[:10], "analyzed_at": "2026-10-30 10:00:03",
                         "analysis_trace": {"analysis_id": "ana-pdf", "source_rows": n+10, "model_version": "unit-model"}},
            "external_analysis": {"model": "saved-test-model", "generated_at": "2026-10-30 10:01:00",
                                  "advice": {"summary": "已保存的 AI 复核摘要，不是新的调用。"},
                                  "assisted_decisions": [{"sample_id": n, "ai_risk_level": "high", "combined_risk_level": "high", "recommended_action": "逐样本建议：先核对授权来源。"}]}}


def test_pdf_embeds_chinese_and_all_rows_without_html_or_ai_calls():
    data = payload()
    original = copy.deepcopy(data)
    content = build_report_pdf(data)
    assert content.startswith(b"%PDF-")
    doc = PdfReader(io.BytesIO(content))
    text = "\n".join(page.extract_text() for page in doc.pages)
    for phrase in ("隐私与攻击风险分析报告", "198.51.100.125", "逐样本建议", "已保存的 AI 复核摘要", "125 / 135 条", "共导出 125 条", "提交时间"):
        assert phrase in text
    assert len(doc.pages) > 2
    assert sum("AI 结论 / 建议" in page.extract_text() for page in doc.pages) > 1
    fonts = []
    for page in doc.pages:
        for ref in page["/Resources"].get("/Font", {}).values():
            font = ref.get_object()
            if font.get("/FontDescriptor"):
                fonts.append(font["/FontDescriptor"].get_object())
    assert any("/FontFile2" in font for font in fonts)
    assert data == original


def test_pdf_handles_markup_long_strings_and_missing_ai():
    data = payload(1)
    data["external_analysis"] = {}
    data["analysis"]["detections"][0]["reason"] = '<img src="https://never.invalid/image.png"/><script>do_not_run</script>' + "长" * 1600
    content = build_report_pdf(data)
    text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(content)).pages)
    assert "本次未使用 AI" in text
    assert "do_not_run" in "".join(text.split())
    assert "长内容详见平台明细" in text
    assert "无逐样本 AI 结论" in text


def test_report_rows_merge_details_without_losing_low_risk():
    data = payload(3)["analysis"]
    data["risk_ranking"] = [{"id": 2, "ip": "203.0.113.2", "risk_score": .9}]
    data["detections"][0]["risk_level"] = "low"
    result = report_rows(data)
    assert len(result) == 3
    assert result[0]["ip"] == "203.0.113.2"
    assert any(row.get("risk_level") == "low" for row in result)


def test_pdf_endpoint_ownership_revision_and_real_attachment():
    client = a.app.test_client()
    url = "/api/user/reports/pdf-unit/download"
    with patch.object(a.user_submission_manager, "get_report", return_value=payload(2)) as read, \
         patch.object(a, "_create_external_advisor_client") as ai, \
         patch.object(a.user_submission_manager, "analyze") as analyze:
        assert client.get(url).status_code == 403
        read.assert_not_called()
        with client.session_transaction() as session:
            session[a.USER_SUBMISSION_SESSION_KEY] = ["pdf-unit"]
        assert client.get(url + "?analysis_id=stale").status_code == 409
        result = client.get(url + "?analysis_id=ana-pdf")
        assert result.status_code == 200
        assert result.data.startswith(b"%PDF-")
        assert result.mimetype == "application/pdf"
        assert '.pdf"' in result.headers["Content-Disposition"]
        assert "no-store" in result.headers["Cache-Control"]
        ai.assert_not_called(); analyze.assert_not_called()


def test_pdf_endpoint_missing_busy_and_failure_unlock():
    client = a.app.test_client()
    with client.session_transaction() as session:
        session[a.USER_SUBMISSION_SESSION_KEY] = ["pdf-unit"]
    url = "/api/user/reports/pdf-unit/download"
    with patch.object(a.user_submission_manager, "get_report", return_value=None):
        assert client.get(url).status_code == 404
    with patch.object(a.user_submission_manager, "get_report", return_value={"analysis": {}}):
        assert client.get(url).status_code == 409
    a._pdf_export_lock.acquire()
    try:
        assert client.get(url).status_code == 429
    finally:
        a._pdf_export_lock.release()
    with patch.object(a.user_submission_manager, "get_report", return_value=payload(1)), \
         patch("src.report_export.build_report_pdf", side_effect=ImportError("reportlab")):
        result = client.get(url)
        assert result.status_code == 503
    assert not a._pdf_export_lock.locked()


def test_report_screen_has_no_duplicate_chart_and_page_is_not_cached():
    html = Path("index.html").read_text(encoding="utf-8")
    report = html.split('<section class="page" id="pg-report">', 1)[1].split("</section>", 1)[0]
    assert "reportCharts" not in report
    assert "风险分布" not in report
    assert "主要触发因素" not in report
    assert "buildReportDocument" not in html
    assert "risk-report.html" not in html
    response = a.app.test_client().get("/")
    assert response.status_code == 200
    assert "no-store" in response.headers["Cache-Control"]
