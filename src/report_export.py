"""Small, offline PDF export. Reads saved evidence; never invokes a detector/AI."""
import os
import re
import threading
from io import BytesIO
from xml.sax.saxutils import escape

_FONT_LOCK = threading.Lock()
_FONT_NAME = "PlatformCJK"


def _dict(value):
    return value if isinstance(value, dict) else {}


def _list(value):
    return value if isinstance(value, list) else []


def _text(value):
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(value if value is not None else "未记录"))


def risk_label(value):
    return {"low": "低风险", "medium": "中风险", "high": "高风险", "critical": "严重风险"}.get(str(value), "未评估")


def report_rows(analysis):
    """Export every saved analyzed row, not just the screen's priority preview."""
    ranking = _list(analysis.get("risk_ranking") or analysis.get("high_risk_reasons"))
    details = {str(r.get("id")): r for r in ranking if isinstance(r, dict)}
    rows, seen = [], set()
    for row in _list(analysis.get("detections")) + ranking:
        if not isinstance(row, dict):
            continue
        key = str(row.get("id"))
        if key in seen:
            continue
        rows.append(dict(row, **details.get(key, {})))
        seen.add(key)
    def score(row):
        try:
            return float(row.get("risk_score") or 0)
        except (TypeError, ValueError):
            return 0
    return sorted(rows, key=score, reverse=True)


def build_report_pdf(payload):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, LongTable

    with _FONT_LOCK:
        if _FONT_NAME not in pdfmetrics.getRegisteredFontNames():
            font_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "fonts", "wqy-microhei.ttc")
            pdfmetrics.registerFont(TTFont(_FONT_NAME, font_path, subfontIndex=0))

    blue, gray = colors.HexColor("#5279A4"), colors.HexColor("#65758A")
    body = ParagraphStyle("body", fontName=_FONT_NAME, fontSize=9, leading=14,
                          textColor=colors.HexColor("#26394C"), wordWrap="CJK", alignment=TA_LEFT)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=12)
    title = ParagraphStyle("title", parent=body, fontSize=21, leading=30, textColor=blue, spaceAfter=7*mm)
    heading = ParagraphStyle("heading", parent=body, fontSize=12, leading=18, textColor=blue,
                             spaceBefore=5*mm, spaceAfter=3*mm, keepWithNext=True)
    def para(value, style=body, cell=False):
        value = _text(value)
        # Prevent a malformed stored field from making one unsplittable table
        # row taller than a page. Normal platform fields are already shorter.
        if cell and len(value) > 600:
            value = value[:600] + "（长内容详见平台明细）"
        return Paragraph(escape(value).replace("\n", "<br/>"), style)
    def lines(values):
        return "\n".join(_text(value) for value in values if value not in (None, ""))
    def table_style():
        return TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EFF4F9")),
            ("LINEBELOW", (0, 0), (-1, 0), .6, colors.HexColor("#CDDAE8")),
            ("LINEBELOW", (0, 1), (-1, -1), .3, colors.HexColor("#E1E8F0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ])

    payload = _dict(payload)
    submission, analysis = _dict(payload.get("submission")), _dict(payload.get("analysis"))
    trace, privacy = _dict(analysis.get("analysis_trace")), _dict(analysis.get("privacy_risk"))
    external = _dict(payload.get("external_analysis") or submission.get("external_analysis"))
    advice = _dict(external.get("advice"))
    decisions = {str(d.get("sample_id")): d for d in _list(external.get("assisted_decisions")) if isinstance(d, dict)}
    rows = report_rows(analysis)
    summary = _dict(analysis.get("risk_summary"))
    def count(key):
        return int(summary.get(key, summary.get(key + "_count", 0)) or 0)
    total = int(analysis.get("total") or len(rows))
    stream = BytesIO()
    document = SimpleDocTemplate(stream, pagesize=A4, leftMargin=16*mm, rightMargin=16*mm,
                                 topMargin=18*mm, bottomMargin=18*mm,
                                 title="隐私与攻击风险分析报告", author="密码攻击检测与隐私训练平台")
    width = A4[0] - 32*mm
    story = [para("隐私与攻击风险分析报告", title)]
    meta = [("文件", submission.get("filename")), ("提交编号", submission.get("id")),
            ("提交时间", submission.get("upload_time")), ("检测时间", analysis.get("analyzed_at")),
            ("检测范围", "%s / %s 条" % (total, trace.get("source_rows", submission.get("row_count", total))))]
    table = Table([[para(k, small), para(v, small)] for k, v in meta], colWidths=[24*mm, width-24*mm])
    table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    story.extend([table, para("一、检测结论", heading)])
    story.append(para("高风险 %s 条    中风险 %s 条    低风险 %s 条" %
                      (count("high") + count("critical"), count("medium"), count("low"))))
    story.append(para("隐私等级：%s；规则评分：%s（不是泄露概率）。归档方式：%s。" % (
        privacy.get("level_zh") or risk_label(privacy.get("level")), privacy.get("score", "未评估"),
        (submission.get("encryption") or "AES 加密") if submission.get("encrypted") else "未记录")))
    story.append(para(_dict(analysis.get("dual_risk")).get("recommended_action") or
                      ("优先核查中高风险记录，并结合业务确认。" if count("high")+count("medium") else "本次未发现中高风险记录。")))
    story.append(para("二、处理计划", heading))
    for index, item in enumerate(_list(analysis.get("suggestions")) or ["结合业务核实异常记录。"], 1):
        story.append(para("%s. %s" % (index, item)))
    story.append(para("三、已保存的 AI 复核结论", heading))
    if advice.get("summary"):
        story.append(para(advice["summary"]))
        story.append(para("模型：%s    复核时间：%s" % (external.get("model", "未记录"), external.get("generated_at", "未记录")), small))
        scope = _dict(external.get("review_scope"))
        reviewed = scope.get("reviewed", len(decisions))
        story.append(para("已复核 %s 条；范围：%s。" % (reviewed, scope.get("label") or "以逐样本已存结论为准"), small))
        for key, label in (("privacy_findings", "隐私判断"), ("attack_findings", "攻击判断"), ("recommended_actions", "AI 建议")):
            for item in _list(advice.get(key)):
                story.append(para("%s：%s" % (label, item)))
    else:
        story.append(para("本次未使用 AI。检测结论来自本地模型。"))
    story.append(para("下载只读取保存结果，不重新检测或调用 AI。", small))
    story.append(para("四、样本明细", heading))
    story.append(para("共导出 %s 条已保存的样本，按本地风险分数排序。未保存的 IP 或 AI 结论不作推断。" % len(rows), small))
    header = ["IP / 样本", "本地风险", "判断依据", "本地建议", "AI 结论 / 建议"]
    cells = [[para(value, small) for value in header]]
    for row in rows:
        decision = decisions.get(str(row.get("id")))
        ai_text = "无逐样本 AI 结论"
        if decision:
            ai_text = lines(["AI：" + risk_label(decision.get("ai_risk_level")),
                             "综合：" + risk_label(decision.get("combined_risk_level")),
                             decision.get("recommended_action") or decision.get("reason")])
        values = [lines([row.get("ip") or (decision or {}).get("ip") or "未提供 IP", "样本 %s" % row.get("id", "-"), row.get("username")]),
                  lines([risk_label(row.get("risk_level")), "分数 %s" % row.get("risk_score", "未记录")]),
                  row.get("reason") or row.get("dominant_factor") or "无异常依据记录",
                  row.get("suggestion") or row.get("action_suggestion") or "结合业务复核", ai_text]
        cells.append([para(value, small, cell=True) for value in values])
    if len(cells) > 1:
        table = LongTable(cells, colWidths=[width*v for v in (.19, .12, .24, .23, .22)], repeatRows=1)
        table.setStyle(table_style())
        story.append(table)
    else:
        story.append(para("暂无已保存的样本明细。"))
    story.append(para("五、数据与模型追溯", heading))
    for label, key in (("数据修订", "data_revision"), ("检测模型", "model_version"),
                       ("预处理版本", "preprocessing_version"), ("策略版本", "analysis_policy_version")):
        story.append(para("%s：%s" % (label, trace.get(key) or "未记录"), small))

    def page_frame(canvas, doc):
        canvas.saveState()
        canvas.setFont(_FONT_NAME, 8)
        canvas.setFillColor(gray)
        canvas.drawString(16*mm, A4[1]-11*mm, "密码攻击检测与隐私训练平台")
        canvas.drawString(16*mm, 10*mm, "风险类型及 AI 判断用于辅助复核，不代表真实攻击已经发生。")
        canvas.drawRightString(A4[0]-16*mm, 10*mm, "第 %s 页" % doc.page)
        canvas.restoreState()
    document.build(story, onFirstPage=page_frame, onLaterPages=page_frame)
    return stream.getvalue()
