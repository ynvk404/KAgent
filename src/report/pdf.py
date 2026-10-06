"""Local Unicode Platypus renderer. Source text is always literal."""
from __future__ import annotations

import hashlib
import io
import os
import threading
import unicodedata
from html import escape
from pathlib import Path

from src.report.model import MAX_DOCUMENT, MAX_PAGES, MAX_PDF, ReportDocument, ReportError
from src.tools.execution.sensitive import is_sensitive_path

_FONT_LOCK = threading.Lock()  # ReportLab font registration/subsetting is global.
FONT_CANDIDATES = (
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf", "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf"),
    ("/usr/share/fonts/truetype/noto/NotoSansDisplay-Regular.ttf", "/usr/share/fonts/truetype/noto/NotoSansDisplay-Bold.ttf"),
)
VIETNAMESE = frozenset(range(0x1EA0, 0x1EFA)) | {ord("Đ"), ord("đ")}
FONT_ERROR = "a Vietnamese-capable local TrueType font is required. Set KAGENT_REPORT_FONT_REGULAR (and optionally KAGENT_REPORT_FONT_BOLD) to local TTF files."


class BoundedBuffer(io.BytesIO):
    def write(self, data):
        if max(self.tell() + len(data), len(self.getbuffer())) > MAX_PDF:
            raise ReportError("PDF output exceeds report byte limit; reduce report detail and retry.")
        return super().write(data)


def _font_bytes(path: str) -> bytes:
    resource = Path(path)
    if resource.suffix.lower() != ".ttf" or resource.is_symlink() or is_sensitive_path(str(resource)) or is_sensitive_path(str(resource.resolve())):
        raise ValueError("invalid font resource")
    fd = os.open(resource, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        import stat
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 16 * 1024 * 1024:
            raise ValueError("invalid font bound")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("invalid font bound")
        return raw
    finally:
        os.close(fd)


def render_pdf(document: ReportDocument) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.pdfgen.canvas import Canvas
        from reportlab.platypus import Flowable, LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle
    except ImportError:
        raise ReportError("PDF dependency unavailable. Install the project's declared dependencies in the active environment.") from None
    texts = document.text_values()
    if sum(len(t.encode("utf-8", "replace")) for t in texts) > MAX_DOCUMENT:
        raise ReportError("Sanitized report exceeds document size limit.")
    required = {ord(c) for t in texts for c in unicodedata.normalize("NFC", t) if not c.isspace()}
    required |= {ord(c) for c in "KAgent Assessment Summary Confirmed findings Evidence Recorded attack surface coverage Methodology limitations Page0123456789"}
    override = os.getenv("KAGENT_REPORT_FONT_REGULAR")
    candidates = ((override, os.getenv("KAGENT_REPORT_FONT_BOLD") or override),) if override else FONT_CANDIDATES
    with _FONT_LOCK:
        regular = bold = None
        for regular_path, bold_path in candidates:
            try:
                raw = _font_bytes(regular_path)
                name = "KAgentReport-" + hashlib.sha256(raw).hexdigest()[:16]
                face = TTFont(name, io.BytesIO(raw), validate=1)
                if not VIETNAMESE.issubset(face.face.charToGlyph) or not required.issubset(face.face.charToGlyph):
                    continue
                regular = face
                try:
                    bold_raw = _font_bytes(bold_path)
                    bold = TTFont("KAgentReport-" + hashlib.sha256(bold_raw).hexdigest()[:16], io.BytesIO(bold_raw), validate=1)
                    if not required.issubset(bold.face.charToGlyph):
                        bold = regular
                except Exception:
                    bold = regular
                break
            except Exception:
                continue
        if regular is None or bold is None:
            raise ReportError(FONT_ERROR)
        pdfmetrics.registerFont(regular)
        pdfmetrics.registerFont(bold)
        body = ParagraphStyle("report-body", fontName=regular.fontName, fontSize=9, leading=13,
                              spaceAfter=5, splitLongWords=1)
        heading = ParagraphStyle("report-heading", parent=body, fontName=bold.fontName,
                                 fontSize=13, leading=18, spaceBefore=14, spaceAfter=8, keepWithNext=True)
        title = ParagraphStyle("report-title", parent=heading, fontSize=19, leading=25)
        small = ParagraphStyle("report-small", parent=body, fontSize=8, leading=11)
        width, height = A4
        margin = 42
        table_width = width - margin * 2
        buffer = BoundedBuffer()
        template = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=margin, rightMargin=margin,
                                     topMargin=margin + 14, bottomMargin=margin + 10,
                                     title="KAgent assessment snapshot", author="KAgent", subject="Recorded assessment snapshot")

        def paragraph(text: str, style=body):
            literal = escape(unicodedata.normalize("NFC", text), quote=True)
            return Paragraph(literal.replace("\n", "<br/>").replace("\t", "    "), style)

        story: list[Flowable] = [paragraph("KAgent assessment snapshot", title), paragraph(document.status)]
        # Data gaps are visible at the beginning even when the report spans pages.
        for warning in document.limitations:
            if any(word in warning.lower() for word in ("incomplete", "withheld", "unavailable", "omitted", "binding")):
                story.append(paragraph(warning, small))

        def table(rows, labels=("Field", "Recorded value")):
            if not rows:
                return
            data = [[paragraph(c, small) for c in labels]]
            data.extend([paragraph(a, small), paragraph(b, small)] for a, b in rows)
            tab = LongTable(data, colWidths=(table_width * .27, table_width * .73), repeatRows=1,
                            splitByRow=1, splitInRow=1, hAlign="LEFT")
            tab.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
                ("LINEBELOW", (0, 0), (-1, 0), .5, colors.HexColor("#aaaaaa")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(tab)
            story.append(Spacer(1, 8))

        table(document.metadata)
        story.append(paragraph("Assessment summary", heading))
        for text in document.summary:
            story.append(paragraph(text))
        table(tuple((severity, str(count)) for severity, count in document.severity_counts), ("Recorded severity", "Persisted findings"))
        story.append(paragraph("Requested goals and phases", heading))
        table(document.goals or (("Requested vulnerability classes", "No requested vulnerability classes recorded."),))
        table(document.phases)
        story.append(paragraph("Confirmed findings", heading))
        for index, finding in enumerate(document.findings, 1):
            story.append(paragraph(f"{index}. {finding.title} ({finding.severity})", heading))
            # Prose remains splittable; no whole-finding KeepTogether.
            for label, text in finding.details:
                story.append(paragraph(label, small))
                story.append(paragraph(text))
        if not document.findings:
            story.append(paragraph("No exportable persisted finding details in this snapshot; see summary and data gaps."))
        story.append(paragraph("Evidence summary", heading))
        table(document.evidence or (("Evidence", "No linked evidence metadata available."),), ("Evidence ID", "Metadata and availability"))
        story.append(paragraph("Recorded attack surface and coverage", heading))
        story.append(paragraph("Input inventory is discovery/input analysis, not proof of vulnerability testing."))
        table(document.inventory or (("Inventory", "No attack-surface inputs recorded."),), ("Input ID", "Recorded disposition"))
        table(document.validations or (("Validation", "No validation recorded."),), ("Candidate ID", "Latest canonical validation"))
        table(document.coverage or (("Coverage", "No selected coverage rows; availability is described in limitations."),), ("Endpoint", "Recorded contextual variant"))
        story.append(paragraph("Methodology and limitations", heading))
        story.append(paragraph("KAgent follows detection/discovery → confirmation → optional bounded impact validation → stop/report. Only recorded activity is represented."))
        for text in document.limitations:
            story.append(paragraph(text))
        story.append(paragraph("Report files request private modes (0600 files/0700 new directories). Filesystem and WSL mount settings determine whether those modes are enforced."))

        def page(canvas, doc):
            if doc.page > MAX_PAGES:
                raise ReportError("PDF exceeds report page limit; reduce report detail and retry.")
            canvas.saveState()
            canvas.setFont(regular.fontName, 8)
            canvas.drawString(margin, height - 30, "KAgent — recorded assessment snapshot")
            canvas.drawRightString(width - margin, 27, f"Page {doc.page}")
            canvas.restoreState()

        def canvas_factory(*args, **kwargs):
            kwargs["invariant"] = 1
            kwargs["pageCompression"] = 1
            return Canvas(*args, **kwargs)

        try:
            template.build(story, onFirstPage=page, onLaterPages=page, canvasmaker=canvas_factory)
            return buffer.getvalue()
        except ReportError:
            raise
        except Exception:
            raise ReportError("PDF layout failed. Check local fonts and report size; retry with a smaller snapshot.") from None
