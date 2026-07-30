"""
report_helpers.py
─────────────────────────────────────────────────────────────────────────────
Layout, typography, and document-structure utilities for ReportLab output.

Provides
────────
  * escape_for_reportlab      — safe interpolation of scan data into Paragraphs
  * register_report_fonts     — Unicode-capable TTF registration with fallback
  * ReportDocTemplate         — BaseDocTemplate with a real clickable TOC,
                                PDF outline bookmarks, and running headers
  * NumberedCanvas            — "Page X of Y" plus classification footer
  * severity_bar_chart /
    severity_donut            — ReportLab vector charts (no image deps)
"""

from __future__ import annotations

import html
import os
from datetime import date, datetime
from typing import Dict, List, Optional, Sequence, Tuple

from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import BaseDocTemplate, Frame, PageTemplate, Paragraph

# ─────────────────────────────────────────────────────────────────────────────
# Text safety
# ─────────────────────────────────────────────────────────────────────────────


def escape_for_reportlab(text) -> str:
    """
    Escape a dynamic string for safe use inside a ReportLab Paragraph.

    Scan output routinely contains angle brackets and ampersands (HTML bodies,
    XML fragments, shell output). Without escaping these raise ExpatError mid
    build, so every interpolated value passes through here.
    """
    if text is None:
        return ""
    return html.escape(str(text), quote=True)


def date_only(value) -> str:
    """
    Reduce a feed timestamp to an ISO date, or "" when it is not parseable.

    Feeds return a mix of "2024-07-01", "2024-07-01T00:00:00.000Z" and datetime
    objects; the report only ever shows the date part.
    """
    if not value:
        return ""
    if isinstance(value, (datetime, date)):
        return value.strftime("%Y-%m-%d")
    text = str(value).strip()
    if not text:
        return ""
    candidate = text.replace("Z", "").split("T")[0].split(" ")[0]
    try:
        return datetime.strptime(candidate, "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError:
        return ""


def age_in_days(value, now: Optional[datetime] = None) -> Optional[int]:
    """Whole days between a feed timestamp and today, or None if unparseable."""
    iso = date_only(value)
    if not iso:
        return None
    reference = (now or datetime.now()).date()
    try:
        published = datetime.strptime(iso, "%Y-%m-%d").date()
    except ValueError:
        return None
    return max((reference - published).days, 0)


def ordinal(value: float) -> str:
    """
    Format a rank with its ordinal suffix: 93.4 -> "93.4th", 62 -> "62nd".

    Used for EPSS percentiles, where the value is a rank among all scored CVEs
    and must not be confused with the probability itself.
    """
    rounded = round(float(value), 1)
    if rounded == int(rounded):
        n = int(rounded)
        if 10 <= n % 100 <= 20:
            suffix = "th"
        else:
            suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
        return f"{n}{suffix}"
    return f"{rounded:g}th"


def clean_control_chars(text: str) -> str:
    """
    Strip control characters that ReportLab cannot render.

    Preserves newline and tab; replaces the rest with a visible placeholder so
    binary noise in a banner does not silently vanish from the evidence block.
    """
    if not text:
        return ""
    out = []
    for ch in str(text):
        code = ord(ch)
        if ch in ("\n", "\t"):
            out.append(ch)
        elif code < 32 or code == 127:
            out.append("·")
        else:
            out.append(ch)
    return "".join(out)


def truncate_with_notice(text: str, limit: int) -> Tuple[str, bool]:
    """
    Truncate long text, reporting whether truncation occurred.

    Returning the flag lets the caller print an explicit "output truncated"
    marker rather than silently dropping evidence.
    """
    if not text:
        return "", False
    text = str(text)
    if len(text) <= limit:
        return text, False
    return text[:limit].rstrip(), True


# ─────────────────────────────────────────────────────────────────────────────
# Fonts
# ─────────────────────────────────────────────────────────────────────────────

_FONT_STATE: Dict[str, str] = {}

#: Candidate Unicode TTFs, in preference order, as (family, regular, bold, mono).
_FONT_CANDIDATES: Sequence[Tuple[str, str, str]] = (
    ("DejaVuSans", "DejaVuSans.ttf", "DejaVuSans-Bold.ttf"),
    ("NotoSans", "NotoSans-Regular.ttf", "NotoSans-Bold.ttf"),
    ("Arial", "arial.ttf", "arialbd.ttf"),
    ("SegoeUI", "segoeui.ttf", "segoeuib.ttf"),
)

_FONT_SEARCH_DIRS = (
    os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts"),
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/truetype/noto",
    "/usr/share/fonts/TTF",
    "/Library/Fonts",
    "/System/Library/Fonts",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "fonts"),
)


def _locate(filename: str) -> Optional[str]:
    for directory in _FONT_SEARCH_DIRS:
        candidate = os.path.join(directory, filename)
        if os.path.isfile(candidate):
            return candidate
    return None


def register_report_fonts() -> Dict[str, str]:
    """
    Register a Unicode-capable font family, falling back to the built-in
    Helvetica when no TTF is available.

    Returns a mapping with 'regular', 'bold', and 'mono' keys naming the fonts
    the document should use. Callers must read these rather than hardcoding
    'Helvetica', otherwise non-ASCII scan output renders as black boxes.
    """
    if _FONT_STATE:
        return dict(_FONT_STATE)

    resolved = {"regular": "Helvetica", "bold": "Helvetica-Bold", "mono": "Courier"}

    for family, regular_file, bold_file in _FONT_CANDIDATES:
        regular_path = _locate(regular_file)
        bold_path = _locate(bold_file)
        if not regular_path:
            continue
        try:
            pdfmetrics.registerFont(TTFont(family, regular_path))
            resolved["regular"] = family
            if bold_path:
                pdfmetrics.registerFont(TTFont(f"{family}-Bold", bold_path))
                resolved["bold"] = f"{family}-Bold"
            else:
                resolved["bold"] = family
            break
        except Exception:
            continue

    # A monospaced Unicode face keeps evidence blocks aligned. DejaVuSansMono
    # is the common companion to the families above.
    for mono_file, mono_name in (
        ("DejaVuSansMono.ttf", "DejaVuSansMono"),
        ("consola.ttf", "Consolas"),
        ("cour.ttf", "CourierNewTTF"),
    ):
        mono_path = _locate(mono_file)
        if not mono_path:
            continue
        try:
            pdfmetrics.registerFont(TTFont(mono_name, mono_path))
            resolved["mono"] = mono_name
            break
        except Exception:
            continue

    _FONT_STATE.update(resolved)
    return dict(resolved)


# ─────────────────────────────────────────────────────────────────────────────
# Canvas: page numbering + classification marking
# ─────────────────────────────────────────────────────────────────────────────


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that stamps "Page X of Y" and a classification marking on
    every page. The total page count is unknown until the document is complete,
    so page state is buffered and the footer drawn during save().
    """

    classification = "CONFIDENTIAL"
    product_label = "CCure Audit PRO"
    footer_font = "Helvetica"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_footer(total)
            super().showPage()
        super().save()

    def _draw_footer(self, page_count: int):
        self.saveState()
        page_w, _ = self._pagesize
        margin = 18 * mm

        self.setStrokeColor(colors.HexColor("#CBD5E0"))
        self.setLineWidth(0.5)
        self.line(margin, 12 * mm, page_w - margin, 12 * mm)

        self.setFont(self.footer_font, 7.5)
        self.setFillColor(colors.HexColor("#475569"))
        self.drawString(margin, 6.5 * mm, self.product_label)

        self.setFillColor(colors.HexColor("#B91C1C"))
        self.drawCentredString(page_w / 2.0, 6.5 * mm, self.classification)

        self.setFillColor(colors.HexColor("#475569"))
        self.drawRightString(
            page_w - margin, 6.5 * mm, f"Page {self._pageNumber} of {page_count}"
        )
        self.restoreState()


# ─────────────────────────────────────────────────────────────────────────────
# Document template with TOC + outline bookmarks
# ─────────────────────────────────────────────────────────────────────────────


class ReportDocTemplate(BaseDocTemplate):
    """
    Document template that produces a genuine table of contents.

    Flowables tagged with a ``toc_level`` attribute are registered with the
    TOC machinery during layout, which is what supplies real page numbers and
    clickable links. The same hook writes the PDF outline so the document is
    navigable in any viewer's sidebar.
    """

    def __init__(self, filename, **kwargs):
        self.allow_splitting = 1
        self._bookmark_counter = 0
        page_size = kwargs.pop("pagesize", None)
        margin = kwargs.pop("margin", 18 * mm)
        top_margin = kwargs.pop("topMargin", 20 * mm)
        bottom_margin = kwargs.pop("bottomMargin", 18 * mm)
        self.header_text = kwargs.pop("header_text", "")

        super().__init__(
            filename,
            pagesize=page_size,
            leftMargin=margin,
            rightMargin=margin,
            topMargin=top_margin,
            bottomMargin=bottom_margin,
            **kwargs,
        )

        frame = Frame(
            self.leftMargin,
            self.bottomMargin,
            self.width,
            self.height,
            id="body",
        )
        self.addPageTemplates(
            [
                PageTemplate(
                    id="report",
                    frames=[frame],
                    onPage=self._draw_header,
                )
            ]
        )

    def beforeDocument(self):
        """
        Reset per-pass state.

        multiBuild lays the document out repeatedly until TOC page numbers stop
        changing. If the bookmark counter carried over between passes the keys
        would differ each time, the TOC entries would never compare equal, and
        the build would abort as unresolved. This hook runs at the start of
        every pass, so resetting here makes identical content produce identical
        keys and the build converges.
        """
        self._bookmark_counter = 0

    def _draw_header(self, canv, doc):
        if not self.header_text or doc.page == 1:
            return
        canv.saveState()
        canv.setFont(NumberedCanvas.footer_font, 7.5)
        canv.setFillColor(colors.HexColor("#94A3B8"))
        canv.drawString(
            self.leftMargin,
            self.pagesize[1] - 12 * mm,
            self.header_text,
        )
        canv.setStrokeColor(colors.HexColor("#E2E8F0"))
        canv.setLineWidth(0.5)
        canv.line(
            self.leftMargin,
            self.pagesize[1] - 14 * mm,
            self.pagesize[0] - self.rightMargin,
            self.pagesize[1] - 14 * mm,
        )
        canv.restoreState()

    def afterFlowable(self, flowable):
        """Register headings with the TOC and the PDF outline."""
        level = getattr(flowable, "toc_level", None)
        if level is None or not isinstance(flowable, Paragraph):
            return

        text = flowable.getPlainText()
        if not text:
            return

        self._bookmark_counter += 1
        key = f"sect{self._bookmark_counter}"
        self.canv.bookmarkPage(key)
        self.notify("TOCEntry", (level, text, self.page, key))

        closed = level > 0
        self.canv.addOutlineEntry(text[:120], key, level=min(level, 3), closed=closed)


# ─────────────────────────────────────────────────────────────────────────────
# Charts
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_CHART_COLORS: Dict[str, colors.Color] = {
    "Critical": colors.HexColor("#7F1D1D"),
    "High": colors.HexColor("#DC2626"),
    "Medium": colors.HexColor("#EA580C"),
    "Low": colors.HexColor("#CA8A04"),
    "None": colors.HexColor("#0284C7"),
    "Unscored": colors.HexColor("#64748B"),
}


def severity_bar_chart(
    counts: Dict[str, int],
    width: float = 176 * mm,
    height: float = 46 * mm,
    font: str = "Helvetica",
    bold_font: str = "Helvetica-Bold",
) -> Drawing:
    """
    Horizontal bar chart of finding counts by severity.

    Bars are drawn manually rather than via HorizontalBarChart so each row can
    carry its own colour and an exact count label, which a stacked chart cannot
    express cleanly at this size.
    """
    tiers = [
        t
        for t in ("Critical", "High", "Medium", "Low", "None", "Unscored")
        if counts.get(t)
    ]
    if not tiers:
        tiers = ["Critical", "High", "Medium", "Low"]

    drawing = Drawing(width, height)
    maximum = max((counts.get(t, 0) for t in tiers), default=0) or 1

    label_w = 52
    value_w = 34
    track_w = width - label_w - value_w - 8
    row_h = height / len(tiers)
    bar_h = min(row_h * 0.56, 11)

    for index, tier in enumerate(tiers):
        value = counts.get(tier, 0)
        y = height - (index + 1) * row_h + (row_h - bar_h) / 2

        drawing.add(
            String(
                0,
                y + bar_h / 2 - 3.2,
                tier,
                fontName=bold_font,
                fontSize=8,
                fillColor=colors.HexColor("#334155"),
            )
        )
        # Track
        drawing.add(
            Rect(
                label_w,
                y,
                track_w,
                bar_h,
                fillColor=colors.HexColor("#F1F5F9"),
                strokeColor=None,
            )
        )
        if value:
            drawing.add(
                Rect(
                    label_w,
                    y,
                    max(track_w * (value / maximum), 1.5),
                    bar_h,
                    fillColor=SEVERITY_CHART_COLORS.get(tier, colors.grey),
                    strokeColor=None,
                )
            )
        drawing.add(
            String(
                label_w + track_w + 6,
                y + bar_h / 2 - 3.2,
                str(value),
                fontName=bold_font,
                fontSize=8.5,
                fillColor=colors.HexColor("#0F172A"),
            )
        )

    return drawing


def severity_donut(
    counts: Dict[str, int],
    width: float = 74 * mm,
    height: float = 56 * mm,
    font: str = "Helvetica",
) -> Optional[Drawing]:
    """Donut chart of the severity mix. Returns None when there is nothing to plot."""
    tiers = [
        (t, counts.get(t, 0))
        for t in ("Critical", "High", "Medium", "Low", "None", "Unscored")
    ]
    tiers = [(t, v) for t, v in tiers if v > 0]
    if not tiers:
        return None

    drawing = Drawing(width, height)
    pie = Pie()
    pie.x = width / 2 - 26
    pie.y = height / 2 - 26
    pie.width = 52
    pie.height = 52
    pie.data = [v for _, v in tiers]
    pie.labels = None
    pie.innerRadiusFraction = 0.55
    pie.slices.strokeColor = colors.white
    pie.slices.strokeWidth = 1.2

    for index, (tier, _) in enumerate(tiers):
        pie.slices[index].fillColor = SEVERITY_CHART_COLORS.get(tier, colors.grey)

    drawing.add(pie)

    total = sum(v for _, v in tiers)
    drawing.add(
        String(
            width / 2,
            height / 2 + 1,
            str(total),
            fontName=font,
            fontSize=13,
            textAnchor="middle",
            fillColor=colors.HexColor("#0F172A"),
        )
    )
    drawing.add(
        String(
            width / 2,
            height / 2 - 9,
            "findings",
            fontName=font,
            fontSize=6.5,
            textAnchor="middle",
            fillColor=colors.HexColor("#64748B"),
        )
    )
    return drawing


def host_risk_chart(
    host_rows: List[Tuple[str, Dict[str, int]]],
    width: float = 176 * mm,
    row_height: float = 9.0,
    font: str = "Helvetica",
    bold_font: str = "Helvetica-Bold",
) -> Optional[Drawing]:
    """
    Stacked severity bar per host, ordered most-affected first.

    Gives the reader a single view of which hosts carry the risk, which a flat
    finding list cannot convey.
    """
    rows = [(name, c) for name, c in host_rows if sum(c.values()) > 0]
    if not rows:
        return None

    rows = rows[:15]
    height = row_height * len(rows) + 6
    drawing = Drawing(width, height)

    label_w = 62
    total_w = 30
    track_w = width - label_w - total_w - 8
    peak = max(sum(c.values()) for _, c in rows) or 1

    for index, (name, counts) in enumerate(rows):
        y = height - (index + 1) * row_height + 1.5
        bar_h = row_height * 0.62

        label = name if len(name) <= 22 else name[:21] + "…"
        drawing.add(
            String(
                0,
                y + 1,
                label,
                fontName=font,
                fontSize=7,
                fillColor=colors.HexColor("#334155"),
            )
        )

        offset = label_w
        total = sum(counts.values())
        for tier in ("Critical", "High", "Medium", "Low", "None", "Unscored"):
            value = counts.get(tier, 0)
            if not value:
                continue
            segment = track_w * (value / peak)
            drawing.add(
                Rect(
                    offset,
                    y,
                    max(segment, 0.8),
                    bar_h,
                    fillColor=SEVERITY_CHART_COLORS.get(tier, colors.grey),
                    strokeColor=None,
                )
            )
            offset += segment

        drawing.add(
            String(
                label_w + track_w + 6,
                y + 1,
                str(total),
                fontName=bold_font,
                fontSize=7,
                fillColor=colors.HexColor("#0F172A"),
            )
        )

    return drawing


def chart_legend(
    counts: Dict[str, int],
    width: float = 176 * mm,
    font: str = "Helvetica",
) -> Drawing:
    """Colour key for the severity charts."""
    tiers = [
        t
        for t in ("Critical", "High", "Medium", "Low", "None", "Unscored")
        if counts.get(t)
    ]
    drawing = Drawing(width, 10)
    x = 0.0
    for tier in tiers:
        drawing.add(
            Rect(x, 1.5, 7, 7, fillColor=SEVERITY_CHART_COLORS[tier], strokeColor=None)
        )
        drawing.add(
            String(
                x + 10,
                3.4,
                f"{tier} ({counts.get(tier, 0)})",
                fontName=font,
                fontSize=7,
                fillColor=colors.HexColor("#475569"),
            )
        )
        x += 30 + len(tier) * 3.4
    return drawing
