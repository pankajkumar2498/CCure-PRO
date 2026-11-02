"""
core/pdf_text.py — ReportLab text safety and Unicode fonts.

The three primitives every PDF this application renders needs, whichever
product renders it: escaping a dynamic value for a Paragraph, making control
characters visible rather than unrenderable, and registering a Unicode font
family with a Helvetica fallback.

Moved out of ``reporting/report_helpers.py``, which re-exports them unchanged:
the platform's audit-log export (``ccure_platform.audit_log.export``) renders a
PDF too, and reaching into Audit's report renderers for them made the shared
platform depend on a product. Shared, product-neutral infrastructure, like
``core.upload_guard``.
"""

from __future__ import annotations

import html
import os
from typing import Dict, Optional, Sequence, Tuple

from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

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
