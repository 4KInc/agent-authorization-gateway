"""Per-receipt PDF claim packet generator.

Produces a 3-page auditor-ready PDF for a single receipt:
  Page 1 — Receipt details, body fields, signature, verification status
  Page 2 — Merkle inclusion proof table + on-chain anchor details
  Page 3 — Independent verification instructions (4 steps)

Requires: reportlab >= 4.0.0
"""

from __future__ import annotations

import io
import textwrap
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Flowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Colour palette ──────────────────────────────────────────────────
NAVY = colors.HexColor("#0f172a")
ACCENT_BLUE = colors.HexColor("#1e40af")
LIGHT_BLUE_BG = colors.HexColor("#eff6ff")
GREEN = colors.HexColor("#16a34a")
RED = colors.HexColor("#dc2626")
GREY = colors.HexColor("#64748b")
WHITE = colors.white


# ── Custom flowables ────────────────────────────────────────────────
class HeaderBar(Flowable):
    """Full-width dark navy header bar with white text."""

    def __init__(self, text: str, width: float = 7.5 * inch, height: float = 0.5 * inch):
        super().__init__()
        self.text = text
        self.width = width
        self.height = height

    def draw(self):
        self.canv.setFillColor(NAVY)
        self.canv.rect(0, 0, self.width, self.height, fill=1, stroke=0)
        self.canv.setFillColor(WHITE)
        self.canv.setFont("Helvetica-Bold", 14)
        self.canv.drawString(0.2 * inch, 0.15 * inch, self.text)


class Badge(Flowable):
    """Coloured PASS / FAIL badge."""

    def __init__(self, label: str, status: str):
        super().__init__()
        self.label = label
        self.status = status.upper() if status else "N/A"
        self.width = 3.5 * inch
        self.height = 0.35 * inch

    def draw(self):
        colour = GREEN if self.status == "PASS" else RED if self.status == "FAIL" else GREY
        # Badge pill
        self.canv.setFillColor(colour)
        self.canv.roundRect(2.2 * inch, 0, 1.0 * inch, self.height, 4, fill=1, stroke=0)
        self.canv.setFillColor(WHITE)
        self.canv.setFont("Helvetica-Bold", 11)
        self.canv.drawCentredString(2.7 * inch, 0.1 * inch, self.status)
        # Label
        self.canv.setFillColor(NAVY)
        self.canv.setFont("Helvetica", 11)
        self.canv.drawString(0, 0.1 * inch, self.label)


class InfoBox(Flowable):
    """Light-blue rounded info box with wrapped text."""

    def __init__(self, text: str, width: float = 7.5 * inch):
        super().__init__()
        self.text = text
        self.width = width
        self._lines = textwrap.wrap(text, width=100)
        self.height = max(0.4 * inch, len(self._lines) * 14 + 12)

    def draw(self):
        self.canv.setFillColor(LIGHT_BLUE_BG)
        self.canv.roundRect(0, 0, self.width, self.height, 6, fill=1, stroke=0)
        self.canv.setFillColor(NAVY)
        self.canv.setFont("Helvetica", 9)
        y = self.height - 14
        for line in self._lines:
            self.canv.drawString(8, y, line)
            y -= 14


# ── Styles ──────────────────────────────────────────────────────────
_styles = getSampleStyleSheet()

STYLE_HEADING = ParagraphStyle(
    "ClaimHeading",
    parent=_styles["Heading2"],
    textColor=ACCENT_BLUE,
    spaceAfter=6,
    spaceBefore=12,
)
STYLE_BODY = ParagraphStyle(
    "ClaimBody",
    parent=_styles["Normal"],
    fontSize=9,
    leading=12,
    textColor=NAVY,
)
STYLE_SMALL = ParagraphStyle(
    "ClaimSmall",
    parent=_styles["Normal"],
    fontSize=8,
    leading=10,
    textColor=GREY,
)
STYLE_MONO = ParagraphStyle(
    "ClaimMono",
    parent=_styles["Normal"],
    fontName="Courier",
    fontSize=8,
    leading=10,
    textColor=NAVY,
)


# ── Helpers ─────────────────────────────────────────────────────────
def _safe(val, default: str = "N/A") -> str:
    """Return a string representation, falling back to *default*."""
    if val is None:
        return default
    if isinstance(val, list):
        return ", ".join(str(v) for v in val) if val else default
    return str(val)


def _truncate(s: str, maxlen: int = 64) -> str:
    s = str(s)
    return s if len(s) <= maxlen else s[: maxlen - 3] + "..."


def _kv_table(pairs: list[tuple[str, str]], col_widths=None) -> Table:
    """Build a two-column key-value table with alternating row shading."""
    col_widths = col_widths or [2.0 * inch, 5.5 * inch]
    data = [[Paragraph(f"<b>{k}</b>", STYLE_BODY), Paragraph(v, STYLE_BODY)] for k, v in pairs]
    t = Table(data, colWidths=col_widths)
    style_commands = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
    ]
    for i in range(0, len(data), 2):
        style_commands.append(("BACKGROUND", (0, i), (-1, i), LIGHT_BLUE_BG))
    t.setStyle(TableStyle(style_commands))
    return t


# ── Main generator ──────────────────────────────────────────────────
def generate_receipt_pdf(
    receipt: dict,
    verification: dict | None = None,
    inclusion_proof: dict | None = None,
    anchor: dict | None = None,
    policy: dict | None = None,
) -> bytes:
    """Generate a 3-page PDF claim packet for a single receipt.

    Parameters
    ----------
    receipt : dict
        The receipt envelope (body, sig, receipt_hash, _meta).
    verification : dict | None
        Output of verify_receipt().to_dict() — receipt_integrity, chain_validity, errors.
    inclusion_proof : dict | None
        Merkle inclusion proof (root, path, leaf_index, etc.).
    anchor : dict | None
        On-chain anchor record (tx_hash, block_number, merkle_root, etc.).
    policy : dict | None
        Policy snapshot dict (optional).

    Returns
    -------
    bytes
        PDF file content.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=0.5 * inch,
        rightMargin=0.5 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
    )

    body = receipt.get("body", {}) if isinstance(receipt, dict) else {}
    sig = receipt.get("sig", {}) if isinstance(receipt, dict) else {}
    meta = receipt.get("_meta", {}) if isinstance(receipt, dict) else {}
    receipt_hash = receipt.get("receipt_hash", "N/A") if isinstance(receipt, dict) else "N/A"

    verification = verification or {}
    inclusion_proof = inclusion_proof or {}
    anchor = anchor or {}

    elements: list = []

    # ── PAGE 1: Receipt Details ─────────────────────────────────────
    elements.append(HeaderBar("GATE  |  Claim Packet"))
    elements.append(Spacer(1, 12))

    ts_raw = body.get("ts", "")
    try:
        ts_display = datetime.fromisoformat(ts_raw).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        ts_display = _safe(ts_raw)

    elements.append(Paragraph("Receipt Overview", STYLE_HEADING))
    elements.append(_kv_table([
        ("Sequence", _safe(body.get("seq"))),
        ("Decision", _safe(body.get("decision"))),
        ("Agent", _safe(meta.get("agent_id"))),
        ("Action", _safe(meta.get("action"))),
        ("Resource", _safe(meta.get("resource"))),
        ("Timestamp", ts_display),
        ("Reasons", _safe(body.get("reasons"))),
    ]))
    elements.append(Spacer(1, 10))

    # Receipt body fields
    elements.append(Paragraph("Receipt Body", STYLE_HEADING))
    body_pairs = []
    for k in sorted(body.keys()):
        val = body[k]
        body_pairs.append((k, _truncate(_safe(val), 90)))
    elements.append(_kv_table(body_pairs))
    elements.append(Spacer(1, 10))

    # Cryptographic signature
    elements.append(Paragraph("Cryptographic Signature", STYLE_HEADING))
    elements.append(_kv_table([
        ("Algorithm", _safe(sig.get("alg", "EdDSA"))),
        ("Key ID (kid)", _safe(sig.get("kid"))),
        ("Signature", _truncate(_safe(sig.get("value")), 80)),
        ("Receipt Hash", _truncate(_safe(receipt_hash), 80)),
    ]))
    elements.append(Spacer(1, 10))

    # Verification status badges
    elements.append(Paragraph("Verification Status", STYLE_HEADING))
    elements.append(Badge("Receipt Integrity", verification.get("receipt_integrity", "N/A")))
    elements.append(Spacer(1, 4))
    elements.append(Badge("Chain Validity", verification.get("chain_validity", "N/A")))
    errors = verification.get("errors", [])
    if errors:
        elements.append(Spacer(1, 6))
        for err in errors[:5]:
            if isinstance(err, dict):
                err_text = f"{err.get('check', 'error')}: {err.get('message', str(err))}"
            else:
                err_text = str(err)
            elements.append(Paragraph(f"<font color='#dc2626'>&#x2022; {err_text}</font>", STYLE_BODY))

    # Page break
    from reportlab.platypus import PageBreak
    elements.append(PageBreak())

    # ── PAGE 2: Merkle Proof & On-Chain Anchor ──────────────────────
    elements.append(HeaderBar("GATE  |  Merkle Proof & On-Chain Anchor"))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Merkle Inclusion Proof", STYLE_HEADING))
    if inclusion_proof:
        proof_pairs = [
            ("Merkle Root", _truncate(_safe(inclusion_proof.get("root")), 80)),
            ("Leaf Index", _safe(inclusion_proof.get("leaf_index"))),
            ("Tree Size", _safe(inclusion_proof.get("tree_size"))),
        ]
        elements.append(_kv_table(proof_pairs))
        elements.append(Spacer(1, 6))

        # Proof path table
        path = inclusion_proof.get("path", [])
        if path:
            elements.append(Paragraph("Proof Path", STYLE_HEADING))
            path_data = [
                [Paragraph("<b>Step</b>", STYLE_BODY),
                 Paragraph("<b>Direction</b>", STYLE_BODY),
                 Paragraph("<b>Hash</b>", STYLE_BODY)],
            ]
            for i, step in enumerate(path):
                if isinstance(step, dict):
                    direction = step.get("direction", step.get("side", ""))
                    hash_val = step.get("hash", step.get("sibling", ""))
                else:
                    direction = ""
                    hash_val = str(step)
                path_data.append([
                    Paragraph(str(i + 1), STYLE_BODY),
                    Paragraph(str(direction), STYLE_BODY),
                    Paragraph(_truncate(str(hash_val), 60), STYLE_MONO),
                ])
            pt = Table(path_data, colWidths=[0.6 * inch, 1.2 * inch, 5.7 * inch])
            pt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT_BLUE),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, 0), 0.5, ACCENT_BLUE),
            ]))
            elements.append(pt)
    else:
        elements.append(InfoBox(
            "No Merkle inclusion proof available for this receipt. "
            "The receipt may not yet be included in an anchored batch."
        ))

    elements.append(Spacer(1, 14))

    # On-chain anchor
    elements.append(Paragraph("On-Chain Anchor (Base L2)", STYLE_HEADING))
    if anchor:
        tx_hash = _safe(anchor.get("tx_hash"))
        block_number = _safe(anchor.get("block_number"))
        basescan_url = f"https://basescan.org/tx/{tx_hash}" if tx_hash != "N/A" else "N/A"

        # Build anchor table with BaseScan as a clickable hyperlink
        anchor_pairs = [
            ("Transaction Hash", _truncate(tx_hash, 80)),
            ("Block Number", block_number),
            ("Merkle Root", _truncate(_safe(anchor.get("merkle_root")), 80)),
            ("Artifact Count", _safe(anchor.get("artifact_count", anchor.get("receipt_count")))),
            ("Anchored At", _safe(anchor.get("timestamp", anchor.get("anchored_at")))),
        ]
        col_widths = [2.0 * inch, 5.5 * inch]
        data = [
            [Paragraph(f"<b>{k}</b>", STYLE_BODY), Paragraph(v, STYLE_BODY)]
            for k, v in anchor_pairs
        ]
        # Add BaseScan link as a clickable hyperlink so the full URL is one target
        if basescan_url != "N/A":
            data.append([
                Paragraph("<b>BaseScan Link</b>", STYLE_BODY),
                Paragraph(
                    f'<a href="{basescan_url}" color="#1e40af">{basescan_url}</a>',
                    STYLE_BODY,
                ),
            ])
        else:
            data.append([
                Paragraph("<b>BaseScan Link</b>", STYLE_BODY),
                Paragraph("N/A", STYLE_BODY),
            ])
        t = Table(data, colWidths=col_widths)
        style_commands = [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ]
        for i in range(0, len(data), 2):
            style_commands.append(("BACKGROUND", (0, i), (-1, i), LIGHT_BLUE_BG))
        t.setStyle(TableStyle(style_commands))
        elements.append(t)
    else:
        elements.append(InfoBox(
            "No on-chain anchor found for this receipt's batch. "
            "Receipts are anchored periodically (every 10 receipts or 1 hour)."
        ))

    elements.append(PageBreak())

    # ── PAGE 3: Independent Verification Instructions ───────────────
    elements.append(HeaderBar("GATE  |  Independent Verification"))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph(
        "Follow these four steps to independently verify this receipt without "
        "trusting the Gate operator.",
        STYLE_BODY,
    ))
    elements.append(Spacer(1, 10))

    steps = [
        (
            "Step 1: Verify the Ed25519 Signature",
            "Canonicalize the receipt body (JSON with sorted keys, no whitespace). "
            "Compute SHA-256 of the canonical bytes to get the receipt hash. "
            "Verify the Ed25519 signature in the 'sig' field against the receipt hash "
            "using the public key identified by 'kid'. The public key can be fetched "
            "from the Gate's /keys endpoint or from a trusted key registry.",
        ),
        (
            "Step 2: Verify the Hash Chain",
            "Each receipt's 'prev_receipt' field must equal the receipt_hash of the "
            "immediately preceding receipt (by sequence number). The genesis receipt "
            "(seq=1) has prev_receipt set to the zero hash. This forms a tamper-evident "
            "chain: modifying any receipt breaks the linkage for all subsequent receipts.",
        ),
        (
            "Step 3: Verify Merkle Inclusion",
            "Using the proof path from Page 2, recompute the Merkle root from the "
            "receipt's artifact hash (leaf). At each step, concatenate the current hash "
            "with the sibling hash (respecting left/right direction) and compute SHA-256. "
            "The final hash must equal the Merkle root shown on Page 2.",
        ),
        (
            "Step 4: Verify the On-Chain Anchor",
            "Look up the anchor transaction on BaseScan using the TX hash from Page 2. "
            "Read the calldata from the transaction — it contains the Merkle root that "
            "was anchored. Confirm it matches the root computed in Step 3. The block "
            "timestamp provides a third-party attestation of when the batch existed.",
        ),
    ]

    for title, description in steps:
        elements.append(Paragraph(title, STYLE_HEADING))
        elements.append(InfoBox(description))
        elements.append(Spacer(1, 8))

    # Footer with generation timestamp
    elements.append(Spacer(1, 20))
    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    elements.append(Paragraph(
        f"<font color='#64748b'>Generated by Gate Agent Authorization Gateway on {gen_time}. "
        f"Receipt seq={_safe(body.get('seq'))}.</font>",
        STYLE_SMALL,
    ))

    doc.build(elements)
    return buf.getvalue()
