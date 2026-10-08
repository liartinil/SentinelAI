from __future__ import annotations

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


def safe_text(value):
    if value is None:
        return "—"

    value = str(value)

    return (
        value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _p(value, style):
    return Paragraph(
        safe_text(value),
        style
    )


def _table(
    rows,
    widths,
    header=True
):
    table = Table(
        rows,
        colWidths=widths,
        repeatRows=1 if header else 0,
    )

    style = [
        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.35,
            colors.HexColor("#AFC2D1")
        ),
        (
            "VALIGN",
            (0, 0),
            (-1, -1),
            "TOP"
        ),
        (
            "TOPPADDING",
            (0, 0),
            (-1, -1),
            6
        ),
        (
            "BOTTOMPADDING",
            (0, 0),
            (-1, -1),
            6
        ),
        (
            "LEFTPADDING",
            (0, 0),
            (-1, -1),
            5
        ),
        (
            "RIGHTPADDING",
            (0, 0),
            (-1, -1),
            5
        ),
    ]

    if header:
        style += [
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#0B2340")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
        ]

    table.setStyle(
        TableStyle(style)
    )

    return table


def build_scan_pdf(
    scan: dict,
    user: dict
) -> bytes:

    payload = scan.get("payload") or {}

    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title="SentinelAI Security Report",
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "SentinelTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#123A63"),
        fontSize=20,
        leading=24,
    )

    body = ParagraphStyle(
        "SentinelBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        wordWrap="CJK",
    )

    small = ParagraphStyle(
        "SentinelSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#666666"),
        wordWrap="CJK",
    )

    heading = ParagraphStyle(
        "SentinelHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=17,
        spaceBefore=7,
        spaceAfter=7,
    )

    story = []

    # -----------------------
    # HEADER
    # -----------------------

    story.append(
        Paragraph(
            "SentinelAI Security Report",
            title_style
        )
    )

    story.append(
        Spacer(
            1,
            3 * mm
        )
    )

    user_name = (
        user.get("name")
        or user.get("username")
        or "User"
    )

    user_email = (
        user.get("email")
        or "—"
    )

    story.append(
        Paragraph(
            f"Generated for: "
            f"{safe_text(user_name)} "
            f"({safe_text(user_email)})",
            body
        )
    )

    target = (
        payload.get("final_url")
        or scan.get("url")
        or payload.get("requested_url")
        or "Unknown target"
    )

    story.append(
        Paragraph(
            f"Target: {safe_text(target)}",
            body
        )
    )

    story.append(
        Paragraph(
            f"Scanned at: "
            f"{safe_text(scan.get('created_at'))}",
            small
        )
    )

    story.append(
        Spacer(
            1,
            5 * mm
        )
    )

    # -----------------------
    # SUMMARY
    # -----------------------

    summary_rows = [
        [
            _p(
                "<b>Security Score</b>",
                body
            ),
            _p(
                "<b>Risk</b>",
                body
            ),
            _p(
                "<b>HTTP</b>",
                body
            ),
            _p(
                "<b>Hostname</b>",
                body
            ),
        ],
        [
            _p(
                f"{scan.get('score', '—')}/100",
                body
            ),
            _p(
                str(
                    scan.get(
                        "risk",
                        "—"
                    )
                ).upper(),
                body
            ),
            _p(
                payload.get(
                    "http_status",
                    "—"
                ),
                body
            ),
            _p(
                payload.get(
                    "hostname",
                    "—"
                ),
                body
            ),
        ],
    ]

    story.append(
        _table(
            summary_rows,
            [
                40 * mm,
                35 * mm,
                30 * mm,
                70 * mm,
            ]
        )
    )

    story.append(
        Spacer(
            1,
            6 * mm
        )
    )

    # -----------------------
    # EXECUTIVE SUMMARY
    # -----------------------

    findings = (
        payload.get(
            "findings"
        )
        or []
    )

    warning_count = sum(
        1
        for f in findings
        if f.get("status") != "pass"
    )

    story.append(
        Paragraph(
            "Executive Summary",
            heading
        )
    )

    story.append(
        Paragraph(
            (
                "SentinelAI performed a passive defensive "
                "assessment of the public web configuration. "
                f"The target received a security score of "
                f"{safe_text(scan.get('score'))}/100 "
                f"with {warning_count} finding(s) "
                "requiring review. "
                "No exploitation, brute force, payload "
                "injection, or port scanning was performed."
            ),
            body
        )
    )

    story.append(
        Spacer(
            1,
            5 * mm
        )
    )

    # -----------------------
    # FINDINGS
    # -----------------------

    story.append(
        Paragraph(
            "Security Findings",
            heading
        )
    )

    finding_rows = [
        [
            _p(
                "<b>Check</b>",
                small
            ),
            _p(
                "<b>Status</b>",
                small
            ),
            _p(
                "<b>Details</b>",
                small
            ),
        ]
    ]

    for finding in findings:

        finding_rows.append(
            [
                _p(
                    finding.get(
                        "name",
                        ""
                    ),
                    small
                ),
                _p(
                    str(
                        finding.get(
                            "status",
                            ""
                        )
                    ).upper(),
                    small
                ),
                _p(
                    finding.get(
                        "detail",
                        ""
                    ),
                    small
                ),
            ]
        )

    if len(
        finding_rows
    ) > 1:

        story.append(
            _table(
                finding_rows,
                [
                    52 * mm,
                    30 * mm,
                    93 * mm,
                ]
            )
        )

    else:

        story.append(
            Paragraph(
                "No detailed findings were available.",
                body
            )
        )

    story.append(
        Spacer(
            1,
            6 * mm
        )
    )

    # -----------------------
    # TLS
    # -----------------------

    tls = (
        payload.get("tls")
        or {}
    )

    if tls:

        story.append(
            Paragraph(
                "TLS / SSL Details",
                heading
            )
        )

        tls_rows = [
            [
                _p(
                    "<b>Field</b>",
                    small
                ),
                _p(
                    "<b>Value</b>",
                    small
                ),
            ],
            [
                _p(
                    "Protocol",
                    small
                ),
                _p(
                    tls.get(
                        "protocol"
                    ),
                    small
                ),
            ],
            [
                _p(
                    "Cipher",
                    small
                ),
                _p(
                    tls.get(
                        "cipher"
                    ),
                    small
                ),
            ],
            [
                _p(
                    "Certificate expires",
                    small
                ),
                _p(
                    tls.get(
                        "expires_at"
                    ),
                    small
                ),
            ],
            [
                _p(
                    "Days until expiry",
                    small
                ),
                _p(
                    tls.get(
                        "days_until_expiry"
                    ),
                    small
                ),
            ],
            [
                _p(
                    "Issuer",
                    small
                ),
                _p(
                    tls.get(
                        "issuer_common_name"
                    ),
                    small
                ),
            ],
        ]

        story.append(
            _table(
                tls_rows,
                [
                    50 * mm,
                    125 * mm,
                ]
            )
        )

        story.append(
            Spacer(
                1,
                6 * mm
            )
        )

    # -----------------------
    # REDIRECTS
    # -----------------------

    redirects = (
        payload.get(
            "redirect_chain"
        )
        or []
    )

    if redirects:

        story.append(
            Paragraph(
                "Redirect Chain",
                heading
            )
        )

        redirect_rows = [
            [
                _p(
                    "<b>Status</b>",
                    small
                ),
                _p(
                    "<b>URL</b>",
                    small
                ),
            ]
        ]

        for item in redirects:

            redirect_rows.append(
                [
                    _p(
                        item.get(
                            "status"
                        ),
                        small
                    ),
                    _p(
                        item.get(
                            "url"
                        ),
                        small
                    ),
                ]
            )

        story.append(
            _table(
                redirect_rows,
                [
                    30 * mm,
                    145 * mm,
                ]
            )
        )

        story.append(
            Spacer(
                1,
                6 * mm
            )
        )

    # -----------------------
    # WEB CONFIG
    # -----------------------

    story.append(
        Paragraph(
            "Web Configuration",
            heading
        )
    )

    config_rows = [
        [
            _p(
                "<b>Item</b>",
                small
            ),
            _p(
                "<b>Result</b>",
                small
            ),
        ],
        [
            _p(
                "robots.txt",
                small
            ),
            _p(
                "Found"
                if payload.get(
                    "robots_txt"
                )
                else "Not found",
                small
            ),
        ],
        [
            _p(
                "sitemap.xml",
                small
            ),
            _p(
                "Found"
                if payload.get(
                    "sitemap_xml"
                )
                else "Not found",
                small
            ),
        ],
        [
            _p(
                "CORS allow origin",
                small
            ),
            _p(
                payload.get(
                    "cors_allow_origin"
                )
                or "Not exposed",
                small
            ),
        ],
        [
            _p(
                "Mixed content",
                small
            ),
            _p(
                payload.get(
                    "mixed_content_count",
                    0
                ),
                small
            ),
        ],
        [
            _p(
                "Server header",
                small
            ),
            _p(
                payload.get(
                    "server"
                )
                or "Not exposed",
                small
            ),
        ],
    ]

    story.append(
        _table(
            config_rows,
            [
                55 * mm,
                120 * mm,
            ]
        )
    )

    story.append(
        Spacer(
            1,
            6 * mm
        )
    )

    # -----------------------
    # RECOMMENDATIONS
    # -----------------------

    story.append(
        Paragraph(
            "Recommended Next Steps",
            heading
        )
    )

    recommendations = []

    rec_map = {
        "HSTS":
            "Enable Strict-Transport-Security after HTTPS is fully deployed.",

        "Content-Security-Policy":
            "Deploy and test Content-Security-Policy to reduce script injection risk.",

        "X-Content-Type-Options":
            "Set X-Content-Type-Options: nosniff.",

        "X-Frame-Options":
            "Use CSP frame-ancestors or X-Frame-Options.",

        "Referrer-Policy":
            "Configure an appropriate Referrer-Policy.",

        "Permissions-Policy":
            "Restrict unnecessary browser features.",

        "CORS":
            "Review allowed origins and avoid unnecessary wildcard access.",

        "Server Header":
            "Reduce unnecessary server/version disclosure.",

        "Mixed Content":
            "Replace HTTP resources with HTTPS equivalents.",
    }

    for finding in findings:

        if (
            finding.get(
                "status"
            )
            == "pass"
        ):
            continue

        name = (
            finding.get(
                "name"
            )
            or "Issue"
        )

        recommendation = (
            rec_map.get(
                name,
                "Review this finding and apply the relevant hardening guidance."
            )
        )

        recommendations.append(
            [
                _p(
                    name,
                    small
                ),
                _p(
                    recommendation,
                    small
                ),
            ]
        )

    if recommendations:

        recommendation_rows = [
            [
                _p(
                    "<b>Finding</b>",
                    small
                ),
                _p(
                    "<b>Recommendation</b>",
                    small
                ),
            ]
        ]

        recommendation_rows.extend(
            recommendations
        )

        story.append(
            _table(
                recommendation_rows,
                [
                    55 * mm,
                    120 * mm,
                ]
            )
        )

    else:

        story.append(
            Paragraph(
                (
                    "No major passive configuration warnings "
                    "were detected. Continue monitoring and "
                    "test security changes regularly."
                ),
                body
            )
        )

    # -----------------------
    # BUILD
    # -----------------------

    try:

        doc.build(
            story
        )

        pdf = (
            buffer.getvalue()
        )

        if not pdf:
            raise ValueError(
                "Generated PDF is empty."
            )

        return pdf

    except Exception:

        # minimal fallback PDF

        fallback = BytesIO()

        fallback_doc = SimpleDocTemplate(
            fallback,
            pagesize=A4
        )

        fallback_story = [
            Paragraph(
                "SentinelAI Security Report",
                styles["Title"]
            ),

            Spacer(
                1,
                12
            ),

            Paragraph(
                safe_text(target),
                styles["BodyText"]
            ),

            Spacer(
                1,
                8
            ),

            Paragraph(
                (
                    "Security Score: "
                    f"{safe_text(scan.get('score'))}/100"
                ),
                styles["BodyText"]
            ),

            Paragraph(
                (
                    "Risk: "
                    f"{safe_text(scan.get('risk'))}"
                ),
                styles["BodyText"]
            ),
        ]

        fallback_doc.build(
            fallback_story
        )

        return (
            fallback.getvalue()
        )