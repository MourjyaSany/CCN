"""Generate the 21ECC402L Project Review-1 deck for NetShield-GNN.

Every text element, flowchart block and arrow is a native, editable PowerPoint
shape. The background image, SRMIST logo, red footer and slide number live on
the slide master, so they are identical on every slide and are edited once.

Run:  python build_deck.py            -> NetShield-GNN_Review1.pptx
      python make_assets.py first if assets/ is empty.
"""

from __future__ import annotations

import copy
from pathlib import Path

from lxml import etree
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.dml import MSO_LINE_DASH_STYLE
from pptx.enum.shapes import MSO_CONNECTOR, MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, MSO_AUTO_SIZE, PP_ALIGN
from pptx.opc.constants import RELATIONSHIP_TYPE as RT
from pptx.oxml.ns import qn
from pptx.util import Emu, Inches, Pt

HERE = Path(__file__).resolve().parent
ASSETS = HERE / "assets"
OUT = HERE / "NetShield-GNN_Review1.pptx"

# --------------------------------------------------------------------------- #
# design tokens
# --------------------------------------------------------------------------- #
RED = RGBColor(0xD6, 0x00, 0x00)        # headings, title
FOOTER_RED = "C00000"                   # footer band (matches the template)
BLUE = RGBColor(0x16, 0x72, 0xB8)       # secondary
INK = RGBColor(0x1A, 0x1A, 0x1A)        # body text
MUTED = RGBColor(0x40, 0x40, 0x40)
NAVY = RGBColor(0x1F, 0x3A, 0x5F)       # diagram outlines / headers
BLOCK = RGBColor(0xDC, 0xEB, 0xF8)      # light-blue process block
BLOCK_ALT = RGBColor(0xE9, 0xF1, 0xF8)
ACTION_RED = RGBColor(0xFC, 0xE4, 0xE4)
DECISION = RGBColor(0xFF, 0xF4, 0xD6)
BAND = RGBColor(0xF2, 0xF4, 0xF7)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)

SERIF = "Times New Roman"
SANS = "Calibri"

SLIDE_W, SLIDE_H = Inches(13.333), Inches(7.5)
FOOTER_H = Inches(0.40)
MARGIN = Inches(0.45)
TITLE_Y, TITLE_H = Inches(0.30), Inches(0.90)
CONTENT_TOP = Inches(1.40)
CONTENT_BOTTOM = SLIDE_H - FOOTER_H - Inches(0.18)

LOGO_W = Inches(2.85)
LOGO_X = SLIDE_W - LOGO_W - Inches(0.40)
LOGO_Y = Inches(0.28)

# --------------------------------------------------------------------------- #
# low-level XML helpers
# --------------------------------------------------------------------------- #
NSMAP = ('xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
         'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
         'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"')


def _xml(fragment: str) -> etree._Element:
    return etree.fromstring(f"<root {NSMAP}>{fragment}</root>")[0]


def strip_style(shape) -> None:
    """Remove the theme style reference so no theme shadow/fill leaks in."""
    style = shape._element.find(qn("p:style"))
    if style is not None:
        shape._element.remove(style)


def add_arrowhead(line_fmt, end: str = "tail") -> None:
    ln = line_fmt._get_or_add_ln()
    for tag in ("a:headEnd", "a:tailEnd"):
        old = ln.find(qn(tag))
        if old is not None and tag == f"a:{end}End":
            ln.remove(old)
    ln.append(_xml(f'<a:{end}End type="triangle" w="med" len="med"/>'))


# --------------------------------------------------------------------------- #
# master / theme setup
# --------------------------------------------------------------------------- #
def configure_theme_fonts(prs: Presentation) -> None:
    master = prs.slide_master
    theme_part = master.part.part_related_by(RT.THEME)
    root = etree.fromstring(theme_part.blob)
    a = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
    root.find(f".//{a}majorFont/{a}latin").set("typeface", SANS)
    root.find(f".//{a}minorFont/{a}latin").set("typeface", SERIF)
    theme_part._blob = etree.tostring(root, xml_declaration=True, encoding="UTF-8",
                                      standalone=True)


def configure_master(prs: Presentation) -> None:
    master = prs.slide_master
    mpart = master.part

    # Background picture.
    _, bg_rid = mpart.get_or_add_image_part(str(ASSETS / "background.png"))
    c_sld = master._element.find(qn("p:cSld"))
    old_bg = c_sld.find(qn("p:bg"))
    if old_bg is not None:
        c_sld.remove(old_bg)
    c_sld.insert(0, _xml(
        f'<p:bg><p:bgPr><a:blipFill dpi="0" rotWithShape="1"><a:blip r:embed="{bg_rid}"/>'
        '<a:srcRect/><a:stretch><a:fillRect/></a:stretch></a:blipFill>'
        '<a:effectLst/></p:bgPr></p:bg>'))

    sp_tree = c_sld.find(qn("p:spTree"))
    _, logo_rid = mpart.get_or_add_image_part(str(ASSETS / "srm_logo.png"))
    from PIL import Image
    lw, lh = Image.open(ASSETS / "srm_logo.png").size
    logo_h = int(LOGO_W * lh / lw)
    fy = SLIDE_H - FOOTER_H

    sp_tree.append(_xml(
        f'<p:pic><p:nvPicPr><p:cNvPr id="901" name="SRMIST Logo" descr="SRM Institute of '
        f'Science and Technology logo"/><p:cNvPicPr><a:picLocks noChangeAspect="1"/>'
        f'</p:cNvPicPr><p:nvPr userDrawn="1"/></p:nvPicPr><p:blipFill><a:blip r:embed="{logo_rid}"/>'
        f'<a:stretch><a:fillRect/></a:stretch></p:blipFill><p:spPr><a:xfrm>'
        f'<a:off x="{int(LOGO_X)}" y="{int(LOGO_Y)}"/><a:ext cx="{int(LOGO_W)}" cy="{logo_h}"/>'
        f'</a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr></p:pic>'))
    sp_tree.append(_xml(
        f'<p:sp><p:nvSpPr><p:cNvPr id="902" name="Footer Band"/><p:cNvSpPr/>'
        f'<p:nvPr userDrawn="1"/></p:nvSpPr><p:spPr><a:xfrm><a:off x="0" y="{int(fy)}"/>'
        f'<a:ext cx="{int(SLIDE_W)}" cy="{int(FOOTER_H)}"/></a:xfrm><a:prstGeom prst="rect">'
        f'<a:avLst/></a:prstGeom><a:solidFill><a:srgbClr val="{FOOTER_RED}"/></a:solidFill>'
        f'<a:ln><a:noFill/></a:ln></p:spPr><p:txBody><a:bodyPr/><a:lstStyle/><a:p>'
        f'<a:endParaRPr lang="en-IN"/></a:p></p:txBody></p:sp>'))
    num_w = Inches(0.9)
    sp_tree.append(_xml(
        f'<p:sp><p:nvSpPr><p:cNvPr id="903" name="Slide Number"/><p:cNvSpPr txBox="1"/>'
        f'<p:nvPr userDrawn="1"/></p:nvSpPr><p:spPr><a:xfrm>'
        f'<a:off x="{int(SLIDE_W - num_w - Inches(0.25))}" y="{int(fy)}"/>'
        f'<a:ext cx="{int(num_w)}" cy="{int(FOOTER_H)}"/></a:xfrm><a:prstGeom prst="rect">'
        f'<a:avLst/></a:prstGeom><a:noFill/></p:spPr><p:txBody><a:bodyPr wrap="none" lIns="0" '
        f'tIns="0" rIns="0" bIns="0" anchor="ctr"/><a:lstStyle/><a:p><a:pPr algn="r"/>'
        f'<a:fld id="{{6D2B6C2A-6F0B-4C47-9C2E-6A1F3B8E0A01}}" type="slidenum"><a:rPr lang="en-IN" '
        f'sz="1600"><a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill><a:latin '
        f'typeface="{SANS}"/></a:rPr><a:t>&#8249;#&#8250;</a:t></a:fld></a:p></p:txBody></p:sp>'))

    # Title style: large red sans, left aligned; body style: serif charcoal.
    tx = master._element.find(qn("p:txStyles"))
    t1 = tx.find(qn("p:titleStyle")).find(qn("a:lvl1pPr"))
    t1.set("algn", "l")
    d = t1.find(qn("a:defRPr"))
    d.set("sz", "4000")
    d.set("b", "0")
    for child in list(d):
        if child.tag in (qn("a:solidFill"),):
            d.remove(child)
    d.insert(0, _xml('<a:solidFill><a:srgbClr val="D60000"/></a:solidFill>'))


def configure_title_layout(prs: Presentation):
    """Return the Title-Only layout with its title placeholder in the house position."""
    layout = prs.slide_layouts[5]
    ph = layout.placeholders[0]
    ph.left, ph.top, ph.width, ph.height = MARGIN, TITLE_Y, Inches(9.0), TITLE_H
    ph.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    return layout


# --------------------------------------------------------------------------- #
# shape helpers
# --------------------------------------------------------------------------- #
def set_title(slide, text: str) -> None:
    title = slide.shapes.title
    title.text_frame.text = ""
    p = title.text_frame.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    r = p.add_run()
    r.text = text
    r.font.name = SANS
    r.font.size = Pt(40)
    r.font.color.rgb = RED
    r.font.bold = False
    title.text_frame.margin_left = 0
    title.name = "Title"


def _e(*vals) -> list[int]:
    """EMU coordinates must be integers: a float such as 1773936.0 is written
    verbatim into the XML, which the schema tolerates but PowerPoint rejects."""
    return [int(round(v)) for v in vals]


def textbox(slide, x, y, w, h, name: str, anchor=MSO_ANCHOR.TOP, margin=0):
    tb = slide.shapes.add_textbox(*_e(x, y, w, h))
    tb.name = name
    tf = tb.text_frame
    tf.word_wrap = True
    tf.auto_size = MSO_AUTO_SIZE.NONE
    tf.vertical_anchor = anchor
    for side in ("margin_left", "margin_right", "margin_top", "margin_bottom"):
        setattr(tf, side, margin)
    return tb


def run(paragraph, text: str, size: float, bold=False, italic=False, color=INK,
        font=SERIF, underline=False):
    r = paragraph.add_run()
    r.text = text
    f = r.font
    f.name, f.size, f.bold, f.italic, f.underline = font, Pt(size), bold, italic, underline
    f.color.rgb = color
    return r


def _ppr(paragraph):
    return paragraph._p.get_or_add_pPr()


def bulletize(paragraph, indent_in: float = 0.32, char: str = "•",
              color: str = "1A1A1A") -> None:
    ppr = _ppr(paragraph)
    ppr.set("marL", str(int(Inches(indent_in))))
    ppr.set("indent", str(-int(Inches(indent_in))))
    for tag in ("a:buNone", "a:buChar", "a:buAutoNum", "a:buClr", "a:buFont"):
        for el in ppr.findall(qn(tag)):
            ppr.remove(el)
    ppr.append(_xml(f'<a:buClr><a:srgbClr val="{color}"/></a:buClr>'))
    ppr.append(_xml('<a:buFont typeface="Arial"/>'))
    ppr.append(_xml(f'<a:buChar char="{char}"/>'))


def numberize(paragraph, start: int, indent_in: float = 0.55) -> None:
    ppr = _ppr(paragraph)
    ppr.set("marL", str(int(Inches(indent_in))))
    ppr.set("indent", str(-int(Inches(indent_in))))
    ppr.append(_xml('<a:buClr><a:srgbClr val="1672B8"/></a:buClr>'))
    ppr.append(_xml('<a:buFont typeface="+mj-lt"/>'))
    ppr.append(_xml(f'<a:buAutoNum type="arabicPeriod" startAt="{start}"/>'))


def spacing(paragraph, after_pt: float = 0, before_pt: float = 0, line: float | None = None):
    paragraph.space_after = Pt(after_pt)
    paragraph.space_before = Pt(before_pt)
    if line is not None:
        paragraph.line_spacing = line


def labelled_list(slide, x, y, w, h, items, size, name, after=10, line=1.0,
                  indent=0.32):
    """Bulleted list of (bold label, explanation) pairs."""
    tb = textbox(slide, x, y, w, h, name)
    tf = tb.text_frame
    for i, (label, body) in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        bulletize(p, indent)
        spacing(p, after_pt=after, line=line)
        run(p, f"{label}: ", size, bold=True)
        run(p, body, size)
    return tb


def box(slide, shape_type, x, y, w, h, name, fill=BLOCK, line=NAVY, line_w=1.25,
        radius: float | None = None, dash=False):
    shp = slide.shapes.add_shape(shape_type, *_e(x, y, w, h))
    shp.name = name
    strip_style(shp)
    if fill is None:
        shp.fill.background()
    else:
        shp.fill.solid()
        shp.fill.fore_color.rgb = fill
    if line is None:
        shp.line.fill.background()
    else:
        shp.line.color.rgb = line
        shp.line.width = Pt(line_w)
        if dash:
            shp.line.dash_style = MSO_LINE_DASH_STYLE.DASH
    if radius is not None:
        shp.adjustments[0] = radius
    tf = shp.text_frame
    tf.word_wrap = True
    tf.auto_size = MSO_AUTO_SIZE.NONE
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    for side in ("margin_left", "margin_right"):
        setattr(tf, side, Inches(0.08))
    for side in ("margin_top", "margin_bottom"):
        setattr(tf, side, Inches(0.04))
    return shp


def block_text(shape, header: str, lines: list[str], h_size=13, b_size=11.5,
               header_color=NAVY, align=PP_ALIGN.CENTER):
    tf = shape.text_frame
    p = tf.paragraphs[0]
    p.alignment = align
    spacing(p, after_pt=2)
    run(p, header, h_size, bold=True, color=header_color, font=SANS)
    for line in lines:
        q = tf.add_paragraph()
        q.alignment = align
        spacing(q, after_pt=0, line=0.95)
        run(q, line, b_size, color=INK, font=SANS)


def arrow(slide, x1, y1, x2, y2, name, color=NAVY, width=1.75, dash=False):
    c = slide.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, *_e(x1, y1, x2, y2))
    c.name = name
    strip_style(c)
    c.line.color.rgb = color
    c.line.width = Pt(width)
    if dash:
        c.line.dash_style = MSO_LINE_DASH_STYLE.DASH
    add_arrowhead(c.line)
    return c


def poly_arrow(slide, points, name, color=NAVY, width=1.75, dash=False):
    """Open polyline with an arrowhead on the last segment (editable freeform)."""
    pts = [tuple(_e(x, y)) for x, y in points]
    fb = slide.shapes.build_freeform(pts[0][0], pts[0][1], scale=1.0)
    fb.add_line_segments(pts[1:], close=False)
    shp = fb.convert_to_shape()
    shp.name = name
    strip_style(shp)
    shp.fill.background()
    shp.line.color.rgb = color
    shp.line.width = Pt(width)
    if dash:
        shp.line.dash_style = MSO_LINE_DASH_STYLE.DASH
    add_arrowhead(shp.line)
    return shp


def label(slide, x, y, w, h, text, size=12, bold=True, color=NAVY, name="Label",
          align=PP_ALIGN.CENTER, italic=False, font=SANS):
    tb = textbox(slide, x, y, w, h, name, anchor=MSO_ANCHOR.MIDDLE)
    p = tb.text_frame.paragraphs[0]
    p.alignment = align
    run(p, text, size, bold=bold, color=color, font=font, italic=italic)
    return tb


def I(v: float) -> Emu:  # noqa: E743 - short inch helper used in layouts
    return Inches(v)


# --------------------------------------------------------------------------- #
# slides
# --------------------------------------------------------------------------- #
def slide_title(prs, blank):
    s = prs.slides.add_slide(blank)
    tb = textbox(s, I(1.0), I(1.15), I(11.333), I(5.55), "Title Page Text",
                 anchor=MSO_ANCHOR.MIDDLE)
    tf = tb.text_frame

    def para(first=False, after=0, before=0, line=None):
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        p.alignment = PP_ALIGN.CENTER
        spacing(p, after_pt=after, before_pt=before, line=line)
        return p

    run(para(first=True, after=4), "21ECC402L - Project Review - 1", 30, bold=True,
        color=BLUE, font=SANS)
    run(para(after=6), "On", 18, bold=True, italic=True, font=SANS)
    run(para(after=8, line=1.05),
        "Intelligent DDoS Detection and Automated Mitigation for IoT–Cloud Networks "
        "Using Dynamic Fuzzing and Graph Neural Networks", 32, bold=True, color=RED, font=SANS)
    run(para(after=4), "by", 18, italic=True, font=SANS, underline=True)
    for name, reg in (("Bangsuka Haldar", "RA2311004010142"), ("Aishna", "RA2311004010151"),
                      ("Mourjya Sanyal", "RA2311004010160")):
        p = para(after=2)
        run(p, f"{name} ", 20, bold=True, color=BLUE, font=SANS)
        run(p, f"({reg})", 20, bold=True, font=SANS)
    run(para(before=16, after=2), "Dr. T Ramya", 20, bold=True, color=RED, font=SANS)
    run(para(), "Assistant Professor, Department of ECE", 18, font=SANS)
    s.notes_slide.notes_text_frame.text = (
        "Title: NetShield-GNN - graph-based DDoS detection with closed-loop mitigation "
        "for IoT-cloud networks.")
    return s


def slide_flow(prs, layout):
    s = prs.slides.add_slide(layout)
    set_title(s, "Flow of presentation")
    items = ["Introduction", "Problem Statement", "Objectives", "Methodology",
             "Block Diagram", "Tools to be Used", "Performance Metrics Studied",
             "Expected Results", "Future Work", "Conclusion", "References"]
    cols = [(items[:6], 1, I(1.15)), (items[6:], 7, I(7.05))]
    for col_items, start, x in cols:
        tb = textbox(s, x, I(1.75), I(5.4), I(4.9), f"Agenda {start}")
        tf = tb.text_frame
        for i, item in enumerate(col_items):
            p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
            numberize(p, start)
            spacing(p, after_pt=20)
            run(p, item, 24)
    return s


def slide_intro(prs, layout):
    s = prs.slides.add_slide(layout)
    set_title(s, "Introduction")
    tb = textbox(s, MARGIN, I(1.6), I(12.43), I(5.25), "Introduction Text")
    p = tb.text_frame.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    spacing(p, line=1.2)
    parts = [
        ("NetShield-GNN", True), (" is a research framework for ", False),
        ("Distributed Denial-of-Service (DDoS)", True),
        (" detection and mitigation in IoT–edge–cloud networks, where large fleets of "
         "low-power "
         "sensors, cameras and controllers are easily compromised and recruited into "
         "botnets. Because such attacks are distributed and individually low-rate, the "
         "evidence rarely sits in any single device; it lies in the relationships between "
         "devices, access routers and the edge gateway. The system therefore simulates the "
         "network packet by packet, exports ", False),
        ("IPFIX-style flow records", True),
        (" every five seconds, converts each window into a graph, and classifies every "
         "node as Benign, Suspicious or Malicious with a ", False),
        ("GraphSAGE graph neural network", True),
        (". Detections drive a graduated rate-limit, block or isolate policy at the ", False),
        ("edge gateway", True),
        (" inside the running simulation, so recovery is measured rather than assumed, "
         "enabling safe and reproducible evaluation before real deployment.", False),
    ]
    for text, bold in parts:
        run(p, text, 22, bold=bold)
    s.notes_slide.notes_text_frame.text = (
        "Domain: IoT network security. Key idea: DDoS evidence is relational, so a graph "
        "model sees what per-device rules cannot.")
    return s


def slide_problem(prs, layout):
    s = prs.slides.add_slide(layout)
    set_title(s, "Problem Statement")
    tb = textbox(s, MARGIN, I(1.9), I(12.43), I(4.2), "Problem Statement Text")
    p = tb.text_frame.paragraphs[0]
    p.alignment = PP_ALIGN.LEFT
    spacing(p, line=1.3)
    parts = [
        ("IoT botnets launch DDoS attacks that saturate the edge-to-cloud uplink and "
         "exhaust server resources. Conventional ", False),
        ("per-device threshold detectors", True),
        (" examine each device in isolation, so distributed low-rate, pulsing and slowloris "
         "attacks evade them, while legitimate surges such as firmware updates raise false "
         "alarms. Testing automated mitigation on a live network is also unsafe. ", False),
        ("A detector is needed that exploits the network’s relational structure and is "
         "validated in a closed loop without risk to real infrastructure.", True),
    ]
    for text, bold in parts:
        run(p, text, 26, bold=bold)
    return s


def slide_objectives(prs, layout):
    s = prs.slides.add_slide(layout)
    set_title(s, "Objectives")
    items = [
        ("Packet-Level Network Simulation",
         "Build an in-memory discrete-event IoT–edge–cloud simulator covering seven "
         "topology families and six DDoS attack families."),
        ("Graph-Based Detection",
         "Model each 5 s window as a graph and classify every node as Benign, Suspicious "
         "or Malicious using GraphSAGE."),
        ("Closed-Loop Mitigation",
         "Rate-limit, block or isolate flagged devices at the gateway while the attack is "
         "still running, protecting clean-device QoS."),
        ("Robustness via Dynamic Fuzzing",
         "Generate unseen attack-parameter combinations (rate, size, pulsing, botnet size) "
         "to stress-test the detectors."),
        ("Comparative Evaluation",
         "Benchmark GraphSAGE against threshold, Random Forest and LightGBM detectors with "
         "run-grouped cross-validation."),
        ("Real-Time Monitoring",
         "Expose live telemetry, alerts and mitigation approvals through a REST/WebSocket "
         "API and an operations console."),
    ]
    labelled_list(s, MARGIN, I(1.55), I(12.43), I(5.3), items, 21, "Objectives List",
                  after=9)
    return s


def slide_methodology(prs, layout):
    s = prs.slides.add_slide(layout)
    set_title(s, "Methodology")
    W, H = I(2.55), I(0.98)
    cols = [I(0.45), I(3.55), I(6.65), I(9.75)]
    r1, r2, r3 = I(1.45), I(3.12), I(4.92)

    def step(i, x, y, header, lines, rounded=False, fill=BLOCK, line=NAVY):
        kind = MSO_SHAPE.ROUNDED_RECTANGLE if rounded else MSO_SHAPE.RECTANGLE
        b = box(s, kind, x, y, W, H, f"Step {i}", fill=fill, line=line,
                radius=0.16 if rounded else None)
        block_text(b, f"{i}. {header}", lines, h_size=13, b_size=11.5,
                   header_color=RED if fill is ACTION_RED else NAVY)
        return b

    step(1, cols[0], r1, "Scenario & Fuzzing Input",
         ["YAML: topology, attack, seed", "Fuzzer: grid · random · mutation"])
    step(2, cols[1], r1, "Discrete-Event Simulation",
         ["IoT apps + botnet, Reno TCP", "7 topologies · 6 attack families"])
    step(3, cols[2], r1, "Flow Telemetry Export",
         ["IPFIX-style 5-tuple flow records", "aggregated per 5 s window"])
    step(4, cols[3], r1, "Feature & Graph Build",
         ["46 features per node-window", "physical + traffic edges"])
    step(5, cols[3], r2, "GraphSAGE Inference",
         ["2-layer mean aggregation", "P(hostile) for every node"])

    dx, dw, dh = I(6.75), I(2.35), I(1.30)
    dy = r2 + (H - dh) / 2
    dia = box(s, MSO_SHAPE.DIAMOND, dx, dy, dw, dh, "Decision", fill=DECISION, line=NAVY)
    dia.text_frame.margin_left = dia.text_frame.margin_right = 0
    p = dia.text_frame.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    run(p, "P(hostile) ≥ 0.80 ?", 13, bold=True, color=NAVY, font=SANS)

    step(6, cols[1], r2, "Mitigation Policy Ladder",
         ["0.80–0.85 rate-limit · ≥0.85 block", "≥0.95 for 2 windows: isolate"],
         rounded=True, fill=ACTION_RED, line=RGBColor(0xC0, 0x00, 0x00))
    step(7, cols[0], r2, "Gateway Enforcement",
         ["throttle / drop by ingress node", "spoof-proof, active from time t"],
         rounded=True, fill=ACTION_RED, line=RGBColor(0xC0, 0x00, 0x00))
    step(8, cols[2], r3, "Normal Forwarding",
         ["no rule installed", "release after 3 clean windows"], rounded=True)
    step(9, cols[0], r3, "Evaluation & Dashboard",
         ["detection + QoS metrics, logs", "live console, reports"])

    cy1, cy2, cy3 = r1 + H / 2, r2 + H / 2, r3 + H / 2
    for a, b in ((0, 1), (1, 2), (2, 3)):
        arrow(s, cols[a] + W, cy1, cols[b], cy1, f"Arrow {a + 1}-{b + 1}")
    arrow(s, cols[3] + W / 2, r1 + H, cols[3] + W / 2, r2, "Arrow 4-5")
    arrow(s, cols[3], cy2, dx + dw, cy2, "Arrow 5-D")
    arrow(s, dx, cy2, cols[1] + W, cy2, "Arrow Yes", color=RGBColor(0xC0, 0x00, 0x00))
    arrow(s, cols[1], cy2, cols[0] + W, cy2, "Arrow 6-7", color=RGBColor(0xC0, 0x00, 0x00))
    arrow(s, dx + dw / 2, dy + dh, dx + dw / 2, r3, "Arrow No")
    arrow(s, cols[2], cy3, cols[0] + W, cy3, "Arrow 8-9")
    arrow(s, cols[0] + W / 2, r2 + H, cols[0] + W / 2, r3, "Arrow 7-9")

    label(s, cols[1] + W + I(0.05), cy2 - I(0.36), I(0.5), I(0.28), "YES", 12,
          color=RGBColor(0xC0, 0x00, 0x00), name="Yes Label")
    label(s, dx + dw / 2 + I(0.08), dy + dh + I(0.04), I(0.5), I(0.28), "NO", 12,
          name="No Label", align=PP_ALIGN.LEFT)

    # Closed loop: enforcement changes packet handling inside the simulation.
    gap_y = r1 + H + (r2 - r1 - H) / 2
    fx = cols[0] + W - I(0.35)
    tx = cols[1] + I(0.45)
    poly_arrow(s, [(fx, r2), (fx, gap_y), (tx, gap_y), (tx, r1 + H)], "Feedback Loop",
               color=RGBColor(0xC0, 0x00, 0x00), width=1.75, dash=True)
    label(s, I(0.45), I(6.13), I(12.43), I(0.32),
          "Dashed red arrow: rules installed at window t change packet handling inside the "
          "running simulation from t onwards (closed loop).", 12, bold=False, italic=True,
          color=MUTED, name="Methodology Caption", align=PP_ALIGN.LEFT)
    s.notes_slide.notes_text_frame.text = (
        "Steps 1-5 run once per 5-second window. The decision uses the mitigation trigger "
        "probability 0.80; the ladder escalates with confidence and persistence.")
    return s


def slide_block_diagram(prs, layout):
    s = prs.slides.add_slide(layout)
    set_title(s, "Block Diagram")
    tiers = ["INPUT MODULES", "SIMULATION CORE", "DETECTION & CONTROL",
             "INTERFACE & OUTPUT"]
    ty = [I(1.42), I(2.82), I(4.22), I(5.62)]
    th = I(0.98)
    lx, lw = I(0.45), I(1.35)
    bx0 = I(1.95)
    bw, gap = I(2.55), I(0.25)
    cx = [bx0 + i * (bw + gap) for i in range(4)]

    for i, (name, y) in enumerate(zip(tiers, ty)):
        band = box(s, MSO_SHAPE.RECTANGLE, lx - I(0.05), y - I(0.07), I(12.53), th + I(0.14),
                   f"Tier Band {i + 1}", fill=BAND, line=RGBColor(0xC9, 0xD3, 0xDE),
                   line_w=0.75)
        band.text_frame.text = ""
        tag = box(s, MSO_SHAPE.ROUNDED_RECTANGLE, lx, y, lw, th, f"Tier Label {i + 1}",
                  fill=BLUE, line=None, radius=0.12)
        p = tag.text_frame.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        run(p, name, 12, bold=True, color=WHITE, font=SANS)

    def blk(col, row, header, lines, w=None, x=None, fill=BLOCK):
        b = box(s, MSO_SHAPE.RECTANGLE, x if x is not None else cx[col], ty[row],
                w or bw, th, header, fill=fill)
        block_text(b, header, lines, h_size=12.5, b_size=11)
        return b

    # Tier 1 - inputs
    blk(0, 0, "Scenario Configuration", ["layered YAML", "topology · attack · seed"])
    blk(1, 0, "IoT Traffic Models", ["MQTT · HTTP · bulk TCP · CoAP/UDP"])
    blk(2, 0, "Botnet Attack Generators", ["UDP · SYN · HTTP · ICMP · ACK",
                                          "slowloris · mixed"])
    blk(3, 0, "Dynamic Fuzzing Engine", ["grid · random · mutation", "adaptive search"])
    # Tier 2 - simulation core
    blk(0, 1, "Topology Builder", ["7 families, BFS routing", "IoT→router→gateway→cloud"])
    eng_x, eng_w = cx[1], cx[3] - gap - cx[1]
    eng = box(s, MSO_SHAPE.RECTANGLE, eng_x, ty[1], eng_w, th, "Discrete-Event Engine",
              fill=BLOCK)
    eng.text_frame.margin_right = Inches(2.25)
    block_text(eng, "Discrete-Event Network Engine",
               ["store-and-forward links, drop-tail queues", "Reno TCP, cloud server (SYN backlog, workers)"],
               h_size=12.5, b_size=11)
    filt_w = I(1.95)
    filt_x = eng_x + eng_w - filt_w - I(0.12)
    filt = box(s, MSO_SHAPE.ROUNDED_RECTANGLE, filt_x, ty[1] + I(0.12), filt_w, th - I(0.24),
               "Gateway Packet Filter", fill=ACTION_RED, line=RGBColor(0xC0, 0x00, 0x00),
               radius=0.18)
    block_text(filt, "Gateway Packet Filter", ["enforcement point"], h_size=11.5, b_size=10.5,
               header_color=RGBColor(0xC0, 0x00, 0x00))
    blk(3, 1, "Telemetry Collector", ["IPFIX-style flows", "per-window QoS metrics"])
    # Tier 3 - detection and control (data flows right to left)
    blk(3, 2, "Feature Extractor", ["46 node-window features", "leakage-checked labels"])
    blk(2, 2, "Window Graph Builder", ["physical + traffic edges", "edge attributes"])
    blk(1, 2, "GNN Detector", ["GraphSAGE (2 layers)", "baselines: RF · LightGBM"])
    blk(0, 2, "Mitigation Engine", ["policy ladder + approvals", "rate-limit / block / isolate"],
        fill=ACTION_RED)
    # Tier 4 - interface and output
    blk(0, 3, "Rule Export", ["OpenFlow · nftables", "P4Runtime"])
    blk(1, 3, "FastAPI Service", ["REST · WebSocket · SSE", "JWT roles, audit log"])
    blk(2, 3, "Operations Console", ["React + TypeScript", "topology, alerts, approvals"])
    blk(3, 3, "Storage & Reports", ["SQLite runs, CSV corpus", "figures, metric reports"])

    mid = lambda c: cx[c] + bw / 2  # noqa: E731
    bot = lambda r: ty[r] + th  # noqa: E731
    # tier 1 -> tier 2
    arrow(s, mid(0), bot(0), mid(0), ty[1], "Config to Topology")
    arrow(s, mid(1), bot(0), mid(1), ty[1], "Traffic to Engine")
    arrow(s, mid(2) - I(0.45), bot(0), mid(2) - I(0.45), ty[1], "Attacks to Engine")
    arrow(s, cx[3], ty[0] + th / 2, cx[2] + bw, ty[0] + th / 2, "Fuzz to Attacks")
    # inside tier 2
    arrow(s, cx[0] + bw, ty[1] + th / 2, eng_x, ty[1] + th / 2, "Topology to Engine")
    arrow(s, eng_x + eng_w, ty[1] + th / 2, cx[3], ty[1] + th / 2, "Engine to Telemetry")
    # tier 2 -> tier 3 and tier 3 chain (right to left)
    arrow(s, mid(3), bot(1), mid(3), ty[2], "Telemetry to Features")
    for a, b in ((3, 2), (2, 1), (1, 0)):
        arrow(s, cx[a], ty[2] + th / 2, cx[b] + bw, ty[2] + th / 2, f"Tier3 {a}-{b}")
    # mitigation engine -> gateway packet filter (closed loop)
    gap_y = bot(1) + (ty[2] - bot(1)) / 2
    fxm = filt_x + filt_w / 2
    poly_arrow(s, [(mid(0) + I(0.6), ty[2]), (mid(0) + I(0.6), gap_y), (fxm, gap_y),
                   (fxm, ty[1] + th - I(0.12))], "Install Rules",
               color=RGBColor(0xC0, 0x00, 0x00), dash=True)
    label(s, fxm + I(0.1), gap_y - I(0.12), I(1.6), I(0.24), "install rules", 11,
          bold=False, italic=True, color=RGBColor(0xC0, 0x00, 0x00), name="Install Label",
          align=PP_ALIGN.LEFT)
    # tier 3 -> tier 4
    arrow(s, mid(0), bot(2), mid(0), ty[3], "Mitigation to Rule Export")
    arrow(s, mid(1), bot(2), mid(1), ty[3], "Detector to API")
    arrow(s, cx[1] + bw, ty[3] + th / 2, cx[2], ty[3] + th / 2, "API to Console")
    arrow(s, mid(3), bot(2), mid(3), ty[3], "Features to Storage")
    s.notes_slide.notes_text_frame.text = (
        "Architecture view: modules and the data that flows between them. The dashed red "
        "path is the control loop from the mitigation engine back into the packet path.")
    return s


def slide_tools(prs, layout):
    s = prs.slides.add_slide(layout)
    set_title(s, "Tools to be used")
    items = [
        ("Python 3.10+", "core language for the simulator, feature pipeline, training and "
                         "evaluation scripts."),
        ("PyTorch & PyTorch Geometric", "build and train the GraphSAGE, GATv2 and "
                                        "E-GraphSAGE models."),
        ("scikit-learn & LightGBM", "Random Forest and gradient-boosted baselines, and "
                                    "evaluation metrics."),
        ("NumPy & pandas", "flow aggregation, node-window feature matrices and run-grouped "
                           "dataset splits."),
        ("NS-3 (via WSL2) & NetAnim", "cross-check scenarios in a standard simulator, with "
                                      "animation."),
        ("FastAPI & Uvicorn", "REST and WebSocket API serving live simulation state, alerts "
                              "and approvals."),
        ("React + TypeScript (Vite)", "operations console for topology, alerts, mitigation "
                                      "and replay."),
        ("Optuna", "adaptive (TPE) adversary that searches for evasive attack parameters."),
    ]
    labelled_list(s, MARGIN, I(1.65), I(12.43), I(5.2), items, 21, "Tools List", after=17)
    return s


def slide_metrics(prs, layout):
    s = prs.slides.add_slide(layout)
    set_title(s, "Performance Metrics studied")
    col_w = I(6.0)
    cats = [
        ("Detection Accuracy & Reliability", MARGIN, [
            ("Macro-F1 Score", "mean per-class F1 over Benign / Suspicious / Malicious; "
                               "robust to class imbalance."),
            ("Attack Recall (%)", "share of hostile node-windows that are detected."),
            ("False-Positive Rate (%)", "benign node-windows wrongly flagged; drives "
                                        "collateral blocking."),
            ("PR-AUC & ECE", "ranking quality and calibration of P(hostile), which the "
                             "policy thresholds."),
        ]),
        ("Network QoS & Mitigation", MARGIN + col_w + I(0.43), [
            ("Time to Detect / Mitigate / Recover (s)", "attack start to first flag, first "
                                                        "rule and restored service."),
            ("Throughput (Mbit/s) & Uplink Utilisation (%)", "goodput reaching the cloud and "
                                                             "bottleneck load."),
            ("Latency p50/p99 (ms) & Jitter (ms)", "one-way delay of clean devices "
                                                    "(RFC 3550 jitter)."),
            ("Loss Ratio & SLO Availability (%)", "clean packets lost, or delivered within "
                                                  "the 100 ms SLO."),
            ("Collateral Byte Ratio (%)", "clean-device traffic dropped by mitigation."),
        ]),
    ]
    for title, x, items in cats:
        head = box(s, MSO_SHAPE.ROUNDED_RECTANGLE, x, I(1.45), col_w, I(0.48),
                   f"{title} Header", fill=BLUE, line=None, radius=0.2)
        p = head.text_frame.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        run(p, title, 18, bold=True, color=WHITE, font=SANS)
        labelled_list(s, x, I(2.12), col_w, I(4.75), items, 19, f"{title} List", after=10,
                      indent=0.28)
    return s


def slide_expected(prs, layout):
    s = prs.slides.add_slide(layout)
    set_title(s, "Expected Results")
    items = [
        ("Detection Within One Window", "attacking bots should be flagged at the first "
         "5 s window boundary after onset, the design floor of a windowed detector."),
        ("Relational Detection of Stealthy Attacks", "GraphSAGE is expected to find "
         "distributed low-rate and slowloris bots that per-device thresholds miss."),
        ("Low False-Alarm Rate", "flash crowds, firmware and reboot storms should not "
         "trigger mitigation of legitimate devices."),
        ("Closed-Loop Recovery", "clean-device loss and latency should return towards the "
         "pre-attack baseline while the attack is still running."),
        ("Minimal Collateral Damage", "ingress-keyed rules should restrict only compromised "
         "nodes, even when source addresses are spoofed."),
        ("Structural Generalisation", "detection should hold on topology families "
         "withheld from training."),
    ]
    labelled_list(s, MARGIN, I(1.55), I(12.43), I(5.3), items, 21, "Expected Results List",
                  after=9)
    return s


def slide_future(prs, layout):
    s = prs.slides.add_slide(layout)
    set_title(s, "Future Work")
    items = [
        ("Physical Testbed Validation", "run the agent on a Mininet / Open vSwitch testbed "
         "and on ESP32 or Raspberry Pi nodes, installing real OpenFlow rules."),
        ("In-Loop NS-3 Enforcement", "integrate the GNN detector into the NS-3 model so "
         "protocol-exact attacks are mitigated inside NS-3 runs."),
        ("Learned Mitigation Policy", "replace fixed probability thresholds with "
         "reinforcement learning driven by measured QoS feedback."),
        ("Federated & Streaming Deployment", "train jointly across gateways and serve "
         "inference through a Redis Streams + ONNX Runtime pipeline."),
        ("Real-Traffic Evaluation", "extend validation to public captures such as "
         "CICIoT2023, adding labels for each device and calibration for each site."),
    ]
    labelled_list(s, MARGIN, I(1.6), I(12.43), I(5.2), items, 22, "Future Work List",
                  after=12)
    return s


def slide_conclusion(prs, layout):
    s = prs.slides.add_slide(layout)
    set_title(s, "Conclusion")
    items = [
        ("Problem", "IoT DDoS attacks are distributed, so per-device thresholds miss "
                    "low-rate bots and misfire on legitimate surges."),
        ("Proposed Solution", "NetShield-GNN classifies every node of a per-window network "
                              "graph with GraphSAGE, using packet-level simulation as its "
                              "data source."),
        ("Closed-Loop Defence", "detections drive a graduated rate-limit, block and isolate "
                                "policy at the gateway, measured inside the same run."),
        ("Expected Contribution", "a safe, reproducible platform and protocol to compare "
                                  "graph-based and conventional detectors on accuracy, "
                                  "timeliness and QoS."),
    ]
    labelled_list(s, MARGIN, I(1.7), I(12.43), I(5.0), items, 23, "Conclusion List",
                  after=16)
    return s


def slide_references(prs, layout):
    s = prs.slides.add_slide(layout)
    set_title(s, "References")
    # IEEE style: (authors + title, italic venue, remainder).
    refs = [
        ('W. L. Hamilton, R. Ying, and J. Leskovec, “Inductive representation learning '
         'on large graphs,” in ', 'Proc. Adv. Neural Inf. Process. Syst. (NeurIPS)',
         ', vol. 30, Long Beach, CA, USA, 2017, pp. 1024–1034.'),
        ('W. W. Lo, S. Layeghy, M. Sarhan, M. Gallagher, and M. Portmann, “E-GraphSAGE: '
         'A graph neural network based intrusion detection system for IoT,” in ',
         'Proc. IEEE/IFIP Netw. Oper. Manage. Symp. (NOMS)',
         ', Budapest, Hungary, 2022, pp. 1–9.'),
        ('C. Kolias, G. Kambourakis, A. Stavrou, and J. Voas, “DDoS in the IoT: Mirai '
         'and other botnets,” ', 'Computer', ', vol. 50, no. 7, pp. 80–84, 2017.'),
        ('E. C. P. Neto, S. Dadkhah, R. Ferreira, A. Zohourian, R. Lu, and A. A. Ghorbani, '
         '“CICIoT2023: A real-time dataset and benchmark for large-scale attacks in IoT '
         'environment,” ', 'Sensors', ', vol. 23, no. 13, Art. no. 5941, 2023.'),
        ('G. F. Riley and T. R. Henderson, “The ns-3 network simulator,” in ',
         'Modeling and Tools for Network Simulation',
         ', K. Wehrle, M. Güneş, and J. Gross, Eds. Berlin, Germany: Springer, '
         '2010, pp. 15–34.'),
        ('B. Claise, B. Trammell, and P. Aitken, “Specification of the IP Flow '
         'Information Export (IPFIX) protocol for the exchange of flow information,” ',
         'IETF RFC 7011', ', Sep. 2013.'),
    ]
    tb = textbox(s, MARGIN, I(1.55), I(12.43), I(5.35), "References List")
    tf = tb.text_frame
    for i, (head, venue, tail) in enumerate(refs):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        ppr = _ppr(p)
        ppr.set("marL", str(int(Inches(0.5))))
        ppr.set("indent", str(-int(Inches(0.5))))
        spacing(p, after_pt=8)
        run(p, f"[{i + 1}]\t", 17)
        run(p, head, 17)
        run(p, venue, 17, italic=True)
        run(p, tail, 17)
    return s


# --------------------------------------------------------------------------- #
def build() -> Path:
    prs = Presentation()
    prs.slide_width, prs.slide_height = SLIDE_W, SLIDE_H
    prs.core_properties.title = "NetShield-GNN - 21ECC402L Project Review 1"
    prs.core_properties.author = "Bangsuka Haldar, Aishna, Mourjya Sanyal"
    prs.core_properties.subject = ("Intelligent DDoS Detection and Automated Mitigation for "
                                   "IoT-Cloud Networks Using Dynamic Fuzzing and GNNs")
    configure_theme_fonts(prs)
    configure_master(prs)
    title_only = configure_title_layout(prs)
    blank = prs.slide_layouts[6]

    slide_title(prs, blank)
    slide_flow(prs, title_only)
    slide_intro(prs, title_only)
    slide_problem(prs, title_only)
    slide_objectives(prs, title_only)
    slide_methodology(prs, title_only)
    slide_block_diagram(prs, title_only)
    slide_tools(prs, title_only)
    slide_metrics(prs, title_only)
    slide_expected(prs, title_only)
    slide_future(prs, title_only)
    slide_conclusion(prs, title_only)
    slide_references(prs, title_only)

    prs.save(OUT)
    print(f"wrote {OUT} ({len(prs.slides)} slides)")
    return OUT


if __name__ == "__main__":
    build()
