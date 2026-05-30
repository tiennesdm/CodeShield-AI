import os
import re
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Image,
    PageBreak,
    HRFlowable,
    Preformatted,
)

def main():
    md_path = "/Users/shubhammehta/.gemini/antigravity/brain/5c87f215-c1e1-47fd-be3c-2687d241665e/project_architecture.md"
    pdf_path = "/Users/shubhammehta/Documents/New project/ai-code-sheild/project_architecture.pdf"
    image_path = "/Users/shubhammehta/.gemini/antigravity/brain/5c87f215-c1e1-47fd-be3c-2687d241665e/project_architecture_governance_1780115060062.png"
    
    if not os.path.exists(md_path):
        print(f"Error: {md_path} not found.")
        return

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#1E3A5F"),
        alignment=TA_CENTER,
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        textColor=colors.HexColor("#64748B"),
        alignment=TA_CENTER,
        spaceAfter=25
    )

    h1_style = ParagraphStyle(
        "H1Style",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#1E3A5F"),
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        "H2Style",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#2563EB"),
        spaceBefore=12,
        spaceAfter=8,
        keepWithNext=True
    )

    h3_style = ParagraphStyle(
        "H3Style",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0f766e"),
        spaceBefore=10,
        spaceAfter=6,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#334155"),
        spaceAfter=8
    )

    bullet_style = ParagraphStyle(
        "BulletStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#334155"),
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    )

    code_style = ParagraphStyle(
        "CodeStyle",
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1E293B"),
        backColor=colors.HexColor("#F8FAFC"),
        borderWidth=0.5,
        borderColor=colors.HexColor("#E2E8F0"),
        borderPadding=6,
        spaceBefore=8,
        spaceAfter=8
    )

    story = []
    
    # Title page elements
    story.append(Spacer(1, 40))
    story.append(Paragraph("CodeShield AI", title_style))
    story.append(Paragraph("System Architecture & Data Flow", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563EB"), spaceAfter=20))
    
    with open(md_path, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.split("\n")
    in_code_block = False
    code_text = []

    for line in lines:
        stripped = line.strip()
        
        # Handle code block toggle
        if stripped.startswith("```"):
            if in_code_block:
                in_code_block = False
                code_content = "\n".join(code_text)
                story.append(Preformatted(code_content, code_style))
                code_text = []
            else:
                in_code_block = True
            continue
            
        if in_code_block:
            code_text.append(line)
            continue
            
        # Parse Markdown headers
        if stripped.startswith("# "):
            title = stripped[2:]
            # Skip the first main title since we drew it custom
            if "System Architecture" in title or "CodeShield AI" in title:
                continue
            story.append(Paragraph(title, h1_style))
        elif stripped.startswith("## "):
            h_text = stripped[3:]
            story.append(Paragraph(h_text, h2_style))
        elif stripped.startswith("### "):
            h_text = stripped[4:]
            story.append(Paragraph(h_text, h3_style))
        elif stripped.startswith("!["):
            # Image block
            if os.path.exists(image_path):
                story.append(Spacer(1, 10))
                # Fits perfectly within available 7 inches (504 pt) width
                story.append(Image(image_path, width=6.5 * inch, height=3.5 * inch))
                story.append(Spacer(1, 5))
                story.append(Paragraph("<font size=8><b>Figure:</b> CodeShield AI System Architecture Map</font>", ParagraphStyle("Caption", parent=styles["Normal"], alignment=TA_CENTER, textColor=colors.HexColor("#64748B"))))
                story.append(Spacer(1, 10))
        elif stripped.startswith("- "):
            # Bullet list
            item_text = stripped[2:]
            item_text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', item_text)
            item_text = item_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            story.append(Paragraph(f"&bull; {item_text}", bullet_style))
        elif re.match(r"^\d+\.\s+", stripped):
            # Numbered list
            match = re.match(r"^(\d+)\.\s+(.*)", stripped)
            num = match.group(1)
            item_text = match.group(2)
            item_text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', item_text)
            item_text = item_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            story.append(Paragraph(f"{num}. {item_text}", bullet_style))
        elif stripped == "---":
            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceBefore=10, spaceAfter=15))
        elif stripped == "":
            continue
        else:
            # Paragraph text
            text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', stripped)
            text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            # Support bold markdown inline **bold** -> <b>bold</b>
            text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', text)
            story.append(Paragraph(text, body_style))
            
    doc.build(story)
    print(f"Successfully generated PDF at {pdf_path}")

if __name__ == "__main__":
    main()
