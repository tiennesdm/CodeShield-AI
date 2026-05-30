import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Image,
    PageBreak,
    HRFlowable,
    Table,
    TableStyle,
)

def main():
    pdf_path = "/Users/shubhammehta/Documents/New project/ai-code-sheild/project_architecture_beginner.pdf"
    image_path = "/Users/shubhammehta/Documents/New project/ai-code-sheild/docs/images/project_architecture_governance.png"
    
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles for a modern, clean look
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=26,
        leading=30,
        textColor=colors.HexColor("#1E3A5F"),
        alignment=TA_CENTER,
        spaceAfter=10
    )
    
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        textColor=colors.HexColor("#64748B"),
        alignment=TA_CENTER,
        spaceAfter=20
    )

    h1_style = ParagraphStyle(
        "H1Style",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#1E3A5F"),
        spaceBefore=14,
        spaceAfter=10,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        "H2Style",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#2563EB"),
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

    caption_style = ParagraphStyle(
        "CaptionStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8,
        textColor=colors.HexColor("#64748B"),
        alignment=TA_CENTER,
        spaceAfter=15
    )

    story = []
    
    # ----------------------------------------------------
    # COVER PAGE
    # ----------------------------------------------------
    story.append(Spacer(1, 10))
    story.append(Paragraph("CodeShield AI", title_style))
    story.append(Paragraph("Beginner's Guide: Codebase Connections & System Flow", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563EB"), spaceAfter=15))
    
    # ----------------------------------------------------
    # SECTION 1: WELCOME & THE CORE ANALOGY
    # ----------------------------------------------------
    story.append(Paragraph("1. Welcome! Let's Understand the Analogy First", h1_style))
    intro_text = (
        "If you are new to software engineering or AI, this system might look complicated. "
        "Let's make it simple. Think of CodeShield AI as a **high-security automated vault** "
        "and code scanning as a **safety audit process**."
    )
    story.append(Paragraph(intro_text, body_style))
    
    # Analogy Table
    analogy_data = [
        ["System Component", "Real-World Analogy", "What it does in CodeShield AI"],
        ["main.py", "The Reception Desk / Front Desk", "Accepts requests from the UI or CLI and forwards them to the workers."],
        ["scanner/engine.py", "The General Inspector", "Scans code looking for obvious issues like weak passwords or SQL queries."],
        ["agents/orchestrator.py", "The Team Supervisor (HAL)", "Coordinates multiple specialized AI agents, telling them who works when."],
        ["ai_triage.py", "The Security Analyst", "Uses AI (like Gemini/GPT) to double-check if the security warnings are real or false alarms."],
        ["auto_fix.py", "The Expert Carpenter", "Generates safe, valid code patches to fix the security weaknesses."],
        ["database/json_db.py", "The Filing Cabinet", "Stores scan logs and results into simple JSON files in the scans/ directory."]
    ]
    
    t = Table(analogy_data, colWidths=[1.8 * inch, 1.8 * inch, 3.2 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 15))
    
    # ----------------------------------------------------
    # SECTION 2: HIGH-LEVEL ARCHITECTURE MAP
    # ----------------------------------------------------
    story.append(Paragraph("2. The System Architecture Diagram", h1_style))
    story.append(Paragraph(
        "Here is the map showing how all parts connect. When the User uploads a folder, it enters through the **Controller**, "
        "gets scanned in **Scanning**, gets verified by the **AI Swarm**, and finally logged in the **Database**.", body_style
    ))
    
    if os.path.exists(image_path):
        story.append(Image(image_path, width=6.5 * inch, height=3.5 * inch))
        story.append(Paragraph("Figure 1: CodeShield AI System Architecture Map (Frontend -> Backend -> Swarm -> Database)", caption_style))
    else:
        story.append(Paragraph("[Architecture Map Image Not Found - Diagram Section Skipped]", caption_style))
        
    story.append(PageBreak())
    
    # ----------------------------------------------------
    # SECTION 3: STEP-BY-STEP DATA FLOW
    # ----------------------------------------------------
    story.append(Paragraph("3. Step-by-Step Code Flow: How Files Talk to Each Other", h1_style))
    story.append(Paragraph(
        "Let's trace exactly what happens inside the codebase when you click **'Start Scan'** or run the CLI tool in your terminal. "
        "Follow these numbered steps:", body_style
    ))
    
    flow_steps = [
        ("Step 1: The Entrypoint", "main.py", 
         "The user submits a folder or ZIP file. FastAPI in <b>main.py</b> catches the request at <code>POST /api/scan/zip</code>, creates a unique <b>Scan ID</b>, and saves it in the database."),
        ("Step 2: Unpacking & Checking", "scanner/engine.py", 
         "<b>main.py</b> extracts the ZIP to a temporary directory and triggers the Scan Engine in <b>scanner/engine.py</b>. The engine detects what programming languages are in the folder."),
        ("Step 3: Finding Vulnerabilities", "scanner/tools/", 
         "<b>scanner/engine.py</b> runs security scanners like <i>Bandit</i> (for Python) or <i>ESLint</i> (for JavaScript) from the <b>scanner/tools/</b> folder. These scanners output raw findings."),
        ("Step 4: Starting the AI Swarm", "agents/workflows.py", 
         "Once the raw scan is completed, <b>main.py</b> starts the Multi-Agent Swarm in <b>agents/workflows.py</b> to check the results. The supervisor coordinates who inspects what."),
        ("Step 5: Verifying Real Warnings", "ai_triage.py", 
         "The swarm delegates warnings to <b>ai_triage.py</b>. This module uses an LLM (Gemini or OpenAI) to check the surrounding lines of code and filter out false alarms."),
        ("Step 6: Writing the Auto-Fix", "auto_fix.py", 
         "If the user requests a fix, the server calls <b>auto_fix.py</b>. This module asks the LLM to write a code patch, parses it into an AST (Abstract Syntax Tree) to verify it is secure and valid, and generates a code diff."),
        ("Step 7: Saving the Result", "database/json_db.py", 
         "Finally, all updates (verdicts, risk scores, progress, and fixes) are serialized and saved atomically into the scans directory by <b>database/json_db.py</b>, which the frontend displays to the user.")
    ]
    
    for title, file, desc in flow_steps:
        story.append(Paragraph(f"<b>{title}</b> (File: <code>{file}</code>)", h2_style))
        story.append(Paragraph(desc, body_style))
        story.append(Spacer(1, 4))
        
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceBefore=10, spaceAfter=15))
    
    # ----------------------------------------------------
    # SECTION 4: BEGINNER GLOSSARY & REASSURANCE
    # ----------------------------------------------------
    story.append(Paragraph("4. Beginner Glossary: Basic Security Concepts", h1_style))
    story.append(Paragraph(
        "Here are three basic terms you will see everywhere in this project:", body_style
    ))
    
    story.append(Paragraph("1. <b>SAST (Static Application Security Testing):</b> Reading source code like a book to find bugs before running it (e.g., searching for hardcoded keys in a file).", bullet_style))
    story.append(Paragraph("2. <b>SCA (Software Composition Analysis):</b> Auditing project libraries and dependencies (e.g., checking package.json or requirements.txt) to see if you are using outdated, vulnerable third-party packages.", bullet_style))
    story.append(Paragraph("3. <b>Taint Analysis:</b> Tracking user input variables. If input variables flow into dangerous operations (like raw database queries) without sanitization, it flags a vulnerability.", bullet_style))
    
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "<b>Tip for Beginners:</b> Start by looking at <code>main.py</code> to see how requests are accepted. Then, check <code>database/json_db.py</code> to see how data is written. "
        "Once you understand the basic FastAPI server flow, dive into <code>agents/orchestrator.py</code> to see how agents coordinate!", body_style
    ))

    doc.build(story)
    print(f"Successfully generated beginner PDF at {pdf_path}")

if __name__ == "__main__":
    main()
