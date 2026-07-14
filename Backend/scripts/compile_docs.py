import os
import sys
import re

try:
    import docx
    from docx import Document
    from docx.shared import Pt, Inches, RGBColor
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
except ImportError:
    print("python-docx is not installed. Attempting to install it first...")
    import subprocess

    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-docx"])
    from docx import Document
    from docx.shared import Pt, Inches, RGBColor
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn


def set_cell_background(cell, color_hex):
    """Sets background color of a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), color_hex)
    tc_pr.append(shd)


def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Sets cell padding (margins) in twentieths of a point (dxa)."""
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = OxmlElement("w:tcMar")
    for m, val in [("top", top), ("bottom", bottom), ("left", left), ("right", right)]:
        node = OxmlElement(f"w:{m}")
        node.set(qn("w:w"), str(val))
        node.set(qn("w:type"), "dxa")
        tc_mar.append(node)
    tc_pr.append(tc_mar)


def add_header_footer(doc):
    """Adds page headers and footers to the document."""
    section = doc.sections[0]
    header = section.header
    hp = header.paragraphs[0]
    hp.text = "CCure-Audit-PRO — Technical Documentation Suite"
    hp.alignment = 2  # Right-aligned
    hp.style.font.size = Pt(8.5)
    hp.style.font.italic = True

    footer = section.footer
    fp = footer.paragraphs[0]
    fp.text = "CCure-Audit-PRO (Production Build 2026) | Confidential"
    fp.alignment = 1  # Center-aligned
    fp.style.font.size = Pt(8.5)


def parse_markdown_to_docx(doc_files, output_path):
    print(f"Creating output docx at: {output_path}")
    doc = Document()
    add_header_footer(doc)

    # Set standard margins (1 inch)
    for section in doc.sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Document Title Page
    title_p = doc.add_paragraph()
    title_p.alignment = 1  # Center
    title_run = title_p.add_run("CCure-Audit-PRO\n")
    title_run.font.size = Pt(28)
    title_run.font.bold = True
    title_run.font.name = "Arial"

    subtitle_run = title_p.add_run("Enterprise Technical Documentation Suite\n\n")
    subtitle_run.font.size = Pt(18)
    subtitle_run.font.italic = True
    subtitle_run.font.name = "Arial"

    meta_p = doc.add_paragraph()
    meta_p.alignment = 1
    meta_run = meta_p.add_run(
        "Compiled Directly from Running Codebase Implementation\nDate: July 2026 | Version 2.4.0-Prod"
    )
    meta_run.font.size = Pt(11)
    meta_run.font.name = "Arial"

    doc.add_page_break()

    for file_path in doc_files:
        if not os.path.isfile(file_path):
            print(f"Warning: File {file_path} does not exist. Skipping.")
            continue

        print(f"Parsing: {os.path.basename(file_path)}")

        # Add section header representing the file name
        section_title = (
            os.path.basename(file_path).replace(".md", "").replace("_", " ").title()
        )
        p = doc.add_paragraph()
        run = p.add_run(section_title)
        run.font.size = Pt(20)
        run.font.bold = True
        run.font.color.rgb = RGBColor(0, 51, 102)  # Dark Blue
        p.style = doc.styles["Heading 1"]

        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        in_code_block = False
        code_text = []
        in_table = False
        table_rows = []

        for line in lines:
            stripped = line.strip()

            # Code block detection
            if stripped.startswith("```"):
                if in_code_block:
                    # End of code block
                    p = doc.add_paragraph()
                    p.paragraph_format.left_indent = Inches(0.4)
                    run = p.add_run("".join(code_text))
                    run.font.name = "Consolas"
                    run.font.size = Pt(9.5)
                    # Light grey background
                    p_format = p.paragraph_format
                    p_format.space_before = Pt(6)
                    p_format.space_after = Pt(6)
                    in_code_block = False
                    code_text = []
                else:
                    # Start of code block
                    in_code_block = True
                continue

            if in_code_block:
                code_text.append(line)
                continue

            # Table detection
            if stripped.startswith("|") and stripped.endswith("|"):
                # Parse row cells
                cells = [c.strip() for c in stripped.split("|")[1:-1]]
                # Skip the delimiter row (e.g. |---|---|)
                if all(re.match(r"^:?-+:?$", c) for c in cells):
                    continue
                in_table = True
                table_rows.append(cells)
                continue
            else:
                if in_table and table_rows:
                    # Create the Word Table
                    num_cols = max(len(r) for r in table_rows)
                    word_table = doc.add_table(rows=len(table_rows), cols=num_cols)
                    word_table.style = "Table Grid"

                    for r_idx, row_cells in enumerate(table_rows):
                        for c_idx, cell_value in enumerate(row_cells):
                            if c_idx >= len(word_table.rows[r_idx].cells):
                                continue
                            cell = word_table.rows[r_idx].cells[c_idx]
                            cell.text = cell_value

                            # Styling
                            set_cell_margins(
                                cell, top=100, bottom=100, left=150, right=150
                            )
                            if r_idx == 0:
                                # Header styling
                                set_cell_background(cell, "003366")  # Dark Blue
                                for p in cell.paragraphs:
                                    for r in p.runs:
                                        r.font.bold = True
                                        r.font.color.rgb = RGBColor(255, 255, 255)
                                        r.font.size = Pt(9.5)
                            else:
                                # Zebra striping
                                if r_idx % 2 == 0:
                                    set_cell_background(cell, "F2F2F2")  # Light Grey
                                for p in cell.paragraphs:
                                    for r in p.runs:
                                        r.font.size = Pt(9.0)
                    doc.add_paragraph()  # space after table
                    in_table = False
                    table_rows = []

            # Headings
            match = re.match(r"^(#{1,6})\s+(.*)", stripped)
            if match:
                level = len(match.group(1))
                text_val = match.group(2)
                p = doc.add_paragraph()
                run = p.add_run(text_val)
                run.font.bold = True
                run.font.name = "Arial"
                if level == 1:
                    run.font.size = Pt(16)
                    run.font.color.rgb = RGBColor(0, 51, 102)
                    p.style = doc.styles["Heading 2"]
                elif level == 2:
                    run.font.size = Pt(13)
                    run.font.color.rgb = RGBColor(0, 51, 102)
                    p.style = doc.styles["Heading 3"]
                else:
                    run.font.size = Pt(11)
                    p.style = doc.styles["Normal"]
                continue

            # Lists
            match_list = re.match(r"^[-*+]\s+(.*)", stripped)
            if match_list:
                p = doc.add_paragraph(style="List Bullet")
                p.add_run(match_list.group(1))
                continue

            match_num_list = re.match(r"^\d+\.\s+(.*)", stripped)
            if match_num_list:
                p = doc.add_paragraph(style="List Number")
                p.add_run(match_num_list.group(1))
                continue

            # Alert blocks (e.g. > [!IMPORTANT])
            if stripped.startswith(">"):
                alert_text = stripped[1:].strip()
                p = doc.add_paragraph()
                p.paragraph_format.left_indent = Inches(0.4)
                run = p.add_run(alert_text)
                run.font.italic = True
                run.font.color.rgb = RGBColor(102, 102, 102)
                continue

            if stripped == "":
                continue

            # Normal paragraph
            p = doc.add_paragraph()
            p.add_run(stripped)

        doc.add_page_break()

    doc.save(output_path)
    print("Document compiled successfully!")


if __name__ == "__main__":
    repo_root = "c:/Users/pankaj/Downloads/Automation Tool/CCure-Audit-PRO"
    doc_dir = os.path.join(repo_root, "docs")

    files_to_compile = [
        os.path.join(doc_dir, "SYSTEM_ARCHITECTURE.md"),
        os.path.join(doc_dir, "BACKEND_API_REFERENCE.md"),
        os.path.join(doc_dir, "DATABASE_SCHEMA.md"),
        os.path.join(doc_dir, "AUTHENTICATION_AND_AUTHORIZATION.md"),
        os.path.join(doc_dir, "FRONTEND_ARCHITECTURE.md"),
        os.path.join(doc_dir, "DEVELOPER_SETUP_GUIDE.md"),
        os.path.join(doc_dir, "RBAC_Management_Permissions.md"),
        os.path.join(doc_dir, "SCAN_ENGINE_DEEP_DIVE.md"),
    ]

    output_docx = os.path.join(doc_dir, "CCure_Audit_PRO_Documentation.docx")
    parse_markdown_to_docx(files_to_compile, output_docx)
