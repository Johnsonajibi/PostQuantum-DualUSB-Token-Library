"""
Create PDF from WHITEPAPER.md using reportlab
"""

from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Preformatted
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
import re

def create_pdf():
    """Convert markdown to PDF"""
    
    whitepaper_path = Path(__file__).parent / "WHITEPAPER.md"
    pdf_output = whitepaper_path.with_suffix('.pdf')
    
    if not whitepaper_path.exists():
        print(f"Error: {whitepaper_path} not found!")
        return
    
    print("Creating PDF from WHITEPAPER.md...")
    
    # Read markdown
    with open(whitepaper_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Create PDF document
    doc = SimpleDocTemplate(
        str(pdf_output),
        pagesize=letter,
        rightMargin=inch,
        leftMargin=inch,
        topMargin=inch,
        bottomMargin=inch
    )
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Define styles
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    heading1_style = ParagraphStyle(
        'CustomHeading1',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=12,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#34495e'),
        spaceAfter=10,
        spaceBefore=10,
        fontName='Helvetica-Bold'
    )
    
    heading3_style = ParagraphStyle(
        'CustomHeading3',
        parent=styles['Heading3'],
        fontSize=12,
        textColor=colors.HexColor('#7f8c8d'),
        spaceAfter=8,
        spaceBefore=8,
        fontName='Helvetica-Bold'
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['BodyText'],
        fontSize=11,
        textColor=colors.black,
        spaceAfter=12,
        alignment=TA_JUSTIFY,
        fontName='Helvetica'
    )
    
    code_style = ParagraphStyle(
        'Code',
        parent=styles['Code'],
        fontSize=9,
        fontName='Courier',
        textColor=colors.HexColor('#2c3e50'),
        backColor=colors.HexColor('#f5f5f5'),
        leftIndent=20,
        rightIndent=20,
        spaceAfter=12
    )
    
    # Parse markdown
    lines = content.split('\n')
    i = 0
    in_code_block = False
    code_lines = []
    
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        
        # Skip horizontal rules
        if stripped.startswith('---'):
            elements.append(Spacer(1, 0.2*inch))
            i += 1
            continue
        
        # Code blocks
        if stripped.startswith('```'):
            if not in_code_block:
                in_code_block = True
                code_lines = []
            else:
                # End of code block
                in_code_block = False
                code_text = '\n'.join(code_lines)
                if code_text.strip():
                    # Split long code lines
                    code_formatted = []
                    for code_line in code_lines:
                        if len(code_line) > 90:
                            # Wrap long lines
                            while len(code_line) > 90:
                                code_formatted.append(code_line[:90])
                                code_line = '  ' + code_line[90:]
                            code_formatted.append(code_line)
                        else:
                            code_formatted.append(code_line)
                    
                    code_text = '\n'.join(code_formatted)
                    pre = Preformatted(code_text, code_style)
                    elements.append(pre)
                    elements.append(Spacer(1, 0.1*inch))
            i += 1
            continue
        
        if in_code_block:
            code_lines.append(line)
            i += 1
            continue
        
        # Main title (first # )
        if stripped.startswith('# ') and not stripped.startswith('## '):
            text = stripped.replace('# ', '')
            # Remove markdown formatting
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
            text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
            text = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', text)
            elements.append(Paragraph(text, title_style))
            elements.append(Spacer(1, 0.2*inch))
        
        # Heading 2
        elif stripped.startswith('## '):
            text = stripped.replace('## ', '')
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
            text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
            text = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', text)
            elements.append(Spacer(1, 0.15*inch))
            elements.append(Paragraph(text, heading1_style))
        
        # Heading 3
        elif stripped.startswith('### '):
            text = stripped.replace('### ', '')
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
            text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
            text = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', text)
            elements.append(Paragraph(text, heading2_style))
        
        # Heading 4
        elif stripped.startswith('#### '):
            text = stripped.replace('#### ', '')
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
            text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
            text = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', text)
            elements.append(Paragraph(text, heading3_style))
        
        # Bullet points
        elif stripped.startswith('- ') or stripped.startswith('* '):
            text = stripped[2:]
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
            text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
            text = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', text)
            bullet_style = ParagraphStyle('Bullet', parent=body_style, leftIndent=20, bulletIndent=10)
            elements.append(Paragraph(f'• {text}', bullet_style))
        
        # Numbered lists
        elif re.match(r'^\d+\. ', stripped):
            text = re.sub(r'^\d+\. ', '', stripped)
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
            text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
            text = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', text)
            num_style = ParagraphStyle('Numbered', parent=body_style, leftIndent=20)
            elements.append(Paragraph(text, num_style))
        
        # Tables (simplified - just convert to text for now)
        elif stripped.startswith('|'):
            # Skip table headers and collect rows
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith('|'):
                if '---' not in lines[i]:
                    table_lines.append(lines[i].strip())
                i += 1
            i -= 1
            
            if table_lines:
                elements.append(Paragraph('<b>[Table content - see DOCX for formatted tables]</b>', body_style))
        
        # Normal paragraph
        elif stripped and not stripped.startswith('[') and not stripped.startswith('**'):
            text = stripped
            # Convert markdown to HTML-like formatting
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
            text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
            text = re.sub(r'`(.*?)`', r'<font name="Courier" color="#c7254e">\1</font>', text)
            text = re.sub(r'\[(.*?)\]\((.*?)\)', r'<u><font color="blue">\1</font></u>', text)
            
            try:
                elements.append(Paragraph(text, body_style))
            except:
                # If paragraph fails, add as preformatted
                elements.append(Preformatted(stripped, code_style))
        
        # Empty line
        elif not stripped:
            pass  # Spacing handled by styles
        
        i += 1
    
    # Build PDF
    try:
        print("Building PDF...")
        doc.build(elements)
        print(f"✓ PDF created successfully: {pdf_output}")
        print(f"\nFile size: {pdf_output.stat().st_size / 1024:.1f} KB")
        return True
    except Exception as e:
        print(f"✗ Error creating PDF: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = create_pdf()
    if success:
        print("\n" + "="*60)
        print("PDF CONVERSION COMPLETE!")
        print("="*60)
        print("\nNote: Tables are simplified in PDF.")
        print("For best formatting, use the DOCX file.")
