"""
Convert WHITEPAPER_COMPLETE.md to professional PDF
Uses reportlab for high-quality PDF generation
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Preformatted
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER, TA_LEFT
from reportlab.lib import colors
from reportlab.pdfgen import canvas
import re

def parse_markdown(md_file):
    """Parse markdown file into structured content"""
    with open(md_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    elements = []
    lines = content.split('\n')
    i = 0
    
    while i < len(lines):
        line = lines[i].strip()
        
        # Skip mermaid diagrams (can't render in PDF easily)
        if line.startswith('```mermaid'):
            while i < len(lines) and not lines[i].strip().startswith('```') or i == 0:
                i += 1
            i += 1  # Skip closing ```
            elements.append(('diagram_placeholder', 'Diagram: See markdown source'))
            continue
        
        # Skip empty lines
        if not line:
            i += 1
            continue
        
        # Headings
        if line.startswith('#'):
            level = len(line) - len(line.lstrip('#'))
            text = line.lstrip('#').strip()
            elements.append(('heading', level, text))
        
        # Code blocks
        elif line.startswith('```'):
            code_lang = line[3:].strip()
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith('```'):
                code_lines.append(lines[i])
                i += 1
            elements.append(('code', '\n'.join(code_lines)))
        
        # Tables
        elif '|' in line and '----|' in lines[min(i+1, len(lines)-1)]:
            table_lines = [line]
            i += 1
            # Skip separator line
            i += 1
            while i < len(lines) and '|' in lines[i]:
                table_lines.append(lines[i].strip())
                i += 1
            elements.append(('table', table_lines))
            continue
        
        # Lists
        elif line.startswith(('- ', '* ', '+ ')) or (line and line[0].isdigit() and '.' in line[:3]):
            elements.append(('list_item', line))
        
        # Horizontal rule
        elif line.startswith('---'):
            elements.append(('hr', None))
        
        # Blockquotes
        elif line.startswith('>'):
            elements.append(('blockquote', line[1:].strip()))
        
        # Regular paragraphs
        else:
            elements.append(('paragraph', line))
        
        i += 1
    
    return elements

def create_pdf(md_file, output_file):
    """Generate PDF from markdown"""
    print(f"Converting {md_file} to {output_file}...")
    
    # Create PDF document
    doc = SimpleDocTemplate(
        output_file,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    
    # Styles
    styles = getSampleStyleSheet()
    
    # Custom styles
    styles.add(ParagraphStyle(
        name='CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    ))
    
    styles.add(ParagraphStyle(
        name='CustomHeading1',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=12,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    ))
    
    styles.add(ParagraphStyle(
        name='CustomHeading2',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#34495e'),
        spaceAfter=10,
        spaceBefore=10,
        fontName='Helvetica-Bold'
    ))
    
    styles.add(ParagraphStyle(
        name='CustomHeading3',
        parent=styles['Heading3'],
        fontSize=12,
        textColor=colors.HexColor('#7f8c8d'),
        spaceAfter=8,
        spaceBefore=8,
        fontName='Helvetica-Bold'
    ))
    
    styles.add(ParagraphStyle(
        name='CustomCode',
        parent=styles['Code'],
        fontSize=8,
        fontName='Courier',
        textColor=colors.HexColor('#2c3e50'),
        backColor=colors.HexColor('#f8f9fa'),
        leftIndent=20,
        rightIndent=20
    ))
    
    # Parse markdown
    elements_data = parse_markdown(md_file)
    
    # Build PDF elements
    story = []
    
    for item in elements_data:
        if item[0] == 'heading':
            level, text = item[1], item[2]
            
            # Clean markdown formatting
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
            text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
            text = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', text)
            
            if level == 1:
                story.append(Paragraph(text, styles['CustomTitle']))
                story.append(Spacer(1, 0.3*inch))
            elif level == 2:
                story.append(Spacer(1, 0.2*inch))
                story.append(Paragraph(text, styles['CustomHeading1']))
            elif level == 3:
                story.append(Paragraph(text, styles['CustomHeading2']))
            else:
                story.append(Paragraph(text, styles['CustomHeading3']))
        
        elif item[0] == 'paragraph':
            text = item[1]
            # Clean markdown
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
            text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
            text = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', text)
            
            story.append(Paragraph(text, styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
        
        elif item[0] == 'code':
            code_text = item[1]
            # Limit code block size
            lines = code_text.split('\n')
            if len(lines) > 50:
                code_text = '\n'.join(lines[:50]) + '\n... [truncated]'
            
            story.append(Preformatted(code_text, styles['CustomCode']))
            story.append(Spacer(1, 0.15*inch))
        
        elif item[0] == 'table':
            # Parse table
            table_lines = item[1]
            data = []
            for line in table_lines:
                cells = [cell.strip() for cell in line.split('|')[1:-1]]
                data.append(cells)
            
            if data:
                t = Table(data)
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(t)
                story.append(Spacer(1, 0.2*inch))
        
        elif item[0] == 'list_item':
            text = item[1]
            text = re.sub(r'^[\-\*\+]\s+', '• ', text)
            text = re.sub(r'^\d+\.\s+', '• ', text)
            text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
            text = re.sub(r'`(.*?)`', r'<font name="Courier">\1</font>', text)
            
            story.append(Paragraph(text, styles['Normal']))
        
        elif item[0] == 'hr':
            story.append(Spacer(1, 0.1*inch))
            story.append(PageBreak())
        
        elif item[0] == 'diagram_placeholder':
            story.append(Paragraph(f'<i>{item[1]}</i>', styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
        
        elif item[0] == 'blockquote':
            text = item[1]
            story.append(Paragraph(f'<i>"{text}"</i>', styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
    
    # Build PDF
    print("Building PDF...")
    doc.build(story)
    print(f"✓ PDF created: {output_file}")

if __name__ == '__main__':
    create_pdf('WHITEPAPER_COMPLETE.md', 'WHITEPAPER_COMPLETE.pdf')
