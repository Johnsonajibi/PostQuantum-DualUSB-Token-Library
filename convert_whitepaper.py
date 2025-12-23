"""
Convert WHITEPAPER.md to PDF and DOCX formats
"""

import os
from pathlib import Path

def convert_markdown_to_formats():
    """Convert markdown to PDF and DOCX using pandoc"""
    
    whitepaper_path = Path(__file__).parent / "WHITEPAPER.md"
    
    if not whitepaper_path.exists():
        print(f"Error: {whitepaper_path} not found!")
        return
    
    # Output paths
    pdf_output = whitepaper_path.with_suffix('.pdf')
    docx_output = whitepaper_path.with_suffix('.docx')
    
    print("Converting WHITEPAPER.md to PDF and DOCX...")
    print(f"Source: {whitepaper_path}")
    
    try:
        # Convert to PDF
        print("\n[1/2] Converting to PDF...")
        pdf_cmd = f'pandoc "{whitepaper_path}" -o "{pdf_output}" --pdf-engine=xelatex -V geometry:margin=1in -V fontsize=11pt --toc --toc-depth=3'
        result = os.system(pdf_cmd)
        
        if result == 0:
            print(f"✓ PDF created: {pdf_output}")
        else:
            print(f"✗ PDF conversion failed. Trying alternative method...")
            # Try without xelatex
            pdf_cmd_alt = f'pandoc "{whitepaper_path}" -o "{pdf_output}" -V geometry:margin=1in -V fontsize=11pt --toc --toc-depth=3'
            result_alt = os.system(pdf_cmd_alt)
            if result_alt == 0:
                print(f"✓ PDF created: {pdf_output}")
            else:
                print("✗ PDF conversion requires pandoc and LaTeX. See installation instructions below.")
        
        # Convert to DOCX
        print("\n[2/2] Converting to Microsoft Word (DOCX)...")
        docx_cmd = f'pandoc "{whitepaper_path}" -o "{docx_output}" --toc --toc-depth=3 --reference-doc=reference.docx 2>nul || pandoc "{whitepaper_path}" -o "{docx_output}" --toc --toc-depth=3'
        result = os.system(docx_cmd)
        
        if result == 0:
            print(f"✓ DOCX created: {docx_output}")
        else:
            print("✗ DOCX conversion requires pandoc. See installation instructions below.")
        
        print("\n" + "="*60)
        print("CONVERSION COMPLETE!")
        print("="*60)
        
        if pdf_output.exists():
            print(f"📄 PDF:  {pdf_output}")
        if docx_output.exists():
            print(f"📝 DOCX: {docx_output}")
            
    except Exception as e:
        print(f"\nError during conversion: {e}")
        print("\nTo install pandoc:")
        print("  Windows: choco install pandoc  (or download from https://pandoc.org/installing.html)")
        print("  Linux:   sudo apt-get install pandoc texlive-xetex")
        print("  Mac:     brew install pandoc basictex")

if __name__ == "__main__":
    convert_markdown_to_formats()
