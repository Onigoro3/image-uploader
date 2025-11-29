# converter.py
import sys
from pdf2docx import Converter

def convert_pdf_to_docx(pdf_file, docx_file):
    try:
        # PDFを読み込み
        cv = Converter(pdf_file)
        # Wordに変換（start=0, end=Noneですべてのページ）
        cv.convert(docx_file, start=0, end=None)
        cv.close()
        print("SUCCESS")
    except Exception as e:
        print(f"ERROR: {str(e)}")

if __name__ == "__main__":
    # Node.jsから引数を受け取る [1]=入力PDF, [2]=出力Word
    if len(sys.argv) > 2:
        convert_pdf_to_docx(sys.argv[1], sys.argv[2])
    else:
        print("ERROR: Invalid arguments")