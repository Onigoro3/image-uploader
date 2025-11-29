# converter.py
import sys
import os
from pdf2docx import Converter
import pdfplumber
import pandas as pd

def convert_to_docx(pdf_file, docx_file):
    try:
        cv = Converter(pdf_file)
        cv.convert(docx_file, start=0, end=None)
        cv.close()
        print("SUCCESS")
    except Exception as e:
        print(f"ERROR: {str(e)}")

def convert_to_xlsx(pdf_file, xlsx_file):
    try:
        # pdfplumberでPDFを開く
        with pdfplumber.open(pdf_file) as pdf:
            # Excel作成の準備
            with pd.ExcelWriter(xlsx_file, engine='openpyxl') as writer:
                has_tables = False
                
                for i, page in enumerate(pdf.pages):
                    # ページ内の表を抽出
                    tables = page.extract_tables()
                    
                    if tables:
                        has_tables = True
                        for j, table in enumerate(tables):
                            # データフレームに変換
                            df = pd.DataFrame(table)
                            # 空のデータを除去
                            df = df.dropna(how='all').dropna(axis=1, how='all')
                            
                            # シート書き込み (Page1_Table1 のような名前)
                            sheet_name = f"P{i+1}_Table{j+1}"
                            df.to_excel(writer, sheet_name=sheet_name, index=False, header=False)
                
                # 表が1つも見つからなかった場合
                if not has_tables:
                    # 空のシートを作成してエラー回避
                    df = pd.DataFrame(["このPDFから表データは検出されませんでした。"])
                    df.to_excel(writer, sheet_name="NoData", index=False, header=False)

        print("SUCCESS")
    except Exception as e:
        print(f"ERROR: {str(e)}")

if __name__ == "__main__":
    # 引数: [1]=入力パス, [2]=出力パス, [3]=形式(docx/xlsx)
    if len(sys.argv) > 3:
        input_path = sys.argv[1]
        output_path = sys.argv[2]
        target_format = sys.argv[3]

        if target_format == 'docx':
            convert_to_docx(input_path, output_path)
        elif target_format == 'xlsx':
            convert_to_xlsx(input_path, output_path)
        else:
            print("ERROR: Unknown format")
    else:
        print("ERROR: Invalid arguments")