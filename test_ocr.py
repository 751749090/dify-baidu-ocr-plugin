# test_ocr.py
import os,json,base64
from baidu_idcard_ocr import BaiduIDCardOCR
import pytest



def test_ocr():
    # 从环境变量获取凭证
    api_key = "vfIn4xQCXmE6N3LDPuqFuT8R"
    secret_key = "RAHxknlozFikFnSpzBvv6LSEUG118HXm"

    ocr = BaiduIDCardOCR(api_key, secret_key)

    # 测试本地文件
    print("测试本地文件:")
    result = ocr.recognize(r"C:\Users\matt\Desktop\id.jpg")
    print(json.dumps(result, indent=2, ensure_ascii=False))

    # 测试Base64
    with open("test_idcard.jpg", "rb") as f:
        base64_data = f"data:image/jpeg;base64,{base64.b64encode(f.read()).decode()}"
    print("\n测试Base64:")
    print(ocr.recognize(base64_data))


if __name__ == "__main__":
    test_ocr()