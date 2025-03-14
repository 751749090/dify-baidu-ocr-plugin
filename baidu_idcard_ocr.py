# baidu_idcard_ocr.py
import os
import requests
import base64
import time
import logging
from pathlib import Path
from typing import Dict, Any, Union, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 配置日志
logger = logging.getLogger(__name__)

class BaiduIDCardOCR:
    """百度身份证OCR识别核心类（优化版）"""

    def __init__(self, api_key: str, secret_key: str):
        self.api_key = api_key
        self.secret_key = secret_key
        self.token_url = "https://aip.baidubce.com/oauth/2.0/token"
        self.idcard_url = "https://aip.baidubce.com/rest/2.0/ocr/v1/idcard"

        # 配置带重试机制的HTTP会话
        self.session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["POST"]
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.headers.update({"Content-Type": "application/x-www-form-urlencoded"})

        self.access_token: Optional[str] = None
        self.token_expire_time: float = 0

    def _get_access_token(self) -> str:
        """智能获取访问令牌（带本地缓存）"""
        current_time = time.time()
        if self.access_token and current_time < self.token_expire_time:
            return self.access_token

        params = {
            "grant_type": "client_credentials",
            "client_id": self.api_key,
            "client_secret": self.secret_key
        }

        try:
            response = self.session.post(self.token_url, params=params, timeout=5)
            response.raise_for_status()
            token_data = response.json()
        except requests.RequestException as e:
            logger.error(f"Token request failed: {str(e)}")
            raise RuntimeError(f"获取访问令牌失败: {str(e)}")

        self.access_token = token_data["access_token"]
        self.token_expire_time = time.time() + token_data["expires_in"] - 300
        return self.access_token

    def _load_image(self, image_input: Union[str, bytes]) -> bytes:
        """通用图片加载方法（支持多种输入格式）"""
        try:
            if isinstance(image_input, bytes):
                return image_input

            if isinstance(image_input, str):
                # 处理base64数据
                if image_input.startswith("data:image"):
                    _, data = image_input.split(",", 1)
                    return base64.b64decode(data)

                # 处理URL
                if image_input.startswith(("http://", "https://")):
                    resp = self.session.get(image_input, timeout=10)
                    resp.raise_for_status()
                    return resp.content

                # 处理本地文件路径
                if Path(image_input).is_file():
                    return Path(image_input).read_bytes()

            raise ValueError("不支持的图片输入类型")
        except Exception as e:
            logger.error(f"图片加载失败: {str(e)}")
            raise

    def _validate_image(self, image_data: bytes) -> None:
        """高效图片验证"""
        # 大小验证
        if len(image_data) > 4 * 1024 * 1024:
            raise ValueError("图片大小超过4MB限制")

        # 格式验证（优化版）
        header = bytes(image_data[:4])
        if header.startswith(b'\xFF\xD8\xFF'):  # JPEG
            return
        if header.startswith(b'\x89PNG'):       # PNG
            return
        if header.startswith(b'BM'):            # BMP
            return
        raise ValueError("仅支持JPEG/PNG/BMP格式")

    def recognize(self,
                 image: Union[bytes, str],
                 card_side: str = "front",
                 detect_quality: bool = True) -> Dict[str, Any]:
        """
        执行OCR识别（带完整错误处理）
        """
        try:
            # 加载并验证图片
            raw_image = self._load_image(image)
            self._validate_image(raw_image)

            # 获取访问令牌
            access_token = self._get_access_token()

            # 构造请求参数
            params = {
                "access_token": access_token,
                "id_card_side": card_side,
                "detect_quality": "true" if detect_quality else "false"
            }

            data = {
                "image": base64.b64encode(raw_image).decode(),
                "detect_risk": "true"
            }

            # 发送OCR请求
            response = self.session.post(
                self.idcard_url,
                params=params,
                data=data,
                timeout=10
            )
            response.raise_for_status()
            result = response.json()

            if "error_code" in result:
                logger.warning(f"API返回错误: {result}")
                return {
                    "success": False,
                    "error_type": "API_ERROR",
                    "error_code": result["error_code"],
                    "message": result.get("error_msg", "未知错误")
                }

            return self._format_result(result, card_side)

        except requests.RequestException as e:
            logger.error(f"网络请求异常: {str(e)}")
            return {
                "success": False,
                "error_type": "NETWORK_ERROR",
                "message": f"网络通信异常: {str(e)}"
            }
        except ValueError as e:
            logger.warning(f"输入验证失败: {str(e)}")
            return {
                "success": False,
                "error_type": "INVALID_INPUT",
                "message": str(e)
            }
        except Exception as e:
            logger.error(f"未处理异常: {str(e)}", exc_info=True)
            return {
                "success": False,
                "error_type": "UNKNOWN_ERROR",
                "message": f"系统异常: {str(e)}"
            }

    def _format_result(self, data: Dict, card_side: str) -> Dict:
        """结构化结果处理"""
        FIELD_MAPPING = {
            "front": {
                "姓名": "name",
                "性别": "gender",
                "民族": "ethnicity",
                "出生": "birth_date",
                "住址": "address",
                "公民身份号码": "id_number"
            },
            "back": {
                "签发机关": "issued_by",
                "有效期限": "valid_period"
            }
        }

        result = {
            "success": True,
            "data": {},
            "quality_info": {
                "image_quality": data.get("image_status", "unknown"),
                "risk_warning": data.get("risk_type", "normal")
            }
        }

        words = data.get("words_result", {})
        for ch_key, en_key in FIELD_MAPPING.get(card_side, {}).items():
            result["data"][en_key] = words.get(ch_key, {}).get("words", "")

        return result


class BaiduIDCardOCRPlugin:
    """Dify插件主类（优化版）"""

    def __init__(self, config: Dict):
        # 参数校验
        required_keys = ["BAIDU_API_KEY", "BAIDU_SECRET_KEY"]
        missing = [k for k in required_keys if k not in config]
        if missing:
            raise ValueError(f"缺少必要配置参数: {', '.join(missing)}")

        self.ocr_engine = BaiduIDCardOCR(
            api_key=config["BAIDU_API_KEY"],
            secret_key=config["BAIDU_SECRET_KEY"]
        )

    def execute(self, parameters: Dict) -> Dict:
        """标准化的插件入口方法"""
        try:
            # 参数验证
            if "image" not in parameters:
                return self._format_error("MISSING_PARAM", "缺少image参数")

            # 执行OCR识别
            ocr_result = self.ocr_engine.recognize(
                image=self._process_input(parameters["image"]),
                card_side=parameters.get("card_side", "front"),
                detect_quality=parameters.get("detect_quality", True)
            )

            # 格式化输出
            if ocr_result["success"]:
                return {
                    "success": True,
                    "data": ocr_result.get("data", {}),
                    "quality_info": ocr_result.get("quality_info", {})
                }
            return {
                "success": False,
                "error": {
                    "type": ocr_result.get("error_type", "UNKNOWN"),
                    "code": ocr_result.get("error_code", "N/A"),
                    "message": ocr_result.get("message", "")
                }
            }

        except Exception as e:
            logger.error(f"插件执行异常: {str(e)}", exc_info=True)
            return self._format_error("PLUGIN_ERROR", str(e))

    def _process_input(self, image_input) -> Union[bytes, str]:
        """统一处理输入数据"""
        try:
            # 处理文件路径输入
            if isinstance(image_input, str):
                if Path(image_input).exists():
                    with open(image_input, "rb") as f:
                        return f.read()
                return image_input  # 可能是base64字符串
            return image_input  # 二进制数据直接传递
        except Exception as e:
            logger.error(f"输入处理失败: {str(e)}")
            raise ValueError(f"无效的图片输入: {str(e)}")

    def _format_error(self, error_type: str, message: str) -> Dict:
        """统一错误格式"""
        return {
            "success": False,
            "error": {
                "type": error_type,
                "message": message
            }
        }


def get_tool(config: Dict):
    """Dify标准入口函数"""
    return BaiduIDCardOCRPlugin(config)