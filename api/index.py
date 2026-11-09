# -*- coding: utf-8 -*-
"""
Vercel Serverless 适配层
========================
把 backend.py 的业务逻辑包装成 WSGI 应用（Vercel Python 函数入口）。
backend.py 本体零改动：HTTP Server 的 socket I/O 由 _FakeTransport 模拟捕获，
业务方法（路由 / CRUD / Agent 契约 / LLM 调用 / 口令鉴权）原样复用。

环境变量（在 Vercel 控制台 Settings → Environment Variables 配置）：
    DEEPSEEK_API_KEY   大模型 Key（不配置则自动模板降级，页面功能不受影响）
    ADMIN_TOKEN        管理口令（保护写操作与 LLM 配置接口，强烈建议设置）
"""
import io
import json
import os
import sys
from email.message import Message
from http.client import responses as _HTTP_REASONS

# Vercel 代码目录只读：运行数据写到临时盘（实例存活期间有效，冷启动自动重建种子数据）
os.environ.setdefault("DATA_DIR", "/tmp")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import backend  # noqa: E402


class _FakeTransport:
    """模拟 BaseHTTPRequestHandler 的服务器侧 I/O：捕获状态码 / 响应头 / 响应体"""

    def __init__(self):
        self._status = 200
        self._headers = []
        self.wfile = io.BytesIO()

    def send_response(self, status, *args, **kwargs):
        self._status = status

    def send_header(self, name, value):
        self._headers.append((name, str(value)))

    def end_headers(self):
        pass

    def log_message(self, *args, **kwargs):
        pass

    def _read_body(self):
        """与 backend.Handler._read_body 同语义：返回解析后的 dict"""
        if not self._body:
            return {}
        try:
            return json.loads(self._body.decode("utf-8"))
        except Exception:
            return {}


def _make_handler(method, path, headers, body):
    """动态构建处理器：MRO 上 _FakeTransport 优先提供 I/O，业务方法来自 backend.Handler"""
    cls = type("VercelHandler", (_FakeTransport, backend.Handler), {})
    msg = Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    h = cls.__new__(cls)          # 跳过 BaseHTTPRequestHandler.__init__（无 socket 场景）
    _FakeTransport.__init__(h)
    h.command = (method or "GET").upper()
    h.path = path
    h.request_version = "HTTP/1.1"
    h.headers = msg
    h._body = body
    return h


def _dispatch(h):
    m = h.command
    if m == "GET":
        h.do_GET()
    elif m == "POST":
        h.do_POST()
    elif m in ("PUT", "PATCH"):
        h.do_PUT()
    elif m == "DELETE":
        h.do_DELETE()
    elif m == "OPTIONS":
        h.do_OPTIONS()
    else:
        h._send({"ok": False, "error": "不支持的请求方法 " + m}, 405)


def app(environ, start_response):
    """WSGI 入口：Vercel 自动识别 api/index.py 中的 app 变量"""
    method = (environ.get("REQUEST_METHOD") or "GET").upper()
    path = environ.get("PATH_INFO", "/") or "/"
    qs = environ.get("QUERY_STRING", "")
    if qs:
        path = path + "?" + qs
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    body = environ["wsgi.input"].read(length) if length > 0 else b""
    headers = {}
    for k, v in environ.items():
        if k.startswith("HTTP_"):
            headers[k[5:].replace("_", "-")] = v
    if environ.get("CONTENT_TYPE"):
        headers["Content-Type"] = environ["CONTENT_TYPE"]

    h = _make_handler(method, path, headers, body)
    try:
        _dispatch(h)
    except Exception as e:
        h = _make_handler(method, path, headers, body)   # 全新缓冲，避免半截响应
        h._send({"ok": False, "error": "后端处理异常：%s" % e}, 500)

    out = h.wfile.getvalue()
    skip = ("content-length", "transfer-encoding", "connection")
    hdrs = [(k, v) for k, v in h._headers if k.lower() not in skip]
    if not any(k.lower() == "content-type" for k, v in hdrs):
        hdrs.append(("Content-Type", "application/json; charset=utf-8"))
    start_response("%d %s" % (h._status, _HTTP_REASONS.get(h._status, "Response")), hdrs)
    return [out]


handler = app   # 兼容部分模板对 handler 命名的探测
