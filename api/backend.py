# -*- coding: utf-8 -*-
"""
鉴微 AI助手 · 纯标准库后端（演示/集成用）
================================================
职责：
1. 托管前端 insight-replica.html（同源，无 CORS 问题）
2. 平台数据 CRUD（功能一/功能三所需数据：漏洞/资产/软件/知识库/情报库/审计日志）
3. Agent 契约接口（/agent-api/*，见《AI功能后端接入契约.md》）：
   - 功能一 漏洞研判摘要  POST /agent-api/judgement
   - 功能三 修复建议本地化 POST /agent-api/fix-advice
   - 功能三 采纳并建工单   POST /agent-api/fix-advice/adopt
   - 通用   由漏洞建工单   POST /agent-api/tickets
4. LLM 真实分析（OpenAI 兼容协议，纯 urllib）：三种配置方式，优先级从高到低——
   ① 前端「配置中心 → 系统设置」页在线配置（URL/Key/模型，写入 data.json，Key 脱敏）
   ② 环境变量 DEEPSEEK_API_KEY（可加 LLM_BASE_URL / LLM_MODEL）
   ③ 下方 CONFIG["llm"] 源码默认值
   未配置或调用失败自动降级为本地模板生成（响应中 generatedBy 字段标明来源）。
   可选安全：设置环境变量 ADMIN_TOKEN 后，写操作与配置接口需携带 X-Admin-Token 头。

启动：
    python backend.py
    → 前端 http://127.0.0.1:8000/insight-replica.html
    → 数据 http://127.0.0.1:8000/api/<集合名>
依赖：零第三方库（json/sqlite 不需要，数据存 data.json）
"""
import json
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", BASE_DIR)   # 函数计算等只读代码目录环境，用 DATA_DIR 指向可写盘（如 /tmp）
DATA_FILE = os.path.join(DATA_DIR, "data.json")
FRONTEND_FILE = os.path.join(BASE_DIR, "insight-replica.html")
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
# 管理口令：设置后「写操作 + LLM 配置接口」需携带 X-Admin-Token 请求头；留空则不启用鉴权（本地演示模式）
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

# ================================================================
# 配置区 —— LLM 接入默认值（优先级最低）
# 实际生效顺序：运行时配置（data.json llmConfig，由前端「系统设置」页写入）
#            > 环境变量 DEEPSEEK_API_KEY / LLM_BASE_URL / LLM_MODEL
#            > 此处源码默认值
# ================================================================
CONFIG = {
    "llm": {
        "provider": "deepseek",
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-flash",   # DeepSeek-V4.1-Flash（即 v4-flash，当前最便宜的档位）
        "api_key": "",   # 源码默认 Key：建议留空，通过环境变量或前端「系统设置」页注入
        "timeout": 60,
        "effort": "low",             # 推理档位（配合下方 thinking disabled 后不再产生 reasoning tokens）
        "thinking": "disabled",      # 实测有效：关闭思考后 reasoning_tokens=0，最省且正文稳定
        "max_tokens_summary": 420,   # 功能一 摘要输出上限
        "max_tokens_steps": 560,     # 功能二 步骤输出上限
        "temperature": 0.2,
    }
}

_store_lock = threading.Lock()


def _env_key():
    return os.environ.get("DEEPSEEK_API_KEY", "")


def get_llm_effective():
    """LLM 生效配置：运行时覆盖（data.json llmConfig）> 环境变量 > 源码默认值"""
    cfg = dict(CONFIG["llm"])
    try:
        rt = load_store().get("llmConfig") or {}
    except Exception:
        rt = {}
    env = {"base_url": os.environ.get("LLM_BASE_URL", ""), "api_key": _env_key(),
           "model": os.environ.get("LLM_MODEL", "")}
    for k in ("base_url", "api_key", "model"):
        v = (str(rt.get(k) or "").strip() or env.get(k, "")).strip()
        if v:
            cfg[k] = v
    return cfg


def llm_ready():
    return bool(get_llm_effective().get("api_key"))


def llm_config_view():
    """配置查询：Key 永不回显明文，只给尾号；keySource 标明当前生效来源"""
    cfg = get_llm_effective()
    key = cfg.get("api_key", "")
    try:
        rt = load_store().get("llmConfig") or {}
    except Exception:
        rt = {}
    override = bool(str(rt.get("api_key") or "").strip())
    return {"ok": True, "data": {
        "provider": cfg.get("provider", ""),
        "baseUrl": cfg.get("base_url", ""),
        "model": cfg.get("model", ""),
        "temperature": cfg.get("temperature", 0.2),
        "keyConfigured": bool(key),
        "keyMasked": ("已配置（尾号 %s）" % key[-4:]) if key else "未配置",
        "keySource": ("本页自定义 Key（尾号 %s，已替换服务端默认）" % key[-4:]) if override
                     else ("服务端内置 Key（尾号 %s）" % key[-4:]) if key else "未配置",
        "overrideActive": override,
        "adminAuth": bool(ADMIN_TOKEN),
    }}


def save_llm_config(store, body):
    """系统设置页保存 LLM 接入配置；Key 只写盘、不落审计日志、查询接口脱敏"""
    cfg = store.setdefault("llmConfig", {})
    changed = []
    if "baseUrl" in body:
        u = str(body["baseUrl"]).strip().rstrip("/")
        if u and not (u.startswith("http://") or u.startswith("https://")):
            return {"ok": False, "error": "接入地址需以 http:// 或 https:// 开头"}
        cfg["base_url"] = u
        changed.append("接入地址")
    if "apiKey" in body:
        k = str(body["apiKey"]).strip()
        if k:
            cfg["api_key"] = k
            changed.append("API Key")
        else:
            cfg.pop("api_key", None)   # 空值 = 清除运行时覆盖，回落环境变量/默认
            changed.append("API Key（清除覆盖）")
    if "model" in body:
        cfg["model"] = str(body["model"]).strip()
        changed.append("模型名")
    add_audit(store, "大模型配置：更新接入配置（%s）" % ("、".join(changed) or "无变更"))
    save_store(store)
    return {"ok": True, "data": llm_config_view()["data"]}


def test_llm_config(body=None):
    """连通性测试（16 tokens 最小请求）：默认用生效配置；
    body 携带 baseUrl/apiKey/model 时优先用页面输入——分析师无需先保存即可测试"""
    body = body or {}
    cfg = get_llm_effective()
    u = str(body.get("baseUrl") or "").strip().rstrip("/")
    k = str(body.get("apiKey") or "").strip()
    m = str(body.get("model") or "").strip()
    if u:
        if not (u.startswith("http://") or u.startswith("https://")):
            return {"ok": False, "error": "接入地址需以 http:// 或 https:// 开头"}
        cfg["base_url"] = u
    if k:
        cfg["api_key"] = k
    if m:
        cfg["model"] = m
    if not (cfg.get("base_url") and cfg.get("api_key")):
        return {"ok": False, "error": "尚未配置接入地址或 API Key，请先填写并保存"}
    payload = {"model": cfg["model"], "max_tokens": 16, "stream": False,
               "messages": [{"role": "user", "content": "回复：ok"}]}
    req = urllib.request.Request(
        cfg["base_url"] + "/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + cfg["api_key"]},
        method="POST",
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=cfg.get("timeout", 60)) as resp:
            out = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.loads(e.read().decode("utf-8")).get("error", {}).get("message", "")
        except Exception:
            pass
        return {"ok": False, "error": "HTTP %s%s" % (e.code, ("：" + detail) if detail else "")}
    except Exception as e:
        return {"ok": False, "error": "连接失败：%s" % e}
    ms = int((time.time() - t0) * 1000)
    sample = ""
    try:
        sample = (out["choices"][0]["message"].get("content") or "")[:40]
    except Exception:
        pass
    return {"ok": True, "data": {"latencyMs": ms, "model": cfg["model"], "sample": sample}}


# ================================================================
# 测试数据（与前端 LocalActions 的 demo 快照一致；首次运行写入 data.json）
# ================================================================
IP_RAW = [
    [228, 'ZTE ZXR10 1800-2S 安全漏洞', 'CVE-2017-10930', '未授权访问漏洞', 'P0', '超危', '172.31.18.33', '批量导入', '待处理'],
    [229, 'OpenSSH 代码问题漏洞', 'CVE-2023-38408', '逻辑漏洞', 'P0', '超危', '47.95.246.187', 'wjg-demo', '待处理'],
    [230, 'HTTP/2 Bomb 远程拒绝服务漏洞(CVE-2026-49975)', 'CVE-2026-49975', '其他', 'P0', '超危', '192.168.2.102', '批量导入', '待处理'],
    [231, 'DocCms 代码问题漏洞', 'CVE-2019-16192', '逻辑漏洞', 'P0', '超危', '255.255.255.5', '批量导入', '待处理'],
    [232, 'OpenSSH 安全漏洞', 'CVE-2023-28531', '其他', 'P0', '超危', '47.95.246.187', 'wjg-demo', '待处理'],
    [233, 'Redis 代码注入漏洞', 'CVE-2022-0543', '远程代码执行漏洞', 'P0', '超危', '192.168.1.12', 'test4、test1', '待处理'],
    [234, 'Redis 代码注入漏洞', 'CVE-2022-0543', '远程代码执行漏洞', 'P0', '超危', '192.168.1.11', 'test4、test1', '待处理'],
    [235, 'Redis 代码注入漏洞', 'CVE-2022-0543', '远程代码执行漏洞', 'P0', '超危', '192.168.1.10', 'test4、test1', '待处理'],
    [236, 'Redis 代码注入漏洞', 'CVE-2022-0543', '远程代码执行漏洞', 'P0', '超危', '192.168.1.13', 'test', '待处理'],
    [237, 'Redis 代码注入漏洞', 'CVE-2022-0543', '远程代码执行漏洞', 'P0', '超危', '192.168.1.12', 'test', '待处理'],
    [240, 'Apache Log4j2 远程代码执行漏洞(Log4Shell)', 'CVE-2021-44228', '远程代码执行漏洞', 'P0', '超危', '172.17.9.37', '洞鉴01', '待处理'],
    [241, 'Windows SMBv1 远程代码执行漏洞(永恒之蓝)', 'CVE-2017-0144', '远程代码执行漏洞', 'P0', '超危', '255.255.255.5', '批量导入', '待处理'],
    [242, 'Struts2 S2-045 远程代码执行漏洞', 'CVE-2017-5638', '远程代码执行漏洞', 'P0', '超危', '172.16.1.2', '洞鉴01', '待处理'],
    [243, 'Oracle WebLogic 管理控制台未授权命令执行漏洞', 'CVE-2020-14882', '远程代码执行漏洞', 'P0', '超危', '255.255.255.3', '批量导入', '待处理'],
    [244, 'ThinkPHP 5.x 远程代码执行漏洞', 'CVE-2018-20062', '远程代码执行漏洞', 'P0', '超危', '255.255.255.6', '洞鉴01', '待处理'],
    [245, 'Redis 弱口令漏洞', '(空)', '弱口令漏洞', 'P2', '中危', '192.168.2.10', '手动提交', '待处理'],
    [246, 'Apache HTTP Server 路径穿越漏洞', 'CVE-2021-41773', '路径遍历漏洞', 'P1', '高危', '172.16.1.2', '洞鉴01', '待处理'],
    [247, 'Apache Shiro rememberMe 反序列化漏洞', 'CVE-2016-4437', '反序列化漏洞', 'P1', '高危', '172.17.9.37', 'wjg-demo', '待处理'],
    [248, 'Spring Framework 远程代码执行漏洞(Spring4Shell)', 'CVE-2022-22965', '远程代码执行漏洞', 'P1', '高危', '172.17.9.37', 'wjg-demo', '确认中'],
    [249, 'Fastjson 反序列化远程代码执行漏洞', 'CVE-2022-25845', '反序列化漏洞', 'P1', '高危', '172.17.9.37', '批量导入', '待处理'],
    [250, 'Sudo 本地权限提升漏洞(Baron Samedit)', 'CVE-2021-3156', '其他', 'P1', '高危', '10.0.0.1', '手动提交', '待处理'],
    [251, 'OpenSSL Heartbleed 心脏出血漏洞', 'CVE-2014-0160', '敏感信息泄露漏洞', 'P1', '高危', '255.255.255.4', '批量导入', '待处理'],
    [252, 'Linux 内核 Dirty COW 竞态条件提权漏洞', 'CVE-2016-5195', '其他', 'P0', '超危', '192.168.2.10', '手动提交', '待处理'],
    [253, 'OpenSSH 用户名枚举漏洞', 'CVE-2018-15473', '其他', 'P3', '低危', '10.0.0.1', '洞鉴01', '待处理'],
    [254, 'GitLab ExifTool 远程代码执行漏洞', 'CVE-2021-22205', '远程代码执行漏洞', 'P0', '超危', '172.16.1.2', '洞鉴01', '修复中'],
    [255, 'Jenkins 反序列化远程代码执行漏洞', 'CVE-2018-1000861', '反序列化漏洞', 'P1', '高危', '172.16.1.2', '批量导入', '待复测'],
    [256, 'Confluence OGNL 注入远程代码执行漏洞', 'CVE-2022-26134', '远程代码执行漏洞', 'P0', '超危', '10.0.0.1', '洞鉴01', '已修复'],
    [257, 'Tomcat PUT 方法任意文件写入漏洞', 'CVE-2017-12615', '文件上传漏洞', 'P1', '高危', '255.255.255.2', '批量导入', '已修复'],
    [258, 'Zabbix 后端敏感信息泄露漏洞', 'CVE-2022-23134', '敏感信息泄露漏洞', 'P2', '中危', '255.255.255.6', '洞鉴01', '误报'],
    [259, 'Drupal 远程代码执行漏洞(Drupalgeddon2)', 'CVE-2018-7600', '远程代码执行漏洞', 'P2', '中危', '255.255.255.2', '批量导入', '忽略'],
]
WEB_RAW = [
    [301, 'Google Golang /debug/vars 信息泄露漏洞', '(空)', '敏感信息泄露漏洞', 'P0', '超危', 'http://192.168.0.1:9...', '手动提交、洞鉴01', '待处理'],
    [302, '标题', '(空)', '点击劫持', 'P0', '超危', 'https://oa.example-g...', '手动提交', '待处理'],
    [303, 'SpringBoot Actuator Jolokia 端点未授权访问', '(空)', '未授权访问漏洞', 'P1', '高危', 'http://172.17.9.37:9...', '批量导入', '待处理'],
    [304, 'SpringBoot Actuator Jolokia 端点未授权访问', '(空)', '未授权访问漏洞', 'P1', '高危', 'http://172.17.9.37:9...', '批量导入', '待处理'],
    [305, 'SpringBoot Actuator Jolokia 端点未授权访问', '(空)', '未授权访问漏洞', 'P1', '高危', 'http://172.17.9.37:8...', '手动提交', '待处理'],
    [306, 'Swagger UI 敏感信息泄露', '(空)', '其他', 'P2', '中危', 'http://192.168.1.1:8...', '批量导入', '待处理'],
    [307, 'http慢速攻击', 'CVE-2007-6750', '其他', 'P2', '中危', 'http://192.168.1.1:8...', '批量导入', '待处理'],
    [308, '内容安全策略 (CSP) 配置不当 / 缺失', '(空)', '其他', 'P2', '中危', 'http://192.168.1.1:8...', '批量导入', '待处理'],
    [309, '认证验收-网站探测漏洞', '(空)', '不安全的配置漏洞', 'P2', '中危', 'https://192.0.2.99:4...', '批量导入', '待处理'],
    [310, 'Go pprof 调试信息泄露漏洞', '(空)', '敏感信息泄露漏洞', 'P2', '中危', 'http://192.168.0.1:9...', '洞鉴01', '待处理'],
    [311, 'Java 应用反序列化远程代码执行漏洞', '(空)', '反序列化漏洞', 'P0', '超危', 'http://172.17.9.37:8080/', '手动提交', '待处理'],
    [312, 'SQL 注入漏洞(联合查询型)', '(空)', 'SQL注入漏洞', 'P1', '高危', 'https://oa.example-g.../list.jsp', '手动提交', '确认中'],
    [313, '存储型 XSS 漏洞(留言板)', '(空)', 'XSS漏洞', 'P2', '中危', 'http://192.168.0.1:9.../msg', '洞鉴01', '待处理'],
    [314, '任意文件上传漏洞(可上传脚本)', '(空)', '文件上传漏洞', 'P0', '超危', 'http://172.16.1.2:8080/upload', '洞鉴01', '修复中'],
    [315, 'SSRF 服务端请求伪造漏洞(出网探测)', '(空)', '其他', 'P1', '高危', 'http://10.0.0.1:8080/webhook', 'wjg-demo', '待复测'],
    [316, '.git 目录敏感信息泄露', '(空)', '敏感信息泄露漏洞', 'P2', '中危', 'http://255.255.255.6:80/.git/', '批量导入', '已修复'],
    [317, '目录遍历漏洞(可列出目录结构)', '(空)', '路径遍历漏洞', 'P3', '低危', 'http://255.255.255.3:8080/static/', '洞鉴01', '待处理'],
    [318, '管理后台弱口令漏洞(admin/admin)', '(空)', '弱口令漏洞', 'P1', '高危', 'https://oa.example-g.../admin', '手动提交', '待处理'],
    [319, '跨站请求伪造漏洞(CSRF 修改密码接口)', '(空)', 'CSRF漏洞', 'P2', '中危', 'http://192.168.1.1:8.../password', '批量导入', '待处理'],
    [320, 'TLS 1.0 不安全协议启用', '(空)', '不安全的配置漏洞', 'P4', '信息', 'https://1.1.1.1:443/', '洞鉴01', '忽略'],
    [321, 'CORS 跨域策略配置不当', '(空)', '不安全的配置漏洞', 'P2', '中危', 'http://192.168.0.1:9.../api', '批量导入', '已修复'],
]
# 重点演示漏洞的定制文案（与前端 VULN_OVERRIDES 保持一致）
VULN_OVERRIDES = {
    240: {
        "desc": "Apache Log4j2 是 Java 应用广泛使用的日志组件。2.15.0 之前版本的 JNDI Lookup 功能存在远程代码执行漏洞（Log4Shell），攻击者通过可被记录的输入触发 JNDI 加载远程恶意类，即可在目标服务器上执行任意代码。",
        "danger": "利用门槛极低（仅需发送一条包含恶意 JNDI 表达式的字符串），可无认证直接获取服务器控制权，进而横向移动、窃取数据或植入持久化后门。",
        "fix": "1. 将 log4j-core 升级至 2.17.1 及以上版本（本主机当前为 2.14.1）。 2. 短期缓解：移除 JNDI Lookup 插件或设置 log4j2.formatMsgNoLookups=true。 3. 排查应用日志与出网记录，确认是否已被利用，必要时开展应急处置。",
    },
    241: {
        "desc": "Windows SMBv1 服务存在远程代码执行漏洞（永恒之蓝），攻击者无需认证、无需用户交互，即可利用特制数据包在目标主机上执行任意代码。",
        "danger": "可通过 445 端口直接入侵主机并植入勒索或蠕虫类程序（WannaCry 曾大规模利用该漏洞），影响为主机完全失陷并向内网横向扩散。",
        "fix": "1. 安装微软官方安全补丁并停用 SMBv1。 2. 临时缓解：通过防火墙限制 445 端口的来源访问。 3. 排查主机是否出现异常进程与新增账户。",
    },
    246: {
        "desc": "Apache HTTP Server 2.4.49/2.4.50 存在路径穿越漏洞，攻击者利用点号穿越目录读取服务器上的任意文件；在启用 CGI 的环境还可进一步导致远程代码执行。本主机当前版本为 2.4.49，在受影响范围内。",
        "danger": "无需认证即可读取 Web 根目录之外的敏感文件（配置文件、源代码、密钥等）；若目标启用了 mod_cgi，可直接获得服务器命令执行权限。",
        "fix": "1. 将 httpd 升级至 2.4.51 及以上版本（本主机当前为 2.4.49）。 2. 临时缓解：对受影响路径增加访问控制或关闭对应目录的 CGI 支持。 3. 排查访问日志中含 ../ 的异常请求，确认是否已被利用。",
    },
    247: {
        "desc": "Apache Shiro 存在 rememberMe 反序列化漏洞：1.2.4 及之前版本使用固定的 AES 密钥加密 rememberMe Cookie，攻击者可构造恶意序列化数据触发反序列化，实现远程代码执行。",
        "danger": "掌握默认密钥即可无需登录直接接管服务；配合内存马等手段可隐蔽驻留，常规审计难以发现。",
        "fix": "1. 升级 Shiro 至 1.2.5 以上版本，并将 rememberMe 加密密钥更换为随机生成的高强度密钥。 2. 临时缓解：移除或禁用 rememberMe 功能。 3. 排查应用是否存在内存马与异常会话。",
    },
    314: {
        "desc": "目标站点的文件上传接口未校验文件类型与内容，攻击者可上传脚本文件（Webshell）并获得服务器控制权。",
        "danger": "上传 Webshell 后可直接执行系统命令，读取数据库配置、篡改页面，并以此为跳板渗透内网。",
        "fix": "1. 对上传接口增加白名单校验（文件类型、后缀、内容），重命名存储并去除执行权限。 2. 清理已上传的可疑脚本文件并排查是否被利用。 3. 对上传目录统一设置禁止脚本执行。",
    },
}
LEVEL_SCORE = {'超危': 100, '高危': 80, '中危': 50, '低危': 10, '信息': 0}
VPT_RANGES = [('P0', lambda s: s > 80), ('P1', lambda s: s > 74), ('P2', lambda s: s > 49), ('P3', lambda s: s > 0), ('P4', lambda s: True)]


def _build_vulns(raw):
    out = []
    for r in raw:
        out.append({
            "id": r[0], "name": r[1], "cve": r[2], "type": r[3], "vpt": r[4], "level": r[5],
            "asset": r[6], "source": r[7], "status": r[8],
            "org": "根组织机构", "domain": "默认域", "owner": "Admin", "coOwner": "杨昭华",
            "assetName": "BJYH", "biz": "消息推送服务",
            "firstFound": "1970-01-01 08:00:45", "lastUpdate": "2026-05-09 10:41:42", "lastFound": "1970-01-01 08:00:45",
            "proto": "http", "port": "3306", "service": "(空)", "detect": "未知", "exploit": "远程利用",
            "complexity": "(空)", "planFix": "2026-09-15 03:00:00", "cvss": "9.8",
            "cnvd": "CNVD-2017-34593", "cnnvd": "CNNVD-201709-933", "ctid": "CT-60931",
            "exp": "无", "poc": "无", "patch": "无", "wild": "否",
            "tags": ["未修复", "等保"],
            "desc": r[1] + "：检测到目标系统存在该安全漏洞，攻击者可能利用该漏洞获取敏感信息或在一定条件下影响业务可用性。",
            "danger": "攻击者可在没有认证的情况下直接访问对应接口，可能造成数据被非法增删改查，且难以通过定位用户进行异常排查。",
            "fix": "1. 及时升级官方发布的安全补丁。 2. 对外收敛暴露面，关闭不必要的端口与服务。 3. 完善访问控制与身份校验逻辑。",
        })
        out[-1].update(VULN_OVERRIDES.get(r[0], {}))
    return out


def _seed():
    return {
        "vulns": {"ip": _build_vulns(IP_RAW), "web": _build_vulns(WEB_RAW)},
        "assets": [
            ["172.17.9.37", "测试用的12345", "根组织机构", "手动添加", "(空)", "test", "高风险", "Admin"],
            ["172.17.9.37", "测试用的12345", "分公司A", "手动添加", "(空)", "默认域", "高风险", "张三"],
            ["172.17.9.37", "测试", "分公司A", "1", "(空)", "默认域", "高风险", "张三"],
            ["10.0.0.1", "LITE-164测试", "根组织机构", "手动添加", "(空)", "test", "无风险", "Admin"],
            ["172.16.1.2", "测试000444", "某部门", "手动添加", "(空)", "默认域", "无风险", "柯李木_5mKC"],
            ["192.168.2.10", "192.168.2.10", "根组织机构", "手动添加", "(空)", "生产网段", "无风险", "admin_pQ5DiD"],
            ["255.255.255.6", "(空)", "开发中心", "手动添加", "(空)", "默认域", "中风险", "Admin"],
            ["255.255.255.5", "(空)", "开发中心", "手动添加", "(空)", "默认域", "高风险", "Admin"],
            ["255.255.255.4", "(空)", "开发中心", "手动添加", "(空)", "默认域", "高风险", "Admin"],
            ["255.255.255.3", "(空)", "运维中心", "手动添加", "(空)", "默认域", "高风险", "Admin"],
            ["255.255.255.2", "(空)", "运维中心", "手动添加", "(空)", "默认域", "高风险", "Admin"],
        ],
        "software": [
            ["mysql", "(空)", "linux-server-04", "192.168.1.13", "青藤测试", "Admin", "(空)", "agent04xxxxxxxx", "2026-08-25 10:54:41", "手动添加"],
            ["log4j-core", "2.14.1", "app-server-01", "172.17.9.37", "根组织机构", "Admin", "/app/lib", "agent01xxxxxxxx", "2026-10-15 09:20:11", "手动添加"],
            ["redis", "6.2.5", "cache-server-01", "192.168.2.10", "根组织机构", "Admin", "/usr/local/redis", "agent06xxxxxxxx", "2026-10-15 09:22:30", "手动添加"],
            ["httpd", "2.4.49", "web-server-02", "172.16.1.2", "某部门", "柯李木_5mKC", "/usr/local/apache2", "agent02xxxxxxxx", "2026-10-15 09:25:04", "手动添加"],
            ["openssh", "7.6p1", "gw-server-01", "10.0.0.1", "根组织机构", "Admin", "/usr/sbin", "agent10xxxxxxxx", "2026-10-15 09:26:40", "手动添加"],
        ],
        "knowledge": [
            ["LG webOS 安全漏洞", "高危", "其他", "CVE-2023-6317", "2024-04-09"],
            ["Lenovo XClarity Controller 安全漏洞", "低危", "其他", "CVE-2023-29056", "2023-04-28"],
            ["Liferay Portal和Liferay DXP 安全漏洞", "高危", "其他", "CVE-2023-33950", "2023-05-24"],
            ["LimeSurvey 安全漏洞", "高危", "其他", "CVE-2019-16185", "2019-09-09"],
            ["Android Chest Workout应用程序加密问题漏洞", "高危", "密码学问题漏洞", "CVE-2014-5796", "2014-09-09"],
            ["Agenta 代码注入漏洞", "高危", "远程代码执行漏洞", "CVE-2026-27952", "2026-02-26"],
            ["IBM CICS TX 加密问题漏洞", "高危", "密码学问题漏洞", "CVE-2022-34319", "2022-11-14"],
            ["WordPress 插件跨站脚本漏洞", "中危", "XSS漏洞", "CVE-2021-38357", "2021-09-10"],
            ["Citrix Access Gateway会话劫持漏洞", "低危", "敏感信息泄露漏洞", "CVE-2007-0011", "2007-11-05"],
            ["Microsoft Hyper-V 安全漏洞", "中危", "其他", "CVE-2024-43633", "2024-11-12"],
            ["Android 安全漏洞", "超危", "未授权访问漏洞", "CVE-2017-18071", "2018-04-11"],
            ["Apache Log4j2 远程代码执行漏洞(Log4Shell)", "超危", "远程代码执行漏洞", "CVE-2021-44228", "2021-12-10"],
            ["Windows SMBv1 远程代码执行漏洞(永恒之蓝)", "超危", "远程代码执行漏洞", "CVE-2017-0144", "2017-03-14"],
            ["Struts2 S2-045 远程代码执行漏洞", "超危", "远程代码执行漏洞", "CVE-2017-5638", "2017-03-07"],
            ["Apache Shiro rememberMe 反序列化漏洞", "高危", "反序列化漏洞", "CVE-2016-4437", "2016-05-24"],
            ["Spring Framework 远程代码执行漏洞(Spring4Shell)", "高危", "远程代码执行漏洞", "CVE-2022-22965", "2022-03-31"],
            ["Apache HTTP Server 路径穿越漏洞", "高危", "路径遍历漏洞", "CVE-2021-41773", "2021-10-05"],
            ["Redis 沙箱逃逸代码执行漏洞", "超危", "远程代码执行漏洞", "CVE-2022-0543", "2022-02-28"],
            ["OpenSSH 用户名枚举漏洞", "低危", "其他", "CVE-2018-15473", "2018-08-16"],
        ],
        "intel": [
            ["情报2", "高危", "(空)", "其他", "手动提交", "(空)", "(空)", "(空)", "2026-07-31 16:25:55"],
            ["情报漏洞1", "超危", "CVE-2026-0302", "其他", "手动提交", "(空)", "(空)", "(空)", "2026-05-19 10:35:50"],
        ],
        "tickets": [],
        "logs": [["2026-10-20 08:42:38", "tester", "leader", "101.200.128.140", "登录系统", "成功"]],
        "vptConfig": {
            "weights": {"asset": 0, "vuln": 100, "intel": 0},
            "assetProps": {
                "internet": {"weight": 0, "vals": {"是": 100, "否": 50}},
                "importance": {"weight": 100, "vals": {"核心资产": 100, "重要资产": 70, "一般资产": 20}},
                "tags": {"weight": 0, "defaultVal": 0},
            },
            "vulnProps": {
                "level": {"weight": 100, "vals": {"超危": 100, "高危": 80, "中危": 50, "低危": 10, "默认": 0}},
                "type": {"weight": 0, "defaultVal": 50},
                "tags": {"weight": 0, "defaultVal": 0},
                "kbTags": {"weight": 0, "defaultVal": 0},
                "customTags": {"weight": 0, "defaultVal": 0},
            },
            "intelProps": {
                "exp": {"weight": 50, "vals": {"有": 100, "无": 0}},
                "patch": {"weight": 50, "vals": {"有": 0, "无": 100}},
                "wild": {"weight": 0, "vals": {"有": 100, "无": 0}},
                "exploitWay": {"weight": 0, "vals": {"远程利用": 100, "内网利用": 50, "本地利用": 30, "物理利用": 10}},
                "complexity": {"weight": 0, "vals": {"简单": 100, "中等": 50, "复杂": 20}},
            },
            "specialRules": [
                {"score": 81, "conds": [["是否外网资产", "等于", "外网资产"], ["漏洞等级", "等于", "高危"]]},
                {"score": 75, "conds": [["是否外网资产", "等于", "外网资产"], ["漏洞等级", "等于", "中危"]]},
                {"score": 50, "conds": [["是否外网资产", "等于", "外网资产"], ["漏洞等级", "等于", "低危"]]},
            ],
        },
    }


def load_store():
    if not os.path.exists(DATA_FILE):
        with _store_lock:
            if not os.path.exists(DATA_FILE):
                os.makedirs(DATA_DIR, exist_ok=True)
                with open(DATA_FILE, "w", encoding="utf-8") as f:
                    json.dump(_seed(), f, ensure_ascii=False, indent=1)
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_store(store):
    with _store_lock:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(store, f, ensure_ascii=False, indent=1)


def now_ts():
    n = datetime.now()
    return "%04d-%02d-%02d %02d:%02d:%02d" % (n.year, n.month, n.day, n.hour, n.minute, n.second)


def add_audit(store, desc):
    store["logs"].insert(0, [now_ts(), "tester", "leader", "127.0.0.1", desc, "成功"])


# ================================================================
# VPT 评级（与前端 calcVptScore 同口径）
# ================================================================
def calc_vpt(vuln, cfg):
    w, ap, vp, ip = cfg["weights"], cfg["assetProps"], cfg["vulnProps"], cfg["intelProps"]

    def weighted(parts):
        wsum = sum(p[0] for p in parts)
        if wsum <= 0:
            return 0
        return sum(w * v for w, v in parts) / wsum

    asset_score = weighted([
        (ap["importance"]["weight"], ap["importance"]["vals"].get("一般资产", 0)),
        (ap["internet"]["weight"], ap["internet"]["vals"].get("否", 0)),
        (ap["tags"]["weight"], ap["tags"]["defaultVal"]),
    ])
    vuln_score = weighted([
        (vp["level"]["weight"], LEVEL_SCORE.get(vuln.get("level"), 0)),
        (vp["type"]["weight"], vp["type"]["defaultVal"]),
        (vp["tags"]["weight"], vp["tags"]["defaultVal"]),
        (vp["kbTags"]["weight"], vp["kbTags"]["defaultVal"]),
        (vp["customTags"]["weight"], vp["customTags"]["defaultVal"]),
    ])
    intel_score = weighted([
        (ip["exp"]["weight"], ip["exp"]["vals"].get("无", 0)),
        (ip["patch"]["weight"], ip["patch"]["vals"].get("无", 0)),
        (ip["wild"]["weight"], ip["wild"]["vals"].get("无", 0)),
        (ip["exploitWay"]["weight"], ip["exploitWay"]["vals"].get("远程利用", 0)),
        (ip["complexity"]["weight"], ip["complexity"]["vals"].get("简单", 0)),
    ])
    total = w["asset"] / 100 * asset_score + w["vuln"] / 100 * vuln_score + w["intel"] / 100 * intel_score
    for rule in cfg.get("specialRules", []):
        hit = all(c[0] == "漏洞等级" and vuln.get("level") == c[2] for c in rule["conds"])
        if hit:
            return {"score": float(rule["score"]), "byRule": True}
    return {"score": round(total, 2), "byRule": False}


def vpt_key(score):
    for key, cond in VPT_RANGES:
        if cond(score):
            return key
    return "P4"


# ================================================================
# DeepSeek 调用（OpenAI 兼容协议，纯 urllib）
# ================================================================
def call_llm(system, user, max_tokens=None):
    cfg = get_llm_effective()
    payload = {
        "model": cfg["model"],
        "effort": cfg.get("effort", "low"),
        "temperature": cfg.get("temperature", 0.2),
        "max_tokens": max_tokens or cfg.get("max_tokens_summary", 420),
        "stream": False,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    # 实测该 API 支持 thinking disabled：reasoning_tokens 归零，正文稳定，是最省钱的可靠配置
    if cfg.get("thinking", "disabled") == "disabled":
        payload["thinking"] = {"type": "disabled"}
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        cfg["base_url"] + "/chat/completions",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + cfg["api_key"]},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=cfg.get("timeout", 60)) as resp:
        out = json.loads(resp.read().decode("utf-8"))
    content = (out["choices"][0]["message"].get("content") or "").strip()
    if not content:
        # 推理 token 吃满 max_tokens 时 content 可能为空——视为失败，由调用方降级
        raise RuntimeError("模型返回空正文（可能被 reasoning 占满），usage=%s" % json.dumps(out.get("usage", {}), ensure_ascii=False))
    return content


def llm_judgement_summary(facts):
    """功能一：LLM 只负责组织语言，事实全部来自平台数据；失败抛异常由调用方降级"""
    system = (
        "你是漏洞管理平台的研判摘要助手。规则：1) 只允许使用【平台事实】中的信息组织语言，"
        "不得新增技术结论（版本号、攻击细节等）；2) 事实缺失必须写“平台未采集，无法判断”；"
        "3) 输出150字以内中文摘要，讲清：VPT分数来源、情报校准状态、当前处置与责任人、下一步关注点。"
    )
    user = "【平台事实】" + json.dumps(facts, ensure_ascii=False, separators=(",", ":"))
    return call_llm(system, user, CONFIG["llm"]["max_tokens_summary"])


def llm_fix_steps(facts):
    """功能三：LLM 生成本地化修复步骤（3~5 条，一行一条）；失败抛异常由调用方降级"""
    system = (
        "你是漏洞管理平台的修复建议助手。基于【平台事实】输出本地化修复执行步骤：3~5条、每条一行、不编号；"
        "只允许使用平台事实中的信息（资产清单、版本情况、责任人、官方修复建议），"
        "事实缺失环节明确写“需先确认/无法判断”，不得编造版本号或资产。"
    )
    user = "【平台事实】" + json.dumps(facts, ensure_ascii=False, separators=(",", ":"))
    text = call_llm(system, user, CONFIG["llm"]["max_tokens_steps"])
    lines = [ln.strip().lstrip("0123456789.、) ") for ln in text.splitlines() if ln.strip()]
    return lines[:5]


# ================================================================
# Agent 契约接口实现
# ================================================================
def _get_vuln(store, kind, vid):
    for v in store["vulns"].get(kind, []):
        if str(v["id"]) == str(vid):
            return v
    return None


def _facts(store, v, kind):
    """收集平台事实（与前端工具链同源）：归因、情报、资产、软件、知识库、处置记录"""
    cfg = store["vptConfig"]
    c = calc_vpt(v, cfg)
    asset = next((a for a in store["assets"] if a[0] == v["asset"]), None)
    kb = [k for k in store["knowledge"] if (v["cve"] and v["cve"] != "(空)" and k[3] == v["cve"]) or k[0] == v["name"]]
    intel = [k for k in store["intel"] if (v["cve"] and v["cve"] != "(空)" and k[2] == v["cve"]) or k[0] == v["name"]]
    sw = [s for s in store["software"] if s[3] == v["asset"]]
    same_closed = [x for x in store["vulns"][kind] if x["cve"] == v["cve"] and x["status"] == "已修复" and str(x["id"]) != str(v["id"])]
    return c, asset, kb, intel, sw, same_closed


def handle_judgement(store, body):
    kind, vid = body.get("kind", "ip"), body.get("id")
    v = _get_vuln(store, kind, vid)
    if not v:
        return {"ok": False, "error": "漏洞不存在"}
    c, asset, kb, intel, sw, same_closed = _facts(store, v, kind)
    intel_missing = v["exp"] == "无" and v["poc"] == "无" and v["patch"] == "无" and v["wild"] == "否"
    citations = [
        {"label": "VPT 归因", "from": "配置中心 VPT 规则（透明可配置）",
         "detail": (("特殊评分规则直接赋分" if c["byRule"] else "漏洞属性加权：等级「%s」基础分 %d × 权重 100%%" % (v["level"], LEVEL_SCORE.get(v["level"], 0))) +
                    "；属性占比 资产%d%% / 漏洞%d%% / 情报%d%%" % (store["vptConfig"]["weights"]["asset"], store["vptConfig"]["weights"]["vuln"], store["vptConfig"]["weights"]["intel"]))},
        {"label": "情报信息", "from": "漏洞详情 · 情报信息字段",
         "detail": "有无EXP %s · 有无POC %s · 补丁发布 %s · 在野利用 %s" % (v["exp"], v["poc"], v["patch"], v["wild"])},
        {"label": "资产档案", "from": ("资产台账 · 资产IP=" + asset[0]) if asset else "漏洞详情 · 影响资产字段",
         "detail": (asset[0] + "（" + asset[1] + "），责任人 " + asset[7] + "，资产风险 " + asset[6]) if asset else (v["asset"] + "（" + v["assetName"] + "），责任人 " + v["owner"] + "，未纳管")},
    ]
    if kb:
        citations.append({"label": "知识库命中", "from": "漏洞知识库", "detail": "；".join("%s（%s，%s）" % (k[0], k[3], k[1]) for k in kb)})
    if same_closed:
        citations.append({"label": "同源处置", "from": "同 CVE 已修复记录", "detail": "%d 条：%s" % (len(same_closed), "、".join(x["asset"] for x in same_closed[:3]))})
    unknowns = []
    if not asset:
        unknowns.append("资产 %s 未纳管，无法确认当前运行的组件与版本，无法判断升级是否需要停机。" % v["asset"])
    elif not sw:
        unknowns.append("资产已纳管但软件台账未采集组件版本信息。")
    if not kb:
        unknowns.append("知识库未命中同源条目，官方通告细节需人工补充。")

    facts = {"漏洞": {k: v[k] for k in ("name", "level", "vpt", "type", "cve", "asset", "status", "owner", "coOwner", "biz")},
             "VPT归因": {"score": c["score"], "key": vpt_key(c["score"]), "byRule": c["byRule"], "explain": citations[0]["detail"]},
             "情报": {"exp": v["exp"], "poc": v["poc"], "patch": v["patch"], "wild": v["wild"], "全部缺失": intel_missing},
             "资产": citations[2]["detail"], "知识库命中": [k[0] for k in kb], "同源已修复": len(same_closed)}
    generated_by = "template"
    if llm_ready():
        try:
            summary = llm_judgement_summary(facts)
            generated_by = CONFIG["llm"]["provider"]
        except Exception as e:
            summary = _template_judgement(v, c, intel_missing, asset, same_closed)
            citations.append({"label": "降级说明", "from": "后端 LLM 调用", "detail": "DeepSeek 调用失败（%s），本次摘要由模板生成" % e})
    else:
        summary = _template_judgement(v, c, intel_missing, asset, same_closed)
    conf_level = "high" if asset else "mid"
    conf_text = "较高" if asset else "中（资产未纳管，版本信息缺失）"
    return {"ok": True, "data": {
        "vuln": {k: v[k] for k in ("id", "name", "level", "vpt", "type", "cve", "asset", "status")},
        "attribution": {"score": c["score"], "key": vpt_key(c["score"]), "byRule": c["byRule"]},
        "summary": summary, "citations": citations, "unknowns": unknowns,
        "confidence": {"level": conf_level, "text": conf_text},
        "generatedBy": generated_by,
    }}


def _template_judgement(v, c, intel_missing, asset, same_closed):
    parts = [
        "VPT %s 分（%s）的来源：%s" % (c["score"], vpt_key(c["score"]),
                                     "特殊评分规则命中直接赋值。" if c["byRule"] else
                                     "漏洞属性加权，等级「%s」基础分 %d × 权重 100%%。" % (v["level"], LEVEL_SCORE.get(v["level"], 0))),
        "情报四项全部为空，分数未经情报维度校准——评分依据需要核实。" if intel_missing else "情报维度已有字段可校准评分。",
        "当前处置：%s，负责人 %s / %s，业务系统 %s。%s" % (v["status"], v["owner"], v["coOwner"], v["biz"],
                                                     "资产已纳管，修复落实可追踪。" if asset else "资产未纳管，落实无法追踪，建议先完成纳管。"),
    ]
    if same_closed:
        parts.append("平台已有 %d 条同 CVE 漏洞完成处置，可参考其处置方式。" % len(same_closed))
    return "".join(parts)


def handle_fix_advice(store, body):
    kind, vid = body.get("kind", "ip"), body.get("id")
    v = _get_vuln(store, kind, vid)
    if not v:
        return {"ok": False, "error": "漏洞不存在"}
    c, asset, kb, intel, sw, same_closed = _facts(store, v, kind)
    data = {
        "vuln": {k: v[k] for k in ("name", "level", "vpt", "type", "cve", "asset", "source")},
        "assets": [{"ip": asset[0], "name": asset[1], "org": asset[2], "owner": asset[7], "biz": "（平台未关联业务系统）", "from": "资产台账 · 资产IP=" + asset[0]}] if asset
                  else [{"ip": v["asset"], "name": v["assetName"], "org": v["org"], "owner": v["owner"], "biz": v["biz"], "from": "漏洞详情 · 影响资产/负责人字段"}],
        "managed": bool(asset),
        "versionKnown": bool(sw),
        "versionText": "、".join(s[0] + ("" if (s[1] and s[1] != "(空)") else "（版本未采集）") for s in sw),
        "kbFound": bool(kb),
        "kbText": "%s（%s，%s）" % (kb[0][0], kb[0][3], kb[0][1]) if kb else "",
        "sameClosed": same_closed,
        "officialFix": v["fix"],
        "coord": {"owner": v["owner"], "coOwner": v["coOwner"], "biz": v["biz"], "assetOwner": asset[7] if asset else v["owner"]},
        "confidence": "较高" if (asset and sw) else ("中" if asset else "中（该资产未纳管，组件版本信息缺失，建议先纳管采集）"),
        "confLevel": "high" if (asset and sw) else "mid",
        "unknowns": [],
    }
    if not asset:
        data["unknowns"].append("平台资产台账中未收录 %s（未纳管），无法确认该资产当前运行的组件与版本，无法判断升级是否需要停机。" % v["asset"])
    elif not sw:
        data["unknowns"].append("资产已纳管但软件台账中未采集到组件版本信息。")
    if not kb:
        data["unknowns"].append("知识库未命中同 CVE/同名条目，无法补充官方通告细节。")

    facts = dict(data)
    generated_by = "template"
    steps = _builtin_steps(v)
    if llm_ready():
        try:
            steps = llm_fix_steps(facts)
            generated_by = CONFIG["llm"]["provider"]
        except Exception:
            generated_by = "template"
    data["steps"] = steps
    data["generatedBy"] = generated_by
    return {"ok": True, "data": data}


def _builtin_steps(v):
    return [
        "对照官方通告升级相关组件至安全版本（官方建议：%s）。" % v["fix"].split("。")[0],
        "升级或变更前与业务负责人确认停机窗口；无法立即升级时先采取临时缓解：收敛暴露面、关闭受影响端口、限制访问来源。",
        "修复完成后发起复测，确认漏洞闭环。",
    ]


def handle_adopt(store, body):
    kind, vid = body.get("kind", "ip"), body.get("id")
    v = _get_vuln(store, kind, vid)
    if not v:
        return {"ok": False, "error": "漏洞不存在"}
    ticket_id = "T-%s-%s" % (datetime.now().strftime("%Y%m%d"), str(datetime.now().microsecond)[:4])
    store["tickets"].append({"ticketId": ticket_id, "vulnId": v["id"], "kind": kind,
                             "vulnName": v["name"], "createdAt": now_ts(), "from": "fix-advisor", "status": "进行中"})
    add_audit(store, "修复建议助手：采纳本地化修复建议并创建修复工单（漏洞ID %s，工单 %s）" % (vid, ticket_id))
    save_store(store)
    return {"ok": True, "data": {"ticketId": ticket_id}}


def handle_ticket(store, body):
    vid = body.get("vulnId")
    kind = body.get("kind")
    v = None
    for k in ("ip", "web"):
        if kind and k != kind:
            continue
        v = _get_vuln(store, k, vid)
        if v:
            kind = k
            break
    if not v:
        return {"ok": False, "error": "漏洞不存在"}
    ticket_id = "T-%s-%s" % (datetime.now().strftime("%Y%m%d"), str(datetime.now().microsecond)[:4])
    store["tickets"].append({"ticketId": ticket_id, "vulnId": v["id"], "kind": kind,
                             "vulnName": v["name"], "createdAt": now_ts(), "from": body.get("from", "detail"), "status": "进行中"})
    add_audit(store, "%s：创建修复工单（漏洞ID %s，工单 %s）" % ("修复建议助手" if body.get("from") == "fix-advisor" else "漏洞详情", vid, ticket_id))
    save_store(store)
    return {"ok": True, "data": {"ticketId": ticket_id}}


AGENT_ROUTES = {
    "/agent-api/judgement": handle_judgement,
    "/agent-api/fix-advice": handle_fix_advice,
    "/agent-api/fix-advice/adopt": handle_adopt,
    "/agent-api/tickets": handle_ticket,
}

# ================================================================
# 平台数据 CRUD（功能一/功能三所需数据的增删改查）
# 集合名 -> data.json 中的路径
# ================================================================
COLLECTIONS = {
    "vulns-ip":   lambda s: s["vulns"]["ip"],
    "vulns-web":  lambda s: s["vulns"]["web"],
    "assets":     lambda s: s["assets"],
    "software":   lambda s: s["software"],
    "knowledge":  lambda s: s["knowledge"],
    "intel":      lambda s: s["intel"],
    "tickets":    lambda s: s["tickets"],
    "logs":       lambda s: s["logs"],
    "vptconfig":  lambda s: s["vptConfig"],   # 只读
}


def _item_key(it):
    """集合条目主键：dict 用 ticketId/id/name，list 用首元素"""
    if isinstance(it, dict):
        return it.get("ticketId") or it.get("id") or it.get("name")
    return it[0] if it else None


def crud_list(store, name, query):
    items = COLLECTIONS[name](store)
    q = (query or {}).get("q", [""])[0]
    if q:
        hits = [it for it in items if q in json.dumps(it, ensure_ascii=False)]
        return {"ok": True, "data": hits}
    return {"ok": True, "data": items}


VULN_EDITABLE = ("name", "level", "vpt", "status", "owner", "coOwner", "asset", "cve", "type",
                 "fix", "desc", "danger", "exp", "poc", "patch", "wild", "tags", "planFix",
                 "cvss", "proto", "port", "service", "detect", "exploit", "complexity", "org", "domain")


def crud_create(store, name, body):
    items = COLLECTIONS[name](store)
    if name in ("vulns-ip", "vulns-web"):
        new_vuln = _build_vulns([[0, body.get("name", "未命名漏洞"), body.get("cve", "(空)"), body.get("type", "其他"),
                                  body.get("vpt", "P0"), body.get("level", "中危"), body.get("asset", ""), body.get("source", "手动添加"),
                                  body.get("status", "待处理")]])[0]
        new_vuln.update({k: body[k] for k in VULN_EDITABLE if k in body})
        new_id = max([x["id"] for x in items] or [0]) + 1
        new_vuln["id"] = new_id
        items.append(new_vuln)
        add_audit(store, "数据管理：新增 %s 漏洞（ID %d）" % (name, new_id))
        save_store(store)
        return {"ok": True, "data": new_vuln}
    if name == "tickets":
        body = dict(body)
        body.setdefault("ticketId", "T-%s-%s" % (datetime.now().strftime("%Y%m%d"), str(datetime.now().microsecond)[:4]))
        body.setdefault("createdAt", now_ts())
        body.setdefault("from", "manual")
        body.setdefault("status", "进行中")
        body.setdefault("executor", "tester")
        body.setdefault("step", "提交修复建议")
        store["tickets"].append(body)
        add_audit(store, "工单中心：手动创建工单（%s）" % body["ticketId"])
        save_store(store)
        return {"ok": True, "data": body}
    items.append(body)
    add_audit(store, "数据管理：新增 %s 记录" % name)
    save_store(store)
    return {"ok": True, "data": {"created": True}}


def crud_update(store, name, item_id, body):
    items = COLLECTIONS[name](store)
    if name in ("vulns-ip", "vulns-web"):
        for v in items:
            if str(v["id"]) == str(item_id):
                changed = {k: body[k] for k in VULN_EDITABLE if k in body}
                v.update(changed)
                save_store(store)
                add_audit(store, "数据管理：更新 %s 漏洞（ID %s，字段：%s）" % (name, item_id, "、".join(changed) or "无"))
                return {"ok": True, "data": v}
        return {"ok": False, "error": "未找到 ID %s" % item_id}
    if name == "vptconfig":
        store["vptConfig"].update(body)
        save_store(store)
        add_audit(store, "配置中心：更新 VPT 配置")
        return {"ok": True, "data": store["vptConfig"]}
    for i, it in enumerate(items):
        if str(_item_key(it)) == str(item_id):
            if isinstance(it, dict):
                it.update(body)
                saved = it
            else:
                items[i] = body
                saved = body
            save_store(store)
            add_audit(store, "工单中心：更新 %s 记录（%s）" % (name, item_id))
            return {"ok": True, "data": saved}
    return {"ok": False, "error": "未找到 %s" % item_id}


def crud_delete(store, name, item_id):
    items = COLLECTIONS[name](store)
    if name in ("vulns-ip", "vulns-web"):
        before = len(items)
        items[:] = [v for v in items if str(v["id"]) != str(item_id)]
        if len(items) == before:
            return {"ok": False, "error": "未找到 ID %s" % item_id}
        save_store(store)
        add_audit(store, "数据管理：删除 %s 漏洞（ID %s）" % (name, item_id))
        return {"ok": True, "data": {"deleted": item_id}}
    before = len(items)
    items[:] = [it for it in items if str(_item_key(it)) != str(item_id)]
    if len(items) == before:
        return {"ok": False, "error": "未找到 %s" % item_id}
    save_store(store)
    add_audit(store, "工单中心/数据管理：删除 %s 记录（%s）" % (name, item_id))
    return {"ok": True, "data": {"deleted": item_id}}


# ================================================================
# HTTP 层
# ================================================================
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # ---- 工具 ----
    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    def _send(self, payload, status=200, ctype="application/json; charset=utf-8"):
        if isinstance(payload, (dict, list)):
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        else:
            data = payload
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        # 允许 file:// 直开前端时跨域调用后端（演示场景）；同源部署不受影响
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print("[%s] %s" % (now_ts()[11:], fmt % args))

    def _admin_ok(self):
        """ADMIN_TOKEN 未设置 → 鉴权关闭（本地演示模式）；设置后写操作需携带 X-Admin-Token"""
        return not ADMIN_TOKEN or self.headers.get("X-Admin-Token", "") == ADMIN_TOKEN

    def _deny(self):
        self._send({"ok": False, "error": "需要管理员口令：请在「大模型配置」页填写管理口令后重试"}, 401)

    # ---- GET ----
    def do_GET(self):
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        if path in ("/", "/index.html", "/insight-replica.html"):
            # 根路径直接返回前端页面（FC 的 fcapp.run 域名禁止 302 跳转，ExternalRedirectForbidden）
            if os.path.exists(FRONTEND_FILE):
                with open(FRONTEND_FILE, "rb") as f:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    # 禁缓存：前端单文件迭代频繁，避免浏览器展示旧版本
                    self.send_header("Cache-Control", "no-store")
                    # FC 默认域名 fcapp.run 会给无该头的响应强制加 attachment（强制下载），
                    # 显式声明 inline 尝试让浏览器直接渲染；若网关仍覆盖，则需绑定自定义域名
                    self.send_header("Content-Disposition", "inline")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("Content-Length", str(os.path.getsize(FRONTEND_FILE)))
                    self.end_headers()
                    self.wfile.write(f.read())
            else:
                self._send({"ok": False, "error": "前端文件不存在"}, 404)
            return
        if path == "/favicon.ico":
            # 浏览器自动请求网站图标：前端已内嵌 data-uri 图标，此处 204 兜底避免 404
            self.send_response(204)
            self.end_headers()
            return
        if path == "/api/health":
            cfg = get_llm_effective()
            ready = llm_ready()
            self._send({"ok": True, "data": {
                "llm": cfg["provider"] if ready else "未配置（模板降级）",
                "llmReady": ready, "model": cfg.get("model", ""),
                "adminAuth": bool(ADMIN_TOKEN),
                "dataFile": os.path.basename(DATA_FILE)}})
            return
        if path == "/api/llm-config":
            self._send(llm_config_view())
            return
        parts = [p for p in path.split("/") if p]
        if len(parts) == 2 and parts[0] == "api" and parts[1] in COLLECTIONS:
            store = load_store()
            self._send(crud_list(store, parts[1], query))
            return
        if len(parts) == 3 and parts[0] == "api" and parts[1] in COLLECTIONS:
            store = load_store()
            items = COLLECTIONS[parts[1]](store)
            for it in items:
                if str(_item_key(it)) == parts[2]:
                    self._send({"ok": True, "data": it})
                    return
            self._send({"ok": False, "error": "未找到 %s" % parts[2]}, 404)
            return
        self._send({"ok": False, "error": "未知接口 " + path}, 404)

    # ---- OPTIONS（浏览器跨域预检：file:// 直开前端时 PUT/DELETE 会先发预检）----
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ---- POST ----
    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()
        if path == "/api/llm-config/test":
            if not self._admin_ok():
                return self._deny()
            self._send(test_llm_config(body))
            return
        if path == "/api/llm-config":
            if not self._admin_ok():
                return self._deny()
            store = load_store()
            self._send(save_llm_config(store, body))
            return
        if path in AGENT_ROUTES:
            # 状态变更类 agent 路由（建单/采纳）在启用鉴权时需口令；读取类（研判/修复建议）开放
            if path in ("/agent-api/fix-advice/adopt", "/agent-api/tickets") and not self._admin_ok():
                return self._deny()
            store = load_store()
            try:
                result = AGENT_ROUTES[path](store, body)
            except Exception as e:
                result = {"ok": False, "error": "后端处理异常：%s" % e}
            self._send(result)
            return
        parts = [p for p in path.split("/") if p]
        if len(parts) == 2 and parts[0] == "api" and parts[1] in COLLECTIONS:
            if not self._admin_ok():
                return self._deny()
            store = load_store()
            self._send(crud_create(store, parts[1], body))
            return
        self._send({"ok": False, "error": "未知接口 " + path}, 404)

    # ---- PUT（整条更新）----
    def do_PUT(self):
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        body = self._read_body()
        if len(parts) == 2 and parts[0] == "api" and parts[1] == "llm-config":
            if not self._admin_ok():
                return self._deny()
            store = load_store()
            self._send(save_llm_config(store, body))
            return
        if len(parts) == 3 and parts[0] == "api" and parts[1] in COLLECTIONS:
            if not self._admin_ok():
                return self._deny()
            store = load_store()
            self._send(crud_update(store, parts[1], parts[2], body))
            return
        self._send({"ok": False, "error": "未知接口 " + self.path}, 404)

    # ---- PATCH（局部更新，功能三编辑保存常用）----
    def do_PATCH(self):
        self.do_PUT()

    # ---- DELETE ----
    def do_DELETE(self):
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        if len(parts) == 3 and parts[0] == "api" and parts[1] in COLLECTIONS:
            if not self._admin_ok():
                return self._deny()
            store = load_store()
            self._send(crud_delete(store, parts[1], parts[2]))
            return
        self._send({"ok": False, "error": "未知接口 " + self.path}, 404)


if __name__ == "__main__":
    store = load_store()
    print("=" * 60)
    print("鉴微 AI助手 后端已启动  http://%s:%d" % (HOST, PORT))
    print("  前端页面   http://%s:%d/insight-replica.html" % (HOST, PORT))
    print("  健康检查   http://%s:%d/api/health" % (HOST, PORT))
    print("  LLM 状态   %s" % ("已启用（真实分析）" if llm_ready() else "未配置 API Key → 模板降级（可在前端「大模型配置」页配置）"))
    print("  管理口令   %s" % ("已启用（写操作需 X-Admin-Token）" if ADMIN_TOKEN else "未启用（本地演示模式）"))
    print("  数据文件   %s" % DATA_FILE)
    print("=" * 60)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
