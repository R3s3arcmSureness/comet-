# -*- coding: utf-8 -*-
"""apis.py — 四端真实 SDK 敏感 API 目录（生产级修订）

修订说明（对照审计报告 D2）：
- 按平台（android / ios / miniprogram / harmony）建立真实 SDK API 目录
- 方法名 token 用于堆栈帧匹配（精确 token，非子串）
- OOD_MUTATE 提供分布外变体策略（新类名后缀/新包名/.kt/.ets 文件/方法变体）
- 注：小程序云端能力（如读短信/邮箱）标注 cloud=1，生产部署时按 Hook 层实际可见性裁剪
"""
import os

# 每平台: data_type -> 真实 API 方法 token 列表（用于堆栈帧中匹配）
PLATFORM_APIS = {
    "android": {
        "LOCATION": [
            "LocationManager.getLastKnownLocation",
            "LocationManager.requestLocationUpdates",
            "LocationManager.getCurrentLocation",
            "FusedLocationProviderClient.requestLocationUpdates",
            "FusedLocationProviderClient.getLastLocation",
        ],
        "PHONE": [
            "TelephonyManager.getLine1Number",
            "SubscriptionManager.getPhoneNumber",
        ],
        "DEVICE_ID": [
            "TelephonyManager.getImei",
            "TelephonyManager.getDeviceId",
            "TelephonyManager.getMeid",
            "Settings.Secure.getString",
            "WifiManager.getConnectionInfo",
            "AdvertisingIdClient.getAdvertisingIdInfo",
        ],
        "SMS": [
            "ContentResolver.query",
            "SmsManager.sendMultipartTextMessage",
        ],
        "CONTACTS": [
            "ContentResolver.query",
            "ContactsContract.Contacts.CONTENT_URI",
        ],
        "CAMERA_MIC": [
            "CameraManager.openCamera",
            "CameraDevice.createCaptureSession",
            "AudioRecord.startRecording",
            "MediaRecorder.start",
        ],
        "BIOMETRIC": [
            "BiometricPrompt.authenticate",
            "FingerprintManager.authenticate",
        ],
        "HEALTH": [
            "HealthConnectClient.readRecords",
            "HealthConnectClient.aggregate",
        ],
        "EMAIL": [
            "AccountManager.getAccountsByType",
        ],
        "NAME": [
            "AccountManager.getAccounts",
            "ContactsContract.Profile.CONTENT_URI",
        ],
        "EXACT_IMAGE": [
            "ImageCapture.takePicture",
            "CameraXImageCapture.takePicture",
        ],
        "BANK_CARD": [
            "PaymentManager.queryBankCardInfo",
            "BankCardRecognizer.recognize",
        ],
    },
    "ios": {
        "LOCATION": [
            "CLLocationManager startUpdatingLocation",
            "CLLocationManager requestLocation",
            "CLLocationManager location",
        ],
        "PHONE": [
            "CTTelephonyNetworkInfo subscriberCellularProvider",
        ],
        "DEVICE_ID": [
            "ASIdentifierManager advertisingIdentifier",
            "UIDevice identifierForVendor",
        ],
        "SMS": [
            "MFMessageComposeViewController presentMessageComposeViewController",
            "CTMessageCenter interactiveMessage",
        ],
        "CONTACTS": [
            "CNContactStore contacts",
            "CNContactStore requestAccess",
            "CNContactStore unifiedContacts",
        ],
        "CAMERA_MIC": [
            "AVCaptureDevice requestAccess",
            "AVCaptureSession startRunning",
            "AVAudioRecorder record",
        ],
        "BIOMETRIC": [
            "LAContext evaluatePolicy",
        ],
        "HEALTH": [
            "HKHealthStore executeQuery",
            "HKHealthStore requestAuthorizationToShareTypes",
        ],
        "EMAIL": [
            "MailDatabase messageAtURL",
            "MailManager fetchInboxMessages",
        ],
        "NAME": [
            "CNContactStore unifiedContacts",
        ],
        "EXACT_IMAGE": [
            "UIImagePickerController imagePickerController",
            "PHPickerViewController didFinishPicking",
        ],
        "BANK_CARD": [
            "PKAddPaymentPassViewController addPaymentPass",
            "CardRecognizer recognizeCard",
        ],
    },
    "miniprogram": {
        "LOCATION": [
            "wx.getLocation",
            "wx.chooseLocation",
            "wx.onLocationChange",
            "wx.startLocationUpdate",
        ],
        "PHONE": [
            "wx.getPhoneNumber",
            "wx.requestSubscribeMessage",
        ],
        "DEVICE_ID": [
            "wx.getDeviceInfo",
            "wx.getSystemSetting",
        ],
        "SMS": [
            "CloudFunction.readSmsVerify",
        ],
        "CONTACTS": [
            "wx.chooseContact",
        ],
        "CAMERA_MIC": [
            "wx.startRecord",
            "wx.getRecorderManager",
            "CameraContext.startRecord",
            "wx.chooseMedia",
        ],
        "BIOMETRIC": [
            "wx.startFacialRecognitionVerify",
        ],
        "HEALTH": [
            "wx.getWeRunData",
        ],
        "EMAIL": [
            "CloudFunction.syncMailbox",
        ],
        "NAME": [
            "wx.getUserProfile",
            "wx.getUserInfo",
        ],
        "EXACT_IMAGE": [
            "wx.chooseMedia",
            "wx.chooseImage",
        ],
        "BANK_CARD": [
            "CloudFunction.verifyBankCard",
            "wx.chooseInvoice",
        ],
    },
    "harmony": {
        "LOCATION": [
            "geoLocationManager.getLastLocation",
            "geoLocationManager.getCurrentLocation",
            "geoLocationManager.on",
        ],
        "PHONE": [
            "sim.getSimTelephoneNumber",
            "sim.getSimSpn",
        ],
        "DEVICE_ID": [
            "oaid.getOAID",            # 【存疑】真实命名空间为 identifier（见下）
            "identifier.getOAID",      # 【已核验】官方：import identifier from '@ohos.identifier.oaid'
            "identifier.getAAID",      # 【已核验】同模块：应用匿名标识
            "deviceInfo.getSerialNumber",
        ],
        "SMS": [
            "sms.getAllSimMessages",
            "sms.createMessage",
        ],
        "CONTACTS": [
            "contact.queryContacts",
            "contact.queryContactByKey",
        ],
        "CAMERA_MIC": [
            "CameraManager.createCaptureSession",
            "AudioCapturer.start",
            "AudioCapturer.create",
        ],
        "BIOMETRIC": [
            "userAuth.auth",
            "userAuth.getUserAuthInstance",
        ],
        "HEALTH": [
            "healthService.queryLatestHealthData",
        ],
        "EMAIL": [
            "MailService.queryInbox",
        ],
        "NAME": [
            "contact.queryContacts",
            "osAccount.queryOsAccount",
        ],
        "EXACT_IMAGE": [
            "PhotoAccessHelper.getAssets",
            "photoAccessHelper.MediaAssetChangeRequest",
        ],
        "BANK_CARD": [
            "payment.queryBankCardInfo",
            "payment.createPaymentRequest",
        ],
    },
}

# 云端/半私有 API（生产部署时按 Hook 层可见性裁剪）
CLOUD_APIS = {
    "CloudFunction.readSmsVerify", "CloudFunction.syncMailbox",
    "CloudFunction.verifyBankCard", "MailManager fetchInboxMessages",
    "MailDatabase messageAtURL", "CTMessageCenter interactiveMessage",
    "MailService.queryInbox", "healthService.queryLatestHealthData",
    "CloudFunction.verifyIdCard", "OCRPlugin.recognizeIdCard",
    "IdCardRecognizer.recognize", "VNRecognizeTextRequest perform",
    "cardRecognizer recognize",
}

# ID_CARD 无直接系统 API，四端均为 OCR/云端核验路径
PLATFORM_APIS["android"]["ID_CARD"] = ["IdCardRecognizer.recognize", "MLKitTextRecognizer.recognizeText"]
PLATFORM_APIS["ios"]["ID_CARD"] = ["VNRecognizeTextRequest perform", "CardRecognizer recognizeIdCard"]
PLATFORM_APIS["miniprogram"]["ID_CARD"] = ["CloudFunction.verifyIdCard", "OCRPlugin.recognizeIdCard"]
PLATFORM_APIS["harmony"]["ID_CARD"] = ["cardRecognizer recognize", "OCR.recognizeIdCard"]

# 覆盖性断言：每个平台必须支持全部 PII 数据类型
_PII_TYPES = [t for t in
              ["PHONE", "ID_CARD", "BANK_CARD", "DEVICE_ID", "EMAIL", "NAME",
               "EXACT_IMAGE", "HEALTH", "LOCATION", "SMS", "CONTACTS",
               "BIOMETRIC", "CAMERA_MIC"]]
for _p, _m in PLATFORM_APIS.items():
    _missing = [t for t in _PII_TYPES if t not in _m or not _m[t]]
    assert not _missing, f"platform {_p} missing APIs for {_missing}"

# ---------------- 方法 token -> data_type 索引（编译一次） ----------------
def build_api_index():
    """返回 {platform: {method_token_lower: data_type}}
    token 匹配策略：堆栈帧文本中查找 'Class.method' 完整 token（含点/空格），
    如 'LocationManager.getLastKnownLocation(' 或 'CLLocationManager startUpdatingLocation'。
    注意 ContentResolver.query 同时属于 SMS/CONTACTS —— 通过参数 URI 消歧。"""
    idx = {}
    for plat, m in PLATFORM_APIS.items():
        d = {}
        for dt, apis in m.items():
            for a in apis:
                d.setdefault(a.lower(), set()).add(dt)
        idx[plat] = d
    return idx

API_INDEX = build_api_index()

# ---------------- 真实 SDK 目录合并（apis_expanded.py，可开关）----------------
# 由来：原目录每端仅 25–34 条（合计 111），是"未收录 SDK → 漏判"的主要来源。
# apis_expanded.py 由多 Agent 检索四端官方文档构建，合计 813 条，覆盖全部 13 个非 NONE 类型。
# 默认**关闭**：扩充目录会增加 token 命中面，可能改变复核率与误报（需真实日志验证后才默认开）。
#   PC_EXPANDED_APIS=1  开启合并
#   PC_EXPANDED_APIS=0  仅用原目录（默认，保证既有回归逐位不变）
EXPANDED_ENABLED = os.environ.get("PC_EXPANDED_APIS", "0") == "1"
EXPANDED_STATS = {}

def _count_cross_dt_collisions(idx):
    """异型子串碰撞对数（与 check_hardening H4 同口径）。"""
    n = 0
    for _p, _i in idx.items():
        _tk = sorted(_i)
        for _a in _tk:
            for _b in _tk:
                if _a != _b and _a in _b and set(_i[_a]) != set(_i[_b]):
                    n += 1
    return n


if EXPANDED_ENABLED:
    try:
        from apis_expanded import PLATFORM_APIS as _EXP, UNCERTAIN_APIS as _UNCERT
        # 剔除"来源存疑"条目：宁可少收录，也不引入不可信 token（它们会污染类型判定）。
        # 【P0-1 修复】原实现 `if (_p, _dt, _tok) in _uncertain` 把 **三元组** 与一个
        # **字符串集合** 比对，恒为 False ⇒ 剔除逻辑是空操作（注释承诺的排除从未发生）。
        # 现按 token（大小写不敏感）比对，并统计真实剔除数以便回归断言。
        _uncertain = {s.lower() for s in _UNCERT} if _UNCERT else set()
        _base_coll = _count_cross_dt_collisions(API_INDEX)

        # 【P1 修复】**碰撞安全合并**：扩充目录会引入新的"异型子串碰撞"
        # （实测 11 对 vs 基础目录 1 对），使 check_hardening H4 的伪歧义审计失效。
        # 逐条增量检查：候选 token 与其所属平台中**任意现存 token** 若构成子串关系
        # 且两者 dt 集合不同 ⇒ 拒收该候选。这样**只增召回、不增伪歧义**：
        # 合并后的异型碰撞对数恒等于基础目录（见 enable_safe 断言）。
        _cur = {}
        for _p, _m in PLATFORM_APIS.items():
            _d = {}
            for _dt, _lst in _m.items():
                for _t in _lst:
                    _d.setdefault(_t.lower(), set()).add(_dt)
            _cur[_p] = _d

        _added = _excluded = _rejected = 0
        for _p, _m in _EXP.items():
            PLATFORM_APIS.setdefault(_p, {})
            _cur.setdefault(_p, {})
            for _dt, _lst in _m.items():
                dst = PLATFORM_APIS[_p].setdefault(_dt, [])
                for _tok in _lst:
                    _tl = _tok.lower()
                    if _tl in _uncertain:
                        _excluded += 1
                        continue
                    if _dt in _cur[_p].get(_tl, set()):      # 已存在同样的 (token,dt)
                        continue
                    _prosp = _cur[_p].get(_tl, set()) | {_dt}
                    _bad = False
                    for _o, _od in _cur[_p].items():
                        if _o != _tl and (_tl in _o or _o in _tl) and _prosp != _od:
                            _bad = True
                            break
                    if _bad:
                        _rejected += 1
                        continue
                    if not any(x.lower() == _tl for x in dst):
                        dst.append(_tok)
                        _added += 1
                    _cur[_p].setdefault(_tl, set()).add(_dt)

        API_INDEX = build_api_index()
        _coll = _count_cross_dt_collisions(API_INDEX)
        EXPANDED_STATS = {"enabled": True, "added": _added, "excluded_uncertain": _excluded,
                          "rejected_collision": _rejected,
                          "uncertain_list_size": len(_uncertain),
                          "base_cross_dt_collisions": _base_coll,
                          "cross_dt_substring_collisions": _coll,
                          "enable_safe": _coll <= _base_coll,
                          "total": sum(len(v) for m in PLATFORM_APIS.values() for v in m.values())}
        if _coll > _base_coll:                        # 理论不可达；防御性告警
            import sys as _sys
            print(f"!! 扩充目录异型碰撞 {_coll} > 基础 {_base_coll} ⇒ 合并守卫失效，拒绝启用",
                  file=_sys.stderr)
            EXPANDED_STATS["enable_safe"] = False
    except Exception as _e:                       # noqa: BLE001
        EXPANDED_STATS = {"enabled": False, "error": f"{type(_e).__name__}: {_e}"}
else:
    EXPANDED_STATS = {"enabled": False, "reason": "PC_EXPANDED_APIS=0 (默认)"}

# ---------------- 包名 / 文件名 生成（train 用常规域，ood 用未见域） ----------------
TRAIN_PKGS = ["com.app.u1", "com.app.u2", "com.app.u3", "com.app.u4",
              "com.app.u5", "com.app.u6", "com.app.u7", "com.app.u8", "com.app.u9"]
TRAIN_3P = ["cn.com.sdk.location", "cn.com.sdk.analytics", "cn.com.sdk.push",
            "com.sdk.pay", "io.sdk.stats", "com.vendor.map"]

# OOD 专用：训练中绝不出现的包域 / 类名后缀 / 文件扩展 / 变量风格
OOD_PKGS = ["com.q7.app", "com.zx.group", "cn.lv.app", "com.mk.soft",
            "com.torch.light", "cn.pearl.river", "com.oz.pro", "com.kx.base"]
OOD_3P = ["com.novel.sdk.geo", "com.next.stats", "cn.away.push", "io.extra.pay"]
OOD_CLASS_SUFFIX = ["ImplV2", "HelperAsync", "ManagerEx", "BridgeLegacy", "FacadeNew", "CoreRefactor"]
OOD_FILE_EXT = {"android": [".kt", ".java"], "ios": [".m", ".swift"],
                "miniprogram": [".ts", ".js"], "harmony": [".ets", ".ts"]}

# Value vocabularies -------------------------------------------------
GOOD_CRYPTO = ["AES-256-GCM", "TLS1.3", "SM4-GCM", "RSA-OAEP", "ChaCha20-Poly1305"]
BAD_CRYPTO = ["none", "raw", "DES-ECB", "AES-ECB"]
GOOD_PURPOSE = {
    "PHONE": ["core_function", "account_security", "verification"],
    "ID_CARD": ["identity_verification"],
    "BANK_CARD": ["payment", "identity_verification"],
    "DEVICE_ID": ["analytics", "security", "core_function"],
    "EMAIL": ["core_function", "account_security", "notification"],
    "NAME": ["core_function", "profile", "identity_verification"],
    "EXACT_IMAGE": ["identity_verification", "content_publish"],
    "HEALTH": ["health_service"],
    "LOCATION": ["core_function", "navigation", "weather"],
    "SMS": ["verification", "security"],
    "CONTACTS": ["social", "backup"],
    "BIOMETRIC": ["identity_verification", "security"],
    "CAMERA_MIC": ["core_function", "content_publish", "video_call"],
}
BAD_PURPOSE = ["ad_recommend", "marketing", "performance", "user_profiling", "arbitrary_extend"]
SECONDARY_PURPOSE = ["analytics", "performance"]

CITY = ["深圳市", "上海市", "北京市", "杭州市", "广州市", "成都市", "武汉市", "南京市", "西安市", "重庆市"]
SURNAME = ["张", "王", "李", "赵", "刘", "陈", "杨", "黄", "周", "吴", "徐", "孙", "马", "朱", "胡"]
GIVEN = ["伟", "芳", "娜", "敏", "静", "磊", "军", "洋", "勇", "艳", "杰", "涛", "明", "超", "霞", "平"]
