# -*- coding: utf-8 -*-
"""GitHub / HuggingFace 实时检索：找最新、最相关的隐私合规与 PII 检测模型/工具。"""
import json, urllib.request, urllib.parse, time, sys

UA = {"User-Agent": "privacy-compliance-research", "Accept": "application/vnd.github+json"}

def get(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

def gh_search(q, sort="stars", per_page=8):
    url = "https://api.github.com/search/repositories?" + urllib.parse.urlencode(
        {"q": q, "sort": sort, "order": "desc", "per_page": per_page})
    try:
        return get(url)
    except Exception as e:
        return {"_err": str(e)}

def hf_search(q, sort="downloads", limit=8):
    url = "https://huggingface.co/api/models?" + urllib.parse.urlencode(
        {"search": q, "sort": sort, "direction": -1, "limit": limit})
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA["User-Agent"]})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except Exception as e:
        return [{"_err": str(e)}]

def show_gh(title, data):
    print(f"\n{'='*78}\n# {title}\n{'='*78}")
    if "_err" in data:
        print("  ERROR:", data["_err"]); return
    print(f"  total_count = {data.get('total_count')}")
    for it in data.get("items", []):
        print(f"  ★{it.get('stargazers_count'):>6}  {it.get('full_name')}")
        print(f"          lang={it.get('language')}  updated={it.get('updated_at','')[:10]}  push={it.get('pushed_at','')[:10]}  created={it.get('created_at','')[:10]}")
        d = (it.get("description") or "")[:150]
        if d:
            print(f"          {d}")

def show_hf(title, data):
    print(f"\n{'='*78}\n# {title}\n{'='*78}")
    if data and isinstance(data, list) and data and "_err" in data[0]:
        print("  ERROR:", data[0]["_err"]); return
    for it in data:
        print(f"  ⬇{it.get('downloads',0):>9}  {it.get('id')}   ({it.get('pipeline_tag','?')})")

GH_QUERIES = [
    ("隐私/PII 检测 - 最新(2025后)", "PII detection created:>2025-01-01", "updated"),
    ("隐私合规检测 - 最新(2025后)", "privacy compliance detection created:>2025-01-01", "updated"),
    ("敏感数据/合规 - 星标最高", "privacy compliance", "stars"),
    ("移动端隐私合规", "mobile privacy compliance", "stars"),
    ("安卓隐私/敏感API", "android privacy sensitive api", "stars"),
    ("本地/端侧 PII 脱敏模型", "pii redaction local on-device", "stars"),
]

HF_QUERIES = [
    ("PII 检测模型(下载量)", "pii-detection"),
    ("privacy filter", "privacy-filter"),
    ("中文 文本分类(小)", "chinese text classification"),
    ("token classification privacy", "token-classification privacy"),
]

if __name__ == "__main__":
    for t, q, s in GH_QUERIES:
        show_gh(t + f"  [q={q}]", gh_search(q, sort=s))
        time.sleep(2)
    for t, q in HF_QUERIES:
        show_hf(t + f"  [q={q}]", hf_search(q))
        time.sleep(1)
