#!/usr/bin/env python3
"""SBOM(CycloneDX JSON)の部品を OSV.dev の脆弱性DBと突き合わせる最小スクリプト。

使い方: python3 sbom_check.py sbom.json
標準ライブラリだけで動きます（pip install 不要）。
"""
import json
import os
import sys
import urllib.request

OSV_API = os.environ.get("OSV_API", "https://api.osv.dev/v1/querybatch")
BATCH = 500  # 1回のリクエストで問い合わせる部品数


def main(sbom_path: str) -> int:
    # 1. SBOMを読み、部品の識別子(PURL)を取り出す
    with open(sbom_path, encoding="utf-8") as f:
        sbom = json.load(f)
    purls = sorted({c["purl"] for c in sbom.get("components", []) if c.get("purl")})
    print(f"部品数: {len(purls)}")

    # 2. PURLをまとめてOSV.devに問い合わせる
    hits = {}
    for i in range(0, len(purls), BATCH):
        chunk = purls[i : i + BATCH]
        body = {"queries": [{"package": {"purl": p}} for p in chunk]}
        req = urllib.request.Request(
            OSV_API,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as res:
            results = json.load(res)["results"]
        # 結果は問い合わせと同じ順番で返ってくる
        for purl, result in zip(chunk, results):
            ids = [v["id"] for v in result.get("vulns", [])]
            if ids:
                hits[purl] = ids

    # 3. 結果を表示し、1件でもあれば終了コード1（＝CIを失敗させる）
    for purl, ids in hits.items():
        print(f"\n[NG] {purl}")
        for vid in ids:
            print(f"     https://osv.dev/vulnerability/{vid}")
    print(f"\n既知の脆弱性がある部品: {len(hits)} / {len(purls)}")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
