import html, json, datetime as dt
from collections import Counter
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
ASFF_SEV = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 40, "LOW": 1}

def summary(findings):
    c = Counter(f.status for f in findings)
    fails = Counter(f.severity for f in findings if f.status == "FAIL")
    return {"total": len(findings), "pass": c["PASS"], "fail": c["FAIL"], "error": c["ERROR"],
            "fail_by_severity": dict(sorted(fails.items(), key=lambda x: SEV_ORDER[x[0]]))}

def to_asff(findings, account_id, region):
    now = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    out = []
    for f in findings:
        if f.status != "FAIL": continue
        out.append({
            "SchemaVersion": "2018-10-08",
            "Id": f"minicspm/{f.check_id}/{f.resource}",
            "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
            "GeneratorId": f"minicspm-{f.check_id}",
            "AwsAccountId": account_id,
            "Types": ["Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"],
            "CreatedAt": now, "UpdatedAt": now,
            "Severity": {"Label": f.severity, "Normalized": ASFF_SEV[f.severity]},
            "Title": f"CIS {f.cis} {f.title}", "Description": (f.detail or f.title)[:1024],
            "Remediation": {"Recommendation": {"Text": f.remediation[:512] or "See CIS benchmark"}},
            "Resources": [{"Type": "Other", "Id": f.resource, "Region": region}],
            "Compliance": {"Status": "FAILED"},
        })
    return out

def to_html(findings):
    rows = sorted(findings, key=lambda f: (f.status != "FAIL", SEV_ORDER[f.severity], f.check_id))
    s = summary(findings)
    tr = "".join(f"<tr class='{f.status}'><td>{f.status}</td><td>{f.severity}</td><td>{f.check_id}</td><td>{f.cis}</td>"
                 f"<td>{html.escape(f.title)}</td><td>{html.escape(f.resource)}</td><td>{html.escape(f.detail)}</td><td>{html.escape(f.remediation)}</td></tr>" for f in rows)
    return f"""<!doctype html><meta charset=utf-8><title>MiniCSPM report</title>
<style>body{{font-family:sans-serif}}td,th{{border:1px solid #ccc;padding:4px}}.FAIL{{background:#fdd}}.PASS{{background:#dfd}}.ERROR{{background:#ffd}}</style>
<h1>MiniCSPM-AWS report</h1><p>{html.escape(json.dumps(s))}</p>
<table><tr><th>Status</th><th>Sev</th><th>ID</th><th>CIS</th><th>Check</th><th>Resource</th><th>Detail</th><th>Fix</th></tr>{tr}</table>"""
