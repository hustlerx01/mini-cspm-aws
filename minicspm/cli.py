import argparse, json, os, sys
import boto3
from .checks import run_all
from .report import summary, to_asff, to_html

def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only CIS AWS checks")
    ap.add_argument("--region", default=os.environ.get("AWS_DEFAULT_REGION", "ap-south-1"))
    ap.add_argument("--out", default="out")
    ap.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "never"], default="never")
    a = ap.parse_args(argv)
    session = boto3.session.Session(region_name=a.region)
    acct = session.client("sts").get_caller_identity()["Account"]
    findings = run_all(session)
    os.makedirs(a.out, exist_ok=True)
    json.dump([f.to_dict() for f in findings], open(f"{a.out}/findings.json", "w"), indent=2, default=str)
    json.dump(to_asff(findings, acct, a.region), open(f"{a.out}/asff.json", "w"), indent=2)
    open(f"{a.out}/report.html", "w").write(to_html(findings))
    s = summary(findings); print(json.dumps(s, indent=2))
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    if a.fail_on != "never" and any(f.status == "FAIL" and order.index(f.severity) <= order.index(a.fail_on) for f in findings):
        return 2
    return 0

if __name__ == "__main__": sys.exit(main())
