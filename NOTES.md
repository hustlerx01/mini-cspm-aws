# NOTES
- 2026-10-11: built 20 checks + moto sandbox. 8/8 tests pass. Demo: 13 FAIL / 12 PASS.
- Interview angles: why read-only (List/Get/Describe) and a separate scanner role; mapping to CIS numbers; ASFF lets Security Hub own the triage workflow; why one failing check must not kill the scan.
- Gotcha: moto's root account summary has MFA off and can't be changed, so IAM-02 always FAILs in the demo.
- Next: paginators, multi-region loop, CIS 4.x metric filters, run once on a throwaway account using sandbox/main.tf, then destroy.
