# DevSecOps Risk Assessment Report

Generated: 2026-03-08T12:08:47.392713+00:00

Total findings: **100**

## Top 10 Highest Risk Findings

1. **trivy** | score=0.6925 | id=CVE-2023-45133 | asset=package-lock.json
   - type: CVE
   - stage: SCA
   - evidence: babel: arbitrary code execution
   - contributions:
       severity: 0.36
       exposure: 0.06
       criticality: 0.045
       confidence: 0.1275
       freshness: 0.1

2. **trivy** | score=0.6925 | id=CVE-2025-7783 | asset=package-lock.json
   - type: CVE
   - stage: SCA
   - evidence: form-data: Unsafe random function in form-data
   - contributions:
       severity: 0.36
       exposure: 0.06
       criticality: 0.045
       confidence: 0.1275
       freshness: 0.1

3. **trivy** | score=0.6925 | id=CVE-2026-27212 | asset=package-lock.json
   - type: CVE
   - stage: SCA
   - evidence: Prototype pollution in swiper
   - contributions:
       severity: 0.36
       exposure: 0.06
       criticality: 0.045
       confidence: 0.1275
       freshness: 0.1

4. **trivy** | score=0.6525 | id=CVE-2026-26996 | asset=package-lock.json
   - type: CVE
   - stage: SCA
   - evidence: minimatch: minimatch: Denial of Service via specially crafted glob patterns
   - contributions:
       severity: 0.32
       exposure: 0.06
       criticality: 0.045
       confidence: 0.1275
       freshness: 0.1

5. **trivy** | score=0.6525 | id=CVE-2026-27903 | asset=package-lock.json
   - type: CVE
   - stage: SCA
   - evidence: minimatch: minimatch: Denial of Service due to unbounded recursive backtracking via crafted glob patterns
   - contributions:
       severity: 0.32
       exposure: 0.06
       criticality: 0.045
       confidence: 0.1275
       freshness: 0.1

6. **trivy** | score=0.6525 | id=CVE-2026-27904 | asset=package-lock.json
   - type: CVE
   - stage: SCA
   - evidence: minimatch: Minimatch: Denial of Service via catastrophic backtracking in glob expressions
   - contributions:
       severity: 0.32
       exposure: 0.06
       criticality: 0.045
       confidence: 0.1275
       freshness: 0.1

7. **trivy** | score=0.6525 | id=CVE-2022-25883 | asset=package-lock.json
   - type: CVE
   - stage: SCA
   - evidence: nodejs-semver: Regular expression denial of service
   - contributions:
       severity: 0.32
       exposure: 0.06
       criticality: 0.045
       confidence: 0.1275
       freshness: 0.1

8. **trivy** | score=0.6525 | id=GHSA-5c6j-r48x-rmvq | asset=package-lock.json
   - type: CVE
   - stage: SCA
   - evidence: Serialize JavaScript is Vulnerable to RCE via RegExp.flags and Date.prototype.toISOString()
   - contributions:
       severity: 0.32
       exposure: 0.06
       criticality: 0.045
       confidence: 0.1275
       freshness: 0.1

9. **trivy** | score=0.6525 | id=CVE-2024-37890 | asset=package-lock.json
   - type: CVE
   - stage: SCA
   - evidence: nodejs-ws: denial of service when handling a request with many HTTP headers
   - contributions:
       severity: 0.32
       exposure: 0.06
       criticality: 0.045
       confidence: 0.1275
       freshness: 0.1

10. **trivy** | score=0.6125 | id=CVE-2026-22029 | asset=package-lock.json
   - type: CVE
   - stage: SCA
   - evidence: @remix-run/router: react-router: React Router vulnerable to XSS via Open Redirects
   - contributions:
       severity: 0.28
       exposure: 0.06
       criticality: 0.045
       confidence: 0.1275
       freshness: 0.1

## Asset Risk Summary

- package-lock.json | max=0.6925 | avg=0.5627 | count=57
- /app/starbucks/kubernetes/manifest.yml | max=0.4455 | avg=0.4037 | count=20
- /main.tf | max=0.4455 | avg=0.4055 | count=11
- /terraform/main.tf | max=0.4015 | avg=0.4015 | count=7
- /Dockerfile | max=0.4015 | avg=0.4015 | count=2
- app/starbucks/Dockerfile | max=0.315 | avg=0.315 | count=1
- app/starbucks/kubernetes/manifest.yml | max=0.315 | avg=0.315 | count=2
