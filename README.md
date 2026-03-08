# AI-Assisted DevSecOps Risk Assessment

This project implements an AI-assisted DevSecOps pipeline that performs:

- Static code analysis (Semgrep)
- Dependency vulnerability scanning (Trivy)
- Infrastructure security scanning (Checkov)
- Terraform & Kubernetes misconfiguration detection
- Normalization of security findings
- Correlation of duplicate alerts
- Explainable risk scoring
- Machine learning based risk prediction
- CI/CD security gating
- Visualization of security metrics

Pipeline architecture:

Code → Security Scans → Normalize → Correlate → Score → ML Prediction → Security Gate

Tools used:
Semgrep
Trivy
Checkov
Terraform
Python (Scikit-learn, Pandas)
GitHub Actions
