# DevSecOps Risk Assessment Report

Generated: 2026-03-08T15:33:18.722007+00:00

Total findings: **11**

## Top 10 Highest Risk Findings

1. **checkov** | score=0.4455 | id=CKV_K8S_21 | asset=/main.tf
   - type: The default namespace should not be used
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-20
   - contributions:
       severity: 0.08
       exposure: 0.06
       criticality: 0.045
       confidence: 0.12
       freshness: 0.1

2. **checkov** | score=0.4015 | id=CKV_K8S_43 | asset=/main.tf
   - type: Image should use digest
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-39
   - contributions:
       severity: 0.04
       exposure: 0.06
       criticality: 0.045
       confidence: 0.12
       freshness: 0.1

3. **checkov** | score=0.4015 | id=CKV_K8S_22 | asset=/main.tf
   - type: Use read-only filesystem for containers where possible
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-21
   - contributions:
       severity: 0.04
       exposure: 0.06
       criticality: 0.045
       confidence: 0.12
       freshness: 0.1

4. **checkov** | score=0.4015 | id=CKV_K8S_28 | asset=/main.tf
   - type: Minimize the admission of containers with the NET_RAW capability
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-27
   - contributions:
       severity: 0.04
       exposure: 0.06
       criticality: 0.045
       confidence: 0.12
       freshness: 0.1

5. **checkov** | score=0.4015 | id=CKV_K8S_14 | asset=/main.tf
   - type: Image Tag should be fixed - not latest or blank
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-13
   - contributions:
       severity: 0.04
       exposure: 0.06
       criticality: 0.045
       confidence: 0.12
       freshness: 0.1

6. **checkov** | score=0.4015 | id=CKV_K8S_9 | asset=/main.tf
   - type: Readiness Probe Should be Configured
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-8
   - contributions:
       severity: 0.04
       exposure: 0.06
       criticality: 0.045
       confidence: 0.12
       freshness: 0.1

7. **checkov** | score=0.4015 | id=CKV_K8S_12 | asset=/main.tf
   - type: Memory Limits should be set
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-11
   - contributions:
       severity: 0.04
       exposure: 0.06
       criticality: 0.045
       confidence: 0.12
       freshness: 0.1

8. **checkov** | score=0.4015 | id=CKV_K8S_13 | asset=/main.tf
   - type: Memory requests should be set
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-12
   - contributions:
       severity: 0.04
       exposure: 0.06
       criticality: 0.045
       confidence: 0.12
       freshness: 0.1

9. **checkov** | score=0.4015 | id=CKV_K8S_10 | asset=/main.tf
   - type: CPU requests should be set
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-9
   - contributions:
       severity: 0.04
       exposure: 0.06
       criticality: 0.045
       confidence: 0.12
       freshness: 0.1

10. **checkov** | score=0.4015 | id=CKV_K8S_11 | asset=/main.tf
   - type: CPU Limits should be set
   - stage: IaC
   - evidence: https://docs.prismacloud.io/en/enterprise-edition/policy-reference/kubernetes-policies/kubernetes-policy-index/bc-k8s-10
   - contributions:
       severity: 0.04
       exposure: 0.06
       criticality: 0.045
       confidence: 0.12
       freshness: 0.1

## Asset Risk Summary

- /main.tf | max=0.4455 | avg=0.4055 | count=11
