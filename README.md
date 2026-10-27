# AWS Cloud Security Ops

🇺🇸 **English** | 🇧🇷 [Português](README.pt-BR.md)

Study and hands-on repository about **AWS security monitoring**, focused on detecting and investigating common attacks with **CloudTrail**, **GuardDuty** and **Splunk**.

## Why this repo

AWS has 200+ managed services, so covering every attack vector is unrealistic. The goal here is to focus on the most common and impactful attacks, which can be detected with a small share of the SOC effort.

## Structure

| Folder | Content |
|---|---|
| `playbooks/` | Step-by-step investigation guides |
| `detections/` | Detection ideas and GuardDuty findings |
| `labs/` | Hands-on lab notes and evidence |
| `docs/` | Study notes |

## Scenarios covered

- [x] S3 bucket exposure → [playbook](playbooks/s3-bucket-exposure.md)
- [x] Insecure EC2 security groups → [playbook](playbooks/ec2-security-group-exposure.md)
- [ ] RDS exposure
- [ ] Denial-of-wallet attacks

## Tools

AWS CloudTrail · Amazon GuardDuty · Splunk

## Author

Cauã
