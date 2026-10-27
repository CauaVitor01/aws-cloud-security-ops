# AWS Cloud Security Ops

🇺🇸 [English](README.md) | 🇧🇷 **Português**

Repositório de estudos e prática sobre **monitoramento de segurança na AWS**, com foco em detectar e investigar ataques comuns usando **CloudTrail**, **GuardDuty** e **Splunk**.

## Por que este repositório

A AWS tem mais de 200 serviços gerenciados, então cobrir todos os vetores de ataque é inviável. O objetivo aqui é focar nos ataques mais comuns e de maior impacto, que podem ser detectados com uma pequena parte do esforço do SOC.

## Estrutura

| Pasta | Conteúdo |
|---|---|
| `playbooks/` | Guias de investigação passo a passo |
| `detections/` | Ideias de detecção e achados do GuardDuty |
| `labs/` | Notas e evidências de laboratórios práticos |
| `docs/` | Notas de estudo |

## Cenários cobertos

- [x] Exposição de buckets S3 → [playbook](playbooks/s3-bucket-exposure.md)
- [x] Grupos de segurança do EC2 inseguros → [playbook](playbooks/ec2-security-group-exposure.md)
- [ ] Exposição de RDS
- [ ] Ataques de *denial of wallet*

> Os playbooks e as demais pastas estão em inglês.

## Ferramentas

AWS CloudTrail · Amazon GuardDuty · Splunk

## Autor

Cauã
