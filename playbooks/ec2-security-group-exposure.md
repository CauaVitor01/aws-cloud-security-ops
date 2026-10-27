# Playbook: EC2 Security Group Exposure

## Overview

EC2 instances are usually reached over **SSH** or **RDP**, and a **security group (SG)** controls which ports are open. One SG can be attached to many instances. The risk is a port opened to the internet and not properly protected (weak RDP password, exposed SSH keys, vulnerable web service).

## What to alert on

- An SG **modified to allow public RDP**
- An instance **launched with an insecure SG**

Correlating SGs with the resources that use them is hard without AWS access or SOAR automation, so manual investigation is often needed.

## Hunt 1: a new security group was created

| Step | Action | Query |
|---|---|---|
| 1 | Find the creation event, note name and ID | `index=* eventName=CreateSecurityGroup` |
| 2 | Look for insecure inbound rules (`requestParameters`) | `index=* eventName=AuthorizeSecurityGroupIngress sg-xxxxxx` |
| 3 | Find instances using the SG (`responseElements`) | `index=* eventName IN(RunInstances, ModifyInstanceAttribute) sg-xxxxxx` |
| 4 | If rules are insecure, ask the author to harden the SG | N/A |

## Hunt 2: a security group rule was modified

| Step | Action | Query |
|---|---|---|
| 1 | Review the changes, note the SG ID | `index=* eventName IN(*SecurityGroupIngress, ModifySecurityGroupRules)` |
| 2 | Find who created the SG (search 90+ days back if empty) | `index=* earliest=-1y eventName=CreateSecurityGroup sg-xxxxxx` |
| 3 | Find instances using it (RDS also relies on SGs) | `index=* eventName IN(RunInstances, ModifyInstanceAttribute) sg-xxxxxx` |
| 4 | If the change is insecure, ask the author to harden the SG | N/A |

## Before reporting

SGs, network ACLs and VM firewalls overlap. The logs may suggest an instance is exposed while another control keeps it private. Verify with a **port scanner** or ask the IT team first.

## Late detection and defense in depth

Without alerts, exposed SSH, RDP or VNC is an entry point for attackers (for example, the Dota3 miner targets EC2 through exposed SSH). Instances may hold sensitive data, reach critical databases or have permissive IAM roles.

- Alert on insecure SG changes with **CloudTrail**
- Enable **GuardDuty** (`Recon:EC2/PortProbeUnprotectedPort`)
- Collect `auth.log` from VMs and detect **SSH brute force**
- As a last resort, detect the dropped miner with EDR, network or endpoint logs
