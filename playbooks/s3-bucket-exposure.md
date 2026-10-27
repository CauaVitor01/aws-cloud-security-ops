# Playbook: S3 Bucket Exposure

## Overview

New S3 buckets are **private by default**. A bucket only becomes public after someone disables the **S3 Public Access Block** and applies a bucket policy (or a legacy ACL). The best approach is to detect that exact moment.

## Early detection

| Event | Meaning |
|---|---|
| `PutBucketPublicAccessBlock` | Public Access Block was changed |
| `PutBucketPolicy` | A bucket policy was applied |
| `PutBucketAcl` | An ACL was applied (legacy) |

```spl
index=* eventName=PutBucketPublicAccessBlock
index=* eventName=PutBucketPolicy
```

### Reviewing a `PutBucketPolicy` event

Not every policy grants anonymous access. Start with statements where `Effect` is `Allow` and `Principal` is `*`, then read the whole policy:

- **Action:** public read (`GetObject`, `HeadObject`, sometimes `ListObjects`) is common for avatars, static sites and media.
- **Deny statements:** they may limit the exposure.
- **Condition:** for example, an `IpAddress` / `aws:SourceIp` condition can restrict access to an office IP, which makes the policy acceptable.

### Classifying the bucket

Check the bucket name, tags and content (`https://BUCKET.s3.amazonaws.com/FILE`). If it is still unclear, ask the IT team or the bucket owner.

## Late detection

If the exposure was missed, bots will find the bucket. Look for `GetObject` / `HeadObject` events from **anonymous users and external IPs**. If listing is not allowed, attackers must guess file names, which creates many **Access Denied** errors followed by a success.

```spl
index=* eventName IN (GetObject, HeadObject)
```

## GuardDuty

GuardDuty handles complex policy conditions well thanks to automated reasoning. See [`detections/guardduty-findings.md`](../detections/guardduty-findings.md).

## Real-world cases

- **WebWork** (Jun 2024 – Jan 2025): 13M+ records exposed (activity logs and desktop screenshots).
- **WorkComposer:** 21M+ desktop screenshots exposed.
- **Pegasus Airlines** (2022): 23M files (6.5 TB) exposed for at least a month.
