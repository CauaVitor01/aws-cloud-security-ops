# GuardDuty Findings

| Finding | Meaning |
|---|---|
| `Policy:S3/BucketBlockPublicAccessDisabled` | The S3 Public Access Block feature was disabled |
| `Policy:S3/BucketAnonymousAccessGranted` | A bucket was made public through an ACL or bucket policy |
| `Impact:S3/MaliciousIPCaller` | A known malicious IP accessed an exposed S3 bucket |
| `Recon:EC2/PortProbeUnprotectedPort` | An exposed EC2 port was probed |

GuardDuty is especially useful when writing manual rules would require handling every policy condition.
