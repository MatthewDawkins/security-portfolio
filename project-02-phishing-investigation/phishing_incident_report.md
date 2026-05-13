# Phishing Email Investigation — Incident Report

## Email Headers

```
Received: from mail.fakebank-support.com (185.231.181.22)
	by mx.google.com with ESMTPS id x12si123456qkb.123.2025.12.13.14.31.10
	for <user@company.com>
	(version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256);
	Fri, 13 Dec 2025 14:32:10 -0500 (EST)

Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.fakebank-support.com (Postfix) with ESMTP id 4F2A812345
	for <user@company.com>;
	Fri, 13 Dec 2025 14:32:08 -0500 (EST)

From: "FakeBank Security Team" <security@fakebank-support.com>
Reply-To: security@fakebank-login-alert.com
To: user@company.com
Subject: Urgent: Suspicious Login Detected
Date: Fri, 13 Dec 2025 14:32:07 -0500
Message-ID: <202512131432907.4F2A812345@mail.fakebank-support.com>

Authentication-Results: mx.google.com;
	spf=fail (google.com: domain of security@fakebank-support.com does not designate 185.231.181.22 as permitted sender)
	dkim=fail (bad signature)
	dmarc=fail (p=reject dis=none) header.from=fakebank-support.com
```

## Analysis

The email claims to originate from a bank security team but exhibits multiple indicators of phishing. The sender domain (`fakebank-support.com`) does not match the Reply-To domain (`fakebank-login-alert.com`), indicating the attacker is attempting to redirect responses to a separately controlled address.

Authentication checks all failed:
- **SPF:** The sending IP (185.231.181.22) is not an authorized sender for the domain
- **DKIM:** Signature validation failed, indicating the message was not signed by the domain owner
- **DMARC:** Policy set to `reject`; the message fails alignment on both SPF and DKIM

The sending IP is not associated with legitimate bank infrastructure. The subject line and language create urgency, a common social engineering tactic consistent with credential harvesting campaigns.

## Conclusion

This email is a confirmed phishing attempt designed to trick recipients into interacting with a malicious domain and potentially disclosing credentials.

## MITRE ATT&CK Mapping
- Technique: T1566 — Phishing
- Tactic: Initial Access
