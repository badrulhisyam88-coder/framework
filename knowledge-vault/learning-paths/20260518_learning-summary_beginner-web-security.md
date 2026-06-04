---
type: learning-summary
id: LEARN-20260518-BEGINNER-WEB-SECURIT
title: Learning Summary — Beginner Web Security
date: 2026-05-18
learning_path_id: beginner_web_security
level: beginner
duration_hours: 6-8
completion_percent: 100
challenges_completed: 3
challenges_total: 3
tags:
  - learning-summary
  - owasp-a03
  - broken-auth
  - account-takeover
  - owasp-a07
  - mitre-t1078
  - security-questions
  - osint
  - sqli
related_labs: []
recommended_next:
  - intermediate_web_security
  - blue_team_fundamentals
---

# Learning Summary — Beginner Web Security

## Overview

| Field | Value |
|---|---|
| Learning Path | beginner_web_security |
| Level | beginner |
| Estimated Duration | 6-8 hours |
| Completion | 100% (3/3 challenges) |
| Date | 2026-05-18 |

## Path Description

Learn the most fundamental web vulnerabilities through guided, hands-on challenges in OWASP Juice Shop. Builds a solid foundation in injection attacks, cross-site scripting, and authentication failures.


## Challenge Progress

| Challenge ID | Status |
|---|---|
| juice_shop_sqli_beginner_01 | ✓ |
| juice_shop_stored_xss_01 | ✓ |
| juice_shop_broken_auth_01 | ✓ |

## Learning Objectives Covered

- Identify broken authentication patterns in password reset workflows
- Understand how security questions create predictable recovery paths
- Exploit information disclosure to answer secret questions for another account
- Recognise the OWASP Broken Authentication category in a real application
- Understand how SQL injection exploits unsafe string concatenation in queries
- Identify the structure of a SQL WHERE clause and its truth-value evaluation
- Craft a basic injection payload that forces an authentication bypass
- Distinguish between parameterized and unsafe query patterns
- Distinguish between reflected and stored (persistent) XSS
- Understand how unsanitized user input is rendered as executable HTML
- Craft a basic XSS payload and observe its execution in another session
- Identify the output context that determines which payload format works

## Key Concepts

- Broken Authentication occurs when authentication mechanisms can be bypassed or subverted
- Knowledge-based authentication (security questions) fails when answers are guessable or discoverable
- Defense-in-depth means no single factor should be the only barrier to account access
- SQL injection exploits the failure to separate executable code from user-supplied data
- Authentication bypass works by crafting input that makes the WHERE clause always evaluate TRUE
- Parameterized queries prevent injection by treating user input as data, never as code
- Stored XSS differs from reflected XSS because the payload persists in the database and affects all future visitors
- Output encoding converts characters like < and > into their HTML entity equivalents, preventing them from being interpreted as markup
- Context matters: a payload that works in an HTML body may need a different form inside a tag attribute

## Blue Team Coverage

Key mitigations encountered across this learning path:

- Replace knowledge-based security questions with time-based OTP or email link recovery
- Rate-limit and CAPTCHA-protect the Forgot Password endpoint
- Replace dynamic string concatenation with parameterized queries or prepared statements
- Implement strict input validation to reject unexpected characters in auth fields
- Apply context-aware output encoding before rendering user-supplied content
- Implement a strict Content Security Policy that blocks inline script execution

## Personal Notes

All 3 challenges completed on first attempt.

## Recommended Next Steps

- `intermediate_web_security`
- `blue_team_fundamentals`

## Related Labs

<!-- Link to individual lab walkthrough files exported for each completed challenge -->

## Related Findings

<!-- Link to any FIND-* documents if lab concepts map to real findings -->
