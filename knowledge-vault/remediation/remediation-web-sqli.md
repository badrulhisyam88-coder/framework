---
type: remediation
id: REM-WEB-20260518-001
title: "Remediation: SQL Injection"
date: "2026-05-18"
category: web
severity: high
status: draft
tags:
  - remediation
  - sqli
  - owasp-a03
  - web
related_findings:
  - FIND-WEB-20260518-001
related_concepts: []
---

# Remediation: SQL Injection

## Summary

> SQL Injection occurs when user-supplied input is concatenated into SQL queries without sanitisation.

## Root Cause

The application constructs SQL queries using string concatenation with user-controlled input, allowing attackers to inject arbitrary SQL syntax.

## Affected Components

- Web application query layer
- ORM raw query calls
- Stored procedure inputs

## Short-Term Fix

> Apply immediately to reduce exploitability.

Deploy a WAF rule to block common SQL injection patterns in all input parameters.

```
# Nginx + ModSecurity example
SecRule ARGS "@detectSQLi" "id:1001,deny,status:403,msg:'SQL Injection Detected'"
```

## Long-Term Fix

> Permanent remediation via code or architecture change.

### Developer Guidance

Replace all dynamic SQL string construction with parameterized queries or prepared statements. The database driver treats user input as data, never as executable SQL.

### Recommended Libraries / Functions

| Language | Recommended Approach |
|---|---|
| Python | Use `cursor.execute(sql, params)` — never f-strings in queries |
| JavaScript/Node | Use `pool.query(sql, [params])` with pg / mysql2 |
| Java | Use `PreparedStatement` — never `Statement.executeQuery(sql + input)` |
| PHP | Use PDO with `prepare()` and `bindParam()` |

## Verification Steps

1. Retest the original payload — it should return an error or be rejected cleanly
2. Run a SQLMap scan against the same parameter — expect no injectable parameters found
3. Review application logs for rejected queries

```bash
sqlmap -u 'https://target/login' --data 'user=test&pass=test' --level 1 --risk 1 --batch
```

## References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)

## Related

- Concept: [[concept-sqli]]
- Findings:
- [[internal-sqli-001]]
