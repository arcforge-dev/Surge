# ArcForge Surge

A ruleset builder written in **.NET**.  
It pulls rule sources from upstream projects, parses them line by line, classifies them into **Domain / Non-IP / IP** segments, then reorders, cleans, and regenerates ready-to-use rule files with a unified structure.  
The generated rules are intended to be published via a web interface for browsing and downloading.

> Designed for users who want to unify their own ruleset style, reuse mature upstream rule sources, and generate well-structured, consistent rule outputs.

---

## ✨ Features

- **Line-by-line parsing with controlled rebuilding**  
  Standardizes, classifies, and reorders rules (Domain-first, IP as final fallback)

- **Unified output structure**  
  Generates rules using a consistent directory and file naming layout, suitable for mirroring and redistribution

- **Multiple upstream support**  
  Can aggregate rules from different sources (e.g. ad blocking, streaming services, vendor IP ranges)

- **Automatic noise filtering**  
  Ignores comments, empty lines, and signature placeholders (such as marker lines containing `ruleset.skk.moe`)

- **Extensible rule strategy**  
  Customizable behavior, including:
  - Which prefixes are treated as *Non-IP* rules  
    (`DOMAIN`, `URL-REGEX`, `USER-AGENT`, `PROCESS-NAME`, etc.)
  - Whether IP rules should automatically include `no-resolve`
  - Whether output should be split into `domainset / non_ip / ip` segments

- **Compliant metadata headers**  
  Generated rule files can automatically include license information, upstream attribution, timestamps, and rule counts for traceability and redistribution

---

## 🧠 Rule Segmentation & Ordering (Core Design)

By default, generated rules follow this order:

1. **Domain-based rules first**  
   (`DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `DOMAIN-WILDCARD`, …)

2. **Non-IP rules next**  
   (`URL-REGEX`, `USER-AGENT`, `PROCESS-NAME`, logical `AND` / `OR` combinations, etc.)

3. **IP-based rules as the final fallback**  
   (`IP-CIDR`, `IP-CIDR6`, `IP-ASN`, `GEOIP`, …)

### Why this order?

- Most requests are matched during the string-based phase, without requiring DNS resolution
- IP rules are only evaluated as a last resort, keeping the ruleset clearer and easier to maintain

---

## 🚀 Quick Start

### Requirements
- .NET SDK (recommended: **.NET 10**)

### Run Locally (Example)

> Actual arguments depend on your `Program.cs` and CLI design.  
> The following shows a recommended invocation pattern.

```bash
dotnet restore
dotnet build -c Release

# Run rule generation (example)
dotnet run -c Release -- \
  --out ./dist \
  --origin "local"
```

### Run with Docker

Prebuilt image: `ryancooper001/arcforge-surge:latest`

```bash
docker pull ryancooper001/arcforge-surge:latest
docker run --rm -p 8080:8080 -v surge-ruleset:/RuleSet --name surge ryancooper001/arcforge-surge:latest
```

Then open `http://localhost:8080`.
