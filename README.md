# docker-gatekeeper-agent

A policy-driven security gate for Docker images. Blocks or allows a release based on Trivy scan results and waivers; an LLM only explains the decision, it never makes it.

## Problem

Security sign-off on Docker images before release is usually a manual, ad-hoc review — someone eyeballs a scan report and makes a judgment call. That's slow, inconsistent between reviewers, and hard to audit, which ends up bottlenecking CI/CD.

## Solution

A deterministic policy engine evaluates each vulnerability against a fixed rule set (severity, fix availability, waivers, prod vs. non-prod) and produces the block/allow verdict. An LLM is only used afterward to turn that verdict into a plain-English summary and remediation suggestions — it has no say in the decision itself.

## Setup

```
pip install -r requirements.txt
cp .env.example .env   # then fill in ANTHROPIC_API_KEY
```
