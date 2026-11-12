---
name: subagent-delegation
description: Route and supervise bounded subagent work for pdf2md.mcp, including documentation consistency, PDF-to-Markdown conversion, I/O boundaries, MCP integration, and relevant verification. Use when independent investigation, repetitive work, or review benefits from delegation. Handle small edits directly; this skill does not select the primary agent's operating mode.
---

# Subagent Delegation for pdf2md.mcp

## Repository Goal and Current State

The Rust 2024 workspace provides PDF acquisition and conversion, a separate
Obscura browser worker, content-addressed storage, and attempt history. It
provides an HTTP service with an opt-in read-only Streamable HTTP MCP endpoint. Recheck the repository before
assigning work; this description must not override later implementation changes.

Read applicable [AGENTS.md](../../../AGENTS.md) instructions and the relevant
source of truth: [README.md](../../../README.md) for project status and setup,
[CONTRIBUTING.md](../../../CONTRIBUTING.md) for workflow and public references,
and [SECURITY.md](../../../SECURITY.md) for vulnerability handling. Keep these
documents aligned when implementation changes their claims.

Delegation supports the authorized task; it does not authorize additional
features, external actions, or changes to the primary agent's operating mode.
Respect user instructions, repository guidance, runtime capabilities, and
sandbox permissions. Do not assume custom agents or particular models exist.

## When to Delegate

Handle a short documentation edit, a single known correction, or one simple
check directly. Delegate when a bounded task provides useful parallelism,
reduces bulky evidence processing, or adds independent judgment.

Useful assignments include checking consistency among project documents,
reviewing an already-decided documentation change, and independently reviewing
acquisition, persistence, or browser-worker boundaries. Multiple agents are
unnecessary for routine edits to a few short documents.

As executable behavior is introduced, useful independent assignments include:

- Review conversion behavior against deterministic expected Markdown.
- Prepare small synthetic PDF fixtures for agreed behaviors and failure cases.
- Trace filesystem or network access separately from conversion rules.
- Review the MCP interface against the chosen conversion contract.
- Run documented checks and summarize meaningful failures.

Keep conversion rules separate from filesystem access, network access, and MCP
transport. Do not assume a language, dependency, source directory, transport,
or conversion feature that the repository or authorized task has not chosen.
Surface significant design choices to the coordinating agent before dependent
implementation begins.

## Model Routing and Escalation

Use the least costly available worker that can reliably handle the local
question. These are preferred roles, not guarantees of model availability:

| Delegated work | Preferred model and effort |
|---|---|
| Precise inventory, decided repetitive edits, documentation checks, test/log summaries | `gpt-6-luna` high; max for substantial evidence reconciliation |
| Repository exploration and locating relevant contracts | `gpt-6.1-terra` medium |
| Semantic diagnosis, conversion correctness, ordinary security review | `gpt-6.1-terra` high |
| Difficult integration or unresolved high-consequence review | `gpt-6.1-sol` high; xhigh when justified |
| Authorized defensive security investigation, when available | `gpt-daybreak-blue-latest` high; at most xhigh |

Check the active runtime's supported models and reasoning settings. If a named
model is unavailable, select a supported alternative with the needed capability
and a supported effort level, or perform the work directly. Do not retry an
unsupported alias repeatedly. Never configure Daybreak above xhigh.

Keep mechanical work with Luna only while the transformation and expected
behavior are decided and verifiable. Escalate to Terra when behavior is
ambiguous, a failure needs causal diagnosis, or correctness depends on other
components. Seek Sol or independent review when important uncertainty remains
and consequences justify it. Report established facts, unresolved questions,
and relevant evidence before escalation; avoid repeated escalation without
narrowing the question.

## Assignment and Coordination

Give each worker a bounded objective with:

- Relevant files and repository instructions.
- Allowed edits or an explicit read-only boundary, with file ownership.
- Agreed behavior, constraints, and decisions still needing escalation.
- Available verification commands and expected deliverables.

For example, ask a read-only worker to compare status and validation claims in
README.md and CONTRIBUTING.md, returning conflicting passages and evidence.
Once conversion behavior exists, a fixture worker can cover one agreed behavior
using synthetic PDFs and deterministic expected Markdown, confined to assigned
fixture and test files.

Parallelize independent investigation or work with separate ownership. Avoid
concurrent edits to the same document, interface, configuration, fixture, or
shared generated output. For coupled changes, investigate in parallel if
useful, settle the shared contract, then assign non-overlapping implementation.
Workers share the workspace: preserve unrelated changes and inspect the actual
combined result before reporting completion.

The coordinator owns cross-component decisions and final integration. A worker
must report unexpected ambiguity rather than silently expand scope or redesign
public behavior. Request compact reports containing findings with paths and
symbols or sections, changed files, verification outcomes, and unresolved
questions. Separate observations from inference; omit repetitive logs.

## PDF, Output, and Security Review

Treat PDFs and extracted content as untrusted. When the task affects executable
behavior, direct review toward the relevant boundaries: malformed documents,
resource consumption, filesystem access, external-resource access, and handling
of generated Markdown. A delegation skill does not establish a sandbox or
prove these controls exist.

For consequential parser, resource-control, I/O, or MCP boundary changes, prefer
independent review of the actual patch and affected surrounding code when
permitted and useful. Keep review proportional to the requested change; do not
turn ordinary documentation work into a security audit or assume a trustworthy
security baseline exists. Expand to semantically affected code when evidence
requires it, and state uncovered areas. Honor explicitly requested audit scope.

Follow SECURITY.md for undisclosed vulnerabilities; keep details out of public
issues, PRs, and commit messages. Model availability does not widen testing
authorization or permit accessing documents or systems without permission.

## Verification and Completion

For documentation-only work, read the complete changed text, check links and
anchors, and run these commands from the repository root:

```sh
git status --short
git diff --check
git diff
```

Git diff commands omit untracked files. Read those files directly and check
their whitespace separately before reporting validation. Preserve LICENSE and
unrelated work. Do not invent build, server, formatter, linter, or test commands
while none are configured.

With the first executable behavior, add reproducible setup and validation
instructions, the chosen language's formatting/lint configuration, and tests
alongside behavior. Prefer small synthetic, redistributable PDFs and
deterministic expected Markdown; cover relevant failure cases and record
fixture provenance or generation instructions when needed. Keep private
documents, credentials, and incidental generated output out of version control.
Clean up disposable validation resources even on failure where practical.

Once tooling exists, run the cheapest relevant documented checks first. Broaden
validation when changed contracts or uncertain effects justify it, or repository
policy requires it. Report commands, outcomes, failures, and unavailable or
unexecuted checks. Distinguish local checks from hosted CI, deployment, and
end-to-end MCP client verification; passing one does not establish the others.

Before completion, the coordinator reviews actual edits against the objective,
resolves or reports remaining uncertainty, and confirms documentation matches
the delivered behavior. Follow CONTRIBUTING.md for public references and any
requested commits or PRs: use portable, sanitized context and imperative
Conventional Commits, without secrets, private evidence, or session paths.
Delegation does not authorize staging, committing, publishing, or deployment
beyond the user's task.
