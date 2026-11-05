# ARTEX workflows inside Bee

Research snapshot: 2026-10-22. Proposal for discussion, not an implementation spec.

The [design proposal](../../docs/reconnaissance-workflows.md) captures the intended workflow,
delivery stages, acceptance criteria, and open decisions. This file retains the source inspection
and supporting evidence.

Inspected Bee's current working tree at base commit `ebf2d29e3d3fcca9fd09abcb9671543627081e18`, including the existing uncommitted specs, and `jlgore/ARTEX` at `0ca194271cc31953992b37921ca48c2387e5c399`. This was source inspection; no live-target scans, runtime verification, or application changes were performed.

The recommendation is to make reconnaissance a workflow of Bee tools, evidence, and skills. Bee should own the investigation loop: collect observations, choose a hypothesis, perform a bounded follow-up, preserve evidence, and produce a reviewable finding. ARTEX supplies a useful capability inventory and comparison baseline.

## What ARTEX actually implements

The [scan pipeline](https://github.com/jlgore/ARTEX/blob/0ca194271cc31953992b37921ca48c2387e5c399/app.py#L100) runs a fixed sequence: subdomains, email/auth discovery, ports, DNS, origin-IP candidates, TLS, technologies, rule-based analysis, and finally two LLM summaries. Modules parallelize some collection internally. The LLM does not operate an investigative tool loop.

| ARTEX capability | Implementation | Proposed home in Bee |
|---|---|---|
| Subdomain discovery | CT and passive-DNS services, a short DNS wordlist, HTTP enrichment, takeover signatures | Typed discovery and DNS tools; persist each source and its coverage; keep validation separate from discovery |
| DNS assessment | A/AAAA/MX/NS/TXT/CNAME/SOA, SPF/DMARC/PTR; aggressive mode adds AXFR and timing heuristics | DNS worker with structured results; separate ordinary collection from explicitly enabled active tests |
| Ports | Nmap TCP connect scan with a socket fallback; risk labels keyed to port numbers | Bounded TCP probe or typed Nmap adapter; open ports are observations, not vulnerability findings |
| TLS | Certificate/protocol/cipher/header checks mixed with heuristics and placeholders | Basic certificate inspection plus a versioned external engine for comprehensive checks; retain which checks actually ran |
| Technology detection | Wappalyzer over HTTP responses | Versioned fingerprint corpus applied to already captured exchanges; preserve matching evidence |
| Auth surface and email patterns | Page scraping, common-path requests, linked-page/provider checks | A web-recon skill over HTTP and parsing tools; findings require subsequent investigation |
| Origin-IP discovery | Correlates DNS, headers, CT and mail-server addresses, then probes candidates | Evidence-backed candidate relationships; discovery does not grant authority to connect |
| AI analysis | Owner and hunter summaries through an OpenAI-compatible endpoint | Bee's existing provider and conversation; report templates can express both audiences |
| Reports and progress | Flask state, templates, JSON/PDF generation | Existing REPL/TUI/session events; add evidence-linked Markdown/JSON exports before PDF |

Implementation details to preserve or correct during adaptation:

- [Technology detection](https://github.com/jlgore/ARTEX/blob/0ca194271cc31953992b37921ca48c2387e5c399/modules/tech_detector.py#L41) initializes `exposed_files`, `secrets`, and `endpoints` but does not populate them. It hard-codes confidence to 100 and does not detect versions. These are not implemented capabilities to import.
- [TLS checks](https://github.com/jlgore/ARTEX/blob/0ca194271cc31953992b37921ca48c2387e5c399/modules/ssl_scanner.py#L711) mark CRL checking complete without fetching a CRL. DNSSEC is inferred from the presence of DNSKEY records. The vulnerability function labels TLS 1.1 as Heartbleed. These outputs cannot serve as verified vulnerability evidence.
- [AI prompts](https://github.com/jlgore/ARTEX/blob/0ca194271cc31953992b37921ca48c2387e5c399/modules/AI_analyst.py#L254) read `vulnerability_scan`, which the inspected pipeline does not populate, and receive only small samples of technologies. Bee can instead let its model retrieve exact observations and follow up.
- [JSON export](https://github.com/jlgore/ARTEX/blob/0ca194271cc31953992b37921ca48c2387e5c399/utils/reporting.py#L1081) omits the pipeline's DNS, TLS, and origin-IP sections. An exported report is not a complete scan snapshot.
- Auth discovery is called through the email-enumeration module. Skipping `email` also skips that pipeline's auth-page discovery.
- The pipeline computes intensity-dependent `max_subdomains` but does not apply it. Bee should report and enforce explicit limits, including incomplete coverage.

## Bee: present code versus planned capabilities

| Foundation | Current evidence | Consequence |
|---|---|---|
| Agent loop | [`src/episode.rs`](../../src/episode.rs), [`src/repl.rs`](../../src/repl.rs) | Reuse provider calls, deadlines, transcripts, tool dispatch, and interactive/headless entrypoints |
| Tool execution | [`src/tools.rs`](../../src/tools.rs), [`src/sandbox.rs`](../../src/sandbox.rs), [`src/tools/exec.rs`](../../src/tools/exec.rs) | Network collectors fit the existing worker model; host and enforced execution are explicit postures |
| Honest security outcomes | [`src/tools/outcome.rs`](../../src/tools/outcome.rs) | Reuse completed/unavailable/failed, adding explicit coverage where needed; never convert an unavailable source into an empty successful result |
| External scanners | [`src/scanners/mod.rs`](../../src/scanners/mod.rs), [`src/tools/scanner.rs`](../../src/tools/scanner.rs) | Reuse grant checks, typed argv, deadlines, cancellation, and bounded report normalization |
| Finding ledger and computed severity | [`src/findings.rs`](../../src/findings.rs), [`src/tools/finding.rs`](../../src/tools/finding.rs) | Keep one ledger and human-only verdicts; extend finding locations and evidence rather than inventing a second findings system |
| Basic skill discovery/loading | [`src/skills.rs`](../../src/skills.rs) | A trusted reconnaissance playbook can guide one agent before hybrid profiles land |
| Concurrent episodes | [`src/concurrent.rs`](../../src/concurrent.rs) | Batch execution exists; it is not a parent/child investigation supervisor |
| HTTP interception | [019 spec/plan](../../specs/019-http-intercept/plan.md) | Planned: no current HTTP tool family or `intercept` Cargo feature found |
| Addressable evidence/results | [020 spec](../../specs/020-deterministic-tool-surface/spec.md) | Planned beyond existing transcript call IDs and prose evidence |
| Delegation and hybrid skills | [018](../../specs/018-subagent-scopes/spec.md), [022](../../specs/022-hybrid-agent-skills/spec.md) | Planned; useful later, not a prerequisite for the first recon workflow |

Source code takes precedence over stale overview text. For example, the README says inode-pinned executables are rejected, while current compiler/enforcement-plan code implements resolved inode identities under 017. This inspection does not establish that kernel enforcement passes on the deployment machine.

022 already describes the product direction this proposal needs: investigation quality, evidence, and reusable techniques, with isolation as an execution backend. Preserve ADR-0001's optional configuration inputs and ADR-0002's single `bee` application. New capabilities should work through `bee run` and `bee repl`.

## The additions that unlock the workflow

### 1. Assets and observations before findings

Persist assets and observations alongside the existing evidence system. A discovered hostname, open port, login form, or technology match is useful even when it is not a defect.

Minimal proposed records:

- Asset: stable ID, kind (host/IP/service/URL), normalized identity, scope classification.
- Observation: asset ID, producing tool and version, timestamp, evidence references, measurement, coverage/completeness.
- Relationship: source asset, destination asset, relation such as `resolves_to`, `redirects_to`, or `links_to`, with evidence.
- Hypothesis: a claim to investigate, supporting observation IDs, next validation step, and unresolved questions.

Start with records and indexed queries. A graph database is unnecessary. Deduplicate measurements and let the model ask for bounded subsets instead of repeatedly reading a full report. Do not label inferred email addresses or origin IPs as observed facts.

### 2. Extend the existing evidence and finding model

`Finding.path` and its identity hash are source-file oriented. Introduce a typed resource location covering source files, URLs, DNS names, and services, with backward-compatible reading and stable IDs for existing file findings. Avoid stuffing URLs into a field documented as a repository-relative path.

Use 020's harness-issued result/evidence references across source tools and network tools. Preserve the exact response, DNS answer, certificate, or probe record needed for review, subject to retention and redaction settings. Link to 019 exchanges instead of copying bodies into ledger strings. Evidence IDs must resolve after the session; an ephemeral call ID alone is insufficient.

Keep discovery, hypotheses, candidate findings, and human verdicts distinct. Priority for investigation is separate from vulnerability severity. A computed CVSS score depends on the supplied vector; it does not prove the underlying vulnerability.

### 3. Typed collection and explicit network paths

Proposed tool names, not existing commands:

- `discover_hosts`: operator-enabled passive sources, bounded output, source-by-source outcomes.
- `dns_lookup`: typed names and record types, resolver identity, TTLs and response status.
- `probe_ports`: explicit host/port set with connection and time budgets.
- `inspect_tls`: observed handshake/certificate data; deeper checks delegated to a separately provisioned engine.
- `fingerprint_http`: analyze captured response evidence using a versioned corpus.
- `list_assets` / `get_observation`: bounded retrieval over collected state.

Reuse 019's proposed `http_send`, `http_get`, and `http_history`. Auth-page exploration, takeover investigation, and origin correlation belong mainly in skills over these primitives. Batch ordinary collection inside bounded workers; the model should spend turns deciding what to investigate, not scheduling every DNS packet.

The current `ScanRequest.target` is a `PathBuf`, target validation requires filesystem presence, and the only `ReportKind` is SARIF. Share the subprocess machinery, but give network collection a typed request and observation result. Do not convert every DNS record or open port into a SARIF finding to fit the current adapter.

019 limits ordinary tool children to the HTTP proxy. Direct DNS, port probing, and TLS inspection cannot simply run in that scope. Provide explicitly authorized collector workers with narrow destination sets, separately from HTTP clients and passive-source API egress. A TLS assessment must observe the target's TLS session, not the interception CA's certificate.

The distinction between discovery and authorization applies to redirects, CNAMEs, mail providers, identity providers, and candidate origin addresses. Allowing a passive API as a data source does not make it a testing target. Enforce request/host/concurrency budgets in code; explain any scope refusal in the result.

Before promising comprehensive network confinement, verify the actual protocol path in VM tests. The current loader attaches `socket_connect`, `file_open`, and `bprm_check_security`; the inspected code does not establish coverage for unconnected UDP sends. Treat that as an enforcement gap to resolve or a protocol limitation to state explicitly, not a guarantee inherited from an HTTP design.

### 4. Skills and orchestration

Begin with one trusted web-recon skill: enumerate permitted observations, build an asset inventory, identify auth/API surfaces, prioritize hypotheses, verify one, and report evidence plus coverage gaps.

Use Bee's existing model/provider instead of ARTEX's embedded analyst. Later, 018/022 can split concrete tasks among recon, web-testing, source-review, and validation roles. Keep ordinary collection deterministic; add agents only where independent reasoning or context separation helps.

An example of useful follow-up: discover an API host, capture a reset flow, identify a testable hypothesis from the exchanges, compare a controlled pair of requests within scope, and record the observed result. The report links to evidence and states untested assumptions. A generic list of possible attack classes is not completion.

## Delivery recommendation

1. **Make the common evidence path usable.** Implement the relevant 020 outcome/evidence slice and 019's tool-output framing, error propagation, call attribution, and controlled environment prerequisites. `rig_model.rs` currently discards `is_error` when converting tool messages. Untrusted-page framing is defense in depth; policy and tool boundaries still carry authority.
2. **Ship one live web-recon journey.** Use 019's first request/history/read slice, an asset/observation store, passive parsing/fingerprinting, a trusted skill, and network-aware finding locations. One declared host is enough initially. Produce Markdown/JSON with evidence and honest coverage. No requirement for full MITM, fuzzing, PDF, or delegation.
3. **Broaden collection.** Add DNS/passive-host discovery, TCP probing, and comprehensive TLS adapters with separate worker scopes and protocol-specific checks. Evaluate each against known fixtures and pinned source/tool versions.
4. **Deepen investigation.** Add 019 replay/fuzz capabilities and 018/022 delegation when the single-agent path identifies a real need. Pull evidence links earlier than 019's current M3 so the first useful report is reviewable.

For an earlier comparison, an importer can let Bee investigate saved ARTEX output offline. Mark it as externally supplied observations with incomplete coverage and preserve its provenance. A complete snapshot needs changes to ARTEX's export because its existing JSON omits DNS/TLS/origin data.

A temporary live CLI adapter is possible because the fork already has [`cli.py`](https://github.com/jlgore/ARTEX/blob/0ca194271cc31953992b37921ca48c2387e5c399/cli.py). It needs a scan-only mode (the pipeline always runs AI/rule-based analysis), a complete raw export, typed module/budget inputs, and accurate per-module failures. Its mixed HTTP/DNS/TLS traffic also needs deliberate execution scopes. That adapter is a comparison tool; the proposed product experience remains Bee's investigation loop.

## First milestone acceptance criteria

- An end-to-end fixture session collects observations, selects a follow-up, and writes a finding with resolvable evidence; a clean fixture produces no invented finding.
- Missing tools, failed passive sources, denied redirects, and timeouts appear as explicit coverage gaps. None reads as a clean scan.
- A malformed response or prompt injection cannot authorize another host, change the tool set, or write a human verdict.
- Repeated collection merges observations and sightings without overwriting evidence or human adjudication.
- Reports distinguish observations, hypotheses, findings, verdicts, and untested areas; inventory size and open-port counts do not become automatic vulnerability scores.
- Host-mode checks exercise workflow behavior; separate VM checks verify each claimed enforced network path, cancellation, and child cleanup.

The first product choice is web discovery followed by evidence-backed investigation. Comprehensive infrastructure auditing can then reuse the same records and execution seams without delaying that journey.
