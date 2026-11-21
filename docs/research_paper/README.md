# SentinelAgent Research Paper — AVALANCHE 2026

**Paper Title:** Design and Implementation of SentinelAgent: An AI-Assisted Framework for Cybersecurity Incident Investigation and Human-Approved Response Simulation
**Paper Category:** Implementation / Application Research Paper
**Target Venue:** AVALANCHE 2026 Technical Paper Presentation, KLS Gogte Institute of Technology, Belagavi, Karnataka, India
**Status:** Student research manuscript prepared for conference submission (not yet peer-reviewed, accepted, or indexed).

---

## 1. Overview & Context

This directory contains the complete academic manuscript, source files, bibliography, and architectural diagrams for the research paper based on the **SentinelAgent** platform.

SentinelAgent is an autonomous Security Operations Center (SOC) investigation and response simulation platform designed to address alert fatigue, evidence grounding, and operational safety in AI-assisted security workflows. The paper details the architectural design, algorithmic detection pipeline, provenance-validated LLM investigation mechanism, and human-in-the-loop simulation ledger implemented in the SentinelAgent system.

---

## 2. Research & Technical Focus Areas

The paper details six primary engineering and research contributions:

1. **Dual Threat Detection Engine:**
   - Heuristic sliding-window (1-minute window) rule detector for rapid brute-force pattern recognition.
   - Unsupervised `IsolationForest` anomaly detector (100 estimators, contamination calibrated via `default_target_fpr = 0.05`) operating on 6-dimensional behavioral feature vectors (`total_attempts`, `failed_login_count`, `successful_login_count`, `distinct_usernames`, `failure_ratio`, `success_after_failures`) extracted across 1-minute fixed UTC time windows from streaming SSH authentication telemetry.

2. **Grounded AI Investigation Agent:**
   - Constrained two-phase LLM agent (powered by Google Gemini) operating within a strict 5-round investigation ceiling.
   - Read-only database retrieval tools preventing tool-induced state changes during triage.
   - In-memory provenance registry (`AuthorizedProvenanceSet`) tracking queried database primary keys to validate citations and enforce defense-in-depth against prompt injection and hallucinated evidence.

3. **Two-Person Integrity (Human-in-the-Loop Gate):**
   - Role-based separation of duties requiring distinct operator identities to propose and approve containment actions (`proposer_id != approver_id`). Self-approval is validated and rejected at the application service and API dependency layers (`validate_proposer_approver_separation`), while the PostgreSQL database enforces lifecycle state transitions, SHA-256 payload digest binding, deadline constraints, and trigger-enforced audit logging.

4. **Simulation-Only Response Orchestration:**
   - Safe containment execution confined strictly to a persistent PostgreSQL relational simulation ledger (`simulated_blocklist_entries`).
   - Simulation-only response adapter: Containment actions execute via a dedicated simulation adapter (`simulation.block_source_ip`) that commits simulated block records to the relational database without modifying live firewalls, host network stacks, or operating system routing tables.

5. **Post-Simulation Mathematical Verification & Immutability:**
   - Active probe engine (`VerificationService`) querying network simulation state to mathematically verify policy enforcement.
   - Append-only PostgreSQL triggers (`fn_prevent_immutable_modification()`) enforcing tamper resistance across audit logs, approval records, and probe results.

6. **Defense-in-Depth Container Deployment:**
   - Multi-tier production deployment packaged across six unprivileged services (Ingress Proxy, Frontend, Backend API, Response Worker, Migration Runner, PostgreSQL Database) across five isolated Docker networks (three internal bridge networks, one ingress bridge, and an outbound Docker egress bridge providing internet connectivity for the API and worker services to reach external APIs such as Google Gemini; frontend, database, and migration services have no egress bridge attachment).

---

## 3. Paper Deliverables & Source Files

| File | Description | Format |
| :--- | :--- | :--- |
| [`SentinelAgent_AVALANCHE_2026_Paper.pdf`](SentinelAgent_AVALANCHE_2026_Paper.pdf) | Final two-column research paper manuscript (4 pages, IEEE conference format) | PDF |
| [`SentinelAgent_AVALANCHE_2026_Paper.docx`](SentinelAgent_AVALANCHE_2026_Paper.docx) | Fully styled IEEE conference document (editable Word format) | DOCX |
| [`SentinelAgent_AVALANCHE_2026_Paper.tex`](SentinelAgent_AVALANCHE_2026_Paper.tex) | Complete LaTeX source code conforming to `IEEEtran` conference template | TeX |
| [`references.bib`](references.bib) | BibTeX bibliography containing 17 verified academic and standards citations | BibTeX |

---

## 4. Architectural & Workflow Figures

The paper incorporates three high-resolution architectural and process figures, available in both print-ready 300 DPI raster (`.png`) and scalable vector (`.svg`) formats:

1. **Figure 1: SentinelAgent System Architecture**
   - High-level multi-tier container topology, security boundaries, and data flow between ingestion, detection, LLM investigation, human approval, and PostgreSQL simulation persistence.
   - Files: [`figures/fig1_system_architecture.png`](figures/fig1_system_architecture.png) | [`figures/fig1_system_architecture.svg`](figures/fig1_system_architecture.svg)

2. **Figure 2: End-to-End Investigation and Response Simulation Workflow**
   - Sequence diagram illustrating event ingestion, rule and anomaly detection, LLM investigative tool execution loop, provenance registration, Two-Person Integrity approval, and simulation ledger commit.
   - Files: [`figures/fig2_workflow.png`](figures/fig2_workflow.png) | [`figures/fig2_workflow.svg`](figures/fig2_workflow.svg)

3. **Figure 3: Response Action Lifecycle State Machine**
   - Finite state automaton depicting the progression from `PENDING_APPROVAL` through `APPROVED`, `EXECUTING`, `EXECUTED`, `VERIFIED`, or terminal error/cancellation states.
   - Files: [`figures/fig3_lifecycle.png`](figures/fig3_lifecycle.png) | [`figures/fig3_lifecycle.svg`](figures/fig3_lifecycle.svg)

---

## 5. Academic Citation

If referencing this work or platform architecture:

```bibtex
@unpublished{palled2026sentinelagent,
  author = {Pranav Mahesh Palled and Pranay Pandurang Patil and Omkar Gurav and Mayur Narayan Dharwadkar},
  title  = {Design and Implementation of {SentinelAgent}: An {AI}-Assisted Framework for Cybersecurity Incident Investigation and Human-Approved Response Simulation},
  note   = {Student research manuscript prepared for AVALANCHE 2026, Department of Computer Science and Engineering, KLS Gogte Institute of Technology, Belagavi, Karnataka, India},
  year   = {2026}
}
```
