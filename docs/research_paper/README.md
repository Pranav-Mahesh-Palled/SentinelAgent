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
   - Unsupervised `IsolationForest` anomaly detector (100 estimators, contamination calibrated via `default_target_fpr = 0.05`) operating on 5-dimensional feature vectors (`failed_count`, `distinct_users`, `distinct_ips`, `mean_duration_ms`, `off_hours_ratio`) from streaming SSH authentication telemetry.

2. **Grounded AI Investigation Agent:**
   - Constrained two-phase LLM agent (powered by Google Gemini) operating within a strict 5-round investigation ceiling.
   - Read-only database retrieval tools preventing tool-induced state changes during triage.
   - In-memory provenance registry (`AuthorizedProvenanceSet`) tracking queried database primary keys to validate citations and enforce defense-in-depth against prompt injection and hallucinated evidence.

3. **Two-Person Integrity (Human-in-the-Loop Gate):**
   - Cryptographic and relational role separation requiring distinct operator identities to propose and approve containment actions (`proposer_id != approver_id`). Self-approval is rejected at both the API and database levels.

4. **Simulation-Only Response Orchestration:**
   - Safe containment execution confined strictly to a persistent PostgreSQL ledger (`simulated_blocklist_entries`, `simulated_host_isolations`).
   - Absolute isolation guarantee: zero live firewall, routing table, or operating system state modifications.

5. **Post-Simulation Mathematical Verification & Immutability:**
   - Active probe engine (`VerificationService`) querying network simulation state to mathematically verify policy enforcement.
   - Append-only PostgreSQL triggers (`fn_prevent_immutable_modification()`) enforcing tamper resistance across audit logs, approval records, and probe results.

6. **Defense-in-Depth Container Deployment:**
   - Multi-tier production deployment packaged across six unprivileged services (Ingress Proxy, Frontend, Backend API, Response Worker, Migration Runner, PostgreSQL Database) across five isolated Docker networks (3 internal, 2 external bridge).

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
@inproceedings{palled2026sentinelagent,
  author    = {Pranav Mahesh Palled and Pranay Pandurang Patil and Omkar Gurav and Mayur Narayan Dharwadkar},
  title     = {Design and Implementation of {SentinelAgent}: An {AI}-Assisted Framework for Cybersecurity Incident Investigation and Human-Approved Response Simulation},
  booktitle = {Proceedings of AVALANCHE 2026},
  address   = {Belagavi, Karnataka, India},
  organization = {Department of Computer Science and Engineering, KLS Gogte Institute of Technology},
  year      = {2026}
}
```
