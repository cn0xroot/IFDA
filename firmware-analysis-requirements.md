# Requirements Document: Automated IoT Firmware Binary Analysis System

**Document version:** 1.0
**Date:** 2026-06-10
**Status:** Draft

## 1. Introduction

### 1.1 Purpose
This document specifies the functional and non-functional requirements for an automated analysis system targeting IoT firmware binaries. The system performs vulnerability discovery and binary reverse engineering directly on firmware images and the executables they contain, with the explicit goal of operating without requiring manual unpacking by the analyst.

### 1.2 Scope
The system ingests firmware images (or extracted binaries), automatically identifies and unpacks their contents, and produces structured analysis covering binary structure, attack surface, and candidate vulnerabilities. It is intended for use by security researchers, product security teams, and vendors performing defensive assessment of their own or authorized third-party devices.

### 1.3 Intended use and authorization
This is a defensive and research tool. Operators are responsible for ensuring they have authorization to analyze any firmware they submit. The system should support an audit trail that records who analyzed what and when.

### 1.4 Definitions
- **Firmware image** — a vendor-distributed binary blob, often containing a bootloader, kernel, one or more filesystems, and configuration data.
- **"Without unpacking"** — the analyst is not required to manually extract the image; the system performs identification, carving, and extraction automatically. (Internally the system still extracts contents to analyze them.)
- **Attack surface** — network listeners, IPC endpoints, exposed services, parsers handling untrusted input.

## 2. System Overview

The system is structured as a pipeline:

1. **Ingestion** — accept a firmware image or binary, normalize, record metadata.
2. **Identification & extraction** — recognize container/filesystem formats and automatically extract contents.
3. **Inventory & classification** — enumerate executables, libraries, scripts, configs, and certificates/keys.
4. **Static analysis** — disassembly, decompilation, control/data-flow reconstruction.
5. **Vulnerability discovery** — pattern matching, known-CVE correlation, taint analysis, and optional dynamic/emulated execution.
6. **Reporting** — structured, prioritized findings with evidence and reproduction context.

## 3. Functional Requirements

### 3.1 Ingestion (FR-ING)
- **FR-ING-1** Accept common firmware delivery formats: raw `.bin`, vendor update packages, `.img`, and archive containers (zip, tar, cpio, etc.).
- **FR-ING-2** Compute and store cryptographic hashes (SHA-256) of the input and every extracted artifact for provenance and deduplication.
- **FR-ING-3** Detect and record the input's high-level type (e.g., full image vs. single ELF) before extraction.
- **FR-ING-4** Support batch submission and queueing for large-scale corpus analysis.

### 3.2 Automated identification & extraction (FR-EXT)
- **FR-EXT-1** Automatically identify embedded filesystems (SquashFS, JFFS2, UBIFS, CramFS, ext2/3/4, romfs) and container/compression formats (gzip, LZMA, XZ, LZ4, zlib).
- **FR-EXT-2** Carve and extract nested contents recursively without operator intervention, with a configurable recursion depth limit to prevent runaway extraction.
- **FR-EXT-3** Detect bootloader headers and common vendor packaging (e.g., U-Boot, TRX, and similar header formats) and parse their metadata.
- **FR-EXT-4** Detect encrypted or obfuscated regions and flag them rather than failing silently; report entropy analysis to distinguish compression from encryption.
- **FR-EXT-5** Preserve the extraction tree (offsets, parent/child relationships) so any artifact can be traced back to its location in the original image.

### 3.3 Inventory & classification (FR-INV)
- **FR-INV-1** Enumerate all executables and shared libraries, recording architecture (ARM, MIPS, x86, RISC-V, etc.), endianness, bitness, and ABI.
- **FR-INV-2** Identify the build toolchain, libc variant (uClibc, musl, glibc), and compiler version where derivable.
- **FR-INV-3** Detect interpreted scripts (shell, Lua, Python), init/startup scripts, and service definitions.
- **FR-INV-4** Locate embedded secrets and credential material: private keys, certificates, hardcoded passwords/hashes, API tokens. Report with confidence levels.
- **FR-INV-5** Extract version strings and software bill-of-materials (SBOM) for third-party components.

### 3.4 Binary reverse engineering (FR-RE)
- **FR-RE-1** Disassemble executables for all supported architectures.
- **FR-RE-2** Produce decompiled pseudocode for analyst review.
- **FR-RE-3** Reconstruct control-flow graphs and call graphs; identify function boundaries.
- **FR-RE-4** Recognize standard library functions and common statically-linked routines (signature-based, e.g., FLIRT-style) to reduce analyst noise.
- **FR-RE-5** Detect enabled exploit mitigations per binary: NX, stack canaries, RELRO, PIE/ASLR-compatibility, fortified source.
- **FR-RE-6** Provide cross-references for strings, imports, and function calls to support manual pivoting.
- **FR-RE-7** Expose results through both an interactive interface and a scriptable API for automation.

### 3.5 Vulnerability discovery (FR-VUL)
- **FR-VUL-1** **Known-vulnerability correlation:** match identified components and versions against vulnerability databases (CVE/NVD and equivalents) to flag known-vulnerable software.
- **FR-VUL-2** **Dangerous-function detection:** locate uses of unsafe APIs (`strcpy`, `sprintf`, `system`, `popen`, `memcpy` with attacker-influenced lengths, command-execution sinks).
- **FR-VUL-3** **Taint / data-flow analysis:** trace data from untrusted sources (network input, `nvram`/config reads, environment, request parameters) to sensitive sinks (memory copies, command execution, format strings) and report reachable paths.
- **FR-VUL-4** **Vulnerability class coverage:** buffer overflows, command injection, format-string bugs, integer overflows feeding allocations/copies, path traversal, use of weak/hardcoded crypto, and authentication-logic weaknesses.
- **FR-VUL-5** **Cross-binary analysis:** follow calls and data across binary/library boundaries (e.g., a CGI handler calling into a shared library).
- **FR-VUL-6** **Optional emulated/dynamic analysis:** where feasible, emulate the firmware or individual services to validate reachability and reduce false positives. This should be optional and sandboxed.
- **FR-VUL-7** **Findings prioritization:** each finding carries severity, confidence, affected component, evidence (disassembly/decompiled snippet, taint path), and remediation guidance.
- **FR-VUL-8** **Suppression & triage state:** allow analysts to mark findings as confirmed, false positive, or accepted-risk, with persistence across re-scans.

### 3.6 Reporting & output (FR-REP)
- **FR-REP-1** Generate machine-readable output (JSON) and human-readable reports (HTML/PDF/Markdown).
- **FR-REP-2** Produce an SBOM in a standard format (e.g., CycloneDX or SPDX).
- **FR-REP-3** Support diffing between firmware versions to highlight newly introduced or fixed issues.
- **FR-REP-4** Provide an executive summary plus detailed per-finding sections with reproduction evidence.

### 3.7 Integration & extensibility (FR-INT)
- **FR-INT-1** Expose a REST/CLI API for submission and result retrieval to support CI/CD integration.
- **FR-INT-2** Support a plugin architecture so new extractors, analyzers, and detection rules can be added without modifying the core.
- **FR-INT-3** Allow user-defined detection rules (e.g., YARA-style signatures, custom taint source/sink definitions).

## 4. Non-Functional Requirements

### 4.1 Performance & scalability (NFR-PERF)
- **NFR-PERF-1** Analyze a typical consumer-router image (≤64 MB) end-to-end within a configurable time budget (target: under 30 minutes for static analysis on reference hardware).
- **NFR-PERF-2** Scale horizontally to process a corpus of thousands of images via parallel workers.
- **NFR-PERF-3** Cache and deduplicate identical artifacts across images to avoid redundant analysis.

### 4.2 Accuracy (NFR-ACC)
- **NFR-ACC-1** Report confidence scores; favor precision for high-severity findings while surfacing lower-confidence leads separately.
- **NFR-ACC-2** Track false-positive/false-negative metrics against a labeled benchmark corpus.

### 4.3 Security & isolation (NFR-SEC)
- **NFR-SEC-1** Treat all firmware as untrusted; perform extraction and any emulation in sandboxed/isolated environments to prevent malicious images from compromising the host.
- **NFR-SEC-2** Enforce resource limits (CPU, memory, disk, recursion depth) to mitigate decompression bombs and malformed inputs.
- **NFR-SEC-3** Maintain access control and an audit log of submissions and analyses.
- **NFR-SEC-4** Protect extracted secrets and findings at rest and in transit.

### 4.4 Architecture coverage (NFR-ARCH)
- **NFR-ARCH-1** Support, at minimum, ARM (32/64), MIPS (LE/BE), x86/x86-64. Additional architectures (RISC-V, PowerPC, SuperH) are desirable.

### 4.5 Usability & maintainability (NFR-USE)
- **NFR-USE-1** Provide clear logs and surface partial results when individual stages fail (graceful degradation).
- **NFR-USE-2** Keep vulnerability databases and signature sets updatable independent of releases.
- **NFR-USE-3** Document the API, plugin interface, and rule format.

### 4.6 Deployment (NFR-DEP)
- **NFR-DEP-1** Support on-premises and containerized deployment; avoid mandatory transmission of customer firmware to third-party services.

## 5. Constraints & Assumptions
- Encrypted firmware images may be partially or wholly unanalyzable without keys; the system flags rather than defeats encryption.
- Decompilation and taint analysis are heuristic; results require analyst validation.
- Operators are assumed to have legal authorization to analyze submitted firmware.

## 6. Acceptance Criteria
- Given a representative set of unencrypted vendor firmware images, the system extracts contents, inventories binaries with correct architecture detection, and produces prioritized findings without manual unpacking.
- Known-vulnerable components in a benchmark corpus are correctly flagged via CVE correlation.
- A seeded vulnerability (e.g., a command-injection path from a network input) is detected and reported with a traceable source-to-sink path.

## 7. Open Questions
- Required throughput / corpus size at scale?
- Which existing tooling to build on versus implement (extraction, disassembly/decompilation engines)?
- Depth of dynamic/emulation support in the first release?
- Compliance/reporting standards the output must conform to?
