# From memory evidence to a defensible DFIR report

Recording guide for the completed `2580_5.vmem` experiment. Target length: approximately 6–7 minutes. The analysis recording and this report-writing recording are separate chapters.

This is a controlled dataset experiment, not a report of an intrusion into a production organisation. The dataset creator confirmed that Task Scheduler and the logging mechanisms were used to launch and record the sample. That provenance is part of the interpretation.

## Verified case facts

These values were read from the running backend and its saved plugin outputs; no analysis was rerun. The accompanying [evidence extract](report-writing-evidence.json) preserves the identifiers, model result, selected findings, region metadata, listing excerpt, and creator confirmation used below.

| Item | Saved result |
| --- | --- |
| Investigation | `4ab70cc1-3819-417d-a34c-9aae27c9bb73` |
| Process analysis | `65f1ffda-d96a-412a-9f13-6404576f899c` |
| Image | `2580_5.vmem`, 4,412,228,315 bytes |
| Image SHA-256 | `777d71d7106e5ded19592c075058da12049bfcd658221e70f0579ad4bbd9cff4` |
| Subject | `malware.exe`, PID 2580, PPID 3768, WOW64 |
| Command line | `"Z:\malware.exe"` |
| Model | Trained VADViT checkpoint; Exploit score `0.804653` (80.47%) |
| Other leading classes | HackTool 9.33%; Virus 2.26%; Rootkit 2.03% |
| Coverage | 80 extracted VADs; 49 grid regions ranked; five regions analysed |
| Triage | 22 requested plugins produced output; aggressive profile; 33 scored objects |
| Processing provenance | Triage records `local artifacts`; some plugin outputs were reused |
| Saved result generated | `2026-10-01T23:36:12.863284+00:00` |

Do not describe 80.47% as the probability that a vulnerability was exploited. It is the model's class score. Do not call 80 extracted VADs 80 attention-ranked regions: the saved ranked grid has 49.

The top five attention scores below are relative display values. They are not probabilities of maliciousness or shares that sum to 100%.

| Rank | Patch (zero-based) | Region | Relative attention | Backing |
| --- | --- | --- | --- | --- |
| 1 | 7, r1/c0 | `0x72ce0000` | 1.000000 | `\Windows\SysWOW64\dhcpcsvc.dll` |
| 2 | 1, r0/c1 | `0x2ea0000` | 0.629570 | Private; no backing file |
| 3 | 11, r1/c4 | `0x72d80000` | 0.429805 | `\Windows\SysWOW64\cryptsp.dll` |
| 4 | 5, r0/c5 | `0x72c20000` | 0.408780 | `\Windows\SysWOW64\ncrypt.dll` |
| 5 | 3, r0/c3 | `0x72bd0000` | 0.389522 | `\Windows\SysWOW64\ncryptsslp.dll` |

## Prepare the recording

Resume the existing investigation at:

```text
http://127.0.0.1:5173/?investigation=4ab70cc1-3819-417d-a34c-9aae27c9bb73
```

Keep the completed PID 2580 deep-dive available. Use its saved results; the guide requires no new analysis. Open this guide beside the application and copy only the text inside each labelled block. Adjust the examination date if recording later.

The controls say **Add**, **In report**, and **Remove from report**. Compact table controls may appear as icons. Select evidence where it is displayed, then annotate it in **Report → Evidence & findings**. On a region, the Add control at the top right of **Attention-ranked VAD regions** applies to the currently selected region.

Pause after each paste until **Saved** appears. Edit narrative before opening **Preview & export** so the preview loads the saved text.

Current export detail: **Scope & objectives** and **Examiner information** save in the editor, but the HTML templates do not print those fields. The hypothesis blocks below include a compact examination context so those details survive in both exported audiences. The executive summary appears in the executive export, not the technical export. Region exhibits and their notes appear in the technical export.

## 1. Open with the question — 0:00–0:45

Show **Report → Acquisition** and the image hash. Then enter **Narrative**. Introduce the exercise with this spoken line:

```text
This is the reporting chapter of a controlled malware-memory experiment. I will show how I turn ranked leads into a report: establish the question, distinguish the collection harness from sample behavior, examine the memory evidence, and state what the evidence cannot yet prove.
```

Paste into **Examiner information**:

```text
Yasin Dehfouli | Independent research and portfolio demonstration | Examination of saved results: 2026-10-01 UTC. The sample was deliberately launched using Task Scheduler for dataset creation. This is a controlled experiment, not a production incident response engagement.
```

Paste into **Scope & objectives**:

```text
Examine the single memory image 2580_5.vmem to assess the executable memory associated with malware.exe (PID 2580), account for the dataset launch and logging harness, and evaluate the trained model's Exploit prediction against observable memory properties.

The examination uses saved Volatility 3 outputs and the completed VADViT analysis. Triage requested 22 plugins; saved processing records include reuse of local plugin artifacts. Five of 49 attention-ranked grid regions were analysed, from 80 extracted VADs. This is a focused review, not exhaustive reverse engineering.

The original acquisition procedure and a complete custody history are not reconstructed here. No disk examination, packet capture, execution trace, or independent vulnerability verification is included. All quoted process times are UTC values reported by the memory artifacts; they are not the date this report was written.
```

Paste this initial version into **Hypothesis**:

```text
Examination context: Yasin Dehfouli, 2026-10-01 UTC. Controlled dataset experiment using 2580_5.vmem. Scope: saved memory artifacts and five analysed VAD regions; no disk, packet-capture, or execution-trace examination. Task Scheduler and the logging scripts were dataset instrumentation, as confirmed by the dataset creator.

Working hypothesis developed during review: malware.exe (PID 2580) contains a private executable allocation consistent with loader or payload code. The trained model's Exploit prediction is a lead to test against that allocation, rather than proof that a vulnerability was exploited.

Supporting evidence would include executable bytes outside a file-backed module, observable module-resolution behavior, and independent agreement with malfind at the same address. A documented legitimate runtime allocation or a different explanation established by code review would weaken the hypothesis. File-backed system DLLs are considered separately. Successful exploitation, injection into another process, credential theft, and command-and-control require further evidence.
```

Say this while moving back to the evidence:

```text
This is a working hypothesis written after the experiment, not a claim that I predicted the result in advance. I will revise it after reviewing the evidence and alternative explanations.
```

## 2. Select the report's evidence — 0:45–1:15

In the **VolMemLyzer scored table**, add these five objects. Use the PID and endpoint, not the risk badge, to identify the row.

- [ ] `malware.exe (2580)`
- [ ] `powershell.exe (3768)` — the sample's recorded parent
- [ ] `powershell.exe (5088)` — the logging sibling
- [ ] Persistence object `LOG`
- [ ] `TCPv4 192.168.124.219:49691 → 172.172.255.217:443`

In the completed **VADViT deep-dive → Attention-ranked VAD regions**, select each of these addresses and press **Add**:

- [ ] `0x72ce0000`
- [ ] `0x2ea0000`
- [ ] `0x72d80000`
- [ ] `0x72c20000`
- [ ] `0x72bd0000`

This selection is five scored objects and five region exhibits. The generic `(task)` row has ambiguous identity and duplicate contributions; leave it out of this focused report. SearchHost and other unselected leads remain in the investigation record. Their omission does not establish that they are benign.

Say:

```text
I am selecting the sample, its launch context, the five regions the model attended to most, and a network lead whose attribution needs checking. The report discloses that this is a selection from the broader triage record.
```

## 3. Account for the harness — 1:15–2:10

Go to **Report → Evidence & findings**. For the two PowerShell findings and LOG, choose **Disposition: Collection artifact** and **Confidence: High confidence**. The confidence here concerns their attribution to the harness, supported by the creator's confirmation and matching command lines; it does not validate every engine inference.

Paste beside **powershell.exe (3768)**:

```text
Dataset launch context. PID 3768 ran C:\Workspace\log_pid.ps1 and is the recorded parent of malware.exe (PID 2580). Its parent, svchost.exe (PID 1232), has the command line ending in -s Schedule. The dataset creator confirms that scheduler and logging mechanisms were used to launch and record the sample. I therefore attribute this finding to the experiment harness rather than attacker persistence.

The process was created at 2024-12-27T07:52:23Z; the sample at 07:55:04Z. These pslist values describe the recorded lineage and timing. They do not establish a malicious initial-access chain. The engine's RWX-memory and enabled SeDebugPrivilege signals do not themselves establish LSASS access or credential theft.
```

Paste beside **powershell.exe (5088)**:

```text
Dataset logging process. PID 5088 ran C:\Workspace\export_logs.ps1 and shares the scheduler-service parent PID 1232 with PID 3768. Its creation time is 2024-12-27T07:52:23Z. The dataset creator confirms that these mechanisms belong to the collection harness. This process is a sibling of the sample's parent, not the recorded parent of malware.exe.

Retained as a collection artifact so the report explains why a Critical engine-ranked lead is outside the sample-behavior assessment. RWX memory and enabled SeDebugPrivilege remain observations; the derived credential-access label is not direct evidence of credential dumping.
```

Paste beside **LOG**:

```text
Dataset collection task. The scheduled_tasks output records an enabled logon task named LOG whose action is PowerShell with arguments C:\Workspace\export_logs.ps1. This matches the command line of PID 5088. The dataset creator confirms that scheduler and logging mechanisms were used for dataset creation, so this task is classified as a collection artifact rather than adversary persistence.

The task's presence is retained in the record. I do not use its stored last-run fields to reconstruct the sample execution time: those fields predate the reported task creation time. The process creation times and parent PIDs provide the relevant recorded launch context.
```

Say as the findings move to **Collection artifacts**:

```text
The artifacts are real, but the context changes their meaning. These scripts belong to my dataset harness. I preserve them in the report instead of presenting scheduled execution and logging as attacker persistence or credential theft.
```

## 4. Connect the model lead to the bytes — 2:10–3:35

Briefly show the **Classification** panel: Exploit, approximately 80%. Show the top-five attention ranking. Then select **rank 2, 0x2ea0000**.

Show **Structure** or the right-hand inspector: 8,192 bytes, private, no backing file, `PAGE_EXECUTE_READWRITE`. Open **Disassembly** and filter using:

```text
0x2ea0b79
```

The saved x86 listing at this address contains `mov eax, dword ptr fs:[0x30]`; immediately following it is a read at `[eax + 0xc]`. Clear the filter when finished. Show **Strings** to locate the embedded HTTP URL. No request to the URL is needed.

Say:

```text
The second-ranked region is the stronger forensic lead: it is private executable memory with no backing file, and malfind independently flagged the same allocation. The x86 listing contains a PEB access followed by a loader-related pointer read. That supports a module-resolution interpretation. It does not identify a vulnerability or prove cross-process injection.
```

Back in **Report → Evidence & findings**, set **malware.exe (2580)** to **Disposition: Undetermined**, **Confidence: Medium confidence**. This assesses the loader/payload interpretation; the sample was deliberately launched, so do not use Attacker activity to imply a production intrusion.

Paste beside **malware.exe (2580)**:

```text
Subject of the controlled experiment. PID 2580 is a WOW64 process with command line "Z:\malware.exe", created at 2024-12-27T07:55:04Z. PPID 3768 ties its recorded launch to the confirmed dataset harness.

The principal behavioral lead is the private 8,192-byte PAGE_EXECUTE_READWRITE allocation at 0x2ea0000, also reported by malfind. It contains x86 instructions and a PEB-access sequence. This supports further examination as loader or payload code; the filename and Critical score alone are not the basis for that assessment.

The trained VADViT model predicts Exploit with class score 0.804653 (80.47%). This is an auxiliary classification result, not a calibrated probability of compromise or evidence of a specific exploited vulnerability. The engine's credential-access correlation combines RWX memory and enabled SeDebugPrivilege; no direct LSASS-access evidence has been established in this review. The model and malfind also examine the same underlying image, so agreement is corroboration across methods, not independent ground truth.
```

Paste beside **region 0x2ea0000**:

```text
Principal memory exhibit. Attention rank 2, patch 1; relative attention 0.629570. Address range 0x2ea0000–0x2ea1fff, 8,192 bytes, private PAGE_EXECUTE_READWRITE memory with no backing file. malfind reports the same base address. Extracted-region SHA-256: a4428fb76a495592f6698f14fd826f15e2c9b34c084d13d6286c6d0ce09255eb.

The saved x86 listing at 0x2ea0b79 reads fs:[0x30], followed at 0x2ea0b7f by a read at [eax + 0xc]. This is consistent with PEB/loader access and supports examination for runtime module resolution. Automated decoder-loop hits require manual validation: the branch at 0x2ea0035 is embedded in a traversal-like sequence, so a backward branch alone does not establish decryption.

An ASCII HTTP URL is present at region-relative offset 0x170b (virtual address 0x2ea170b): hxxp://hi.baidu[.]com/aegifjftrggluze/item/be185dc989cae4f4984aa0df. Its presence is a static observation; no connection to it, C2 exchange, or exfiltration is established. The region's allocation, bytes, and strings support the loader/payload hypothesis, but do not identify the allocating actor, prove execution of every instruction, or demonstrate a successful exploit.
```

## 5. Annotate all five, including alternative explanations — 3:35–4:40

Paste the following beside the other four **Memory regions**. Region cards have a note field but no disposition/confidence selectors. Their order in the exported exhibits follows attention, even though the demo examines rank 2 first.

**Rank 1 — 0x72ce0000:**

```text
Highest model-attention region: patch 7, relative attention 1.000000; 94,208 bytes backed by \Windows\SysWOW64\dhcpcsvc.dll with PAGE_EXECUTE_WRITECOPY protection. The parsed PE identifies i386, while the saved disassembly uses x86-64. I therefore do not rely on its decoded instruction semantics, control-flow counts, or decoder-loop classification until the region is decoded in the correct architecture.

This is a file-backed image mapping, unlike the private allocation at 0x2ea0000. Copy-on-write executable protection and high attention do not establish a malicious modification. The path identifies the reported backing file, not a verified publisher signature. Compare mapped executable pages against the matching trusted on-disk DLL before claiming tampering. Attention rank 1 is a prioritization result, not the strongest evidence of malicious behavior.
```

**Rank 3 — 0x72d80000:**

```text
Attention rank 3, patch 11, relative attention 0.429805. This 86,016-byte file-backed mapping is associated with \Windows\SysWOW64\cryptsp.dll and PAGE_EXECUTE_WRITECOPY protection. The only reported pattern is the writable/executable-region heuristic; that property alone does not establish injection.

The parsed PE identifies i386 but the saved disassembly uses x86-64. Structure analysis covered 65,536 bytes of the allocation. I retain the mapping as model context, with instruction-level interpretation deferred pending correct decoding and comparison against the corresponding trusted DLL. No malicious modification is established by this exhibit.
```

**Rank 4 — 0x72c20000:**

```text
Attention rank 4, patch 5, relative attention 0.408780. This 155,648-byte mapping is backed by \Windows\SysWOW64\ncrypt.dll and uses PAGE_EXECUTE_WRITECOPY protection. The parsed PE identifies i386, but the saved disassembly uses x86-64; decoded loop and indirect-call interpretations are consequently provisional.

Structure analysis covered 65,536 bytes, and the instruction listing is capped. PEB-access byte signatures and system-library names are not independently diagnostic of malware. Establish the correct architecture and compare relevant executable pages with the matching trusted DLL before attributing this mapping to malicious code or tampering.
```

**Rank 5 — 0x72bd0000:**

```text
Attention rank 5, patch 3, relative attention 0.389522. This 131,072-byte mapping reports backing \Windows\SysWOW64\ncryptsslp.dll and PAGE_EXECUTE_WRITECOPY protection. No MZ signature was found at the extracted region start; this does not establish that an attacker erased the header. Missing or unavailable header bytes remain an alternative explanation to investigate.

The structure analysis covered 65,536 bytes and the saved listing uses x86-64. The process is WOW64 and the reported backing is a SysWOW64 DLL, so architecture and image layout need validation before instruction-level claims. Cryptography-provider registry strings are compatible with the reported module role; they do not show registry writes, persistence, or malicious cryptographic use.
```

Say while showing the first and second ranks:

```text
Attention tells me where to look. My report records what I found there. Four of the five regions are file-backed system-library mappings, and several listings need architecture correction. I keep those qualifications next to the evidence instead of treating every highlighted region as malicious.
```

## 6. Close the network attribution gap — 4:40–5:00

For **TCPv4 192.168.124.219:49691 → 172.172.255.217:443**, choose **Disposition: Undetermined**, **Confidence: Insufficient evidence**. Paste:

```text
Unattributed network lead. netscan reports an ESTABLISHED TCPv4 connection from 192.168.124.219:49691 to 172.172.255.217:443 with no owning PID. This review cannot associate it with malware.exe or the URL embedded at 0x2ea170b. Neither the public address nor port 443 establishes command-and-control. Retain it as an unresolved correlation question, not as confirmed sample communication or exfiltration.
```

Say:

```text
An embedded URL and an unattributed connection are two observations. Without a link between them, I cannot turn them into a C2 story.
```

## 7. Write the assessment and next actions — 5:00–5:55

Return to **Narrative**. Replace the initial **Hypothesis** with this final version. It preserves the hypothesis and records its status after review:

```text
Examination context: Yasin Dehfouli, 2026-10-01 UTC. Controlled dataset experiment using 2580_5.vmem. Scope: saved memory artifacts and five analysed VAD regions; no disk, packet-capture, or execution-trace examination. The image hash identifies the examined input; this report does not reconstruct a complete original acquisition or custody history. Task Scheduler and the logging scripts were dataset instrumentation, as confirmed by the dataset creator.

Working hypothesis developed during review: malware.exe (PID 2580) contains private executable memory consistent with loader or payload code. The principal exhibit is 0x2ea0000: an 8 KiB private RWX allocation with no backing file, also flagged by malfind, containing x86 PEB/loader-access instructions. These observations support the hypothesis at moderate confidence. A legitimate runtime explanation remains testable through code review and allocation/execution tracing.

The trained model predicts Exploit with class score 80.47%; this supports prioritization but does not establish successful exploitation or a specific vulnerability. The highest-attention mapping is a file-backed DLL rather than the principal private-memory exhibit. Several DLL listings use x86-64 despite parsed i386 metadata, limiting instruction-level interpretation. The initial decoder-loop label also requires manual validation rather than acceptance as observed decryption.

The scheduler and logging findings are retained as collection artifacts. Successful exploitation, cross-process injection, credential theft, C2, and exfiltration are not established. RWX memory plus enabled SeDebugPrivilege does not prove LSASS access; the unattributed network connection cannot be linked to the embedded URL. ATT&CK grouping describes heuristic alignment, not a demonstrated chronological attack chain.
```

Paste into **Executive summary**:

```text
This controlled experiment examined a memory image collected after a sample was deliberately launched for dataset creation. The most significant finding is an 8 KiB executable allocation outside a file-backed program module. Its contents support further investigation as loader or payload code.

The classifier ranked the sample in its Exploit category, but the examination did not establish that a vulnerability was successfully exploited. Scheduled execution and logging were part of the research harness and are accounted for separately. The available evidence also does not establish credential theft, external command-and-control, or data loss.

The next step is targeted code validation and correlation with execution and network records. Some system-library disassembly must first be corrected to the appropriate architecture. These findings characterize a research sample and should not be read as a claim of compromise in a production environment.
```

Paste into **Recommendations**:

```text
1. Preserve the examined image, its recorded SHA-256, the saved plugin outputs, region extracts, and model/label versions alongside this report. Retain the dataset harness configuration and logging scripts so launch context remains reproducible.

2. Decode the i386/SysWOW64 mappings in the appropriate architecture. Validate the reported loader and decoder patterns against actual instructions and executable ranges; treat signatures and capped listings as leads until checked.

3. Reverse engineer the private allocation at 0x2ea0000 and trace its allocation and execution in an isolated lab. Determine whether it is self-unpacked sample code, externally introduced code, or a documented runtime allocation. Identify any specific exploit mechanism before naming a vulnerability.

4. Compare the file-backed DLL mappings against trusted copies matching the host build, accounting for relocations, imports, and normal copy-on-write behavior. Establish actual page modifications before alleging DLL tampering.

5. Correlate the embedded URL with lab packet capture, DNS/proxy records, and process-attributed telemetry. Establish direct LSASS access or memory-dumping evidence before making a credential-theft claim.

6. Keep scheduler and logging artifacts labelled as collection instrumentation in dataset documentation. Evaluate classification performance on held-out samples; this single experiment establishes neither general model accuracy nor coverage of all process memory.
```

## 8. Preview and finish — 5:55–6:40

Wait for **Saved**, then select **Preview & export → Technical**. Show:

1. Examination context and final hypothesis.
2. The input hash and method.
3. Collection artifacts, separated from sample findings.
4. All five evidence exhibits, including the analyst note beneath `0x2ea0000`.
5. Recommendations and limitations.

Technical export rounds the model result to approximately 80%; the precise 80.47% remains in the analyst note. The automatic heading **Attack narrative** is an ATT&CK grouping, not a timeline. Explain that distinction if it is visible. The table headed **Chain of custody** records input identity; it is not a complete transfer/acquisition log.

Switch to **Executive** and show the plain-language summary. It intentionally has no detailed region exhibits and filters ordinary findings to Critical/High; the low-risk LOG task may therefore appear only in the technical report even after its collection-artifact disposition is saved. The summary and hypothesis still explain the harness context.

Choose **Open for printing → Print → Save as PDF**. Turn off browser headers/footers and turn on background graphics. Use a filename such as:

```text
MemTriage_2580-5_controlled-memory-examination_technical.pdf
```

Use the technical report as the evidence-rich portfolio artifact; keep the executive version as its companion. **Export raw JSON** exports the consolidated analysis results, not all the analyst annotations. Preserve the HTML/PDF report as the annotated deliverable.

Closing spoken line:

```text
The outcome is a traceable assessment: the principal memory evidence, the confirmed collection context, the model's prediction, and the remaining uncertainty are all visible. Every recommendation addresses a specific gap in the evidence.
```

## Before publishing

- [ ] The subject is presented as a controlled dataset experiment throughout.
- [ ] Five scored objects and all five memory exhibits are selected; no old pins remain from another draft.
- [ ] Both PowerShell processes and LOG are attributed to the confirmed harness.
- [ ] The private allocation has its note, address, protection, and hash in the technical preview.
- [ ] No statement claims successful exploitation, LSASS dumping, C2, or exfiltration from the current evidence.
- [ ] Relative attention is not described as probability, and model confidence is not described as analyst certainty.
- [ ] Disassembly architecture and partial-coverage qualifications remain beside the relevant exhibits.
- [ ] The examination date matches the recording; artifact times remain identified as UTC.
- [ ] The saved PDF contains the annotations and readable page breaks; only then attach it to the portfolio.

Suggested public title:

```text
MemTriage: From memory evidence to a defensible DFIR report
```

Suggested LinkedIn/GitHub caption, to use after recording:

```text
In this follow-up to my MemTriage analysis demo, I turn a controlled malware-memory experiment into an annotated DFIR report.

I document the question and working hypothesis, separate my dataset launch/logging harness from sample behavior, examine VADViT's Exploit prediction and five attention-ranked regions, and connect each assessment to the underlying evidence. The strongest lead is an 8 KiB private executable allocation—not automatically the region with the highest attention score.

The report records alternative explanations, a disassembly architecture limitation, and the evidence still needed before claiming successful exploitation, credential theft, or C2. The technical report and executive summary serve different readers while keeping the same assessment boundaries.
```

The proposed order is an editorial choice for this demonstration, not a mandatory forensic-report format. The treatment of alternative explanations and audience-specific reporting follows the principles in [NIST SP 800-86, sections 3.3–3.4](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-86.pdf). The case-specific statements above derive from the saved experiment and the dataset creator's confirmation.
