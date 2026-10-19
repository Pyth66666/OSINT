# DF-OSINT Investigation Report — Operation Shadow Trace

**Participant:** _<your full name / Participant ID>_
**Assessment:** Operation Shadow Trace — Digital Forensics OSINT (training simulation)
**Case reference (evidence):** OST/DF/2025/047 · Exhibit group BL-047
**Report status:** Fictional training simulation — all subjects, shipments and findings are invented.

---

## A. Evidence inventory

Work was performed on copies only; the originals were never modified.

| # | Original filename | Size | SHA-256 (original = copy) |
|---|---|---|---|
| 1 | `Evidence_01_Confidential_Logistics_Report.pdf.pdf` | 3,031 B | `95851D30DD9F5F54684FD93776E5593F7E80F5752CC1812CA2A0D290EE16DAD4` |
| 2 | `Evidence_02_Drug_Seizure_Examination_Report.pdf` | 31,718 B | `C8119A0FCEA5EAF2EE8251F9F8CEF07F76779DC27175219BC63592299C26123F` |

Hash command used (repeatable):
```
Get-FileHash -Algorithm SHA256 "Evidence_01_Confidential_Logistics_Report.pdf.pdf"
Get-FileHash -Algorithm SHA256 "Evidence_02_Drug_Seizure_Examination_Report.pdf"
```
Both copies were re-hashed after copying and matched the originals, confirming the working copies are intact.

---

## B. PDF findings (Evidence 01)

**Recovered identifier:** `meridiantrace47` (recovered from **four independent layers** — strong corroboration).

| Layer | Location | Extraction | Value |
|---|---|---|---|
| 1. Metadata | `/ReviewerRef` in the Info dictionary | base64 decode of `bWVyaWRpYW50cmFjZTQ3` | `meridiantrace47` |
| 2. Metadata | `/Keywords` | plain text | `Meridian Logistics; BL-047; NX-219; CR-081` (batch / case refs) |
| 3. Embedded attachment | `reviewer_note.txt` (object 10, `/Type /EmbeddedFile`) | base64 decode | `meridiantrace47` |
| 4. Hidden text layer | last `Tj` on page 1, rendered with `3 Tr` (invisible text mode) at 2 pt | text extraction | `meridiantrace47` |

**Exact commands / methods used:**
```
# Metadata (all fields, incl. non-standard ReviewerRef)
exiftool "Evidence_01_Confidential_Logistics_Report.pdf.pdf"
# Visible + hidden text layer
pdftotext "Evidence_01_Confidential_Logistics_Report.pdf.pdf" -        # alias: single hyphen = stdout
# Embedded attachments
pdfdetach -list "Evidence_01_Confidential_Logistics_Report.pdf.pdf"
pdfdetach -saveall "Evidence_01_Confidential_Logistics_Report.pdf.pdf"
# Object-level inspection / hidden content
qpdf --qdf --object-streams=disable in.pdf out.pdf ; pdf-parser -a in.pdf
# Decode the two base64 values
python -c "import base64;print(base64.b64decode('bWVyaWRpYW50cmFjZTQ3').decode())"
```
**Proof / evidence behind the finding:**
- The identifier appears **four times** by four different mechanisms, so it is not a coincidence of one field.
- The hidden `3 Tr` text run is the key "concealed" artefact: `3 Tr` = invisible render mode, so the string never shows on the page yet survives in the content stream (`BT 1 0 0 1 55 45 Tm 3 Tr ... (meridiantrace47) Tj ET`).
- The plain-text page content of Evidence 01 (meridian logistics memo, doc ref `MLS/OPS/2025/09-017`) is consistent with the metadata — it is a genuine logistics "internal operations review" referencing `BL-047`, `NX-219`, `CR-081`.

**Documents also carrying supporting refs:** batch `BL-047`, case refs `NX-219` and `CR-081` (all appear later in the shipment dataset).

---

## C. Automated OSINT (Sherlock / Maigret) — verify by hand

**Commands run (equivalent tools acceptable):**
```
sherlock meridiantrace47
maigret meridiantrace47 --top-sites 100
# equivalent:
user-scanner -u "meridiantrace47"
```
**Tool result (automated lead):** the username `meridiantrace47` resolves to a **GitHub** account.
**Hand verification (required — automated hits are leads only):**

| Check | Result |
|---|---|
| `https://api.github.com/users/meridiantrace47` | **HTTP 200** — account exists |
| Profile URL | `https://github.com/meridiantrace47` |
| GitHub user id | `342993032` |
| Repos | 1 public — `https://github.com/meridiantrace47/secret` |
| Bio / company / location | empty (deliberately sparse) |

**Verified profile URL:** `https://github.com/meridiantrace47`

**False positives noted (verified and excluded by hand):**
- `https://github.com/Meridian47` → a **different, unrelated** account: real name **Stefan Mayr**, created 2019-11-20, single repo `pose-bootcamp-code-quality-workshop`. **Not** the same person — name similarity only.
- `meridian_trace47` → **does not exist** as a GitHub account (HTTP 404); it is only a stated alias inside the README.

**Additional identifiers surfaced in the repo's README (secondary findings):**
- Developer alias **`Daniel M.`**
- GitHub alias **`meridian_trace47`** (current dev environment)
- Previous alias **`meridian47`**
- Contact email **`meridiantrace47@gmail.com`**

---

## D. Shipment correlation (repository CSV vs Evidence 02)

**Repository:** `https://github.com/meridiantrace47/secret`
**Files:** `README.md` and `sample_shipments.csv` (30 shipment rows).

**Shipment IDs found in the CSV.** Two groups carry aliases tied to this investigation:

| Group | Batch ref | Rows | Status | Alias column |
|---|---|---|---|---|
| Seized consignments | **BL-047** | SHP-2025-007, -014, -022, -029 | `Seized` | `meridiantrace47` |
| Held consignments | **NX-219** | SHP-2025-004, -009, -011, -016, -019, -024, -026, -028 (8 rows) | `Held for review` | `meridian47` |
| Routine (no alias) | various `BT-###` | 18 rows | `Delivered` | (none) |

**Confirmed matches — CSV vs Evidence 02 (all four BL-047 rows):**

| Shipment | Date | Txn ref | Declared goods | Simulated finding | Mass | Result |
|---|---|---|---|---|---|---|
| SHP-2025-007 (EX-01) | 2025-07-16 | TXN-1047 | Office stationery | Methamphetamine | 6.4 kg | ✅ all fields match |
| SHP-2025-014 (EX-02) | 2025-08-13 | TXN-1054 | Electronic accessories | Heroin | 11.3 kg | ✅ all fields match |
| SHP-2025-022 (EX-03) | 2025-09-11 | TXN-1062 | Machine spare parts | Cocaine | 2.9 kg | ✅ all fields match |
| SHP-2025-029 (EX-04) | 2025-09-18 | TXN-1069 | Printed manuals | MDMA | 7.8 kg | ✅ all fields match |

Also consistent: shared batch **BL-047**, shared sender **Meridian Trading** / receiver **Northstar Distribution**, and the alias **`meridiantrace47`** in the CSV ties to the recovered identifier.

**Discrepancies recorded:**
1. **Declared vs actual weight gap (all four BL-047 rows).** The `declared_weight_kg` exceeds `quantity_kg` by exactly **5.0 kg** each time (11.4 vs 6.4; 16.3 vs 11.3; 7.9 vs 2.9; 12.8 vs 7.8) — a uniform, deliberate pattern, not random error.
2. **Declared goods ≠ actual item.** Every BL-047 row declares benign goods (stationery, accessories, spare parts, manuals) but records a controlled substance.
3. **Two alias identities in one dataset.** `meridiantrace47` (BL-047, seized) vs `meridian47` (NX-219, held) — the README confirms `meridian47` is the *previous* alias of the same developer.
4. **NX-219 rows are incomplete:** related fields (weight/consignee) blank, status `Held for review`, flag `Pending` — unresolved, no confirmed contraband.

**CSV vs Evidence 02 structural note:** Evidence 02 says identifiers are "reproduced from the instructor-provided shipment dataset," and every BL-047 cross-check matched — the two sources corroborate each other exactly.

---

## E. Conclusion

**What the evidence supports:**
- A concealed identifier, `meridiantrace47`, was **recovered and corroborated across four independent layers** of Evidence 01 (metadata, embedded file, invisible text, plus consistent page content).
- That identifier resolves to a **real, hand-verified GitHub account** (`https://github.com/meridiantrace47`) whose public repository `secret` contains a shipment dataset in which the four **seized BL-047 consignments are attributed to the alias `meridiantrace47`**.
- The repository CSV and Evidence 02 **match exactly** on all four BL-047 shipments (date, transaction ref, declared goods, finding, mass), and both link to the same batch and sender/receiver.
- The four consignments share a **uniform +5.0 kg declared-vs-actual weight discrepancy** and declare benign goods while recording controlled substances — a consistent pattern across the group.

**What remains uncertain (limitations):**
- **An alias is not identity.** A matching username does not prove that any person prepared, controlled, or knew about these records. Identity attribution and criminal responsibility are explicitly **outside the scope** of Evidence 02.
- `meridian47`, `meridian_trace47`, "Daniel M.", and `meridiantrace47@gmail.com` are **self-declared strings in a README** — not independently verified, and not confirmed to be one real person.
- The `Meridian47` account (Stefan Mayr) is a **verified false positive** and is excluded.
- The entire dataset is a **fictional training simulation** (see "SIMULATION / TRAINING USE ONLY"); no physical items were seized or tested, and the substance findings are case assumptions.
- The GitHub account was created 2026-10-15, consistent with a training artefact rather than real operational history.
- NX-219 records remain unresolved/held — no contraband confirmed.

**Finding, stated plainly:** the evidence supports a **consistent linkage** between the recovered identifier, a verified public account, and four matched shipment records with a repeated declared-vs-actual discrepancy. It does **not** establish who is responsible, and no criminal conclusion is drawn from an alias, a repository, or a shipment record alone.

---

### Submission checklist
- [x] Report has all five headings, A–E
- [x] Both SHA-256 hashes recorded
- [x] Recovered identifier + exact extraction command shown
- [x] Verified profile URL included
- [x] Matches and uncertainties stated separately
- [ ] Filename set to `DF-OSINT_Investigation_Report_<ParticipantID>.pdf` and opened once before sending
- [ ] Emailed to `mohdzamri.osman@utm.my`, subject **"Investigation Report"**, name + Participant ID in the body