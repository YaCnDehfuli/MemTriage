"""The generated investigation report.

These run against a real seeded investigation (the same captured VolMemLyzer
artifacts test_fixture_seed uses), not canned dicts, so the findings section is
exercised against the actual scoring engine's output shape.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "dumps_2580_5"
STANDIN_IMAGE = FIXTURES / "2580_5.vmem"
STANDIN_SIZE = 4096


@pytest.fixture(autouse=True)
def _offline_and_fast(monkeypatch):
    from memtriage.workers import tasks

    monkeypatch.setattr(tasks.settings, "vol_offline", True)
    monkeypatch.setattr(tasks.settings, "vol_timeout_s", 5)
    monkeypatch.setattr(tasks.settings, "vol_symbol_dirs", [])


@pytest.fixture(autouse=True)
def _standin_image():
    if not STANDIN_IMAGE.is_file():
        STANDIN_IMAGE.write_bytes(b"\x00" * STANDIN_SIZE)


@pytest.fixture()
def triaged(client):
    from memtriage.pipeline.fixture_seed import seed_investigation_from_dumps

    summary = seed_investigation_from_dumps(FIXTURES)
    assert summary["task_result"] == "triaged"
    return summary["investigation_id"]


def _assemble(investigation_id: str, audience: str = "technical"):
    from memtriage.db import SessionLocal
    from memtriage.reporting import assemble

    session = SessionLocal()
    try:
        return assemble(investigation_id, session, audience=audience)
    finally:
        session.close()


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------

def test_assembles_a_populated_document_with_no_analyst_input(triaged):
    doc = _assemble(triaged)

    # The whole point of phase 0: a real document with nothing typed by hand.
    assert doc.findings, "no findings rendered from a dashboard that has scored objects"
    assert doc.overview
    assert doc.custody, "chain of custody must never be empty for a seeded dump"
    assert doc.method["plugin_count"] > 0
    assert doc.sections and doc.sections[0]["number"] == 1


def test_findings_are_written_from_the_engines_own_evidence_strings(triaged):
    doc = _assemble(triaged)
    with_rules = [f for f in doc.findings if f["object"].get("contributions")]
    assert with_rules, "fixture should produce at least one rule-backed object"

    f = with_rules[0]
    # Multi-signal evidence is stored " | "-joined; the prose splits it back out,
    # so assert on the first signal rather than the raw field.
    first_signal = f["object"]["contributions"][0]["evidence"].split(" | ")[0].rstrip(".")
    assert first_signal in f["rationale"], "rationale must quote the rule's evidence"
    assert f["object"]["risk"] in f["headline"]


def test_chain_of_custody_is_complete_and_flags_a_missing_hash(triaged):
    from memtriage.db import SessionLocal
    from memtriage.models import Investigation

    session = SessionLocal()
    try:
        inv = session.get(Investigation, triaged)
        expected = len(inv.dumps)
        inv.dumps[0].sha256 = None
        session.commit()
    finally:
        session.close()

    doc = _assemble(triaged)
    assert len(doc.custody) == expected, "custody is never filtered"
    # A missing hash is stated, not silently dropped — that distinction is the
    # only thing that makes the section worth printing.
    assert doc.custody[0]["sha256_missing"] is True


def test_degraded_extraction_is_surfaced_before_the_findings(triaged):
    doc = _assemble(triaged)
    assert any("degraded" in n.lower() for n in doc.notices)
    ids = [s["id"] for s in doc.sections]
    assert ids.index("notices") < ids.index("narrative")


def test_executive_is_a_strict_subset_of_technical(triaged):
    technical = _assemble(triaged, "technical")
    executive = _assemble(triaged, "executive")

    assert len(executive.findings) <= len(technical.findings)
    assert all(
        f["object"]["risk"] in ("Critical", "High") for f in executive.findings
    )
    # Same facts, fewer of them: an executive finding must exist verbatim in the
    # technical document, never be a separately-worded restatement.
    tech_keys = {f["object"]["key"] for f in technical.findings}
    assert {f["object"]["key"] for f in executive.findings} <= tech_keys

    exec_ids = {s["id"] for s in executive.sections}
    assert "deepdives" not in exec_ids


def test_neither_document_dumps_the_process_census(triaged):
    """The report explains the scored objects; it is not a pslist transcript.

    A full inventory ran to hundreds of rows, none of which the findings refer
    to, and buried the narrative it was printed after. The census size is still
    disclosed on the cover as the process count.
    """
    for audience in ("technical", "executive"):
        doc = _assemble(triaged, audience)
        assert "inventory" not in {s["id"] for s in doc.sections}
        assert doc.case["process_count"] is not None


def test_executive_overview_counts_the_whole_scored_set_not_the_filtered_one(triaged):
    """The opening sentence quotes risk_summary, which is never filtered.

    Counting only the surviving findings made the executive summary contradict
    itself: "scored 7 objects (7 High, 1 Medium)".
    """
    technical = _assemble(triaged, "technical")
    executive = _assemble(triaged, "executive")
    assert executive.overview == technical.overview
    assert len(executive.findings) < len(technical.findings), "fixture must exercise the filter"


def test_unknown_audience_falls_back_to_technical(triaged):
    assert _assemble(triaged, "nonsense").audience == "technical"


def test_missing_investigation_raises_lookup_error():
    with pytest.raises(LookupError):
        _assemble("does-not-exist")


def test_survives_a_missing_triage_artifact(client):
    """A half-finished investigation must render a document, not a 500."""
    from memtriage.db import SessionLocal
    from memtriage.models import Investigation

    session = SessionLocal()
    try:
        inv = Investigation(id="inv-empty", stage="received")
        session.add(inv)
        session.commit()
    finally:
        session.close()

    doc = _assemble("inv-empty")
    assert doc.findings == []
    assert "no scored objects" in doc.overview.lower()
    assert any("no acquisition record" in n.lower() for n in doc.notices)


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def test_renders_both_audiences_to_standalone_html(triaged):
    from memtriage.reporting.render import render

    for audience in ("technical", "executive"):
        html = render(_assemble(triaged, audience))
        assert html.startswith("<!doctype html>")
        assert "<style>" in html, "styles must be embedded, not linked"
        # Standalone: nothing may be fetched from the network or from the app.
        assert "http://" not in html and "https://" not in html
        assert "<link" not in html and "<script" not in html


def test_markup_from_the_memory_image_is_escaped(triaged):
    """A process name is attacker-controlled. It must never become markup."""
    from memtriage.reporting.render import render
    from memtriage.storage import InvestigationPaths

    payload = "<script>alert(1)</script>"
    triage_path = InvestigationPaths(triaged).triage
    triage = json.loads(triage_path.read_text())
    objects = triage["dashboard"]["scored_objects"]
    assert objects, "fixture must have a scored object to poison"
    objects[0]["label"] = payload
    triage_path.write_text(json.dumps(triage))

    html = render(_assemble(triaged))
    assert payload not in html
    assert "&lt;script&gt;" in html


# --------------------------------------------------------------------------
# HTTP surface
# --------------------------------------------------------------------------

def test_preview_endpoint_returns_the_assembled_document(client, triaged):
    r = client.get(f"/api/investigations/{triaged}/report/preview")
    assert r.status_code == 200
    body = r.json()
    assert body["investigation_id"] == triaged
    assert body["audience"] == "technical"
    assert body["findings"]


def test_html_endpoint_sets_its_own_csp_and_allows_sameorigin_framing(client, triaged):
    r = client.get(f"/api/investigations/{triaged}/report.html?audience=executive")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")

    csp = r.headers["content-security-policy"]
    # Without this the global `default-src 'none'` blanks the embedded stylesheet.
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "script-src 'none'" in csp
    assert "frame-ancestors 'self'" in csp
    # The preview iframes this exact response; DENY would break it.
    assert r.headers["x-frame-options"] == "SAMEORIGIN"


def test_other_routes_keep_the_strict_default_headers(client, triaged):
    r = client.get(f"/api/investigations/{triaged}")
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"


def test_report_for_unknown_investigation_is_404(client):
    assert client.get("/api/investigations/nope/report.html").status_code == 404
    assert client.get("/api/investigations/nope/report/preview").status_code == 404


# --------------------------------------------------------------------------
# Attack narrative (the spine)
# --------------------------------------------------------------------------

def test_findings_are_grouped_into_attack_stages_in_attck_order(triaged):
    from memtriage.reporting.stages import TACTIC_ORDER

    doc = _assemble(triaged)
    assert doc.stages, "a scored dashboard must produce at least one stage"

    rank = {t: i for i, t in enumerate(TACTIC_ORDER)}
    ranks = [rank.get(s["tactic"], len(TACTIC_ORDER)) for s in doc.stages]
    assert ranks == sorted(ranks), "stages must run in ATT&CK progression order"

    # Every finding is told exactly once: grouping must not duplicate or drop.
    # Matched on `ref`, not `key` — scored-object keys are not unique.
    grouped = [f["ref"] for s in doc.stages for f in s["findings"]]
    assert sorted(grouped) == sorted(f["ref"] for f in doc.findings)
    assert len(grouped) == len(set(grouped))


def _colliding_doc():
    """A document holding two findings that share a scored key.

    Two scheduled tasks both key as `task:powershell`, because the key comes
    from the interpreter and not the script path. This is built directly rather
    than drawn from the fixture: whether any given image happens to surface two
    such tasks depends on the scoring thresholds, and this is a test about ref
    identity, not about calibration.
    """
    from memtriage.reporting.assembly import ReportDocument, evidence_ref

    def finding(label):
        obj = {"object_type": "persistence", "key": "task:powershell", "label": label,
               "pid": None, "score": 12, "risk": "Medium", "confidence": 0.7,
               "tactics": ["Persistence"], "techniques": ["T1053.005"],
               "contributions": []}
        return {"object": obj, "ref": evidence_ref(obj), "headline": "", "rationale": "",
                "techniques": ""}

    doc = ReportDocument(investigation_id="t", audience="technical", generated_at="2026-09-16T00:00:00Z")
    doc.findings = [finding(r"Upd :: powershell.exe -f C:\a.ps1"),
                    finding(r"Sync :: powershell.exe -f C:\b.ps1")]
    return doc


def test_findings_that_share_a_key_get_distinct_refs():
    doc = _colliding_doc()
    keys = [f["object"]["key"] for f in doc.findings]
    refs = [f["ref"] for f in doc.findings]
    assert len(set(keys)) < len(keys), "the two tasks must still collide on key"
    assert len(set(refs)) == len(refs), "refs must disambiguate colliding keys"


def test_an_ambiguous_bare_key_note_is_dropped_not_double_attached():
    """A note keyed on a non-unique `key` must not land on two findings."""
    from memtriage.reporting.assembly import _attach_notes

    doc = _colliding_doc()
    doc.analyst = {"finding_notes": {"task:powershell": "AMBIGUOUS"}}
    _attach_notes(doc)
    assert [f for f in doc.findings if f.get("analyst_note")] == []
    assert doc.analyst["notes_unmatched"] == 1

    # The same note, addressed by the unambiguous ref, does attach.
    precise = _colliding_doc()
    target = precise.findings[0]["ref"]
    precise.analyst = {"finding_notes": {target: "PRECISE"}}
    _attach_notes(precise)
    attached = [f for f in precise.findings if f.get("analyst_note")]
    assert len(attached) == 1 and attached[0]["ref"] == target


def test_a_multi_tactic_finding_is_told_under_its_earliest_stage():
    from memtriage.reporting import stages

    obj = {"tactics": ["Defense Evasion", "Execution"]}
    assert stages.stage_of(obj) == "Execution"
    # A rule may name several tactics in one string.
    assert stages.stage_of({"tactics": ["Defense Evasion, Privilege Escalation"]}) == "Privilege Escalation"
    assert stages.stage_of({"tactics": []}) == stages.UNMAPPED


def test_progression_never_claims_a_sequence(triaged):
    doc = _assemble(triaged)
    lowered = doc.progression.lower()
    assert "not a demonstrated sequence" in lowered or "not a sequence" in lowered


# --------------------------------------------------------------------------
# Analyst layer
# --------------------------------------------------------------------------

def test_analyst_notes_bind_by_key_and_unmatched_ones_are_counted(triaged):
    base = _assemble(triaged)
    real_key = base.findings[0]["object"]["key"]
    stage = base.stages[0]["tactic"]

    from memtriage.db import SessionLocal
    from memtriage.reporting import assemble

    session = SessionLocal()
    try:
        doc = assemble(triaged, session, audience="technical", analyst={
            "hypothesis": "Staging consistent with sandbox-evasion tooling.",
            "recommendations": "Correlate with disk and network telemetry.",
            "finding_notes": {real_key: "This is the one that matters.",
                              "no-such-key": "Should never render."},
            "stage_notes": {stage: "Stage-level insight."},
        })
    finally:
        session.close()

    attached = [f for f in doc.findings if f.get("analyst_note")]
    assert len(attached) == 1 and attached[0]["object"]["key"] == real_key
    assert doc.analyst["notes_unmatched"] == 1, "a stale key must be counted, not rendered"

    ids = [s["id"] for s in doc.sections]
    assert "hypothesis" in ids and "recommendations" in ids
    assert ids.index("hypothesis") < ids.index("narrative")


def test_a_stale_note_key_never_renders_against_the_wrong_finding(triaged):
    from memtriage.db import SessionLocal
    from memtriage.reporting import assemble
    from memtriage.reporting.render import render

    session = SessionLocal()
    try:
        doc = assemble(triaged, session, analyst={
            "finding_notes": {"key-that-no-longer-exists": "MISPLACED NOTE"},
        })
    finally:
        session.close()
    assert "MISPLACED NOTE" not in render(doc)


def test_sections_without_analyst_input_are_simply_absent(triaged):
    ids = [s["id"] for s in _assemble(triaged).sections]
    assert "hypothesis" not in ids and "recommendations" not in ids


# --------------------------------------------------------------------------
# Phase 1: the persisted analyst layer
# --------------------------------------------------------------------------

def _first_ref(investigation_id: str) -> tuple[str, str]:
    doc = _assemble(investigation_id)
    return doc.findings[0]["ref"], doc.findings[0]["object"]["label"]


def test_evidence_create_is_idempotent_by_ref(client, triaged):
    ref, label = _first_ref(triaged)
    body = {"evidence_kind": "finding", "ref": ref, "label": label}

    first = client.post(f"/api/investigations/{triaged}/report/evidence", json=body)
    second = client.post(f"/api/investigations/{triaged}/report/evidence", json=body)
    assert first.status_code == second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert first.json()["disposition"] == "undetermined"

    listed = client.get(f"/api/investigations/{triaged}/report/evidence").json()
    assert len(listed) == 1


def test_a_note_survives_the_round_trip_with_its_paragraphs(client, triaged):
    """sanitize_text's defaults would flatten this and truncate it at 2048."""
    ref, label = _first_ref(triaged)
    created = client.post(f"/api/investigations/{triaged}/report/evidence",
                          json={"ref": ref, "label": label}).json()

    note = "First paragraph, on the parent process.\n\nSecond paragraph. " + ("x" * 3000)
    r = client.patch(
        f"/api/investigations/{triaged}/report/evidence/{created['id']}",
        json={"analyst_note": note},
    )
    assert r.status_code == 200
    saved = r.json()["analyst_note"]
    assert "\n\n" in saved, "paragraph breaks must survive sanitization"
    assert "…[truncated]" not in saved and len(saved) > 3000


def test_a_stale_write_is_rejected_rather_than_clobbering(client, triaged):
    ref, label = _first_ref(triaged)
    created = client.post(f"/api/investigations/{triaged}/report/evidence",
                          json={"ref": ref, "label": label}).json()
    stale = created["version"]

    ok = client.patch(f"/api/investigations/{triaged}/report/evidence/{created['id']}",
                      json={"analyst_note": "first writer", "if_version": stale})
    assert ok.status_code == 200
    assert ok.json()["version"] == stale + 1

    conflict = client.patch(
        f"/api/investigations/{triaged}/report/evidence/{created['id']}",
        json={"analyst_note": "second writer", "if_version": stale},
    )
    assert conflict.status_code == 422
    still = client.get(f"/api/investigations/{triaged}/report/evidence").json()[0]
    assert still["analyst_note"] == "first writer"


def test_the_document_follows_pins_strictly(client, triaged):
    """Pinned evidence is the report; nothing else from triage is presented as findings."""
    before = _assemble(triaged)
    assert len(before.findings) > 2, "fixture must leave unpinned findings behind"
    chosen = before.findings[:2]
    for f in chosen:
        client.post(f"/api/investigations/{triaged}/report/evidence",
                    json={"ref": f["ref"], "label": f["object"]["label"]})

    body = client.get(f"/api/investigations/{triaged}/report/preview").json()
    assert body["curated"] is True
    assert sorted(f["ref"] for f in body["findings"]) == sorted(f["ref"] for f in chosen)
    narrated = [f["ref"] for s in body["stages"] for f in s["findings"]]
    assert sorted(narrated) == sorted(f["ref"] for f in chosen)

    # The selection is disclosed against the full scored set, never implied to be it.
    assert body["scored_total"] == len(before.findings)
    html = client.get(f"/api/investigations/{triaged}/report.html").text
    assert f"out of {len(before.findings)} object(s) scored" in html
    unpinned = before.findings[2]["object"]["label"]
    assert unpinned not in "".join(f["object"]["label"] for f in body["findings"])


def test_pin_identity_covers_every_scored_object_even_when_curated(client, triaged):
    """The UI pins from `refs`; losing them would hide every unpinned pin control."""
    before = _assemble(triaged)
    first = before.findings[0]
    client.post(f"/api/investigations/{triaged}/report/evidence",
                json={"ref": first["ref"], "label": first["object"]["label"]})

    body = client.get(f"/api/investigations/{triaged}/report/preview").json()
    assert len(body["findings"]) == 1
    assert sorted(r["ref"] for r in body["refs"]) == sorted(f["ref"] for f in before.findings)


def test_executive_discloses_the_same_denominator_as_technical(client, triaged):
    first = _assemble(triaged).findings[0]
    client.post(f"/api/investigations/{triaged}/report/evidence",
                json={"ref": first["ref"], "label": first["object"]["label"]})
    tech = client.get(f"/api/investigations/{triaged}/report/preview?audience=technical").json()
    exe = client.get(f"/api/investigations/{triaged}/report/preview?audience=executive").json()
    assert tech["scored_total"] == exe["scored_total"]


def test_no_pins_means_the_complete_uncurated_record(client, triaged):
    body = client.get(f"/api/investigations/{triaged}/report/preview").json()
    assert body["curated"] is False
    assert len(body["findings"]) == body["scored_total"] > 0


def test_an_examiner_artifact_is_relabelled_not_deleted(client, triaged):
    """The acquisition harness leaves real, correctly-scored traces.

    A scheduled task that launches a sample after logon is genuine persistence.
    The report must record it and attribute it to collection, not present it as
    adversary activity and not drop it.
    """
    before = _assemble(triaged)
    target = next(f for f in before.findings if "powershell" in f["object"]["label"].lower())
    created = client.post(f"/api/investigations/{triaged}/report/evidence",
                          json={"ref": target["ref"], "label": target["object"]["label"]}).json()
    client.patch(f"/api/investigations/{triaged}/report/evidence/{created['id']}",
                 json={"disposition": "examiner_artifact",
                       "analyst_note": "Sandbox harness: launches the sample from Z: after logon."})

    body = client.get(f"/api/investigations/{triaged}/report/preview").json()
    assert len(body["examiner_artifacts"]) == 1
    narrated = [f["ref"] for s in body["stages"] for f in s["findings"]]
    assert target["ref"] not in narrated, "must not appear in the attack narrative"

    html = client.get(f"/api/investigations/{triaged}/report.html").text
    assert "Collection artifacts" in html
    assert "Sandbox harness" in html


def test_narrative_round_trips_and_reaches_the_document(client, triaged):
    listed = client.get(f"/api/investigations/{triaged}/report/narrative").json()
    assert set(listed) == {"hypothesis", "executive_summary", "scope_objectives",
                           "recommendations", "examiner_info"}
    assert listed["hypothesis"]["content"] == ""

    r = client.put(f"/api/investigations/{triaged}/report/narrative/hypothesis",
                   json={"content": "malware.exe ran first; everything else follows it.",
                         "source": "drafted"})
    assert r.status_code == 200 and r.json()["source"] == "drafted"

    html = client.get(f"/api/investigations/{triaged}/report.html").text
    assert "malware.exe ran first" in html
    assert "Hypothesis" in html


def test_unknown_narrative_section_and_disposition_are_rejected(client, triaged):
    assert client.put(f"/api/investigations/{triaged}/report/narrative/nope",
                      json={"content": "x"}).status_code == 422
    ref, label = _first_ref(triaged)
    created = client.post(f"/api/investigations/{triaged}/report/evidence",
                          json={"ref": ref, "label": label}).json()
    assert client.patch(
        f"/api/investigations/{triaged}/report/evidence/{created['id']}",
        json={"disposition": "made_up"}).status_code == 422


def test_evidence_is_scoped_to_its_investigation(client, triaged):
    ref, label = _first_ref(triaged)
    created = client.post(f"/api/investigations/{triaged}/report/evidence",
                          json={"ref": ref, "label": label}).json()
    assert client.patch(
        f"/api/investigations/other-investigation/report/evidence/{created['id']}",
        json={"analyst_note": "x"}).status_code == 404


def test_unpinning_the_last_evidence_returns_the_complete_record(client, triaged):
    before = _assemble(triaged)
    ref = before.findings[0]["ref"]
    created = client.post(f"/api/investigations/{triaged}/report/evidence",
                          json={"ref": ref, "label": "x"}).json()
    assert len(client.get(f"/api/investigations/{triaged}/report/preview").json()["findings"]) == 1

    client.delete(f"/api/investigations/{triaged}/report/evidence/{created['id']}")
    after = client.get(f"/api/investigations/{triaged}/report/preview").json()
    assert after["curated"] is False
    assert len(after["findings"]) == len(before.findings)


def test_exhibits_fall_back_to_measured_properties_under_a_placeholder_model():
    """Attention ranking from an untrained checkpoint is noise, not evidence."""
    from memtriage.reporting.exhibits import forensic_rank

    rwx_shellcode = {
        "patterns": [{"severity": "high"}, {"severity": "high"}],
        "flags": ["rwx", "private-executable", "no-file-backing"],
        "instruction_count": 300,
        "strings": [{"category": "url"}],
    }
    benign_mapped = {
        "patterns": [{"severity": "low"}],
        "flags": [],
        "instruction_count": 4000,
        "strings": [],
    }
    # Code density alone must never outrank unambiguously anomalous protection.
    assert forensic_rank(rwx_shellcode) > forensic_rank(benign_mapped)
    assert forensic_rank({"patterns": [], "flags": []}) == 0


def test_region_exhibits_follow_pins_and_bind_notes_by_content_address():
    from memtriage.reporting.assembly import ReportDocument, _apply_curation, _attach_notes

    shellcode = {"ref": "2580|aaaa", "addr": "0x400000", "attention": 0.2}
    benign = {"ref": "2580|bbbb", "addr": "0x7ff000", "attention": 0.9}
    doc = ReportDocument(
        investigation_id="i", audience="technical", generated_at="",
        exhibits=[benign, shellcode],
        analyst={"pinned_regions": ["2580|aaaa"],
                 "region_notes": {"2580|aaaa": "GetPC gadget and a C2 URL."}},
    )
    _apply_curation(doc)
    _attach_notes(doc)

    assert doc.curated is True
    assert [e["ref"] for e in doc.exhibits] == ["2580|aaaa"], "higher attention is not a pin"
    assert doc.exhibits[0]["analyst_note"] == "GetPC gadget and a C2 URL."
