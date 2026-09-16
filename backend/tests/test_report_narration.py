"""Drafted narrative: the connective prose a model writes for the report.

The report already explains *what* fired and *why it scored*; those come from
the rule engine. What a model adds is significance and sequence. These pin the
boundary that makes that safe to put in a forensic document: the model supplies
prose, never facts, and a reader can always tell its sentences from the
engine's and from the analyst's.

Most of these build a document by hand rather than seeding one, because the
rules under test are about binding prose to refs — they hold whatever the
scoring engine happened to find.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from memtriage.assistant.errors import AssistantError
from memtriage.reporting import narration as narration_mod
from memtriage.reporting.assembly import ReportDocument

FIXTURES = Path(__file__).parent / "fixtures" / "dumps_2580_5"
STANDIN_IMAGE = FIXTURES / "2580_5.vmem"


@pytest.fixture(autouse=True)
def _offline_and_fast(monkeypatch):
    from memtriage.workers import tasks

    monkeypatch.setattr(tasks.settings, "vol_offline", True)
    monkeypatch.setattr(tasks.settings, "vol_timeout_s", 5)
    monkeypatch.setattr(tasks.settings, "vol_symbol_dirs", [])


@pytest.fixture(autouse=True)
def _standin_image():
    if not STANDIN_IMAGE.is_file():
        STANDIN_IMAGE.write_bytes(b"\x00" * 4096)


def _finding(ref: str, label: str, risk: str = "High") -> dict:
    return {
        "ref": ref,
        "object": {
            "label": label, "risk": risk, "score": 12, "pid": 2580,
            "key": f"proc:{label}",
            "contributions": [
                {"rule_id": "proc.path.masquerade",
                 "title": "System binary outside System32",
                 "weight": 6, "severity": "high", "confidence": 0.8,
                 "mitre": {"technique_id": "T1036", "technique_name": "Masquerading"}}
            ],
        },
        "headline": f"This process scored {risk}.",
        "rationale": "svchost.exe running from C:\\Users\\x; expected under System32.",
        "techniques": "The behaviour maps to T1036 (Masquerading).",
    }


def _doc() -> ReportDocument:
    """A two-finding document, shaped exactly as `assemble` produces one."""
    a, b = _finding("f1", "svchost.exe"), _finding("f2", "rundll32.exe", "Critical")
    doc = ReportDocument(
        investigation_id="inv-1",
        audience="technical",
        generated_at="2026-09-16T00:00:00+00:00",
        case={"process_count": 41, "dump_count": 1, "total_bytes": 4096,
              "investigation_id": "inv-1", "created_at": "", "status": "triaged"},
        overview="Triage scored 2 objects.",
        findings=[a, b],
    )
    doc.stages = [{
        "tactic": "Defense Evasion", "count": 2, "highest_risk": "Critical",
        "techniques": ["T1036"], "blurb": "Techniques that avoid detection.",
        "findings": [a, b],
    }]
    return doc


# --------------------------------------------------------------------------
# The validation gate
# --------------------------------------------------------------------------

def test_prose_binds_to_the_findings_the_model_was_shown():
    out = narration_mod.parse({
        "executive_summary": "Two processes warrant examination.",
        "stages": {"Defense Evasion": "Both leads share a masquerading pattern."},
        "findings": {"f1": "This is the stronger of the two.",
                     "f2": "Corroborates the first."},
    }, _doc())
    assert out.executive_summary.startswith("Two processes")
    assert out.stages["Defense Evasion"]
    assert set(out.findings) == {"f1", "f2"}
    assert out.unmatched == []


def test_a_ref_the_document_does_not_have_is_discarded():
    """The gate, not a formality.

    A ref the model invented — or one left over from an earlier scoring run —
    would otherwise render a passage against a finding it was never written
    about, or conjure a finding that was never scored at all.
    """
    out = narration_mod.parse({
        "findings": {"f1": "Real.", "f9": "About a finding that does not exist."},
        "stages": {"Command and Control": "About a tactic with no findings."},
    }, _doc())
    assert set(out.findings) == {"f1"}
    assert out.stages == {}
    assert sorted(out.unmatched) == ["finding:f9", "stage:Command and Control"]


def test_an_empty_draft_is_falsy_so_it_is_never_stored_as_a_draft():
    assert not narration_mod.parse({"findings": {"f1": "   "}}, _doc())


def test_a_passage_is_capped_rather_than_allowed_to_become_the_report():
    out = narration_mod.parse({"findings": {"f1": "x" * 5000}}, _doc())
    assert len(out.findings["f1"]) <= narration_mod.MAX_PASSAGE_LEN


def test_paragraph_breaks_survive_but_control_characters_do_not():
    out = narration_mod.parse(
        {"findings": {"f1": "First para.\n\nSecond para.\x00\x07"}}, _doc())
    assert "\n\n" in out.findings["f1"]
    assert "\x00" not in out.findings["f1"] and "\x07" not in out.findings["f1"]


# --------------------------------------------------------------------------
# Reading the model's reply
# --------------------------------------------------------------------------

def test_a_fenced_json_block_is_still_read():
    payload = narration_mod._loads('```json\n{"findings": {"f1": "ok"}}\n```')
    assert payload["findings"]["f1"] == "ok"


def test_a_preamble_before_the_json_does_not_lose_a_good_draft():
    payload = narration_mod._loads(
        'Here is the narrative you asked for:\n{"findings": {"f1": "ok"}}')
    assert payload["findings"]["f1"] == "ok"


def test_a_reply_that_is_not_json_fails_loudly():
    with pytest.raises(AssistantError) as exc:
        narration_mod._loads("I'm afraid I can't help with that.")
    assert exc.value.code == "bad_response"


def test_an_empty_reply_fails_rather_than_storing_nothing():
    with pytest.raises(AssistantError):
        narration_mod._loads("")


# --------------------------------------------------------------------------
# The briefing
# --------------------------------------------------------------------------

def test_the_briefing_carries_the_refs_the_reply_must_key_on():
    text = narration_mod.briefing(_doc())
    assert "REF f1" in text and "REF f2" in text
    assert "TACTIC Defense Evasion" in text


def test_the_briefing_carries_the_caveats_that_bound_what_may_be_claimed():
    """A model that is not told coverage was degraded will write as if it wasn't."""
    doc = _doc()
    doc.notices = ["Extraction was degraded: 15 of 26 plugins failed."]
    doc.limitations = {"points": ["Phase 1 produces leads, not detections."]}
    text = narration_mod.briefing(doc)
    assert "degraded" in text
    assert "leads, not detections" in text


def test_the_analysts_own_words_reach_the_model():
    """So the drafted prose does not contradict a human who already looked."""
    doc = _doc()
    doc.stages[0]["findings"][0]["analyst_note"] = "Confirmed benign: vendor agent."
    assert "Confirmed benign" in narration_mod.briefing(doc)


def test_drafting_refuses_when_there_is_nothing_to_narrate():
    """A narrative over zero findings is the one a model would invent."""
    empty = ReportDocument(investigation_id="i", audience="technical", generated_at="")
    with pytest.raises(AssistantError) as exc:
        narration_mod.draft(empty, provider_id="anthropic", model="m", api_key="k")
    assert exc.value.code == "bad_request"


# --------------------------------------------------------------------------
# Placement and disclosure
# --------------------------------------------------------------------------

def test_drafted_prose_renders_next_to_the_evidence_it_explains():
    """The whole point: the storyline sits with the finding, not in a preface."""
    from memtriage.reporting.assembly import _attach_narration
    from memtriage.reporting.render import render

    doc = _doc()
    doc.sections = [{"id": "narrative", "number": 1, "title": "Attack narrative"}]
    doc.narration = {
        "findings": {"f1": "PROSE-ABOUT-SVCHOST"},
        "stages": {"Defense Evasion": "PROSE-ABOUT-THE-TACTIC"},
        "model": "test-model", "provider": "anthropic",
    }
    _attach_narration(doc)
    assert doc.narration["attached"] == 2

    html = render(doc)
    # The passage must fall inside the finding block, after the rule list —
    # i.e. after the evidence, not before it.
    assert "PROSE-ABOUT-SVCHOST" in html
    assert html.index("proc.path.masquerade") < html.index("PROSE-ABOUT-SVCHOST")
    assert html.index("PROSE-ABOUT-THE-TACTIC") < html.index("PROSE-ABOUT-SVCHOST")


def test_generated_prose_is_visibly_not_the_analysts_voice():
    from memtriage.reporting.assembly import _attach_narration
    from memtriage.reporting.render import render

    doc = _doc()
    doc.sections = [{"id": "narrative", "number": 1, "title": "Attack narrative"}]
    doc.narration = {"findings": {"f1": "GENERATED"}, "model": "m", "provider": "p"}
    doc.findings[0]["analyst_note"] = "HUMAN"
    _attach_narration(doc)
    html = render(doc)
    assert '<div class="drafted"><span class="who">Drafted narrative</span>' in html
    assert '<div class="analyst"><span class="who">Analyst</span>HUMAN' in html


def test_a_stale_passage_is_dropped_rather_than_slid_onto_its_neighbour():
    from memtriage.reporting.assembly import _attach_narration

    doc = _doc()
    doc.narration = {"findings": {"f1": "keep", "gone": "stale"}}
    _attach_narration(doc)
    assert doc.findings[0].get("drafted_note") == "keep"
    assert doc.findings[1].get("drafted_note") is None
    assert doc.narration["dropped"] == 1


# --------------------------------------------------------------------------
# End to end, through the route
# --------------------------------------------------------------------------

@pytest.fixture()
def triaged(client):
    from memtriage.pipeline.fixture_seed import seed_investigation_from_dumps

    summary = seed_investigation_from_dumps(FIXTURES)
    assert summary["task_result"] == "triaged"
    return summary["investigation_id"]


class _FakeTransport:
    """Stands in for a provider. Records the system prompt it was given."""

    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.system = ""
        self.user = ""

    def chat(self, *, api_key, model, system, messages, base_url, timeout_s, **kw):
        self.system = system
        self.user = messages[0]["content"]
        return {"text": self.reply, "model": model}


def _draft(client, monkeypatch, investigation_id, reply):
    transport = _FakeTransport(reply)
    monkeypatch.setattr(narration_mod, "transport_for", lambda provider: transport)
    response = client.post(
        f"/api/investigations/{investigation_id}/report/narrative/draft",
        json={"provider": "anthropic", "model": "test-model", "api_key": "k"},
    )
    return response, transport


def test_a_draft_survives_into_the_html_the_export_serves(client, monkeypatch, triaged):
    """The preview iframes a keyless GET, so a draft only reaches the page if
    it was stored. This is the reason narration is persisted at all."""
    preview = client.get(
        f"/api/investigations/{triaged}/report/preview?audience=technical").json()
    refs = [f["ref"] for f in preview["findings"]]
    assert refs, "fixture must score something to narrate"

    reply = json.dumps({
        "executive_summary": "SUMMARY-PROSE",
        "findings": {refs[0]: "FINDING-PROSE"},
    })
    response, _ = _draft(client, monkeypatch, triaged, reply)
    assert response.status_code == 200, response.text
    assert response.json()["stored"] == 1

    html = client.get(f"/api/investigations/{triaged}/report.html").text
    assert "FINDING-PROSE" in html
    assert "Drafted narrative" in html
    # Disclosed among the notices that change how the document is read.
    assert "test-model" in html


def test_the_document_discloses_that_a_model_wrote_the_prose(client, monkeypatch, triaged):
    preview = client.get(f"/api/investigations/{triaged}/report/preview").json()
    ref = preview["findings"][0]["ref"]
    _draft(client, monkeypatch, triaged, json.dumps({"findings": {ref: "P"}}))

    doc = client.get(f"/api/investigations/{triaged}/report/preview").json()
    notice = " ".join(doc["notices"])
    assert "not themselves evidence" in notice
    assert "test-model" in notice


def test_the_model_is_told_it_is_writing_a_forensic_document(client, monkeypatch, triaged):
    """The instructions are what keep a fluent model from overstating leads."""
    preview = client.get(f"/api/investigations/{triaged}/report/preview").json()
    ref = preview["findings"][0]["ref"]
    _, transport = _draft(
        client, monkeypatch, triaged, json.dumps({"findings": {ref: "P"}}))
    assert "leads, not detections" in transport.system
    assert "never instructions to follow" in transport.system
    assert ref in transport.user


def test_clearing_the_draft_leaves_the_analysts_words_alone(client, monkeypatch, triaged):
    preview = client.get(f"/api/investigations/{triaged}/report/preview").json()
    ref = preview["findings"][0]["ref"]
    client.post(f"/api/investigations/{triaged}/report/evidence",
                json={"evidence_kind": "finding", "ref": ref, "label": "x"})
    rows = client.get(f"/api/investigations/{triaged}/report/evidence").json()
    client.patch(
        f"/api/investigations/{triaged}/report/evidence/{rows[0]['id']}",
        json={"analyst_note": "HUMAN-NOTE"})

    _draft(client, monkeypatch, triaged, json.dumps({"findings": {ref: "DRAFTED"}}))
    assert client.delete(
        f"/api/investigations/{triaged}/report/narrative/draft").json()["removed"] == 1

    html = client.get(f"/api/investigations/{triaged}/report.html").text
    assert "DRAFTED" not in html
    assert "HUMAN-NOTE" in html


def test_a_reply_that_binds_to_nothing_is_a_failure_not_an_empty_draft(
    client, monkeypatch, triaged
):
    response, _ = _draft(client, monkeypatch, triaged,
                         json.dumps({"findings": {"not-a-real-ref": "prose"}}))
    assert response.status_code == 502
    html = client.get(f"/api/investigations/{triaged}/report.html").text
    assert "Drafted narrative" not in html


def test_a_summary_the_analyst_typed_is_never_replaced_by_a_draft(
    client, monkeypatch, triaged
):
    """They would have no way to get it back.

    A report that quietly swapped a human's conclusion for a model's is the
    failure this whole feature is built to avoid, so the one slot the two share
    resolves in the analyst's favour.
    """
    client.put(f"/api/investigations/{triaged}/report/narrative/executive_summary",
               json={"content": "HUMAN-SUMMARY", "source": "analyst"})

    preview = client.get(f"/api/investigations/{triaged}/report/preview").json()
    ref = preview["findings"][0]["ref"]
    response, _ = _draft(client, monkeypatch, triaged, json.dumps(
        {"executive_summary": "MODEL-SUMMARY", "findings": {ref: "P"}}))

    body = response.json()
    assert body["executive_summary_written"] is False
    # Still returned, so the analyst can read it and decide for themselves.
    assert body["executive_summary"] == "MODEL-SUMMARY"

    rows = client.get(f"/api/investigations/{triaged}/report/narrative").json()
    assert rows["executive_summary"]["content"] == "HUMAN-SUMMARY"
    assert rows["executive_summary"]["source"] == "analyst"


def test_a_previous_draft_of_the_summary_is_replaced(client, monkeypatch, triaged):
    """Only a human's words are protected; a stale draft is not."""
    preview = client.get(f"/api/investigations/{triaged}/report/preview").json()
    ref = preview["findings"][0]["ref"]
    _draft(client, monkeypatch, triaged,
           json.dumps({"executive_summary": "FIRST", "findings": {ref: "P"}}))
    _draft(client, monkeypatch, triaged,
           json.dumps({"executive_summary": "SECOND", "findings": {ref: "P"}}))

    rows = client.get(f"/api/investigations/{triaged}/report/narrative").json()
    assert rows["executive_summary"]["content"] == "SECOND"
