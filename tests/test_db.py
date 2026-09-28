"""Smoke tests for the DB backbone: schema, upsert, metadata, work queues."""

import json

from pipeline.db import Database
from pipeline.models import (
    BypassStage, DefenseProfile, Outcome, PinLayer, Stage, TlsStack, WorkState,
)


def _db(tmp_path):
    return Database(tmp_path / "test.db")


def test_upsert_and_metadata_roundtrip(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("123", "us", bundle_id="com.x.y", name="X",
                  all_categories=["Finance", "Business"], raw_json='{"k":1}')
    with db.connect() as c:
        row = c.execute("SELECT * FROM apps WHERE app_id='123'").fetchone()
    assert row["bundle_id"] == "com.x.y"
    assert json.loads(row["all_categories"]) == ["Finance", "Business"]
    assert row["stage"] == "crawled"


def test_upsert_ignores_unknown_fields(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("1", "us", not_a_real_column="oops", name="Ok")
    with db.connect() as c:
        row = c.execute("SELECT name FROM apps WHERE app_id='1'").fetchone()
    assert row["name"] == "Ok"


def test_static_profile_and_pinned_queue(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("1", "us")
    db.save_acquisition("1", WorkState.POSITIVE, ipa_path="/x/1.ipa")
    prof = DefenseProfile(pins_flag=True, pin_layer=PinLayer.L3_LIBRARY,
                          pin_library="TrustKit", tls_stack=TlsStack.NATIVE,
                          appattest_flag=True)
    db.save_static_profile("1", prof)
    needing = db.apps_needing(Stage.DYNAMIC_DONE)
    assert [r["app_id"] for r in needing] == ["1"]  # pinned app awaits dynamic


def test_outcome_removes_from_dynamic_queue(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("1", "us")
    db.save_acquisition("1", WorkState.POSITIVE, ipa_path="/x/1.ipa")
    db.save_static_profile("1", DefenseProfile(pins_flag=True))
    db.save_outcome("1", Outcome.BYPASSED, BypassStage.DYLIB, pinned=True,
                    work_state=WorkState.POSITIVE)
    assert db.apps_needing(Stage.DYNAMIC_DONE) == []


def test_untested_outcome_stays_in_queue(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("1", "us")
    db.save_acquisition("1", WorkState.POSITIVE, ipa_path="/x/1.ipa")
    db.save_static_profile("1", DefenseProfile(pins_flag=True))
    db.save_outcome("1", Outcome.INCONCLUSIVE, BypassStage.NONE, pinned=False,
                    work_state=WorkState.UNTESTED)
    assert [r["app_id"] for r in db.apps_needing(Stage.DYNAMIC_DONE)] == ["1"]


def test_add_column_if_missing_is_idempotent(tmp_path):
    db = _db(tmp_path)
    db.add_column_if_missing("outcome", "notes", "TEXT")
    db.add_column_if_missing("outcome", "notes", "TEXT")  # no error second time
    with db.connect() as c:
        cols = {r["name"] for r in c.execute("PRAGMA table_info(outcome)")}
    assert "notes" in cols


def test_attestation_queue_only_appattest_apps(tmp_path):
    db = _db(tmp_path)
    db.upsert_app("1", "us")
    db.upsert_app("2", "us")
    db.save_acquisition("1", WorkState.POSITIVE)
    db.save_acquisition("2", WorkState.POSITIVE)
    db.save_static_profile("1", DefenseProfile(appattest_flag=True))
    db.save_static_profile("2", DefenseProfile(appattest_flag=False))
    needing = [r["app_id"] for r in db.apps_needing(Stage.ATTESTATION_DONE)]
    assert needing == ["1"]
