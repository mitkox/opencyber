"""Tests for the deterministic CVE exploit-chain model (cve_chain.py)."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import opencyber.engagements as engagements
from opencyber import audit, cve_chain, workspace
from opencyber.poc_schema import PocError, canonical_json, canonical_sha256, poc_path


FOOTHOLD_STEPS = [
    {
        "cve_id": "CVE-2026-0001",
        "asset": "app.example.test",
        "requires": ["net:http:8080"],
        "provides": ["auth:user"],
        "basis": "Advisory: pre-auth authentication bypass in the login handler.",
        "source": "nvd",
    },
    {
        "cve_id": "CVE-2026-0002",
        "asset": "app.example.test",
        "requires": ["auth:user"],
        "provides": ["file:read:/var/www/*"],
        "basis": "Post-auth local file inclusion in the template loader.",
        "source": "nuclei",
    },
]

NUCLEI_JSONL = "\n".join(
    [
        json.dumps(
            {
                "template-id": "cve-2026-0001",
                "matched-at": "https://app.example.test/login",
                "info": {"classification": {"cve-id": ["CVE-2026-0001"]}},
            }
        ),
        json.dumps(
            {
                "template-id": "tech-detect",
                "matched-at": "https://app.example.test/",
                "info": {},
            }
        ),
        json.dumps(
            {
                "template-id": "cve-2026-0002",
                "host": "db.example.test",
                "info": {"classification": {"cve-id": "CVE-2026-0002"}},
            }
        ),
    ]
) + "\n"

TRIVY_JSON = json.dumps(
    {
        "SchemaVersion": 2,
        "ArtifactName": "app:1.0",
        "Results": [
            {
                "Target": "app:1.0 (debian 12)",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2026-0003", "PkgName": "openssl"},
                    {"VulnerabilityID": "GHSA-aaaa-bbbb-cccc", "PkgName": "openssl"},
                ],
            }
        ],
    }
)

GENERIC_JSON = json.dumps(
    [
        {"cve_id": "CVE-2026-0004", "note": "from scanner"},
        {"CVE": "CVE-2026-0005"},
    ]
)


def _copy(value):
    return json.loads(json.dumps(value))


class ChainTestCase(unittest.TestCase):
    """Temp workspace + offline CVE DB isolation shared by all chain tests."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.workspace_patch = patch.object(engagements, "WORKSPACE", self.root)
        self.workspace_patch.start()
        self.env_patch = patch.dict(
            os.environ,
            {"OPENCYBER_CVE_DB": str(self.root / "missing-cve.sqlite")},
        )
        self.env_patch.start()
        self.engagement = engagements.create_engagement(
            "Chain", ["app.example.test", "db.example.test"]
        )
        self.engagement_id = self.engagement["engagement_id"]

    def tearDown(self):
        self.env_patch.stop()
        self.workspace_patch.stop()
        self.temporary.cleanup()

    # -- helpers ---------------------------------------------------------

    def plan(self, steps=None, entry=None, artifacts=None, chain_name=""):
        return cve_chain.plan_chain(
            self.engagement_id,
            _copy(FOOTHOLD_STEPS) if steps is None else steps,
            ["net:http:8080"] if entry is None else entry,
            artifacts=artifacts,
            chain_name=chain_name,
        )

    def assertRefused(self, reason, func, *args, **kwargs):
        with self.assertRaises(PocError) as caught:
            func(*args, **kwargs)
        self.assertEqual(caught.exception.reason, reason, str(caught.exception))
        return caught.exception

    def chain_path(self, chain_id):
        return poc_path(self.engagement_id, "chains", f"{chain_id}.json")

    def write_artifact(self, path, content):
        return workspace.write_workspace_file(self.engagement_id, path, content)

    def write_artifact_bundle(self):
        self.write_artifact("artifacts/nuclei.jsonl", NUCLEI_JSONL)
        self.write_artifact("artifacts/trivy.json", TRIVY_JSON)
        self.write_artifact("artifacts/generic.json", GENERIC_JSON)


# ---------------------------------------------------------------------------
# Chain planning
# ---------------------------------------------------------------------------


class ChainCoverageTests(ChainTestCase):
    def test_complete_verdict_declares_complete_coverage(self):
        record = self.plan()
        self.assertEqual(record["coverage"]["status"], "complete")
        self.assertEqual(record["coverage"]["examined"], 2)
        self.assertEqual(record["coverage"]["total"], 2)
        self.assertTrue(record["coverage"]["exhausted"])
        self.assertTrue(any("could not be verified" in item for item in record["limitations"]))
        self.assertTrue(any("not observed" in item for item in record["limitations"]))

    def test_incomplete_verdict_is_partial_and_names_the_missing_capability(self):
        steps = _copy(FOOTHOLD_STEPS)
        steps[1]["requires"] = ["auth:admin"]
        record = self.plan(steps=steps)
        self.assertEqual(record["verdict"], "incomplete")
        self.assertEqual(record["coverage"]["status"], "partial")
        self.assertEqual(record["coverage"]["examined"], 1)
        self.assertEqual(record["coverage"]["total"], 2)
        self.assertTrue(any("auth:admin" in item for item in record["limitations"]))

    def test_cyclic_verdict_is_partial_and_names_the_cycle(self):
        steps = [
            {
                "cve_id": "CVE-2026-0101",
                "asset": "app.example.test",
                "requires": ["auth:admin"],
                "provides": ["secret:read:flag"],
                "basis": "step one",
            },
            {
                "cve_id": "CVE-2026-0102",
                "asset": "app.example.test",
                "requires": ["secret:read:flag"],
                "provides": ["auth:admin"],
                "basis": "step two",
            },
        ]
        record = cve_chain.plan_chain(self.engagement_id, steps, [])
        self.assertEqual(record["verdict"], "cyclic")
        self.assertEqual(record["coverage"]["status"], "partial")
        self.assertFalse(record["coverage"]["exhausted"])
        self.assertTrue(any("cyclic" in item and "CVE-2026-0101" in item for item in record["limitations"]))

    def test_load_chain_returns_the_same_coverage_declaration(self):
        record = self.plan()
        loaded = cve_chain.load_chain(self.engagement_id, record["chain_id"])
        self.assertEqual(loaded["coverage"], record["coverage"])
        self.assertEqual(loaded["limitations"], record["limitations"])

    def test_live_chain_tool_returns_coverage_and_typed_refusal(self):
        from opencyber.server import mcp

        tool = mcp._tool_manager._tools["oc_chain_plan"]
        planned = asyncio.run(mcp.call_tool(tool.name, {
            "engagement_id": self.engagement_id,
            "steps": _copy(FOOTHOLD_STEPS),
            "entry_capabilities": ["net:http:8080"],
        })).structured_content
        self.assertTrue(planned["ok"])
        self.assertEqual(planned["coverage"]["status"], "complete")
        refused = asyncio.run(mcp.call_tool(tool.name, {
            "engagement_id": self.engagement_id,
            "steps": [],
            "entry_capabilities": [],
        })).structured_content
        self.assertFalse(refused["ok"])
        self.assertEqual(refused["error"]["code"], "invalid_argument")


class ChainPlanTests(ChainTestCase):
    def test_complete_two_step_chain(self):
        record = self.plan(chain_name="foothold")
        self.assertEqual(record["schema_version"], 1)
        self.assertEqual(record["verdict"], "complete")
        self.assertEqual(record["missing"], [])
        self.assertEqual(record["cycle"], [])
        self.assertEqual(record["assumptions"], [])
        self.assertEqual(record["chain_name"], "foothold")
        self.assertEqual(record["entry_capabilities"], ["net:http:8080"])
        self.assertEqual(
            record["execution_order"], ["CVE-2026-0001", "CVE-2026-0002"]
        )
        self.assertEqual([step["order"] for step in record["steps"]], [1, 2])
        self.assertTrue(all(step["satisfied"] for step in record["steps"]))
        self.assertEqual(record["unverified_cves"], ["CVE-2026-0001", "CVE-2026-0002"])
        self.assertTrue(
            all("unverified_cve" in step["warnings"] for step in record["steps"])
        )
        self.assertRegex(record["chain_id"], r"^chain_\d{8}_[0-9a-f]{32}$")
        self.assertTrue(record["created_at"].endswith("Z"))
        payload = {
            key: value
            for key, value in record.items()
            if key not in ("chain_id", "created_at", "chain_sha256")
        }
        self.assertEqual(record["chain_sha256"], canonical_sha256(payload))

    def test_incomplete_chain_reports_exact_missing_tokens(self):
        steps = _copy(FOOTHOLD_STEPS)
        steps[1]["requires"] = ["auth:admin"]
        record = self.plan(steps=steps)
        self.assertEqual(record["verdict"], "incomplete")
        self.assertEqual(record["missing"], ["auth:admin"])
        self.assertEqual(record["cycle"], [])
        self.assertEqual(record["execution_order"], ["CVE-2026-0001"])
        steps_by_cve = {step["cve_id"]: step for step in record["steps"]}
        self.assertTrue(steps_by_cve["CVE-2026-0001"]["satisfied"])
        self.assertEqual(steps_by_cve["CVE-2026-0001"]["order"], 1)
        self.assertFalse(steps_by_cve["CVE-2026-0002"]["satisfied"])
        self.assertIsNone(steps_by_cve["CVE-2026-0002"]["order"])
        self.assertEqual(steps_by_cve["CVE-2026-0002"]["missing"], ["auth:admin"])

    def test_cycle_is_detected(self):
        steps = [
            {
                "cve_id": "CVE-2026-0101",
                "asset": "app.example.test",
                "requires": ["secret:read:flag"],
                "provides": ["auth:admin"],
                "basis": "Needs the secret before escalating.",
                "source": "manual",
            },
            {
                "cve_id": "CVE-2026-0102",
                "asset": "app.example.test",
                "requires": ["auth:admin"],
                "provides": ["secret:read:flag"],
                "basis": "Needs admin before reading the secret.",
                "source": "manual",
            },
        ]
        record = self.plan(steps=steps, entry=[])
        self.assertEqual(record["verdict"], "cyclic")
        self.assertEqual(record["missing"], ["auth:admin", "secret:read:flag"])
        self.assertEqual(record["execution_order"], [])
        self.assertEqual(
            sorted(record["cycle"]), ["CVE-2026-0101", "CVE-2026-0102"]
        )
        self.assertTrue(all(not step["satisfied"] for step in record["steps"]))
        self.assertTrue(all(step["order"] is None for step in record["steps"]))

    def test_unsupplied_token_outside_the_cycle_is_incomplete(self):
        steps = [
            {
                "cve_id": "CVE-2026-0101",
                "asset": "app.example.test",
                "requires": ["secret:read:flag"],
                "provides": ["auth:admin"],
                "basis": "Needs the secret before escalating.",
                "source": "manual",
            },
            {
                "cve_id": "CVE-2026-0102",
                "asset": "app.example.test",
                "requires": ["auth:admin"],
                "provides": ["secret:read:flag"],
                "basis": "Needs admin before reading the secret.",
                "source": "manual",
            },
            {
                "cve_id": "CVE-2026-0103",
                "asset": "app.example.test",
                "requires": ["info:version"],
                "provides": [],
                "basis": "Blocked on a fingerprint nobody can supply.",
                "source": "manual",
            },
        ]
        record = self.plan(steps=steps, entry=[])
        self.assertEqual(record["verdict"], "incomplete")
        self.assertIn("info:version", record["missing"])
        self.assertEqual(record["cycle"], [])

    def test_entry_capability_superset(self):
        steps = [
            {
                "cve_id": "CVE-2026-0301",
                "asset": "app.example.test",
                "requires": ["auth:admin"],
                "provides": ["file:read:/etc/passwd"],
                "basis": "Admin session already available from the engagement.",
                "source": "manual",
            }
        ]
        record = self.plan(
            steps=steps,
            entry=["net:http:8080", "auth:admin", "info:version"],
        )
        self.assertEqual(record["verdict"], "complete")
        self.assertEqual(record["entry_capabilities"], ["auth:admin", "info:version", "net:http:8080"])
        self.assertEqual(record["missing"], [])
        self.assertEqual(record["execution_order"], ["CVE-2026-0301"])

    def test_steps_are_recorded_in_satisfaction_order(self):
        steps = [
            {
                "cve_id": "CVE-2026-0201",
                "asset": "app.example.test",
                "requires": ["auth:admin"],
                "provides": [],
                "basis": "Depends on the provider below.",
                "source": "manual",
            },
            {
                "cve_id": "CVE-2026-0202",
                "asset": "app.example.test",
                "requires": ["net:http:8080"],
                "provides": ["auth:admin"],
                "basis": "Reachable from the internet directly.",
                "source": "manual",
            },
        ]
        record = self.plan(steps=steps)
        self.assertEqual(record["verdict"], "complete")
        self.assertEqual(
            record["execution_order"], ["CVE-2026-0202", "CVE-2026-0201"]
        )
        self.assertEqual(
            [step["cve_id"] for step in record["steps"]],
            ["CVE-2026-0202", "CVE-2026-0201"],
        )
        self.assertEqual([step["order"] for step in record["steps"]], [1, 2])
        self.assertEqual([step["index"] for step in record["steps"]], [1, 0])

    def test_unobserved_steps_get_warning(self):
        record = self.plan()
        self.assertEqual(record["warnings"], ["unobserved_cve", "unverified_cve"])
        self.assertEqual(record["unobserved_cves"], ["CVE-2026-0001", "CVE-2026-0002"])
        for step in record["steps"]:
            self.assertFalse(step["observed"])
            self.assertEqual(step["observation_locations"], [])
            self.assertIn("unobserved_cve", step["warnings"])

    def test_inferred_entry_capabilities_are_recorded_as_assumption(self):
        steps = [
            {
                "cve_id": "CVE-2026-0401",
                "asset": "app.example.test",
                "requires": [],
                "provides": [],
                "basis": "No precondition beyond authorized access.",
                "source": "manual",
            }
        ]
        record = cve_chain.plan_chain(self.engagement_id, steps, None)
        self.assertEqual(record["verdict"], "complete")
        self.assertEqual(
            record["assumptions"],
            ["entry_capabilities were not supplied; assumed empty"],
        )


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


class ChainValidationTests(ChainTestCase):
    def test_steps_must_be_a_list(self):
        error = self.assertRefused(
            "invalid_steps", cve_chain.plan_chain, self.engagement_id, "nope", []
        )
        self.assertIn("steps must be a list", error.message)
        self.assertRefused(
            "invalid_steps", cve_chain.plan_chain, self.engagement_id, {}, []
        )

    def test_empty_steps_are_rejected(self):
        self.assertRefused("invalid_steps", cve_chain.plan_chain, self.engagement_id, [], [])

    def test_non_object_step_is_rejected_with_index(self):
        error = self.assertRefused(
            "invalid_step", cve_chain.plan_chain, self.engagement_id, ["nope"], []
        )
        self.assertEqual(error.details["index"], 0)

    def test_unknown_step_fields_are_rejected(self):
        steps = _copy(FOOTHOLD_STEPS)
        steps[1]["exploit"] = "run it"
        error = self.assertRefused("invalid_step", self.plan, steps=steps)
        self.assertEqual(error.details["index"], 1)
        self.assertEqual(error.details["fields"], ["exploit"])
        self.assertIn("unknown step field", error.message)

    def test_required_step_fields_are_enforced(self):
        cases = [
            ({"asset": "app.example.test", "basis": "b"}, "cve_id"),
            ({"cve_id": "CVE-2026-0001", "basis": "b"}, "asset"),
            ({"cve_id": "CVE-2026-0001", "asset": "app.example.test"}, "basis"),
        ]
        for step, field in cases:
            with self.subTest(field=field):
                error = self.assertRefused("invalid_step", self.plan, steps=[step])
                self.assertEqual(error.details["field"], field)

    def test_empty_asset_and_basis_are_rejected(self):
        steps = _copy(FOOTHOLD_STEPS)
        steps[0]["asset"] = "   "
        error = self.assertRefused("invalid_step", self.plan, steps=steps)
        self.assertEqual(error.details["field"], "asset")
        steps = _copy(FOOTHOLD_STEPS)
        steps[0]["basis"] = ""
        error = self.assertRefused("invalid_step", self.plan, steps=steps)
        self.assertEqual(error.details["field"], "basis")

    def test_invalid_capability_token_is_rejected(self):
        steps = _copy(FOOTHOLD_STEPS)
        steps[1]["requires"] = ["net:http:99999"]
        error = self.assertRefused("invalid_capability", self.plan, steps=steps)
        self.assertEqual(error.details["index"], 1)
        self.assertIn("step 1", error.message)

    def test_invalid_cve_id_is_rejected(self):
        steps = _copy(FOOTHOLD_STEPS)
        steps[0]["cve_id"] = "CVE-26-1"
        error = self.assertRefused("invalid_cve", self.plan, steps=steps)
        self.assertEqual(error.details["index"], 0)

    def test_invalid_source_is_rejected(self):
        steps = _copy(FOOTHOLD_STEPS)
        steps[0]["source"] = "blog"
        error = self.assertRefused("invalid_step", self.plan, steps=steps)
        self.assertEqual(error.details["field"], "source")

    def test_evidence_path_must_stay_inside_the_engagement(self):
        for bad_path in ("../escape.jsonl", "/etc/passwd"):
            with self.subTest(path=bad_path):
                steps = _copy(FOOTHOLD_STEPS)
                steps[0]["evidence_path"] = bad_path
                error = self.assertRefused("invalid_step", self.plan, steps=steps)
                self.assertEqual(error.details["index"], 0)

    def test_artifact_paths_are_validated(self):
        self.assertRefused(
            "artifact_invalid", self.plan, artifacts="artifacts/nuclei.jsonl"
        )
        self.assertRefused("artifact_invalid", self.plan, artifacts=["../nuclei.jsonl"])
        self.assertRefused("artifact_invalid", self.plan, artifacts=[""])

    def test_chain_name_is_validated(self):
        self.assertRefused(
            "invalid_chain_name", self.plan, chain_name="x" * (cve_chain.MAX_CHAIN_NAME_LENGTH + 1)
        )
        self.assertRefused("invalid_chain_name", self.plan, chain_name=7)

    def test_invalid_entry_capabilities_are_rejected(self):
        self.assertRefused(
            "invalid_capability", cve_chain.plan_chain, self.engagement_id, _copy(FOOTHOLD_STEPS), ["bogus"]
        )
        self.assertRefused(
            "invalid_capability",
            cve_chain.plan_chain,
            self.engagement_id,
            _copy(FOOTHOLD_STEPS),
            "net:http:8080",
        )

    def test_unknown_engagement_is_refused(self):
        missing = "eng_20260101_" + "0" * 32
        steps = _copy(FOOTHOLD_STEPS)
        self.assertRefused(
            "unknown_engagement", cve_chain.plan_chain, missing, steps, []
        )
        self.assertRefused("unknown_engagement", cve_chain.list_chains, missing)
        self.assertRefused("unknown_engagement", cve_chain.parse_artifacts, missing, [])
        self.assertRefused(
            "unknown_engagement",
            cve_chain.load_chain,
            missing,
            "chain_20260101_" + "0" * 32,
        )


# ---------------------------------------------------------------------------
# Artefacts
# ---------------------------------------------------------------------------


class ArtifactTests(ChainTestCase):
    def test_truncated_artifact_is_refused_instead_of_treated_as_complete(self):
        path = "artifacts/large.jsonl"
        self.write_artifact(path, "\n" * 1048576 + NUCLEI_JSONL)
        refused = self.assertRefused("artifact_invalid", cve_chain.parse_artifacts, self.engagement_id, [path])
        self.assertTrue(refused.details["truncated"])

    def test_parse_artifacts_supports_nuclei_trivy_and_generic(self):
        self.write_artifact_bundle()
        parsed = cve_chain.parse_artifacts(
            self.engagement_id,
            ["artifacts/nuclei.jsonl", "artifacts/trivy.json", "artifacts/generic.json"],
        )
        self.assertEqual(
            sorted(parsed),
            [
                "CVE-2026-0001",
                "CVE-2026-0002",
                "CVE-2026-0003",
                "CVE-2026-0004",
                "CVE-2026-0005",
            ],
        )
        nuclei_location = parsed["CVE-2026-0001"]["locations"][0]
        self.assertEqual(parsed["CVE-2026-0001"]["observed"], True)
        self.assertEqual(nuclei_location["path"], "artifacts/nuclei.jsonl")
        self.assertEqual(nuclei_location["line"], 1)
        self.assertEqual(nuclei_location["source"], "nuclei")
        self.assertIn("cve-2026-0001", nuclei_location["detail"])
        self.assertEqual(parsed["CVE-2026-0002"]["locations"][0]["line"], 3)
        trivy_location = parsed["CVE-2026-0003"]["locations"][0]
        self.assertEqual(trivy_location["source"], "trivy")
        self.assertIn("openssl", trivy_location["detail"])
        self.assertEqual(parsed["CVE-2026-0004"]["locations"][0]["source"], "generic")

    def test_plan_marks_observed_steps_and_attaches_locations(self):
        self.write_artifact_bundle()
        steps = _copy(FOOTHOLD_STEPS)
        record = self.plan(
            steps=steps,
            artifacts=["artifacts/nuclei.jsonl", "artifacts/trivy.json"],
        )
        self.assertEqual(record["unobserved_cves"], [])
        self.assertNotIn("unobserved_cve", record["warnings"])
        steps_by_cve = {step["cve_id"]: step for step in record["steps"]}
        self.assertTrue(steps_by_cve["CVE-2026-0001"]["observed"])
        self.assertTrue(steps_by_cve["CVE-2026-0002"]["observed"])
        self.assertEqual(
            steps_by_cve["CVE-2026-0002"]["observation_locations"][0]["path"],
            "artifacts/nuclei.jsonl",
        )
        self.assertEqual(record["artifacts"], ["artifacts/nuclei.jsonl", "artifacts/trivy.json"])

    def test_unobserved_step_gets_warning(self):
        self.write_artifact("artifacts/nuclei.jsonl", NUCLEI_JSONL)
        steps = _copy(FOOTHOLD_STEPS)
        steps.append(
            {
                "cve_id": "CVE-2026-0099",
                "asset": "db.example.test",
                "requires": ["file:read:/var/www/*"],
                "provides": [],
                "basis": "Claimed by the operator but not present in the evidence.",
                "source": "manual",
            }
        )
        record = self.plan(steps=steps, artifacts=["artifacts/nuclei.jsonl"])
        self.assertEqual(record["unobserved_cves"], ["CVE-2026-0099"])
        self.assertIn("unobserved_cve", record["warnings"])
        step = {item["cve_id"]: item for item in record["steps"]}["CVE-2026-0099"]
        self.assertFalse(step["observed"])
        self.assertIn("unobserved_cve", step["warnings"])

    def test_step_evidence_path_is_parsed(self):
        self.write_artifact(
            "artifacts/generic.json",
            json.dumps([{"cve_id": "CVE-2026-0001", "asset": "app.example.test"}]),
        )
        steps = _copy(FOOTHOLD_STEPS)
        steps[0]["evidence_path"] = "artifacts/generic.json"
        record = self.plan(steps=steps, artifacts=None)
        step = {item["cve_id"]: item for item in record["steps"]}["CVE-2026-0001"]
        self.assertTrue(step["observed"])
        self.assertEqual(step["evidence_path"], "artifacts/generic.json")
        self.assertEqual(
            step["observation_locations"][0]["source"], "generic"
        )

    def test_malformed_artifact_line_is_refused_with_location(self):
        self.write_artifact(
            "artifacts/broken.jsonl",
            json.dumps({"template-id": "x", "info": {}}) + "\n" + "this is not json\n",
        )
        error = self.assertRefused(
            "artifact_invalid",
            cve_chain.parse_artifacts,
            self.engagement_id,
            ["artifacts/broken.jsonl"],
        )
        self.assertEqual(error.details["path"], "artifacts/broken.jsonl")
        self.assertEqual(error.details["line"], 2)
        self.assertRefused(
            "artifact_invalid",
            self.plan,
            artifacts=["artifacts/broken.jsonl"],
        )

    def test_unknown_artifact_extension_is_refused(self):
        self.write_artifact("artifacts/notes.txt", "CVE-2026-0001\n")
        error = self.assertRefused(
            "artifact_invalid",
            cve_chain.parse_artifacts,
            self.engagement_id,
            ["artifacts/notes.txt"],
        )
        self.assertEqual(error.details["path"], "artifacts/notes.txt")

    def test_missing_artifact_file_is_refused(self):
        self.assertRefused(
            "artifact_invalid",
            cve_chain.parse_artifacts,
            self.engagement_id,
            ["artifacts/absent.jsonl"],
        )

    def test_invalid_json_artifact_is_refused(self):
        self.write_artifact("artifacts/broken.json", "{not json")
        error = self.assertRefused(
            "artifact_invalid",
            cve_chain.parse_artifacts,
            self.engagement_id,
            ["artifacts/broken.json"],
        )
        self.assertEqual(error.details["path"], "artifacts/broken.json")

    def test_unrecognized_json_structure_is_refused(self):
        self.write_artifact("artifacts/other.json", json.dumps({"foo": "bar"}))
        self.assertRefused(
            "artifact_invalid",
            cve_chain.parse_artifacts,
            self.engagement_id,
            ["artifacts/other.json"],
        )

    def test_malformed_cve_identifier_in_artifact_is_refused(self):
        self.write_artifact("artifacts/generic.json", json.dumps([{"cve_id": "CVE-26-1"}]))
        error = self.assertRefused(
            "artifact_invalid",
            cve_chain.parse_artifacts,
            self.engagement_id,
            ["artifacts/generic.json"],
        )
        self.assertIn("CVE-26-1", error.message)

    def test_non_cve_scanner_identifiers_are_ignored(self):
        self.write_artifact("artifacts/trivy.json", TRIVY_JSON)
        parsed = cve_chain.parse_artifacts(
            self.engagement_id, ["artifacts/trivy.json"]
        )
        self.assertEqual(sorted(parsed), ["CVE-2026-0003"])

    def test_empty_artifact_list_returns_no_observations(self):
        self.assertEqual(
            cve_chain.parse_artifacts(self.engagement_id, []), {}
        )

    def test_local_cve_database_marks_known_cves_verified(self):
        database = self.root / "cve.sqlite"
        connection = sqlite3.connect(database)
        try:
            connection.execute(
                "CREATE TABLE cves (cve_id TEXT PRIMARY KEY, description TEXT, "
                "cvss REAL, published TEXT, json TEXT)"
            )
            connection.execute(
                "INSERT INTO cves VALUES (?, ?, ?, ?, ?)",
                ("CVE-2026-0001", "example", 9.8, "2026-01-01", ""),
            )
            connection.commit()
        finally:
            connection.close()
        with patch.dict(os.environ, {"OPENCYBER_CVE_DB": str(database)}):
            record = self.plan()
        self.assertEqual(record["unverified_cves"], ["CVE-2026-0002"])
        steps_by_cve = {step["cve_id"]: step for step in record["steps"]}
        self.assertNotIn("unverified_cve", steps_by_cve["CVE-2026-0001"]["warnings"])
        self.assertIn("unverified_cve", steps_by_cve["CVE-2026-0002"]["warnings"])

    def test_offline_cve_lookup_failure_does_not_fail_planning(self):
        with patch(
            "opencyber.native_tools._local_cve_lookup",
            side_effect=ValueError("local CVE database is unreadable"),
        ):
            record = self.plan()
        self.assertEqual(record["verdict"], "complete")
        self.assertEqual(record["unverified_cves"], ["CVE-2026-0001", "CVE-2026-0002"])
        self.assertIn("unverified_cve", record["warnings"])

    def test_same_cve_in_multiple_artifacts_has_multiple_locations(self):
        self.write_artifact("artifacts/nuclei.jsonl", NUCLEI_JSONL)
        self.write_artifact(
            "artifacts/generic.json", json.dumps([{"cve_id": "CVE-2026-0001"}])
        )
        parsed = cve_chain.parse_artifacts(
            self.engagement_id, ["artifacts/nuclei.jsonl", "artifacts/generic.json"]
        )
        locations = parsed["CVE-2026-0001"]["locations"]
        self.assertEqual(len(locations), 2)
        self.assertEqual(
            [location["path"] for location in locations],
            ["artifacts/generic.json", "artifacts/nuclei.jsonl"],
        )

    def test_empty_jsonl_artifact_is_tolerated(self):
        self.write_artifact("artifacts/empty.jsonl", "\n\n")
        self.assertEqual(
            cve_chain.parse_artifacts(self.engagement_id, ["artifacts/empty.jsonl"]), {}
        )

    def test_nuclei_line_that_is_not_an_object_is_refused(self):
        self.write_artifact("artifacts/array.jsonl", "[]\n")
        error = self.assertRefused(
            "artifact_invalid",
            cve_chain.parse_artifacts,
            self.engagement_id,
            ["artifacts/array.jsonl"],
        )
        self.assertEqual(error.details["line"], 1)

    def test_trivy_artifact_without_results_wrapper_is_supported(self):
        self.write_artifact(
            "artifacts/trivy-flat.json",
            json.dumps(
                {
                    "ArtifactName": "app:2.0",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2026-0006", "PkgName": "zlib"}
                    ],
                }
            ),
        )
        parsed = cve_chain.parse_artifacts(
            self.engagement_id, ["artifacts/trivy-flat.json"]
        )
        self.assertEqual(sorted(parsed), ["CVE-2026-0006"])
        location = parsed["CVE-2026-0006"]["locations"][0]
        self.assertEqual(location["source"], "trivy")
        self.assertIn("Target=app:2.0", location["detail"])

    def test_generic_json_non_object_entry_is_refused(self):
        self.write_artifact("artifacts/generic.json", json.dumps(["CVE-2026-0001"]))
        self.assertRefused(
            "artifact_invalid",
            cve_chain.parse_artifacts,
            self.engagement_id,
            ["artifacts/generic.json"],
        )


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class ChainDeterminismTests(ChainTestCase):
    @staticmethod
    def _stable_payload(record):
        return {
            key: value
            for key, value in record.items()
            if key not in ("chain_id", "created_at", "chain_sha256")
        }

    def test_identical_inputs_produce_identical_canonical_payloads(self):
        self.write_artifact_bundle()
        artifacts = ["artifacts/nuclei.jsonl", "artifacts/generic.json"]
        first = self.plan(chain_name="stable", artifacts=artifacts)
        second = self.plan(chain_name="stable", artifacts=artifacts)
        self.assertNotEqual(first["chain_id"], second["chain_id"])
        self.assertEqual(
            canonical_json(self._stable_payload(first)),
            canonical_json(self._stable_payload(second)),
        )
        self.assertEqual(first["chain_sha256"], second["chain_sha256"])

    def test_persisted_record_is_canonical_and_atomic(self):
        record = self.plan()
        path = self.chain_path(record["chain_id"])
        self.assertTrue(path.is_file())
        self.assertEqual(path.read_bytes(), canonical_json(record) + b"\n")
        leftovers = [
            item.name
            for item in path.parent.iterdir()
            if item.name.endswith(".tmp")
        ]
        self.assertEqual(leftovers, [])


# ---------------------------------------------------------------------------
# Persistence: load / list / audit
# ---------------------------------------------------------------------------


class ChainPersistenceTests(ChainTestCase):
    def test_audit_event_is_recorded(self):
        record = self.plan()
        events = audit.read_audit(
            self.engagement_id, event="poc.chain.created"
        )["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["chain_id"], record["chain_id"])
        self.assertEqual(events[0]["verdict"], "complete")
        self.assertEqual(events[0]["steps"], 2)
        self.assertTrue(audit.verify_audit(self.engagement_id)["valid"])

    def test_load_chain_roundtrip(self):
        record = self.plan()
        self.assertEqual(
            cve_chain.load_chain(self.engagement_id, record["chain_id"]), record
        )

    def test_load_chain_unknown_and_invalid_ids(self):
        unknown = "chain_20260101_" + "0" * 32
        error = self.assertRefused(
            "unknown_chain", cve_chain.load_chain, self.engagement_id, unknown
        )
        self.assertEqual(error.details["chain_id"], unknown)
        self.assertRefused(
            "invalid_id", cve_chain.load_chain, self.engagement_id, "not-a-chain-id"
        )

    def test_load_chain_detects_tampering(self):
        record = self.plan()
        path = self.chain_path(record["chain_id"])
        data = json.loads(path.read_text(encoding="utf-8"))
        data["verdict"] = "incomplete"
        path.write_bytes(canonical_json(data) + b"\n")
        self.assertRefused(
            "chain_invalid", cve_chain.load_chain, self.engagement_id, record["chain_id"]
        )

    def test_load_chain_detects_corrupt_json(self):
        chain_id = "chain_20260101_" + "1" * 32
        path = self.chain_path(chain_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        self.assertRefused(
            "chain_invalid", cve_chain.load_chain, self.engagement_id, chain_id
        )

    def test_list_chains_returns_newest_first_summaries(self):
        first = self.plan(chain_name="first")
        second = self.plan(chain_name="second")
        listing = cve_chain.list_chains(self.engagement_id)
        self.assertEqual(listing["engagement_id"], self.engagement_id)
        self.assertEqual(listing["invalid"], [])
        self.assertEqual(len(listing["chains"]), 2)
        created = [summary["created_at"] for summary in listing["chains"]]
        self.assertEqual(created, sorted(created, reverse=True))
        summaries = {summary["chain_id"]: summary for summary in listing["chains"]}
        self.assertEqual(set(summaries), {first["chain_id"], second["chain_id"]})
        for summary in summaries.values():
            self.assertEqual(summary["verdict"], "complete")
            self.assertEqual(summary["steps"], 2)
            self.assertIn(summary["chain_name"], {"first", "second"})
            self.assertTrue(summary["created_at"].endswith("Z"))

    def test_load_chain_rejects_records_bound_to_another_id_or_schema(self):
        mutations = {
            "chain_id": "chain_20260101_" + "9" * 32,
            "schema_version": 2,
            "engagement_id": "eng_20260101_" + "9" * 32,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                record = self.plan()
                path = self.chain_path(record["chain_id"])
                data = json.loads(path.read_text(encoding="utf-8"))
                data[field] = value
                path.write_bytes(canonical_json(data) + b"\n")
                self.assertRefused(
                    "chain_invalid",
                    cve_chain.load_chain,
                    self.engagement_id,
                    record["chain_id"],
                )

    def test_list_chains_reports_non_directory_chains_path(self):
        chains_path = poc_path(self.engagement_id, "chains")
        chains_path.parent.mkdir(parents=True, exist_ok=True)
        chains_path.write_text("not a directory", encoding="utf-8")
        listing = cve_chain.list_chains(self.engagement_id)
        self.assertEqual(listing["chains"], [])
        self.assertEqual(listing["invalid"][0]["file"], "chains")
        self.assertIn("not a directory", listing["invalid"][0]["error"])

    def test_list_chains_reports_invalid_file_names(self):
        chains_dir = poc_path(self.engagement_id, "chains")
        chains_dir.mkdir(parents=True, exist_ok=True)
        (chains_dir / "notes.json").write_text("{}", encoding="utf-8")
        listing = cve_chain.list_chains(self.engagement_id)
        self.assertEqual(listing["chains"], [])
        self.assertEqual(listing["invalid"][0]["file"], "notes.json")
        self.assertIn("invalid_id", listing["invalid"][0]["error"])

    def test_list_chains_tolerates_corrupt_and_tampered_files(self):
        good = self.plan(chain_name="good")
        corrupt_id = "chain_20260101_" + "2" * 32
        self.chain_path(corrupt_id).write_text("{broken", encoding="utf-8")
        tampered = self.plan(chain_name="tampered")
        tampered_path = self.chain_path(tampered["chain_id"])
        data = json.loads(tampered_path.read_text(encoding="utf-8"))
        data["chain_name"] = "rewritten"
        tampered_path.write_bytes(canonical_json(data) + b"\n")
        # Ignored: hidden temp files and non-JSON files.
        (self.chain_path(good["chain_id"]).parent / ".stale.tmp").write_text(
            "junk", encoding="utf-8"
        )
        listing = cve_chain.list_chains(self.engagement_id)
        self.assertEqual([summary["chain_id"] for summary in listing["chains"]], [good["chain_id"]])
        invalid_files = {entry["file"] for entry in listing["invalid"]}
        self.assertEqual(
            invalid_files,
            {f"{corrupt_id}.json", f"{tampered['chain_id']}.json"},
        )
        self.assertTrue(
            all("error" in entry for entry in listing["invalid"]),
        )
        tampered_entry = next(
            entry for entry in listing["invalid"] if entry["chain_id"] == tampered["chain_id"]
        )
        self.assertIn("chain_invalid", tampered_entry["error"])

    def test_list_chains_is_empty_without_records(self):
        self.assertEqual(
            cve_chain.list_chains(self.engagement_id),
            {"engagement_id": self.engagement_id, "chains": [], "invalid": []},
        )


if __name__ == "__main__":
    unittest.main()
