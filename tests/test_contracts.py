from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from opencyber.catalog import CATALOG
from opencyber.contracts import (
    CONTRACTS,
    NATIVE_CONTRACTS_COUNT,
    Effect,
    Scope,
    Shape,
    contract_for,
    native_groups,
    validate,
)
from opencyber.diagnostics import FIXED_MCP_TOOL_COUNT, FIXED_TOOL_CATEGORIES
from opencyber.server import mcp


class ContractInventoryTests(unittest.TestCase):
    def test_every_advertised_tool_has_a_contract(self):
        advertised = set(mcp._tool_manager._tools)
        self.assertEqual(advertised, set(CONTRACTS))

    def test_counts_match_the_catalog_and_fixed_inventory(self):
        executable = [contract for contract in CONTRACTS.values() if contract.kind == "executable"]
        native = [contract for contract in CONTRACTS.values() if contract.kind == "native"]
        self.assertEqual(len(executable), len(CATALOG))
        self.assertEqual(len(native), NATIVE_CONTRACTS_COUNT)
        self.assertEqual(len(native), FIXED_MCP_TOOL_COUNT)
        self.assertEqual(len(CONTRACTS), len(CATALOG) + FIXED_MCP_TOOL_COUNT)

    def test_native_groups_match_the_derived_inventory(self):
        self.assertEqual(native_groups(), FIXED_TOOL_CATEGORIES)

    def test_validate_rejects_an_advertised_tool_without_a_contract(self):
        validate(["oc_catalog"])
        with self.assertRaises(RuntimeError):
            validate(["oc_catalog", "oc_does_not_exist"])

    def test_contract_for_unknown_name_fails_closed(self):
        with self.assertRaises(KeyError):
            contract_for("oc_does_not_exist")


class ContractInvariantTests(unittest.TestCase):
    def test_enum_vocabularies_are_complete(self):
        self.assertEqual(
            {shape.value for shape in Shape},
            {"inspect", "search", "trace", "compare", "workflow", "observe", "execute", "manage"},
        )
        self.assertEqual(
            {effect.value for effect in Effect},
            {"process", "filesystem", "network", "device", "secret", "mutation"},
        )
        self.assertEqual(
            {scope.value for scope in Scope},
            {"none", "argv", "url", "device", "engagement"},
        )

    def test_every_contract_is_internally_consistent(self):
        for contract in CONTRACTS.values():
            with self.subTest(tool=contract.name):
                self.assertEqual(contract.name, contract.name.strip())
                self.assertIn(contract.kind, {"native", "executable"})
                self.assertIsInstance(contract.shape, Shape)
                self.assertIsInstance(contract.scope, Scope)
                self.assertTrue(contract.error_codes)
                self.assertEqual(tuple(sorted(contract.error_codes)), contract.error_codes)
                if contract.kind == "executable":
                    self.assertTrue(contract.requires_engagement)
                    self.assertEqual(contract.scope, Scope.ARGV)
                    self.assertTrue(contract.returns_target_content)

    def test_read_only_never_claims_authority_it_lacks(self):
        for contract in CONTRACTS.values():
            with self.subTest(tool=contract.name):
                if contract.read_only:
                    self.assertFalse(contract.destructive)
                    self.assertNotIn(Effect.MUTATION, contract.effects)

    def test_mutation_implies_not_idempotent_unless_declared(self):
        # A tool that mutates and claims idempotence must be intentionally marked.
        for contract in CONTRACTS.values():
            if Effect.MUTATION in contract.effects and contract.idempotent:
                self.assertIn(
                    contract.name,
                    {"oc_workspace_write"},
                    f"{contract.name} mutates but claims idempotence",
                )

    def test_provenance_source_matches_target_content(self):
        for contract in CONTRACTS.values():
            with self.subTest(tool=contract.name):
                if contract.returns_target_content:
                    self.assertEqual(contract.provenance_source, "target")
                elif contract.requires_engagement:
                    self.assertEqual(contract.provenance_source, "engagement")
                else:
                    self.assertEqual(contract.provenance_source, "server")

    def test_known_authorities(self):
        jwt = contract_for("oc_jwt_decode")
        self.assertTrue(jwt.read_only)
        self.assertEqual(jwt.scope, Scope.NONE)
        self.assertFalse(jwt.requires_engagement)

        bash = contract_for("oc_bash")
        self.assertTrue(bash.destructive)
        self.assertFalse(bash.read_only)
        self.assertTrue(bash.open_world)
        self.assertEqual(bash.scope, Scope.NONE)

        nmap = contract_for("oc_nmap")
        self.assertEqual(nmap.kind, "executable")
        self.assertEqual(nmap.group, "network")
        self.assertTrue(nmap.requires_engagement)
        self.assertTrue(nmap.returns_target_content)

        poc_run = contract_for("oc_poc_run")
        self.assertIn("authorization_required", poc_run.error_codes)
        self.assertIn("approval_invalid", poc_run.error_codes)

    def test_arbitrary_network_actions_do_not_advertise_read_only_authority(self):
        # These interfaces accept caller-selected methods, GraphQL mutations,
        # form actions, or JavaScript with arbitrary target side effects.
        for name in (
            "oc_http_request", "oc_graphql_request", "oc_api_fuzz",
            "oc_http_repeater", "oc_http_intruder", "oc_browser_navigate",
            "oc_browser_action", "oc_browser_evaluate",
        ):
            with self.subTest(tool=name):
                tool = mcp._tool_manager._tools[name]
                self.assertFalse(tool.annotations.read_only_hint)
                self.assertTrue(tool.annotations.destructive_hint)
                self.assertIn(Effect.MUTATION, contract_for(name).effects)


class ContractAdvertisementTests(unittest.TestCase):
    def test_annotations_are_advertised(self):
        tool = mcp._tool_manager._tools["oc_catalog"]
        self.assertIsNotNone(tool.annotations)
        self.assertTrue(tool.annotations.read_only_hint)
        self.assertFalse(tool.annotations.destructive_hint)
        self.assertFalse(tool.annotations.open_world_hint)
        self.assertEqual(tool.annotations.title, "Catalog")

    def test_meta_carries_the_contract_block(self):
        tool = mcp._tool_manager._tools["oc_poc_run"]
        self.assertIsNotNone(tool.meta)
        block = tool.meta["opencyber"]
        self.assertEqual(block["contract_schema_version"], 1)
        self.assertEqual(block["kind"], "native")
        self.assertEqual(block["group"], "poc_chain")
        self.assertEqual(block["shape"], "execute")
        self.assertEqual(block["scope"], "engagement")
        self.assertTrue(block["requires_engagement"])
        self.assertTrue(block["returns_target_content"])

    def test_advertised_json_catalog_reports_contract_groups(self):
        catalog = asyncio.run(mcp.call_tool("oc_catalog", {"include_all": False})).structured_content
        native_groups_seen = set(catalog["native_category_counts"])
        self.assertIn("poc_chain", native_groups_seen)
        self.assertIn("browser", native_groups_seen)
        self.assertNotIn("native", native_groups_seen)

    def test_wire_annotations_keep_protocol_aliases_after_sdk_migration(self):
        advertised = next(tool for tool in asyncio.run(mcp.list_tools()) if tool.name == "oc_catalog")
        wire = advertised.model_dump(by_alias=True, exclude_none=True)
        self.assertTrue(wire["annotations"]["readOnlyHint"])
        self.assertFalse(wire["annotations"]["destructiveHint"])
        self.assertIn("inputSchema", wire)
        self.assertIn("outputSchema", wire)
        self.assertIn("opencyber", wire["_meta"])

    def test_binding_does_not_change_advertised_input_schema(self):
        # The envelope is bound after registration. If a future refactor moves
        # wrapping before registration, this row protects the generated schema.
        tool = mcp._tool_manager._tools["oc_nmap"]
        self.assertEqual(tool.parameters["required"], ["engagement_id", "arguments"])
        encoded = json.dumps(tool.parameters, sort_keys=True)
        self.assertIn('"working_directory"', encoded)
        self.assertIn('"stdin"', encoded)

    def test_mcp2_stdio_keeps_identity_wire_metadata_and_structured_refusals(self):
        from opencyber import __version__
        from tests.mcp_smoke import receive, send, structured_result

        with tempfile.TemporaryDirectory() as directory:
            environment = dict(os.environ, OPENCYBER_WORKSPACE=directory, OPENCYBER_MCP_MODE="compact")
            environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
            with subprocess.Popen([sys.executable, "-m", "opencyber.server"], env=environment,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, bufsize=1) as process:
                try:
                    send(process, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                        "protocolVersion": "2025-11-25", "capabilities": {},
                        "clientInfo": {"name": "opencyber-sdk-migration", "version": "1"},
                    }})
                    initialized = receive(process, 1, timeout=10)["result"]
                    self.assertEqual(initialized["serverInfo"]["name"], "OpenCyber Harness")
                    self.assertEqual(initialized["serverInfo"]["version"], __version__)
                    self.assertIn("authorized targets", initialized["instructions"])
                    send(process, {"jsonrpc": "2.0", "method": "notifications/initialized"})
                    send(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
                    tools = receive(process, 2)["result"]["tools"]
                    self.assertEqual(len(tools), NATIVE_CONTRACTS_COUNT)
                    advertised = next(tool for tool in tools if tool["name"] == "oc_http_request")
                    self.assertFalse(advertised["annotations"]["readOnlyHint"])
                    self.assertIn("inputSchema", advertised)
                    self.assertIn("outputSchema", advertised)
                    self.assertIn("opencyber", advertised["_meta"])
                    send(process, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                        "name": "oc_workspace_read", "arguments": {
                            "engagement_id": "eng_20260101_" + "a" * 32, "path": "missing.txt",
                        },
                    }})
                    refused = receive(process, 3)
                    self.assertNotIn("error", refused)
                    payload = structured_result(refused)
                    self.assertFalse(payload["ok"])
                    self.assertEqual(payload["error"]["code"], "engagement_not_found")
                    self.assertEqual(payload["contract"]["server_version"], __version__)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


class PocRefusalAdapterTests(unittest.TestCase):
    """Legacy PoC refusals must also satisfy the shared contract."""

    def test_poc_refusal_carries_a_registered_code_and_unknown_coverage(self):
        from opencyber.poc_schema import PocError
        from opencyber.server import _poc_refusal

        payload = _poc_refusal(PocError("unknown_spec", "no spec with that id", spec_id="spec_x"))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["status"], "refused")
        self.assertEqual(payload["reason"], "unknown_spec")
        self.assertEqual(payload["error"]["code"], "not_found")
        self.assertEqual(payload["error"]["category"], "not_found")
        self.assertEqual(payload["error"]["details"], {"spec_id": "spec_x"})
        self.assertEqual(payload["coverage"]["status"], "unknown")
        self.assertIn("refused before performing target work", payload["limitations"][0])

    def test_unmapped_poc_reason_fails_closed_as_invalid_argument(self):
        from opencyber.poc_schema import PocError
        from opencyber.server import _poc_refusal

        payload = _poc_refusal(PocError("invented_reason", "unknown reason"))
        self.assertEqual(payload["error"]["code"], "invalid_argument")

    def test_authorization_refusal_maps_to_denied(self):
        from opencyber.poc_schema import PocError
        from opencyber.server import _poc_refusal

        payload = _poc_refusal(PocError("authorization_required", "no signed authorization"))
        self.assertEqual(payload["error"]["code"], "authorization_required")
        self.assertEqual(payload["error"]["category"], "denied")


if __name__ == "__main__":
    unittest.main()
