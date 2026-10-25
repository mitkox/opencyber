"""Client-visible authority must cover the operations an interface can perform."""
from __future__ import annotations

import asyncio
import unittest

from opencyber.catalog import CATALOG
from opencyber.server import mcp


class AuthorityBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = {tool.name: tool.model_dump(by_alias=True) for tool in asyncio.run(mcp.list_tools())}

    def test_artifact_and_state_mutations_are_not_advertised_read_only(self):
        # Reports are persisted, sessions are created/closed, serial reads
        # consume buffered data, and network_log(clear=True) removes its log.
        for name in (
            "oc_openapi_audit", "oc_graphql_audit", "oc_jwt_audit",
            "oc_firmware_analyze", "oc_file_triage", "oc_log_timeline", "oc_pcap_triage",
            "oc_browser_create", "oc_browser_close", "oc_browser_network_log",
            "oc_serial_open", "oc_serial_read", "oc_serial_close",
        ):
            with self.subTest(tool=name):
                tool = self.tools[name]
                self.assertFalse(tool["annotations"]["readOnlyHint"])
                self.assertFalse(tool["annotations"]["idempotentHint"])
                self.assertIn("mutation", tool["_meta"]["opencyber"]["effects"])

    def test_engagement_declarations_match_the_actual_public_argument_contract(self):
        for name, tool in self.tools.items():
            with self.subTest(tool=name):
                required = "engagement_id" in tool["inputSchema"].get("required", [])
                self.assertEqual(tool["_meta"]["opencyber"]["requires_engagement"], required)

    def test_unrestricted_executable_arguments_do_not_promise_nondestructive_updates(self):
        # Category alone cannot rule out flags such as curl -X DELETE,
        # debugger code execution, packet injection or firmware writes.
        for spec in CATALOG:
            with self.subTest(tool=spec.name):
                self.assertFalse(self.tools[spec.name]["annotations"]["readOnlyHint"])
                self.assertTrue(self.tools[spec.name]["annotations"]["destructiveHint"])

    def test_target_selected_titles_paths_and_device_labels_are_untrusted_content(self):
        for name in (
            "oc_workspace_list", "oc_process_snapshot", "oc_http_session_list",
            "oc_http_session_get", "oc_http_session_update", "oc_browser_list",
            "oc_browser_get", "oc_browser_set_state", "oc_hardware_inventory",
            "oc_hardware_readiness", "oc_audit_log",
        ):
            with self.subTest(tool=name):
                self.assertTrue(self.tools[name]["_meta"]["opencyber"]["returns_target_content"])

    def test_replacement_clearing_and_arbitrary_execution_declare_destructive_authority(self):
        for name in (
            "oc_execute", "oc_poc_run", "oc_finding_report", "oc_browser_screenshot",
            "oc_browser_network_log", "oc_firmware_analyze", "oc_serial_open",
        ):
            with self.subTest(tool=name):
                self.assertTrue(self.tools[name]["annotations"]["destructiveHint"])
