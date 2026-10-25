import asyncio
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

import opencyber.executor as executor
import opencyber.engagements as engagements
from opencyber.execution_tools import execute_bash, execute_python


class ExecutorTests(unittest.IsolatedAsyncioTestCase):
    async def test_arguments_are_not_shell_interpreted(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            marker = root / "injected"
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                result = await executor.execute_tool(
                    "printf",
                    ["%s", f"$(touch {marker})"],
                    engagement_id=engagement["engagement_id"],
                    working_directory=".",
                )
            self.assertTrue(result["success"])
            self.assertIn("$(touch", result["stdout"])
            self.assertFalse(marker.exists())

    async def test_working_directory_cannot_escape_workspace(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                with self.assertRaises(ValueError):
                    engagements.resolve_engagement_path(
                        engagement["engagement_id"],
                        "../outside",
                        must_exist=False,
                    )

    async def test_output_is_not_truncated(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            payload = "x" * 200_000
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                result = await executor.execute_tool(
                    "python3",
                    ["-c", "print('x' * 200000, end='')"],
                    engagement_id=engagement["engagement_id"],
                )
            self.assertEqual(result["stdout"], payload)

    async def test_long_tool_does_not_block_another_call(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                engagement_id = engagement["engagement_id"]
                long_call = asyncio.create_task(
                    executor.execute_tool("sleep", ["30"], engagement_id=engagement_id)
                )
                await asyncio.sleep(0.05)
                quick = await asyncio.wait_for(
                    executor.execute_tool("printf", ["ready"], engagement_id=engagement_id),
                    timeout=1.0,
                )
                self.assertEqual(quick["stdout"], "ready")
                long_call.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await long_call

    async def test_cancellation_terminates_the_process_group(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                task = asyncio.create_task(
                    executor.execute_tool(
                        "python3",
                        [
                            "-c",
                            "import subprocess,time; subprocess.Popen(['sleep','30']); time.sleep(30)",
                        ],
                        engagement_id=engagement["engagement_id"],
                    )
                )
                await asyncio.sleep(0.1)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, timeout=3.0)

    async def test_bash_supports_pipelines_stdin_and_environment(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                result = await execute_bash(
                    engagement["engagement_id"],
                    "read value; printf '%s:%s' \"$OPENCYBER_TEST\" \"$value\" | tr a-z A-Z",
                    stdin="input\n",
                    environment={"OPENCYBER_TEST": "ready"},
                )
                self.assertTrue(result["success"])
                self.assertEqual(result["stdout"], "READY:INPUT")

    async def test_python_supports_inline_and_workspace_files(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                engagement_id = engagement["engagement_id"]
                inline = await execute_python(
                    engagement_id,
                    source="import json,sys; print(json.dumps({'arg': sys.argv[1]}))",
                    script_arguments=["value"],
                )
                self.assertIn('"arg": "value"', inline["stdout"])
                script = Path(engagement["workspace"]) / "script.py"
                script.write_text("print('workspace-script')\n", encoding="utf-8")
                file_result = await execute_python(engagement_id, path="script.py")
                self.assertEqual(file_result["stdout"], "workspace-script\n")
                with self.assertRaises(ValueError):
                    await execute_python(engagement_id)

    async def test_approval_key_is_not_inherited_by_tool_children(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.dict(
                "os.environ",
                {
                    "OPENCYBER_APPROVAL_KEY": "k" * 64,
                    "OPENCYBER_APPROVAL_KEY_FILE": "/run/secrets/approval",
                },
            ):
                with patch.object(engagements, "WORKSPACE", root):
                    engagement = engagements.create_engagement("Test", ["example.test"])
                    result = await executor.execute_tool(
                        "python3",
                        [
                            "-c",
                            "import os; print(os.environ.get('OPENCYBER_APPROVAL_KEY', 'missing'),"
                            " os.environ.get('OPENCYBER_APPROVAL_KEY_FILE', 'missing'))",
                        ],
                        engagement_id=engagement["engagement_id"],
                    )
            self.assertTrue(result["success"])
            self.assertEqual(result["stdout"].strip(), "missing missing")

    async def test_preflight_replaces_the_optional_scope_check(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.dict("os.environ", {"OPENCYBER_ENFORCE_SCOPE": "1"}):
                with patch.object(engagements, "WORKSPACE", root):
                    engagement = engagements.create_engagement("Test", ["127.0.0.1"])
                    engagement_id = engagement["engagement_id"]
                    with self.assertRaises(ValueError):
                        await executor.execute_tool(
                            "python3", ["-c", "print('blocked')"], engagement_id=engagement_id
                        )
                    result = await executor.execute_tool(
                        "python3",
                        ["-c", "print('allowed')"],
                        engagement_id=engagement_id,
                        preflight={"candidates": ["127.0.0.1"]},
                    )
            self.assertTrue(result["success"])
            self.assertEqual(result["stdout"], "allowed\n")
            self.assertTrue(result["scope_enforced"])


if __name__ == "__main__":
    unittest.main()


class BoundedExecutionTests(unittest.IsolatedAsyncioTestCase):
    """Every executable-backed call runs under a named deadline and output cap."""

    def _workspace(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return temporary, Path(temporary.name).resolve()

    async def test_a_normal_run_reports_completion(self):
        temporary, root = self._workspace()
        with patch.object(engagements, "WORKSPACE", root):
            engagement = engagements.create_engagement("Test", ["example.test"])
            result = await executor.execute_tool(
                "printf", ["ready"], engagement_id=engagement["engagement_id"]
            )
        self.assertTrue(result["ok"])
        self.assertTrue(result["success"])
        self.assertEqual(result["stdout"], "ready")
        self.assertFalse(result["truncated"])
        self.assertFalse(result["timed_out"])
        self.assertNotIn("error", result)

    async def test_a_non_zero_exit_completes_without_an_error_object(self):
        temporary, root = self._workspace()
        with patch.object(engagements, "WORKSPACE", root):
            engagement = engagements.create_engagement("Test", ["example.test"])
            result = await executor.execute_tool(
                "sh", ["-c", "exit 1"], engagement_id=engagement["engagement_id"]
            )
        self.assertTrue(result["ok"])
        self.assertFalse(result["success"])
        self.assertEqual(result["returncode"], 1)
        self.assertNotIn("error", result)

    async def test_deadline_stops_the_process_group(self):
        temporary, root = self._workspace()
        with patch.dict("os.environ", {"OPENCYBER_TOOL_TIMEOUT_S": "0.5"}):
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                result = await executor.execute_tool(
                    "sleep", ["30"], engagement_id=engagement["engagement_id"]
                )
        self.assertFalse(result["ok"])
        self.assertFalse(result["success"])
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["error"]["code"], "timed_out")
        self.assertEqual(result["error"]["limit"]["id"], "tool.timeout_s")
        self.assertLess(result["returncode"], 0)
        self.assertIn("incomplete", result["limitations"][0].lower())

    async def test_output_cap_marks_partial_and_names_the_limit(self):
        temporary, root = self._workspace()
        with patch.dict("os.environ", {"OPENCYBER_TOOL_MAX_OUTPUT_BYTES": "1000"}):
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                result = await executor.execute_tool(
                    "python3",
                    ["-c", "print('y' * 50000, end='')"],
                    engagement_id=engagement["engagement_id"],
                )
        self.assertTrue(result["ok"])
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["stdout"]), 1000)
        self.assertGreaterEqual(result["stdout_bytes"], 50000)
        self.assertEqual(result["coverage"]["status"], "partial")
        self.assertEqual(result["limit"]["id"], "tool.max_output_bytes")
        self.assertEqual(result["limit"]["effective"], 1000)

    async def test_zero_disables_both_ceilings(self):
        temporary, root = self._workspace()
        payload = "z" * 3000
        with patch.dict("os.environ", {"OPENCYBER_TOOL_MAX_OUTPUT_BYTES": "0", "OPENCYBER_TOOL_TIMEOUT_S": "0"}):
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                result = await executor.execute_tool(
                    "python3",
                    ["-c", "print('z' * 3000, end='')"],
                    engagement_id=engagement["engagement_id"],
                )
        self.assertEqual(result["stdout"], payload)
        self.assertFalse(result["truncated"])
        self.assertEqual(result["timeout_s"], 0)

    async def test_invalid_environment_ceiling_fails_closed(self):
        from opencyber.errors import OcError

        temporary, root = self._workspace()
        with patch.dict("os.environ", {"OPENCYBER_TOOL_TIMEOUT_S": "-5"}):
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                with self.assertRaises(OcError) as raised:
                    await executor.execute_tool("printf", ["x"], engagement_id=engagement["engagement_id"])
        self.assertEqual(raised.exception.code, "invalid_argument")
        self.assertEqual(raised.exception.details["setting"], "OPENCYBER_TOOL_TIMEOUT_S")

    async def test_cancellation_kills_a_descendant_that_ignores_term(self):
        temporary, root = self._workspace()
        marker = root / "descendant.pid"
        descendant = None
        task = None
        try:
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                code = (
                    "import pathlib,subprocess,sys,time; "
                    "p=subprocess.Popen([sys.executable,'-c',"
                    "'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)'],"
                    "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                    "time.sleep(.1); pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(60)"
                )
                task = asyncio.create_task(executor.execute_tool(
                    "python3", ["-c", code, str(marker)], engagement["engagement_id"]
                ))
                for _ in range(200):
                    if marker.exists():
                        break
                    await asyncio.sleep(.01)
                self.assertTrue(marker.exists(), "test child did not start")
                descendant = int(marker.read_text())
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 4)
                await asyncio.sleep(.05)
                status = Path(f"/proc/{descendant}/stat")
                self.assertTrue(not status.exists() or status.read_text().split()[2] == "Z",
                                "cancelled tool left a live descendant")
        finally:
            if task is not None and not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            if descendant is not None:
                try:
                    os.kill(descendant, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    async def test_deadline_includes_a_child_that_never_reads_stdin(self):
        temporary, root = self._workspace()
        with patch.dict("os.environ", {"OPENCYBER_TOOL_TIMEOUT_S": "0.1"}):
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                result = await asyncio.wait_for(executor.execute_tool(
                    "sleep", ["30"], engagement["engagement_id"], stdin="x" * (2 * 1024 * 1024)
                ), 3)
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["error"]["code"], "timed_out")

    async def test_invalid_limit_is_rejected_before_any_child_side_effect(self):
        from opencyber.errors import OcError

        temporary, root = self._workspace()
        marker = root / "started"
        with patch.dict("os.environ", {"OPENCYBER_TOOL_TIMEOUT_S": "-1"}):
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                with self.assertRaises(OcError):
                    await executor.execute_tool(
                        "python3", ["-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()", str(marker)],
                        engagement["engagement_id"],
                    )
                await asyncio.sleep(.1)
        self.assertFalse(marker.exists())
