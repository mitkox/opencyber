from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
PUBLISH_WORKFLOW = (ROOT / ".github/workflows/publish-container.yml").read_text(encoding="utf-8")
CANDIDATE_PATH = ROOT / ".github/workflows/build-candidate.yml"
CANDIDATE_WORKFLOW = CANDIDATE_PATH.read_text(encoding="utf-8") if CANDIDATE_PATH.exists() else ""
CI_WORKFLOW = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
IMAGE_SMOKE_WORKFLOW = (ROOT / ".github/workflows/image-smoke.yml").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
SBOM_SCRIPT = (ROOT / "scripts/generate-sbom.sh").read_text(encoding="utf-8")
LICENSE_SCRIPT = (ROOT / "scripts/generate-license-bundle.sh").read_text(encoding="utf-8")


class DistributionComplianceTests(unittest.TestCase):
    def test_base_images_are_digest_pinned(self) -> None:
        from_lines = [line for line in DOCKERFILE.splitlines() if line.startswith("FROM ")]
        self.assertGreaterEqual(len(from_lines), 4)
        external = [line for line in from_lines if "FROM runtime " not in line and "FROM scratch " not in line]
        self.assertTrue(all("@sha256:" in line for line in external))

    def test_mutable_download_selectors_are_not_used(self) -> None:
        self.assertNotRegex(DOCKERFILE, re.compile(r"go install .*@latest"))
        self.assertNotIn("/releases/latest/", DOCKERFILE)

    def test_downloaded_assets_are_checksum_verified(self) -> None:
        self.assertIn("NUCLEI_TEMPLATES_SHA256", DOCKERFILE)
        self.assertIn("/out/yq /usr/local/bin/yq", DOCKERFILE)
        self.assertEqual(DOCKERFILE.count("sha256sum -c -"), 1)
        self.assertIn("ADD --checksum=sha256:", DOCKERFILE)

    def test_restricted_packages_are_not_installed(self) -> None:
        runtime = DOCKERFILE.split(" AS runtime", 1)[1]
        install_block = runtime.split("apt-get install -y --no-install-recommends", 1)[1]
        install_block = install_block.split("&& apt-get clean", 1)[0]
        packages = {
            line.strip().removesuffix("\\").strip()
            for line in install_block.splitlines()
            if line.strip()
        }
        self.assertTrue({"burpsuite", "maltego", "terrascan", "scoutsuite"}.isdisjoint(packages))
        self.assertTrue({"wpscan", "nmap", "autorecon", "netexec", "rustscan"}.issubset(packages))
        self.assertIn("whatweb", packages)
        self.assertIn("ripgrep", packages)
        self.assertNotIn("github.com/tomnomnom/waybackurls", DOCKERFILE)

    def test_sources_are_exported_from_a_separate_target_with_build_caches_preserved(self) -> None:
        self.assertIn("FROM scratch AS corresponding-source", DOCKERFILE)
        self.assertIn("FROM runtime AS final", DOCKERFILE)
        self.assertIn("go-modules.tar.gz", DOCKERFILE)
        self.assertIn("rust-crates.tar.gz", DOCKERFILE)
        self.assertIn("capture-corresponding-source.py", DOCKERFILE)
        self.assertIn("apt-public-exclusions.pref", DOCKERFILE)

    def test_kali_package_set_uses_the_pinned_security_updated_base(self) -> None:
        self.assertIn("kalilinux/kali-rolling:latest@sha256:", DOCKERFILE)

    def test_notices_and_source_offer_are_embedded(self) -> None:
        self.assertIn("THIRD_PARTY_NOTICES.md SOURCE_OFFER.md", DOCKERFILE)
        self.assertIn("/usr/share/opencyber/licenses", DOCKERFILE)

    def test_offline_harness_assets_are_baked_into_the_image(self) -> None:
        self.assertIn("nuclei-templates", DOCKERFILE)
        self.assertIn("opencyber-keyboard-patterns.txt", DOCKERFILE)
        self.assertIn("ln -sfn /usr/share/seclists seclists", DOCKERFILE)
        self.assertIn("scripts/build-go-tools.sh", DOCKERFILE)
        # The nuclei store must be a real directory; a symlink silently disables
        # template discovery.
        self.assertIn("mkdir -p /root/.local/nuclei-templates", DOCKERFILE)
        self.assertNotIn("ln -sfn /usr/share/nuclei-templates /root/.local", DOCKERFILE)

    def test_build_refuses_to_publish_a_degraded_image(self) -> None:
        self.assertIn("opencyber-doctor;", DOCKERFILE)
        self.assertIn("nuclei -tl -silent", DOCKERFILE)
        self.assertIn("HEALTHCHECK", DOCKERFILE)
        self.assertIn('CMD ["opencyber-doctor", "--quiet"]', DOCKERFILE)
        self.assertIn("missing hardware binary", DOCKERFILE)

    def test_hardware_toolchain_is_baked_into_the_image(self) -> None:
        for package in (
            "hackrf",
            "rtl-sdr",
            "rtl-433",
            "bladerf",
            "ubertooth",
            "bluez",
            "bettercap",
            "hcxdumptool",
            "proxmark3",
            "libnfc-bin",
            "openocd",
            "urjtag",
            "avrdude",
            "esptool",
            "stlink-tools",
            "flashrom",
            "sigrok-cli",
            "can-utils",
            "gpsd",
            "lirc",
            "qemu-system-arm",
        ):
            self.assertIn(package, DOCKERFILE)

    def test_hardware_and_airgap_assets_are_embedded(self) -> None:
        self.assertIn("packaging/99-opencyber-hw.rules", DOCKERFILE)
        self.assertIn("/usr/share/opencyber/host/", DOCKERFILE)
        self.assertIn("docs/HARDWARE.md", DOCKERFILE)
        self.assertIn("docs/AIRGAP.md", DOCKERFILE)
        self.assertIn("opencyber-assets --write /usr/share/opencyber/asset-manifest.json", DOCKERFILE)

    def test_airgap_scripts_exist_and_are_executable(self) -> None:
        import os

        for script in (
            ROOT / "scripts/opencyber-run.sh",
            ROOT / "scripts/opencyber-airgap.sh",
        ):
            self.assertTrue(script.is_file(), script)
            self.assertTrue(os.access(script, os.X_OK), script)
            text = script.read_text(encoding="utf-8")
            self.assertIn("set -Eeuo pipefail", text)

    def test_mcp_dependency_uses_the_verified_2_x_api(self) -> None:
        self.assertIn('"mcp>=2.3,<3"', PYPROJECT)
        self.assertIn('"mcp==2.3.0"', DOCKERFILE)
        self.assertNotIn('"mcp>=2.3,<3"', DOCKERFILE)

    def test_python_and_container_playwright_versions_agree(self) -> None:
        import tomllib

        dependency = next(item for item in tomllib.loads(PYPROJECT)["project"]["dependencies"]
                          if item.startswith("playwright=="))
        self.assertIn(dependency, DOCKERFILE)

    def test_release_workflow_signs_provenance_and_sbom_attestations(self) -> None:
        self.assertGreaterEqual(PUBLISH_WORKFLOW.count("uses: actions/attest@"), 3)
        self.assertIn(
            "uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
            PUBLISH_WORKFLOW,
        )
        self.assertIn("sbom-path:", PUBLISH_WORKFLOW)
        self.assertIn("push-to-registry: true", PUBLISH_WORKFLOW)
        self.assertIn("LicenseRef-OpenCyber-Third-Party", DOCKERFILE)
        self.assertIn("IMAGE_NAME: mitkox/opencyber", PUBLISH_WORKFLOW)

    def test_release_workflow_verifies_version_compliance_and_signatures(self) -> None:
        self.assertIn("scripts/check-version-consistency.py --print", PUBLISH_WORKFLOW)
        self.assertIn("scripts/check-image-compliance.sh", CANDIDATE_WORKFLOW)
        self.assertIn("aquasecurity/trivy-action", CANDIDATE_WORKFLOW)
        self.assertIn('"cosign", "sign", "--yes"', (ROOT / "scripts/promote-images.py").read_text())
        self.assertIn("cosign verify", PUBLISH_WORKFLOW)

    def test_image_carries_the_release_version_label(self) -> None:
        self.assertIn("ARG OPENCYBER_VERSION=", DOCKERFILE)
        self.assertIn('com.opencyber.harness.version="${OPENCYBER_VERSION}"', DOCKERFILE)
        self.assertIn('org.opencontainers.image.version="${OPENCYBER_VERSION}"', DOCKERFILE)

    def test_actions_are_pinned_to_commit_shas(self) -> None:
        import re as _re

        for workflow in (CI_WORKFLOW, IMAGE_SMOKE_WORKFLOW, PUBLISH_WORKFLOW, CANDIDATE_WORKFLOW):
            for line in workflow.splitlines():
                if "uses:" not in line or line.strip().startswith("#"):
                    continue
                reference = line.split("uses:", 1)[1].strip().split()[0]
                if reference.startswith("./.github/workflows/"):
                    self.assertTrue((ROOT / reference).is_file())
                    continue
                self.assertNotRegex(
                    reference,
                    _re.compile(r"@(v?\d+(\.\d+)*)$"),
                    f"mutable action reference: {reference}",
                )
                self.assertRegex(reference, _re.compile(r"@[0-9a-f]{40}$"), reference)

    def test_ci_runs_the_new_quality_gates(self) -> None:
        for command in (
            "python -m ruff check",
            "python -m mypy src/opencyber",
            "scripts/generate-tool-docs.py --check",
            "python -m coverage run",
            "python -m build",
            "shellcheck -x install.sh",
        ):
            self.assertIn(command, CI_WORKFLOW)

    def test_tests_run_before_publish_and_on_every_push(self) -> None:
        self.assertIn("uses: ./.github/workflows/ci.yml", CANDIDATE_WORKFLOW)
        self.assertIn("python -m unittest discover -s tests", CI_WORKFLOW)
        build_section = CANDIDATE_WORKFLOW.split("  build:", 1)[1]
        self.assertIn("- quality", build_section)

    def test_candidate_image_layers_cannot_escape_through_actions_caches(self) -> None:
        for workflow in (PUBLISH_WORKFLOW, CANDIDATE_WORKFLOW, IMAGE_SMOKE_WORKFLOW):
            self.assertNotIn("cache-to:", workflow)
            self.assertNotIn("cache-from:", workflow)
        self.assertIn("release-gate.py staging", CANDIDATE_WORKFLOW)
        self.assertIn("release-gate.py public", PUBLISH_WORKFLOW)

    def test_publication_promotes_qualified_candidates_without_stable_aliases(self) -> None:
        self.assertNotIn("docker/build-push-action", PUBLISH_WORKFLOW)
        self.assertNotIn("--clobber", PUBLISH_WORKFLOW)
        self.assertNotIn("--prerelease=false", PUBLISH_WORKFLOW)
        self.assertNotIn(":latest", PUBLISH_WORKFLOW)
        self.assertNotIn("${VERSION%.*}", PUBLISH_WORKFLOW)
        self.assertNotIn("${VERSION%%.*}", PUBLISH_WORKFLOW)
        self.assertIn("release-gate.py fetch", PUBLISH_WORKFLOW)
        self.assertIn("release-gate.py qualify", PUBLISH_WORKFLOW)
        self.assertIn("selection_sha256", PUBLISH_WORKFLOW)
        self.assertIn("qualification_sha256", PUBLISH_WORKFLOW)
        self.assertIn("--latest=false", PUBLISH_WORKFLOW)

    def test_readme_advertises_current_full_tool_count(self) -> None:
        from opencyber.catalog import CATALOG
        from opencyber.diagnostics import FIXED_MCP_TOOL_COUNT

        total = len(CATALOG) + FIXED_MCP_TOOL_COUNT
        normalized = " ".join(README.split())
        self.assertIn(f"{total} security MCP tools", normalized)
        self.assertIn(f"{len(CATALOG)} executable-backed tools", normalized)

    def test_release_checksums_are_archive_relative(self) -> None:
        self.assertIn('(cd "$output_directory" && sha256sum', SBOM_SCRIPT)
        self.assertIn('(cd "$output_directory" && sha256sum', LICENSE_SCRIPT)


if __name__ == "__main__":
    unittest.main()
