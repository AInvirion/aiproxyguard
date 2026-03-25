from pathlib import Path
from aiproxyguard.signatures.loader import (
    load_signatures,
    parse_signatures_from_yaml,
    parse_signatures_from_bundles,
)


class TestSignatureLoader:
    def test_load_single_file(self, tmp_path: Path) -> None:
        sig_file = tmp_path / "test.yaml"
        sig_file.write_text("""
signatures:
  - id: "PI-001"
    name: "Ignore instructions"
    category: "prompt_injection"
    severity: "high"
    patterns:
      - "ignore.*instructions"
      - "disregard.*rules"
    action: "block"
""")
        sigset = load_signatures(str(sig_file))
        assert len(sigset.signatures) == 1
        assert sigset.get("PI-001") is not None
        assert len(sigset.get("PI-001").patterns) == 2

    def test_load_directory(self, tmp_path: Path) -> None:
        (tmp_path / "pi.yaml").write_text("""
signatures:
  - id: "PI-001"
    name: "Test1"
    category: "prompt_injection"
    severity: "high"
    patterns: ["test1"]
    action: "block"
""")
        (tmp_path / "jb.yaml").write_text("""
signatures:
  - id: "JB-001"
    name: "Test2"
    category: "jailbreak"
    severity: "high"
    patterns: ["test2"]
    action: "block"
""")
        sigset = load_signatures(str(tmp_path))
        assert len(sigset.signatures) == 2

    def test_empty_directory(self, tmp_path: Path) -> None:
        sigset = load_signatures(str(tmp_path))
        assert len(sigset.signatures) == 0


class TestParseSignaturesFromYaml:
    def test_parse_valid_yaml(self) -> None:
        yaml_content = """
signatures:
  - id: "PI-001"
    name: "Ignore instructions"
    category: "prompt_injection"
    severity: "high"
    patterns:
      - "ignore.*instructions"
    action: "block"
  - id: "PI-002"
    name: "Override system"
    category: "prompt_injection"
    severity: "medium"
    patterns:
      - "override.*system"
    action: "warn"
"""
        sigset = parse_signatures_from_yaml(yaml_content)
        assert len(sigset.signatures) == 2
        assert sigset.get("PI-001") is not None
        assert sigset.get("PI-002") is not None
        assert sigset.get("PI-001").action == "block"
        assert sigset.get("PI-002").action == "warn"

    def test_parse_empty_yaml(self) -> None:
        sigset = parse_signatures_from_yaml("")
        assert len(sigset.signatures) == 0

    def test_parse_yaml_without_signatures_key(self) -> None:
        yaml_content = """
other_key: value
"""
        sigset = parse_signatures_from_yaml(yaml_content)
        assert len(sigset.signatures) == 0


class TestParseSignaturesFromBundles:
    def test_parse_single_bundle(self) -> None:
        bundles = [
            {
                "id": "bundle-1",
                "content": """
signatures:
  - id: "PI-001"
    name: "Test sig"
    category: "prompt_injection"
    severity: "high"
    patterns: ["test"]
    action: "block"
"""
            }
        ]
        sigset = parse_signatures_from_bundles(bundles)
        assert len(sigset.signatures) == 1
        assert sigset.get("PI-001") is not None

    def test_parse_multiple_bundles(self) -> None:
        bundles = [
            {
                "id": "bundle-1",
                "content": """
signatures:
  - id: "PI-001"
    name: "Prompt injection sig"
    category: "prompt_injection"
    severity: "high"
    patterns: ["ignore.*instructions"]
    action: "block"
"""
            },
            {
                "id": "bundle-2",
                "content": """
signatures:
  - id: "JB-001"
    name: "Jailbreak sig"
    category: "jailbreak"
    severity: "high"
    patterns: ["dan.*mode"]
    action: "block"
"""
            },
        ]
        sigset = parse_signatures_from_bundles(bundles)
        assert len(sigset.signatures) == 2
        assert sigset.get("PI-001") is not None
        assert sigset.get("JB-001") is not None

    def test_parse_empty_bundle_list(self) -> None:
        sigset = parse_signatures_from_bundles([])
        assert len(sigset.signatures) == 0

    def test_parse_bundle_with_empty_content(self) -> None:
        bundles = [{"id": "bundle-1", "content": ""}]
        sigset = parse_signatures_from_bundles(bundles)
        assert len(sigset.signatures) == 0

    def test_parse_bundle_without_content_key(self) -> None:
        bundles = [{"id": "bundle-1"}]
        sigset = parse_signatures_from_bundles(bundles)
        assert len(sigset.signatures) == 0
