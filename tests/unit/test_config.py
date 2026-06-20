# Copyright 2025-2026 AInvirion LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for configuration loading."""

import pytest
from pathlib import Path
from aiproxyguard.config import load_config


class TestConfigLoading:
    """Test configuration file loading."""

    def test_load_minimal_config(self, tmp_path: Path) -> None:
        """Load a minimal valid config."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
server:
  host: "0.0.0.0"
  port: 8080
upstreams:
  openai:
    url: "https://api.openai.com"
""")
        config = load_config(str(config_file))
        assert config.server.host == "0.0.0.0"
        assert config.server.port == 8080
        assert config.upstreams["openai"].url == "https://api.openai.com"

    def test_cost_optimization_response_cache_parsed(self, tmp_path: Path) -> None:
        """response_cache opt-in parses (incl. string-bool coercion)."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
server:
  host: "0.0.0.0"
  port: 8080
upstreams:
  openai:
    url: "https://api.openai.com"
cost_optimization:
  response_cache: "true"
""")
        config = load_config(str(config_file))
        assert config.cost_optimization.response_cache is True

    def test_cost_optimization_response_cache_defaults_off(self, tmp_path: Path) -> None:
        """Absent response_cache defaults to opted-out (off by default, #307)."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
server:
  host: "0.0.0.0"
  port: 8080
upstreams:
  openai:
    url: "https://api.openai.com"
""")
        config = load_config(str(config_file))
        assert config.cost_optimization.response_cache is False

    def test_env_var_substitution(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Environment variables are substituted."""
        monkeypatch.setenv("TEST_API_URL", "https://test.example.com")
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
server:
  host: "0.0.0.0"
  port: 8080
upstreams:
  test:
    url: "${TEST_API_URL}"
""")
        config = load_config(str(config_file))
        assert config.upstreams["test"].url == "https://test.example.com"

    def test_env_var_with_default(self, tmp_path: Path) -> None:
        """Environment variables with defaults work."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
server:
  host: "0.0.0.0"
  port: 8080
upstreams:
  openai:
    url: "${OPENAI_URL:-https://api.openai.com}"
""")
        config = load_config(str(config_file))
        assert config.upstreams["openai"].url == "https://api.openai.com"

    def test_missing_required_field_raises(self, tmp_path: Path) -> None:
        """Missing required fields raise ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
server:
  host: "0.0.0.0"
""")
        with pytest.raises(ValueError, match="port"):
            load_config(str(config_file))

    def test_file_not_found_raises(self, tmp_path: Path) -> None:
        """FileNotFoundError is raised when the config file does not exist."""
        missing = str(tmp_path / "nonexistent.yaml")
        with pytest.raises(FileNotFoundError):
            load_config(missing)

    def test_custom_auth_header_in_upstream(self, tmp_path: Path) -> None:
        """Custom auth_header values are parsed correctly for upstreams."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
server:
  host: "0.0.0.0"
  port: 8080
upstreams:
  custom:
    url: "https://api.example.com"
    auth_header: "X-Custom-Token"
""")
        config = load_config(str(config_file))
        assert config.upstreams["custom"].auth_header == "X-Custom-Token"

    def test_identity_defaults_to_ip(self, tmp_path: Path) -> None:
        """Identity method defaults to 'ip' (secure default)."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
server:
  port: 8080
upstreams:
  openai:
    url: "https://api.openai.com"
""")
        config = load_config(str(config_file))
        assert config.identity.method == "ip"
        assert config.identity.header_name == "X-Client-ID"
        assert config.identity.trust_xff is False

    def test_identity_custom_config(self, tmp_path: Path) -> None:
        """Identity configuration is parsed correctly."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
server:
  port: 8080
upstreams:
  openai:
    url: "https://api.openai.com"
identity:
  method: "token"
  header_name: "X-API-Key"
  trust_xff: true
  hash_token: false
""")
        config = load_config(str(config_file))
        assert config.identity.method == "token"
        assert config.identity.header_name == "X-API-Key"
        assert config.identity.trust_xff is True
        assert config.identity.hash_token is False

    def test_security_defaults(self, tmp_path: Path) -> None:
        """Security config has secure defaults."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
server:
  port: 8080
upstreams:
  openai:
    url: "https://api.openai.com"
""")
        config = load_config(str(config_file))
        assert config.security.max_request_size == 10 * 1024 * 1024  # 10 MB
        assert config.security.max_response_size == 50 * 1024 * 1024  # 50 MB
        assert config.security.expose_details is False

    def test_security_custom_config(self, tmp_path: Path) -> None:
        """Security configuration is parsed correctly."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
server:
  port: 8080
upstreams:
  openai:
    url: "https://api.openai.com"
security:
  max_request_size: 1048576
  max_response_size: 5242880
  expose_details: false
  failure_mode: "closed"
""")
        config = load_config(str(config_file))
        assert config.security.max_request_size == 1048576  # 1 MB
        assert config.security.max_response_size == 5242880  # 5 MB
        assert config.security.expose_details is False
        assert config.security.failure_mode == "closed"
