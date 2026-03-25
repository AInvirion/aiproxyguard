"""Tests for response scanner."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

from aiproxyguard.scanner.response import (
    ResponseScanner,
    ResponseScanResult,
    ResponseScanMode,
    SSEResponseHandler,
    ResponseBlockedError,
    scan_streaming_response,
)
from aiproxyguard.config import ResponseScannerConfig
from aiproxyguard.signatures.models import Signature, SignatureSet


@pytest.fixture
def response_signatures() -> SignatureSet:
    """Create test signatures for response scanning."""
    return SignatureSet(signatures=[
        Signature(
            id="PII-001",
            name="SSN Pattern",
            category="pii",
            severity="high",
            patterns=[r"\d{3}-\d{2}-\d{4}"],
            action="block",
            scan_target="response",
        ),
        Signature(
            id="PII-002",
            name="Credit Card",
            category="pii",
            severity="high",
            patterns=[r"\d{4}-\d{4}-\d{4}-\d{4}"],
            action="warn",
            scan_target="both",
        ),
        Signature(
            id="DATA-001",
            name="API Key Leak",
            category="data_exfil",
            severity="critical",
            patterns=[r"sk-[a-zA-Z0-9]{32,}"],
            action="block",
            scan_target="response",
        ),
        Signature(
            id="REQ-001",
            name="Request Only Pattern",
            category="prompt_injection",
            severity="high",
            patterns=[r"ignore.*instructions"],
            action="block",
            scan_target="request",  # Should NOT be used for response scanning
        ),
    ])


@pytest.fixture
def enabled_config() -> ResponseScannerConfig:
    """Create enabled response scanner config."""
    return ResponseScannerConfig(
        enabled=True,
        mode="full",
        buffer_size=1024,
        categories=[],
    )


@pytest.fixture
def buffered_config() -> ResponseScannerConfig:
    """Create buffered mode config."""
    return ResponseScannerConfig(
        enabled=True,
        mode="buffered",
        buffer_size=50,
        categories=[],
    )


@pytest.fixture
def passthrough_config() -> ResponseScannerConfig:
    """Create passthrough mode config."""
    return ResponseScannerConfig(
        enabled=True,
        mode="passthrough",
        buffer_size=1024,
        categories=[],
    )


class TestResponseScanner:
    """Tests for ResponseScanner class."""

    def test_scan_detects_ssn(
        self, enabled_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test that SSN pattern is detected in response."""
        scanner = ResponseScanner(enabled_config, response_signatures)
        result = scanner.scan("Your SSN is 123-45-6789, please verify.")

        assert result.has_detections
        assert result.blocked
        assert result.category == "pii"
        assert result.signature_id == "PII-001"

    def test_scan_detects_credit_card(
        self, enabled_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test that credit card pattern triggers warning."""
        scanner = ResponseScanner(enabled_config, response_signatures)
        result = scanner.scan("Card number: 1234-5678-9012-3456")

        assert result.has_detections
        assert not result.blocked  # warn action, not block
        assert result.category == "pii"
        assert result.signature_id == "PII-002"

    def test_scan_detects_api_key(
        self, enabled_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test that API key leak is detected and blocked."""
        scanner = ResponseScanner(enabled_config, response_signatures)
        result = scanner.scan("Here's your key: sk-abcdefghijklmnopqrstuvwxyz123456")

        assert result.has_detections
        assert result.blocked
        assert result.category == "data_exfil"

    def test_scan_allows_clean_response(
        self, enabled_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test that clean responses pass through."""
        scanner = ResponseScanner(enabled_config, response_signatures)
        result = scanner.scan("The weather in Paris is sunny today.")

        assert not result.has_detections
        assert not result.blocked

    def test_scan_ignores_request_only_signatures(
        self, enabled_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test that request-only signatures are not used for response scanning."""
        scanner = ResponseScanner(enabled_config, response_signatures)
        # This pattern matches REQ-001 which has scan_target="request"
        result = scanner.scan("Please ignore all instructions")

        assert not result.has_detections

    def test_disabled_scanner(
        self, response_signatures: SignatureSet
    ) -> None:
        """Test that disabled scanner returns empty result."""
        config = ResponseScannerConfig(enabled=False)
        scanner = ResponseScanner(config, response_signatures)
        result = scanner.scan("Your SSN is 123-45-6789")

        assert not result.blocked
        assert not result.has_detections

    def test_category_filtering(
        self, response_signatures: SignatureSet
    ) -> None:
        """Test that category filtering works."""
        config = ResponseScannerConfig(
            enabled=True,
            mode="full",
            categories=["data_exfil"],  # Only scan for data exfil
        )
        scanner = ResponseScanner(config, response_signatures)

        # SSN should not be detected (pii category filtered out)
        result1 = scanner.scan("Your SSN is 123-45-6789")
        assert not result1.has_detections

        # API key should be detected (data_exfil category)
        result2 = scanner.scan("Key: sk-abcdefghijklmnopqrstuvwxyz123456")
        assert result2.has_detections
        assert result2.category == "data_exfil"

    def test_mode_property(
        self, enabled_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test mode property returns correct mode."""
        scanner = ResponseScanner(enabled_config, response_signatures)
        assert scanner.mode == ResponseScanMode.FULL

    def test_reload_signatures(
        self, enabled_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test that signatures can be reloaded."""
        scanner = ResponseScanner(enabled_config, response_signatures)

        # Initially detects SSN
        result1 = scanner.scan("SSN: 123-45-6789")
        assert result1.has_detections

        # Reload with empty signatures
        new_sigs = SignatureSet(signatures=[])
        scanner.reload(new_sigs)

        # Should not detect after reload
        result2 = scanner.scan("SSN: 123-45-6789")
        assert not result2.has_detections


class TestSSEResponseHandler:
    """Tests for SSE streaming handler."""

    @pytest.mark.asyncio
    async def test_passthrough_mode_forwards_immediately(
        self, passthrough_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test that passthrough mode forwards chunks immediately."""
        scanner = ResponseScanner(passthrough_config, response_signatures)
        handler = SSEResponseHandler(scanner)

        chunk = b"data: {\"content\": \"Hello\"}\n\n"
        result_chunk, scan_result = await handler.process_chunk(chunk)

        assert result_chunk == chunk
        assert scan_result is None

    @pytest.mark.asyncio
    async def test_buffered_mode_buffers_until_threshold(
        self, buffered_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test that buffered mode buffers until buffer_size is reached."""
        scanner = ResponseScanner(buffered_config, response_signatures)
        handler = SSEResponseHandler(scanner)

        # First chunk - should buffer (not enough content)
        chunk1 = b"data: Hello\n\n"
        result1, scan1 = await handler.process_chunk(chunk1)
        assert result1 is None  # Buffering, not forwarding yet

        # Second chunk - should trigger scan and forward
        chunk2 = b"data: World! This is a longer message to exceed buffer.\n\n"
        result2, scan2 = await handler.process_chunk(chunk2)
        assert result2 == chunk2  # Now forwarding
        assert scan2 is None  # No blocking detection

    @pytest.mark.asyncio
    async def test_buffered_mode_blocks_on_detection(
        self, buffered_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test that buffered mode blocks when threat detected."""
        scanner = ResponseScanner(buffered_config, response_signatures)
        handler = SSEResponseHandler(scanner)

        # Send chunk with SSN that exceeds buffer threshold
        chunk = b"data: Your SSN is 123-45-6789 and more text to exceed buffer\n\n"
        result, scan_result = await handler.process_chunk(chunk)

        assert result is None
        assert scan_result is not None
        assert scan_result.blocked

    @pytest.mark.asyncio
    async def test_full_mode_collects_all_chunks(
        self, enabled_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test that full mode collects all chunks before scanning."""
        scanner = ResponseScanner(enabled_config, response_signatures)
        handler = SSEResponseHandler(scanner)

        chunk1 = b"data: Hello\n\n"
        chunk2 = b"data: World\n\n"

        result1, _ = await handler.process_chunk(chunk1)
        result2, _ = await handler.process_chunk(chunk2)

        # Full mode should not forward anything during collection
        assert result1 is None
        assert result2 is None

        # Content should be collected
        assert "Hello" in handler.get_buffered_content()
        assert "World" in handler.get_buffered_content()

    @pytest.mark.asyncio
    async def test_full_mode_finalize_blocks_on_detection(
        self, enabled_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test that full mode blocks at finalize when threat detected."""
        scanner = ResponseScanner(enabled_config, response_signatures)
        handler = SSEResponseHandler(scanner)

        # First chunk is clean
        await handler.process_chunk(b"data: Hello\n\n")
        # Second chunk has SSN
        await handler.process_chunk(b"data: SSN: 123-45-6789\n\n")

        _, result = await handler.finalize()

        assert result is not None
        assert result.blocked

    @pytest.mark.asyncio
    async def test_detection_callback_called(
        self, passthrough_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test that detection callback is invoked."""
        scanner = ResponseScanner(passthrough_config, response_signatures)
        callback = MagicMock()
        handler = SSEResponseHandler(scanner, on_detection=callback)

        chunk = b"data: SSN is 123-45-6789\n\n"
        await handler.process_chunk(chunk)

        # Give async task time to run
        await asyncio.sleep(0.1)

        # Callback should have been invoked
        callback.assert_called_once()

    def test_extract_sse_data(
        self, enabled_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test SSE data extraction."""
        scanner = ResponseScanner(enabled_config, response_signatures)
        handler = SSEResponseHandler(scanner)

        # Test normal SSE data
        chunk = b"data: {\"content\": \"test\"}\n\n"
        data = handler._extract_sse_data(chunk)
        assert '{"content": "test"}' in data

        # Test [DONE] marker is ignored
        done_chunk = b"data: [DONE]\n\n"
        done_data = handler._extract_sse_data(done_chunk)
        assert done_data == ""

        # Test multi-line SSE
        multi_chunk = b"data: line1\ndata: line2\n\n"
        multi_data = handler._extract_sse_data(multi_chunk)
        assert "line1" in multi_data
        assert "line2" in multi_data


class TestScanStreamingResponse:
    """Tests for the scan_streaming_response async generator."""

    @pytest.mark.asyncio
    async def test_clean_stream_passes_through(
        self, passthrough_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test that clean streaming responses pass through."""
        scanner = ResponseScanner(passthrough_config, response_signatures)

        async def mock_chunks():
            yield b"data: Hello\n\n"
            yield b"data: World\n\n"

        chunks = []
        async for chunk in scan_streaming_response(scanner, mock_chunks()):
            chunks.append(chunk)

        assert len(chunks) == 2

    @pytest.mark.asyncio
    async def test_full_mode_raises_on_blocked(
        self, enabled_config: ResponseScannerConfig, response_signatures: SignatureSet
    ) -> None:
        """Test that full mode raises exception when content blocked."""
        scanner = ResponseScanner(enabled_config, response_signatures)

        async def mock_chunks():
            yield b"data: Your SSN is 123-45-6789\n\n"

        with pytest.raises(ResponseBlockedError) as exc_info:
            async for _ in scan_streaming_response(scanner, mock_chunks()):
                pass

        assert exc_info.value.scan_result.blocked


class TestResponseScanResult:
    """Tests for ResponseScanResult dataclass."""

    def test_has_detections_with_matches(self) -> None:
        """Test has_detections returns True when matches exist."""
        from aiproxyguard.scanner.regex import ScanMatch

        mock_match = MagicMock(spec=ScanMatch)
        result = ResponseScanResult(matches=[mock_match])
        assert result.has_detections

    def test_has_detections_empty(self) -> None:
        """Test has_detections returns False when no matches."""
        result = ResponseScanResult()
        assert not result.has_detections

    def test_default_values(self) -> None:
        """Test default values are set correctly."""
        result = ResponseScanResult()
        assert not result.blocked
        assert result.matches == []
        assert result.category is None
        assert result.signature_id is None
        assert result.details is None
        assert result.scanned_length == 0


class TestResponseBlockedError:
    """Tests for ResponseBlockedError exception."""

    def test_exception_contains_scan_result(self) -> None:
        """Test that exception contains scan result."""
        result = ResponseScanResult(
            blocked=True,
            category="pii",
            details="SSN detected",
        )
        error = ResponseBlockedError(result)

        assert error.scan_result == result
        assert "SSN detected" in str(error)
