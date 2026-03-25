from aiproxyguard.signatures.models import Signature, SignatureSet


class TestSignatureModels:
    def test_signature_creation(self) -> None:
        sig = Signature(id="PI-001", name="Ignore instructions", category="prompt_injection",
                       severity="high", patterns=["ignore.*instructions"], action="block")
        assert sig.id == "PI-001"
        assert sig.category == "prompt_injection"

    def test_signature_set_lookup(self) -> None:
        sig = Signature(id="PI-001", name="Test", category="prompt_injection",
                       severity="high", patterns=["test"], action="block")
        sigset = SignatureSet(signatures=[sig])
        assert sigset.get("PI-001") == sig
        assert sigset.get("NOTFOUND") is None

    def test_signature_set_by_category(self) -> None:
        sig1 = Signature(id="PI-001", name="Test1", category="prompt_injection",
                        severity="high", patterns=["test1"], action="block")
        sig2 = Signature(id="JB-001", name="Test2", category="jailbreak",
                        severity="high", patterns=["test2"], action="block")
        sigset = SignatureSet(signatures=[sig1, sig2])
        pi_sigs = sigset.by_category("prompt_injection")
        assert len(pi_sigs) == 1
        assert pi_sigs[0].id == "PI-001"
