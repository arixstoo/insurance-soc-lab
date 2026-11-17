"""scripts/indexer_client.py: the lab TLS context accepts the Wazuh CA on Python 3.13+ and
still verifies certificates and host names (no Docker, no certificates needed)."""

from __future__ import annotations

import ssl
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import indexer_client  # noqa: E402


def test_lab_context_drops_only_strict_x509(monkeypatch):
    def strict_default(cafile=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # verify_mode CERT_REQUIRED, check_hostname on
        context.verify_flags |= getattr(ssl, "VERIFY_X509_STRICT", 0) | ssl.VERIFY_X509_TRUSTED_FIRST
        strict_default.cafile = cafile
        return context

    monkeypatch.setattr(indexer_client.ssl, "create_default_context", strict_default)
    context = indexer_client.lab_context()
    assert strict_default.cafile == str(indexer_client.CA_FILE)
    assert not context.verify_flags & getattr(ssl, "VERIFY_X509_STRICT", 0)
    assert context.verify_flags & ssl.VERIFY_X509_TRUSTED_FIRST
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
