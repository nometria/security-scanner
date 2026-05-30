"""Backwards-compat entry point: ``python -m security_scanner.compliance.cli``.

Originally exposed as ``python -m validator.cli`` in the standalone package;
the same CLI now lives under ``security_scanner.compliance``.
"""
from security_scanner.compliance.cli import main
main()
