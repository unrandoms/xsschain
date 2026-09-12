#!/usr/bin/env python3

"""
XSSChain Stored XSS detection package.

Provides YAML-driven stored XSS probing with Playwright DOM verification.
"""

from .prober import StoredXSSProber, StoredProbeConfig, StoredXSSFinding

__all__ = ["StoredXSSProber", "StoredProbeConfig", "StoredXSSFinding"]
