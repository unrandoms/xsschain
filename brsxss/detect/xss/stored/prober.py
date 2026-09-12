#!/usr/bin/env python3

"""
XSSChain Stored XSS Prober

YAML-driven stored XSS detection with Playwright DOM verification.

YAML schema (list of probe dicts):
  - write:
      method: POST          # HTTP method for injection
      url: https://t.co/s  # endpoint that stores the payload
      body: "comment=PAYLOAD&submit=1"  # form body; PAYLOAD is substituted
    read:
      method: GET
      url: https://t.co/comments  # page that renders stored content
    delay: 3               # seconds to wait between write and read

The prober:
  1. Iterates each probe in the YAML file.
  2. For every XSS payload string passed by the caller, substitutes PAYLOAD
     in the write body and POSTs (or GETs) the injection request.
  3. Waits ``delay`` seconds.
  4. Fetches the read URL using a Playwright headless browser.
  5. Listens for ``window.alert`` calls in the page to confirm execution.
  6. Reports a StoredXSSFinding with severity, write URL and read URL.

Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Modified: xsschain fork
Telegram: https://t.me/EasyProTech
"""

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx
import yaml

from brsxss.utils.logger import Logger

logger = Logger("core.stored_xss_prober")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class WriteConfig:
    """Configuration for the injection (write) request"""

    method: str
    url: str
    body: str  # raw body with PAYLOAD placeholder


@dataclass
class ReadConfig:
    """Configuration for the read (verification) request"""

    method: str
    url: str


@dataclass
class StoredProbeConfig:
    """A single stored XSS probe loaded from the YAML file"""

    write: WriteConfig
    read: ReadConfig
    delay: float = 2.0


@dataclass
class StoredXSSFinding:
    """A confirmed stored XSS vulnerability"""

    write_url: str
    read_url: str
    payload: str
    severity: str
    confirmed: bool
    execution_detected: bool
    alert_triggered: bool
    probe_index: int
    timestamp: float = field(default_factory=time.time)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "stored_xss",
            "write_url": self.write_url,
            "read_url": self.read_url,
            "payload": self.payload,
            "severity": self.severity,
            "confirmed": self.confirmed,
            "execution_detected": self.execution_detected,
            "alert_triggered": self.alert_triggered,
            "probe_index": self.probe_index,
            "timestamp": self.timestamp,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------


def load_probe_config(yaml_path: str) -> list[StoredProbeConfig]:
    """
    Parse a YAML file and return a list of StoredProbeConfig objects.

    Raises:
        FileNotFoundError: If the YAML file does not exist.
        ValueError: If the YAML structure is invalid.
    """
    path = Path(yaml_path)
    if not path.exists():
        raise FileNotFoundError(f"Stored XSS probe config not found: {yaml_path}")

    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, list):
        raise ValueError(
            f"Stored XSS YAML must be a list of probe dicts; got {type(raw).__name__}"
        )

    configs: list[StoredProbeConfig] = []
    for idx, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"Probe #{idx} must be a dict, got {type(entry).__name__}")

        write_raw = entry.get("write", {})
        read_raw = entry.get("read", {})

        write_cfg = WriteConfig(
            method=str(write_raw.get("method", "POST")).upper(),
            url=str(write_raw.get("url", "")),
            body=str(write_raw.get("body", "")),
        )
        read_cfg = ReadConfig(
            method=str(read_raw.get("method", "GET")).upper(),
            url=str(read_raw.get("url", "")),
        )
        delay = float(entry.get("delay", 2.0))

        if not write_cfg.url:
            raise ValueError(f"Probe #{idx} missing write.url")
        if not read_cfg.url:
            raise ValueError(f"Probe #{idx} missing read.url")

        configs.append(StoredProbeConfig(write=write_cfg, read=read_cfg, delay=delay))

    logger.info("Loaded %d stored XSS probe configs from %s", len(configs), yaml_path)
    return configs


# ---------------------------------------------------------------------------
# DOM checker via Playwright
# ---------------------------------------------------------------------------


async def _check_dom_execution(
    read_url: str,
    read_method: str,
    timeout_ms: int = 15000,
) -> tuple[bool, bool]:
    """
    Launch a headless Playwright browser, navigate to ``read_url``, and detect
    whether the stored payload executed by intercepting ``window.alert``.

    Returns:
        (execution_detected, alert_triggered) – both bool.

    ``execution_detected`` is True when the page contains a
    ``xsschain_stored_marker`` variable injected by the marker payload OR when
    alert was triggered.  ``alert_triggered`` is True when alert() fired.
    """
    try:
        from playwright.async_api import async_playwright  # type: ignore[import-untyped]
    except ImportError:
        logger.warning(
            "playwright not installed – DOM verification unavailable. "
            "Install with: pip install playwright && playwright install chromium"
        )
        return False, False

    alert_triggered = False
    execution_detected = False

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()

            # Intercept alert() to detect execution
            await page.add_init_script(
                """
                window._xsschain_alerts = 0;
                const _orig_alert = window.alert;
                window.alert = function(msg) {
                    window._xsschain_alerts += 1;
                    _orig_alert && _orig_alert(msg);
                };
                """
            )

            try:
                if read_method == "GET":
                    await page.goto(read_url, timeout=timeout_ms, wait_until="networkidle")
                else:
                    # For non-GET read, navigate then POST via fetch
                    await page.goto("about:blank", timeout=5000)
                    await page.evaluate(
                        f"""
                        fetch({read_url!r}, {{method: {read_method!r}}})
                            .then(r => r.text())
                            .then(html => document.write(html));
                        """
                    )
                    await page.wait_for_timeout(timeout_ms // 2)

                # Check alert count
                alert_count = await page.evaluate("window._xsschain_alerts || 0")
                alert_triggered = int(alert_count) > 0

                # Check for marker variable (set by marker payload variant)
                marker_present = await page.evaluate(
                    "typeof window.xsschain_stored_marker !== 'undefined'"
                )
                execution_detected = alert_triggered or bool(marker_present)

            except Exception as nav_err:
                logger.debug("Navigation error during DOM check: %s", nav_err)
            finally:
                await browser.close()

    except Exception as exc:
        logger.warning("Playwright DOM check failed: %s", exc)

    return execution_detected, alert_triggered


# ---------------------------------------------------------------------------
# HTTP write helper
# ---------------------------------------------------------------------------


async def _send_write_request(
    method: str,
    url: str,
    body: str,
    http_client: httpx.AsyncClient,
) -> Optional[httpx.Response]:
    """Send the write request and return the response (or None on error)."""
    try:
        if method == "POST":
            # Detect JSON vs form-encoded body
            stripped = body.lstrip()
            if stripped.startswith("{") or stripped.startswith("["):
                response = await http_client.post(
                    url,
                    content=body.encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
            else:
                # Parse as application/x-www-form-urlencoded
                form_data: dict[str, str] = {}
                for pair in body.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        form_data[k] = v
                response = await http_client.post(url, data=form_data)
        elif method == "PUT":
            response = await http_client.put(
                url,
                content=body.encode("utf-8"),
            )
        else:
            response = await http_client.get(url)
        return response
    except Exception as exc:
        logger.warning("Write request failed (%s %s): %s", method, url, exc)
        return None


# ---------------------------------------------------------------------------
# Main prober class
# ---------------------------------------------------------------------------


class StoredXSSProber:
    """
    Probes for stored XSS vulnerabilities using a YAML-defined probe list.

    Usage::

        prober = StoredXSSProber(yaml_path="probes.yaml", timeout=15)
        findings = asyncio.run(prober.run(payloads=["<script>alert(1)</script>"]))
        for f in findings:
            print(f.to_dict())
    """

    def __init__(
        self,
        yaml_path: str,
        timeout: int = 15,
        verify_ssl: bool = True,
    ) -> None:
        """
        Args:
            yaml_path: Path to the YAML probe config file.
            timeout:   HTTP request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.configs: list[StoredProbeConfig] = load_probe_config(yaml_path)
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    async def run(
        self,
        payloads: list[str],
        progress_callback: Optional[Any] = None,
    ) -> list[StoredXSSFinding]:
        """
        Run all probes against all supplied payloads.

        Args:
            payloads: List of XSS payload strings (PAYLOAD placeholder substituted).
            progress_callback: Optional callable(current, total) for progress.

        Returns:
            List of StoredXSSFinding for every confirmed execution.
        """
        findings: list[StoredXSSFinding] = []
        total_ops = len(self.configs) * len(payloads)
        completed = 0

        ssl_context: Any = not self.verify_ssl
        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            follow_redirects=True,
        ) as http_client:
            for probe_idx, probe in enumerate(self.configs):
                for payload in payloads:
                    completed += 1
                    if progress_callback:
                        try:
                            progress_callback(completed, total_ops)
                        except Exception:
                            pass

                    # Substitute PAYLOAD placeholder in write body
                    injected_body = probe.write.body.replace("PAYLOAD", payload)

                    logger.debug(
                        "Probe #%d: injecting via %s %s",
                        probe_idx,
                        probe.write.method,
                        probe.write.url,
                    )

                    # Send write request
                    write_resp = await _send_write_request(
                        method=probe.write.method,
                        url=probe.write.url,
                        body=injected_body,
                        http_client=http_client,
                    )

                    if write_resp is None:
                        logger.warning(
                            "Probe #%d: write request returned no response – skipping",
                            probe_idx,
                        )
                        continue

                    write_status = write_resp.status_code
                    logger.debug(
                        "Probe #%d: write response HTTP %d", probe_idx, write_status
                    )

                    # Wait the configured delay
                    if probe.delay > 0:
                        await asyncio.sleep(probe.delay)

                    # DOM verification via Playwright
                    execution_detected, alert_triggered = await _check_dom_execution(
                        read_url=probe.read.url,
                        read_method=probe.read.method,
                        timeout_ms=self.timeout * 1000,
                    )

                    if execution_detected:
                        severity = "high" if alert_triggered else "medium"
                        finding = StoredXSSFinding(
                            write_url=probe.write.url,
                            read_url=probe.read.url,
                            payload=payload,
                            severity=severity,
                            confirmed=True,
                            execution_detected=execution_detected,
                            alert_triggered=alert_triggered,
                            probe_index=probe_idx,
                            notes=(
                                "alert() triggered in DOM"
                                if alert_triggered
                                else "execution marker detected in DOM"
                            ),
                        )
                        findings.append(finding)
                        logger.warning(
                            "Stored XSS confirmed: probe #%d, payload=%s..., "
                            "write=%s, read=%s, severity=%s",
                            probe_idx,
                            payload[:40],
                            probe.write.url,
                            probe.read.url,
                            severity,
                        )
                    else:
                        logger.debug(
                            "Probe #%d: no execution detected for payload=%s...",
                            probe_idx,
                            payload[:40],
                        )

        return findings
