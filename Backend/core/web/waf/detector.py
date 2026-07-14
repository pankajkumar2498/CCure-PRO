"""
core/web/waf/detector.py
────────────────────────────────────────────────────────────────────────────
WAF / CDN detection engine.

Detects the presence of Web Application Firewalls and CDNs before the
main scan begins. This is critical because:
  1. WAFs may block aggressive scanning, causing false negatives
  2. Rate limits must be reduced to avoid IP bans
  3. Stealth payloads should be selected when WAF is present
  4. The report should note WAF presence for context

Detection uses HTTP fingerprinting — response headers, status codes,
and error page patterns unique to each WAF vendor.
"""

import logging
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("ccure.web.waf")

# WAF signature database: (header_name, header_value_pattern, waf_name)
_WAF_HEADER_SIGNATURES: List[Tuple[str, str, str]] = [
    # Cloudflare
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("cf-cache-status", "", "Cloudflare"),
    # AWS WAF / CloudFront
    ("x-amz-cf-id", "", "AWS CloudFront"),
    ("x-amzn-waf-action", "", "AWS WAF"),
    ("x-amz-apigw-id", "", "AWS API Gateway"),
    # Akamai
    ("x-akamai-transformed", "", "Akamai"),
    ("server", "akamaighost", "Akamai"),
    # Imperva / Incapsula
    ("x-cdn", "incapsula", "Imperva Incapsula"),
    ("x-iinfo", "", "Imperva Incapsula"),
    # F5 BIG-IP
    ("server", "big-ip", "F5 BIG-IP"),
    ("x-wa-info", "", "F5 BIG-IP"),
    # Sucuri
    ("server", "sucuri", "Sucuri"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-sucuri-cache", "", "Sucuri"),
    # Barracuda
    ("server", "barracuda", "Barracuda WAF"),
    # Fastly
    ("x-fastly-request-id", "", "Fastly"),
    ("via", "varnish", "Fastly/Varnish"),
    # Azure WAF / Front Door
    ("x-azure-ref", "", "Azure Front Door"),
    ("x-ms-ref", "", "Azure WAF"),
    # Google Cloud
    ("server", "google frontend", "Google Cloud"),
    ("via", "google", "Google Cloud"),
    # DDoS-Guard
    ("server", "ddos-guard", "DDoS-Guard"),
    # ModSecurity
    ("server", "modsecurity", "ModSecurity"),
]

# Error page patterns that indicate WAF blocking
_WAF_BODY_PATTERNS: List[Tuple[str, str]] = [
    ("access denied", "Generic WAF Block"),
    ("attention required! | cloudflare", "Cloudflare"),
    ("incapsula incident", "Imperva Incapsula"),
    ("request blocked", "Generic WAF Block"),
    ("web application firewall", "Generic WAF Block"),
    ("this request was blocked by the security rules", "Azure WAF"),
    ("sucuri website firewall", "Sucuri"),
    ("blocked by aws waf", "AWS WAF"),
]


class WAFDetector:
    """
    Detects WAF/CDN presence using HTTP fingerprinting.

    Usage:
        detector = WAFDetector()
        result = await detector.detect("https://example.com")
        if result["waf_detected"]:
            print(f"WAF: {result['waf_name']}")
    """

    def __init__(self):
        pass

    async def detect(self, target_url: str) -> Dict:
        """
        Detect WAF/CDN presence at the target URL.

        Uses httpx for async HTTP requests with multiple probes:
          1. Normal GET request — check response headers
          2. Malicious-looking request — trigger WAF block page
          3. Non-existent path — check custom error pages

        Args:
            target_url: URL to probe

        Returns:
            {
                "waf_detected": bool,
                "waf_name": str or None,
                "confidence": "high" | "medium" | "low",
                "evidence": [...]
            }
        """
        evidence: List[Dict] = []
        detected_wafs: List[str] = []

        try:
            import httpx
        except ImportError:
            log.warning("httpx not installed — WAF detection disabled")
            return {
                "waf_detected": False,
                "waf_name": None,
                "confidence": "none",
                "evidence": [],
            }

        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (compatible; CCure-Audit-PRO/1.0)"},
        ) as client:

            # Probe 1: Normal GET
            try:
                resp = await client.get(target_url)
                waf_from_headers = self._check_headers(dict(resp.headers))
                if waf_from_headers:
                    detected_wafs.append(waf_from_headers)
                    evidence.append(
                        {
                            "probe": "normal_get",
                            "waf": waf_from_headers,
                            "method": "header_fingerprint",
                        }
                    )
            except Exception as exc:
                log.debug("WAF probe 1 failed: %s", exc)

            # Probe 2: Trigger WAF with suspicious payload in query
            try:
                trigger_url = f"{target_url.rstrip('/')}/?id=1' OR '1'='1"
                resp2 = await client.get(trigger_url)

                # Check for WAF block in response body
                body_lower = resp2.text[:5000].lower()
                for pattern, waf_name in _WAF_BODY_PATTERNS:
                    if pattern in body_lower:
                        detected_wafs.append(waf_name)
                        evidence.append(
                            {
                                "probe": "sqli_trigger",
                                "waf": waf_name,
                                "method": "body_pattern",
                                "status_code": resp2.status_code,
                            }
                        )
                        break

                # 403 response to probe is also a WAF indicator
                if resp2.status_code == 403 and not detected_wafs:
                    waf_from_headers = self._check_headers(dict(resp2.headers))
                    if waf_from_headers:
                        detected_wafs.append(waf_from_headers)
                        evidence.append(
                            {
                                "probe": "sqli_trigger",
                                "waf": waf_from_headers,
                                "method": "header_fingerprint_on_block",
                            }
                        )

            except Exception as exc:
                log.debug("WAF probe 2 failed: %s", exc)

            # Probe 3: XSS trigger in path
            try:
                xss_url = f"{target_url.rstrip('/')}/<script>alert(1)</script>"
                resp3 = await client.get(xss_url)
                if resp3.status_code in (403, 406, 429, 503):
                    waf_from_headers = self._check_headers(dict(resp3.headers))
                    if waf_from_headers and waf_from_headers not in detected_wafs:
                        detected_wafs.append(waf_from_headers)
                        evidence.append(
                            {
                                "probe": "xss_trigger",
                                "waf": waf_from_headers,
                                "method": "block_response",
                            }
                        )
            except Exception as exc:
                log.debug("WAF probe 3 failed: %s", exc)

        # Determine final result
        if detected_wafs:
            # Use the most frequently detected WAF name
            from collections import Counter

            waf_name = Counter(detected_wafs).most_common(1)[0][0]
            confidence = "high" if len(evidence) >= 2 else "medium"

            log.info(
                "WAF detected: %s (confidence=%s, %d probes matched)",
                waf_name,
                confidence,
                len(evidence),
            )

            return {
                "waf_detected": True,
                "waf_name": waf_name,
                "confidence": confidence,
                "evidence": evidence,
            }

        return {
            "waf_detected": False,
            "waf_name": None,
            "confidence": "none",
            "evidence": [],
        }

    @staticmethod
    def _check_headers(headers: Dict[str, str]) -> Optional[str]:
        """Check response headers against WAF signature database."""
        for header_name, pattern, waf_name in _WAF_HEADER_SIGNATURES:
            value = headers.get(header_name, "").lower()
            if not value:
                continue
            if not pattern:
                # Header presence alone is sufficient
                return waf_name
            if pattern in value:
                return waf_name
        return None
