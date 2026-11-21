"""Email over SMTP, always encrypted (STARTTLS on 587 by default, or implicit TLS on 465).

There is deliberately no plaintext mode: credentials and finding details never
cross the wire unencrypted. The SMTP host is checked against the same outbound
policy as every HTTP integration (``allow_private`` opt-in for a LAN relay).

Messages are multipart text + simple HTML, with a ``Message-ID`` derived from
the event id so a mail system can de-duplicate a retried delivery.
"""
from __future__ import annotations

import asyncio
import html
import smtplib
import socket
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any, Optional

from .. import netsafety
from ..base import Capability, Connector, DeliveryResult, Event, HealthResult, register
from ._render import SEV_HEX, facts, severity_label, truncate, when, why

SMTP_TIMEOUT_SEC = 15


def _one_line(s: Any) -> str:
    return " ".join(str(s or "").split())


def build_message(event: Event, *, from_addr: str, to: list[str], subject_prefix: str = "[Paddock]") -> EmailMessage:
    sev = severity_label(event)
    subject = _one_line(f"{subject_prefix} [{sev}] {event.title}" if event.severity else f"{subject_prefix} {event.title}")
    msg = EmailMessage()
    msg["Subject"] = truncate(subject, 250)
    msg["From"] = from_addr
    msg["To"] = ", ".join(to)
    msg["Date"] = formatdate(localtime=False)
    domain = from_addr.rsplit("@", 1)[-1] if "@" in from_addr else "paddock.local"
    msg["Message-ID"] = make_msgid(idstring=event.id.replace("-", ""), domain=domain)
    msg["X-Paddock-Event"] = event.type
    msg["X-Paddock-Event-Id"] = event.id

    rows = facts(event) + [("When", when(event))]
    text_lines = [event.title, "", why(event), ""]
    text_lines += [f"{k}: {v}" for k, v in rows]
    if event.url:
        text_lines += ["", f"Open in Paddock: {event.url}"]
    text_lines += ["", "-- ", "Sent by Paddock. Manage notifications on the Integrations page."]
    msg.set_content("\n".join(text_lines))

    color = SEV_HEX.get(event.severity or "", "#8A8175")
    e = html.escape
    fact_rows = "".join(
        f'<tr><td style="padding:4px 12px 4px 0;color:#7d7468">{e(k)}</td>'
        f'<td style="padding:4px 0;color:#1b1712">{e(str(v))}</td></tr>' for k, v in rows
    )
    button = (f'<p><a href="{e(event.url, quote=True)}" style="display:inline-block;padding:8px 14px;'
              f'background:#1b1712;color:#fbf8f2;text-decoration:none;border-radius:6px">Open in Paddock</a></p>'
              if event.url else "")
    body = f"""<!doctype html><html><body style="margin:0;background:#f4efe6;font-family:-apple-system,Segoe UI,Roboto,sans-serif">
<div style="max-width:600px;margin:24px auto;background:#fbf8f2;border:1px solid #e4dccd;border-radius:10px;overflow:hidden">
<div style="height:4px;background:{color}"></div>
<div style="padding:20px 24px">
<div style="font-size:11px;letter-spacing:.08em;color:#7d7468">PADDOCK · {e(sev.upper())}</div>
<h1 style="font-family:Georgia,serif;font-weight:400;font-size:22px;margin:6px 0 12px;color:#1b1712">{e(event.title)}</h1>
<p style="color:#4a4239;line-height:1.5">{e(why(event))}</p>
<table style="font-size:13px;border-collapse:collapse">{fact_rows}</table>
{button}
</div></div>
<p style="text-align:center;font-size:11px;color:#7d7468">Sent by Paddock. Manage notifications on the Integrations page.</p>
</body></html>"""
    msg.add_alternative(body, subtype="html")
    return msg


@register
class EmailConnector(Connector):
    kind = "email"
    display_name = "Email (SMTP)"
    category = "email"
    capabilities = frozenset({Capability.NOTIFY})
    config_schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["host", "from_addr", "to"],
        "properties": {
            "host": {"type": "string", "format": "hostname", "title": "SMTP host",
                     "description": "e.g. smtp.sendgrid.net or email-smtp.eu-west-1.amazonaws.com"},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 587, "title": "Port"},
            "security": {"type": "string", "enum": ["starttls", "tls"], "default": "starttls",
                         "title": "Encryption", "description": "starttls (587) or implicit tls (465). No plaintext."},
            "from_addr": {"type": "string", "format": "email", "title": "From address"},
            "to": {"type": "array", "items": {"type": "string", "format": "email"}, "minItems": 1,
                   "maxItems": 50, "title": "Recipients"},
            "subject_prefix": {"type": "string", "maxLength": 40, "default": "[Paddock]", "title": "Subject prefix"},
        },
    }
    secret_fields = ("username", "password")
    docs_url = "docs/INTEGRATIONS.md#email"

    # Overridable in tests (a fake that records the conversation).
    smtp_class: Any = smtplib.SMTP
    smtp_ssl_class: Any = smtplib.SMTP_SSL

    async def _check_host(self) -> Optional[DeliveryResult]:
        host, port = self.config.get("host"), int(self.config.get("port") or 587)
        if not host:
            return DeliveryResult(ok=False, retryable=False, detail="SMTP host is not set")
        try:
            check = getattr(self.http, "check_host", None)
            if check is not None:
                await check(host, port)
            else:  # pragma: no cover - the dispatcher always passes a guarded client
                await netsafety.validate_outbound_url(f"https://{host}:{port}/")
        except netsafety.UnsafeURL as exc:
            return DeliveryResult(ok=False, retryable=False, detail=f"blocked by outbound URL policy: {exc}")
        return None

    def _session(self, msg: Optional[EmailMessage]) -> DeliveryResult:
        """Blocking SMTP conversation; run in a worker thread."""
        host, port = self.config["host"], int(self.config.get("port") or 587)
        ctx = ssl.create_default_context()
        user, pw = self.secrets.get("username"), self.secrets.get("password")
        try:
            if (self.config.get("security") or "starttls") == "tls":
                smtp = self.smtp_ssl_class(host, port, timeout=SMTP_TIMEOUT_SEC, context=ctx)
            else:
                smtp = self.smtp_class(host, port, timeout=SMTP_TIMEOUT_SEC)
            try:
                if (self.config.get("security") or "starttls") != "tls":
                    smtp.ehlo()
                    if not smtp.has_extn("starttls"):
                        return DeliveryResult(ok=False, retryable=False,
                                              detail="server does not offer STARTTLS; refusing to send in plaintext")
                    smtp.starttls(context=ctx)
                    smtp.ehlo()
                if user and pw:
                    smtp.login(user, pw)
                if msg is None:
                    code, _ = smtp.noop()
                    return DeliveryResult(ok=200 <= code < 300, status_code=code, retryable=True,
                                          detail=f"SMTP {code}: connected, TLS and login OK")
                refused = smtp.send_message(msg)
                if refused:
                    return DeliveryResult(ok=False, retryable=False,
                                          detail=f"{len(refused)} recipient(s) refused by the server")
                return DeliveryResult(ok=True, status_code=250, external_id=msg["Message-ID"],
                                      detail=f"accepted for {len(self.config.get('to') or [])} recipient(s)")
            finally:
                try:
                    smtp.quit()
                except Exception:  # noqa: BLE001
                    pass
        except smtplib.SMTPAuthenticationError as exc:
            return DeliveryResult(ok=False, retryable=False, status_code=exc.smtp_code,
                                  detail="authentication failed (check username/password)")
        except smtplib.SMTPNotSupportedError:
            return DeliveryResult(ok=False, retryable=False, detail="server does not support a required extension")
        except smtplib.SMTPRecipientsRefused:
            return DeliveryResult(ok=False, retryable=False, detail="all recipients refused by the server")
        except smtplib.SMTPResponseException as exc:
            return DeliveryResult(ok=False, status_code=exc.smtp_code, retryable=400 <= exc.smtp_code < 500,
                                  detail=f"SMTP {exc.smtp_code} from server")
        except ssl.SSLError:
            return DeliveryResult(ok=False, retryable=False, detail="TLS handshake/certificate verification failed")
        except (socket.timeout, TimeoutError):
            return DeliveryResult(ok=False, retryable=True, detail="timed out")
        except (OSError, smtplib.SMTPException) as exc:
            return DeliveryResult(ok=False, retryable=True, detail=f"connection error ({type(exc).__name__})")

    async def deliver(self, event: Event) -> DeliveryResult:
        blocked = await self._check_host()
        if blocked:
            return blocked
        to = [str(t) for t in (self.config.get("to") or [])]
        if not to or not self.config.get("from_addr"):
            return DeliveryResult(ok=False, retryable=False, detail="from address and recipients are required")
        msg = build_message(event, from_addr=self.config["from_addr"], to=to,
                            subject_prefix=self.config.get("subject_prefix") or "[Paddock]")
        return await asyncio.to_thread(self._session, msg)

    async def test(self) -> HealthResult:
        blocked = await self._check_host()
        if blocked:
            return HealthResult(ok=False, detail=blocked.detail)
        res = await asyncio.to_thread(self._session, None)
        return HealthResult(ok=res.ok, detail=res.detail)
