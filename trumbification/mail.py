import requests, json, logging

from .credentials import MAIL_API_KEY, MAIL_SENDER, MAIL_REPLYTO

log = logging.getLogger(__name__)


def send_verification_email(recipient: str, code: str) -> None:
    log.info("Sending email to %s", recipient)
    msg = {
        "api_key": MAIL_API_KEY,
        "to": [recipient],
        "sender": f"Discord Verification <{MAIL_SENDER}>",
        "subject": "WPI Discord Verification",
        "text_body": f"Your verification code is {code}",
        "html_body": f"<h2>Your verification code is</h2><h1>{code}</h1>",
        "custom_headers": [
            {"header": "Reply-To", "value": f"Discord Verification <{MAIL_REPLYTO}>"}
        ],
    }

    res = requests.post("https://api.smtp2go.com/v3/email/send", json=msg)
    log.info(res.content)
