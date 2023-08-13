import os

MAIL_API_KEY=os.environ.get("MAIL_API_KEY")
MAIL_SENDER=os.environ.get("MAIL_SENDER")
MAIL_REPLYTO=os.environ.get("MAIL_REPLYTO")
BOT_TOKEN=os.environ.get("BOT_TOKEN")
HASH_SECRET=os.environ.get("HASH_SECRET")
BOTOWNER_GUILD=int(os.environ.get("BOTOWNER_GUILD"))
BOTOWNER_ALERT_CHANNEL=int(os.environ.get("BOTOWNER_ALERT_CHANNEL"))
BOTOWNER_MENTION=int(os.environ.get("BOTOWNER_MENTION"))
BOTOWNER_ALERT_ENABLED=bool(os.environ.get("BOTOWNER_ALERT_ENABLED"))
