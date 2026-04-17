import smtplib
from email.mime.text import MIMEText

def send_alert(subject, body, to_email):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = "alert@monitoring.local"
    msg['To'] = to_email

    with smtplib.SMTP('localhost') as s:
        s.send_message(msg)
