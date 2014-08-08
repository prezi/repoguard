from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import datetime
import smtplib


class EmailNotifier:
    def __init__(self, email_from, email_to, subject, text, connection_string):
        self.email_from = email_from
        self.email_to = email_to
        self.connection_string = connection_string
        self.mime_message = MIMEMultipart()
        self.prepare_message_headers(subject)
        self.create_mime_message(text)

    @staticmethod
    def create_notification(from_addr, to_addr, text, connection_string='localhost'):
        subject = "[repoguard] possibly vulnerable changes - %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        return EmailNotifier(from_addr, to_addr, subject, text, connection_string)

    def prepare_message_headers(self, subject):
        self.subject = subject
        self.mime_message["Subject"] = subject
        self.mime_message["From"] = self.email_from
        self.mime_message["To"] = self.email_to

    def create_mime_message(self, text):
        self.text = text
        self.mime_message.attach(MIMEText(text.encode("utf-8"), "plain"))

    def send_if_fine(self):
        if self.email_from and self.email_to and self.mime_message:
            self.smtp_send()
        else:
            raise Exception("Mails should have FROM, TO headers and a message as well!")

    def smtp_send(self):
        smtp = smtplib.SMTP(self.connection_string)
        smtp.sendmail(self.email_from, self.email_to, self.mime_message.as_string())
        smtp.quit()
