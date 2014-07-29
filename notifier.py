from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import datetime
import smtplib


class EmailNotifier:
    def __init__(self, email_from, email_to, subject, text):
        self.email_from = email_from
        self.email_to = email_to
        self.mime_message = MIMEMultipart()
        self.prepare_message_headers(subject)
        self.create_mime_message(text)

    @staticmethod
    def create_notification(from_addr, to_addr, text):
        subject = "[repoguard] possibly vulnerable changes - %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        return EmailNotifier(from_addr, to_addr, subject, text)

    def prepare_message_headers(self, subject):
        self.subject = subject
        self.mime_message["Subject"] = subject
        self.mime_message["From"] = self.email_from
        self.mime_message["To"] = self.email_to

    def create_mime_message(self, text):
        self.text = text
        self.mime_message.attach(MIMEText(text.encode("utf-8"), "plain"))

    def send_if_fine(self, connection_string=None):
        if self.email_from and self.email_to and self.mime_message:
            self.smtp_send(connection_string)
        else:
            raise Exception("Mails should have FROM, TO headers and a message as well!")

    def smtp_send(self, connection_string):
        smtp = smtplib.SMTP('localhost')
        smtp.sendmail(self.email_from, self.email_to, self.mime_message.as_string())
        smtp.quit()
