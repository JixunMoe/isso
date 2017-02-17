# -*- encoding: utf-8 -*-

from __future__ import unicode_literals

import io
import sys
import cgi
import time
import json

import socket
import smtplib
import requests

from email.utils import formatdate
from email.header import Header
from email.mime.text import MIMEText

import logging
logger = logging.getLogger("isso")

try:
    import uwsgi
except ImportError:
    uwsgi = None

from isso.compat import PY2K
from isso import local

if PY2K:
    from thread import start_new_thread
else:
    from _thread import start_new_thread


class SMTP(object):

    def __init__(self, isso):

        self.isso = isso
        self.conf = isso.conf.section("smtp")

        # test SMTP connectivity
        try:
            with self:
                logger.info("connected to SMTP server")
        except (socket.error, smtplib.SMTPException):
            logger.exception("unable to connect to SMTP server")

        if uwsgi:
            def spooler(args):
                try:
                    self._sendmail(args[b"subject"].decode("utf-8"),
                                   args["body"].decode("utf-8"))
                except smtplib.SMTPConnectError:
                    return uwsgi.SPOOL_RETRY
                else:
                    return uwsgi.SPOOL_OK

            uwsgi.spooler = spooler

    def __enter__(self):
        klass = (smtplib.SMTP_SSL if self.conf.get('security') == 'ssl' else smtplib.SMTP)
        self.client = klass(host=self.conf.get('host'),
                            port=self.conf.getint('port'),
                            timeout=self.conf.getint('timeout'))

        if self.conf.get('security') == 'starttls':
            if sys.version_info >= (3, 4):
                import ssl
                self.client.starttls(context=ssl.create_default_context())
            else:
                self.client.starttls()

        username = self.conf.get('username')
        password = self.conf.get('password')
        if username and password:
            if PY2K:
                username = username.encode('ascii')
                password = password.encode('ascii')

            self.client.login(username, password)

        return self.client

    def __exit__(self, exc_type, exc_value, traceback):
        self.client.quit()

    def __iter__(self):
        yield "comments.new:after-save", self.notify

    def format(self, thread, comment):

        rv = io.StringIO()

        author = comment["author"] or "Anonymous"
        if comment["email"]:
            author += " <%s>" % comment["email"]

        rv.write(author + " wrote:\n")
        rv.write("\n")
        rv.write(comment["text"] + "\n")
        rv.write("\n")

        if comment["website"]:
            rv.write("User's URL: %s\n" % comment["website"])

        rv.write("IP address: %s\n" % comment["remote_addr"])
        rv.write("Link to comment: %s\n" % (local("origin") + thread["uri"] + "#isso-%i" % comment["id"]))
        rv.write("\n")

        uri = local("host") + "/id/%i" % comment["id"]
        key = self.isso.sign(comment["id"])

        rv.write("---\n")
        rv.write("Delete comment: %s\n" % (uri + "/delete/" + key))

        if comment["mode"] == 2:
            rv.write("Activate comment: %s\n" % (uri + "/activate/" + key))

        rv.seek(0)
        return rv.read()

    def notify(self, thread, comment):

        body = self.format(thread, comment)

        if uwsgi:
            uwsgi.spool({b"subject": thread["title"].encode("utf-8"),
                         b"body": body.encode("utf-8")})
        else:
            start_new_thread(self._retry, (thread["title"], body))

    def _sendmail(self, subject, body):

        from_addr = self.conf.get("from")
        to_addr = self.conf.get("to")

        msg = MIMEText(body, 'plain', 'utf-8')
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = Header(subject, 'utf-8')

        with self as con:
            con.sendmail(from_addr, to_addr, msg.as_string())

    def _retry(self, subject, body):
        for x in range(5):
            try:
                self._sendmail(subject, body)
            except smtplib.SMTPConnectError:
                time.sleep(60)
            else:
                break


class Stdout(object):

    def __init__(self, conf):
        pass

    def __iter__(self):
        yield "comments.new:new-thread", self._new_thread
        yield "comments.new:finish", self._new_comment
        yield "comments.edit", self._edit_comment
        yield "comments.delete", self._delete_comment
        yield "comments.activate", self._activate_comment

    def _new_thread(self, thread):
        logger.info("new thread %(id)s: %(title)s" % thread)

    def _new_comment(self, thread, comment):
        logger.info("comment created: %s", json.dumps(comment))

    def _edit_comment(self, comment):
        logger.info('comment %i edited: %s', comment["id"], json.dumps(comment))

    def _delete_comment(self, id):
        logger.info('comment %i deleted', id)

    def _activate_comment(self, id):
        logger.info("comment %s activated" % id)

class MailGun(object):

    def __init__(self, isso):
        self.isso = isso
        self.conf = isso.conf.section("mailgun")
        self.comments = isso.db.comments

    def __iter__(self):
        yield "comments.new:after-save", self.notify

    def _sendmail(self, thread, comment, parent):
        # Build message.
        data={"from": "Comments <comment@jixun.moe>",
              "subject": thread['title'],
              "text": "",
              "html": "",
              "o:tag": ["New Comment", "newcomment"]}

        if parent and parent['email'] != self.conf.monitor:
            data['to'] = parent['email']
            data['bcc'] = self.conf.monitor
        else:
            data['to'] = self.conf.monitor

        # Generate text and html version of the email.
        author = comment["author"] or "Anonymous"
        url = comment["website"] or ""
        comment_url = (local("origin") + thread["uri"] + "#isso-%i" % comment["id"])
        text = '''
%s%s wrote:

%s

View the comment at: %s<%s>
'''.strip() % (author, ("<%s>" % url) if url else "", comment['text'], thread['title'], comment_url)

        html = '''
<script type="application/ld+json">
{
  "@context": "http://schema.org",
  "@type": "EmailMessage",
  "potentialAction": {
    "@type": "ViewAction",
    "target": %s,
    "name": %s
  },
  "description": %s
}
</script>

<a href="%s" target="_blank">%s</a> have wrote:

<blockquote>%s</blockquote>

View the comment at: <a href="%s" target="_blank">%s</a>
'''.strip() % (
    json.dumps(comment_url), json.dumps("View Comment"), json.dumps('View new comment at "%s"' % thread['title']), 
    url, author, self.isso.render(comment['text']), comment_url, cgi.escape(thread['title']))

    (data['text'], data['html']) = (text, html)
    requests.post(
        'https://api.mailgun.net/v3/%s/messages' % self.conf.domain,
        auth=('api', self.conf.api_key),
        data=data)

    def notify(self, thread, comment):
        parent = None
        if comment['parent']:
            parent = self.comments.get(comment['parent'])

        self._sendmail(self, thread, comment, parent)



