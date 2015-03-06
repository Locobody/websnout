#!/usr/bin/python
from functools import wraps
from tornado.auth import GoogleMixin
from tornado.escape import to_unicode
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop, PeriodicCallback
from tornado.web import asynchronous, Application, HTTPError, RequestHandler
from tornado.websocket import WebSocketHandler
from tornado.options import define, options, parse_command_line
import anyjson
import os.path as op
import logging
import sys
import uuid
import pkg_resources

import base64
import subprocess

FILENAMES = []
POSITIONS = []
LISTENERS = []


AUTH_COOKIE = 'auth'
ALLOW_ALL = 'all'
NAMESPACE = uuid.uuid1()


define('debug',  False, bool)
define('port', 8000, int)
define('files', multiple=True)
define('allow', multiple=True, default=ALLOW_ALL)
define('secret')
define('credentials', default='test:test')


def require_basic_auth(handler_class):
    def wrap_execute(handler_execute):
        def require_basic_auth(handler, kwargs):
            auth_header = handler.request.headers.get('Authorization')
            if auth_header is None or auth_header != options.credentials:
                handler.set_status(401)
                handler.set_header('WWW-Authenticate', 'Basic realm=Restricted')
                handler._transforms = []
                handler.finish()
                return False
            auth_decoded = base64.decodestring(auth_header[6:])
            kwargs['basicauth_user'], kwargs['basicauth_pass'] = auth_decoded.split(':', 2)
            return True
        def _execute(self, transforms, *args, **kwargs):
            if not require_basic_auth(self, kwargs):
                return False
            return handler_execute(self, transforms, *args, **kwargs)
        return _execute
 
    handler_class._execute = wrap_execute(handler_class._execute)
    return handler_class



def authenticated(func):
    @wraps(func)
    def wrapper(handler, *args, **kwargs):
        if options.allow == ALLOW_ALL or handler.get_secure_cookie(AUTH_COOKIE):
            return func(handler, *args, **kwargs)
        return handler.redirect('/signin/')
    return wrapper


def file_uuid(filename):
    return file_uuid.cache.setdefault(filename, str(uuid.uuid5(NAMESPACE, filename.encode('utf8'))))
file_uuid.cache = {}


def periodic():
    
    for i, filename, position in zip(range(len(FILENAMES)), FILENAMES, POSITIONS):
        
        if op.getsize(filename) < position:  # handling possible logrotate
            position = 0
        
        with open(filename, 'r') as tail:
            tail.seek(position)
            count = 0
            for line in tail.readlines(10240):  # to prevent blocking on intensive writes
                count += 1
                for client in LISTENERS:
                    client.write_message(anyjson.serialize([file_uuid(filename), line]))
            POSITIONS[i] = tail.tell()
    
        if count > 1:
            logging.debug('read %d lines from %s', count, filename)
        elif count == 1:
            logging.debug('read %d line from %s', count, filename)
            
                
class TailHandler(WebSocketHandler):

    def open(self):
        logging.info("WebSocket open: %s", self.request.remote_ip)
        if options.allow == ALLOW_ALL or self.get_secure_cookie(AUTH_COOKIE):
            LISTENERS.append(self)

    def on_message(self, message):
        logging.warning('It\'s trying to talk: %s', message)
        self.write_message("Your message was: " + message)
        subprocess.call('/home/user/do_smth.sh', shell=True) #Exec some script on click, for example

    def on_close(self):
        logging.info("WebSocket close: %s", self.request.remote_ip)
        try:
            LISTENERS.remove(self)
        except ValueError:
            pass

@require_basic_auth
class MainHandler(RequestHandler):
    @asynchronous
    @authenticated
    def get(self, *args, **kwargs):
        tails = [(op.basename(f), file_uuid(f)) for f in FILENAMES]
        kwargs = {
            'hostname': self.request.host,
            'tails': tails,
            'username': None
        }
        if options.allow != ALLOW_ALL:
            kwargs['username'] = self.get_secure_cookie(AUTH_COOKIE)
        self.render('template.html', **kwargs)


class SigninHandler(RequestHandler, GoogleMixin):

    @asynchronous
    def get(self, *args, **kwargs):
        if self.get_argument('openid.mode', None):
            self.get_authenticated_user(self.callback)
            return
        self.authenticate_redirect()

    def callback(self, user):
        if user and user.get('email') in options.allow:
            logging.info(u'authorized user: %s %s <%s>', user['first_name'], user['last_name'], user['email'])
            self.set_secure_cookie(AUTH_COOKIE, user['email'])
            self.redirect(self.get_argument('next', '/'))
        else:
            logging.info(u'unauthorized user: %s %s <%s>', user['first_name'], user['last_name'], user['email'])
            raise HTTPError(403)


class SignoutHandler(RequestHandler):

    def get(self, *args, **kwargs):
        self.clear_all_cookies()
        self.redirect('/')


def main():
    parse_command_line()
    
    if options.allow != ALLOW_ALL and not options.secret:
        logging.error('secret should be provided if you are intended to limit access')
        sys.exit(0)
        
    if options.credentials:
        options.credentials = 'Basic ' + base64.b64encode(
            options.credentials)

    for filename in options.files:
        FILENAMES.append(filename)
        POSITIONS.append(op.getsize(filename))

    logging.debug('initializing...')
    
    PeriodicCallback(periodic, 100).start()

    routes = [(r'/', MainHandler), (r'/tail/', TailHandler),
        (r'/signin/', SigninHandler), (r'/signout/', SignoutHandler)]
    
    settings = {  
        'static_path': pkg_resources.resource_filename('webtail', 'static'),  # pylint: disable-msg=E1101
        'template_path': pkg_resources.resource_filename('webtail', 'templates'),  # pylint: disable-msg=E1101
        'cookie_secret': options.secret,
        'debug': options.debug
    }
    
    application = Application(routes, **settings)
    
    
    http_server = HTTPServer(application, ssl_options = {
        "certfile": "server.crt",
        "keyfile": "server.key"
    })
    http_server.listen(options.port)

    try:
        logging.info('starting')
        IOLoop.instance().start()
    except (SystemExit, KeyboardInterrupt):
        logging.info('shutting down')
        IOLoop.instance().stop()
        sys.exit()


if __name__ == '__main__':
    main()
