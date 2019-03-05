import argparse
from ssl import wrap_socket,PROTOCOL_TLSv1_2 
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse,parse_qs
from OpenSSL import crypto, SSL
from random import randint
from pathlib import Path
from multiprocessing import Process
from time import sleep
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, func, text
from sqlalchemy import create_engine
from sqlalchemy.orm import relationship, backref, sessionmaker, close_all_sessions
from sqlalchemy.ext.declarative import declarative_base
from collections import namedtuple

URLTuple = namedtuple('URLTuple',['splash_link','redirect_url'])

def sprint(s,suff='[+]'):
    print(f'{suff} {s}')

########################
# SQLAlchemy ORM Classes
########################
Base = declarative_base()
class RedirectURL(Base):
    __tablename__ = 'redirect_url'
    id = Column(Integer, primary_key=True)
    value = Column(String, nullable=False, doc='Constructed URL value')
    identifier = Column(String, nullable=False, unique=True,
        doc='Identifier value unique to a given origin URL.')

    def to_urltuple(self,splash_url,id_param):
        return URLTuple(splash_url+f'?{id_param}={self.identifier}',self.value)

class AccessLog(Base):
    __tablename__ = 'access_log'
    id = Column(Integer, primary_key=True)
    source_ip = Column(String)
    time = Column(DateTime, default=func.now())
    url_id = Column(Integer, ForeignKey('redirect_url.id'))
    origin_url = relationship(RedirectURL,
        backref = backref('access_logs')
    )

class URLHandler():
    '''
    Object responsible for processing the URL of a given request. It will extract
    the parameters and make database queries to correlate a splash link with the
    appropriate redirect URL, which will be returned to the caller when the ```handle```
    method is called.
    '''

    def __init__(self, db_session, default_url, id_param, splash_url):
        '''
        Initialize a URL handler object.
        '''

        self.db_session = db_session    # session to make queries
        self.default_url = default_url  # default url to return when things go poorly
        self.id_param = id_param        # id_parameter to parse out of the query string
        self.splash_url = splash_url    # base splash url that will receive the id_param parameter and value

    def handle(self, request_handler):
        '''
        Handle the URL from the request by parsing the parameters from the
        URL query string, obtaining the appropriate redirect from the sqlite
        database, followed by passing it back to the caller.
        '''
        
        # PARSE THE QUERY STRING
        params = parse_qs(urlparse(request_handler.path).query)

        # ASSURE THE ID_PARAM IS PROVIDED
        if not self.id_param in params: return self.default_url

        # GET A LIST OF URLS MATCHING THE ARGUMENT TO PARAM_ID
        urls = self.db_session.query(RedirectURL).filter(
            RedirectURL.identifier == params[self.id_param][0]
        ).all()

        # RETURN THE DEFAULT URL SHOULD NO URL BE ASSIGNED THE PARAM_ID ARGUMENT
        if not urls: return self.default_url

        # ADD A HIT TO THE ACCESS LOG FOR THIS URL
        self.db_session.add(
            AccessLog(
                time=func.now(),
                url_id=urls[0].id,
                source_ip=request_handler.client_address[0]
            )
        )
        self.db_session.commit()

        # RETURN THE REDIRECT URL
        return urls[0].value

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    '''
    Request handler that always returns with HTML content forcing a redirect.
    '''

    # SET A CUSTOM SERVER VERSION
    server_version='Microsoft-IIS/8.0'
    sys_version=''

    def do_GET(self):

        #############################
        # CRAFT AND SEND THE RESPONSE
        #############################

        self.send_response(200)
        self.send_header('Content-Type','text/html')
        self.end_headers()
        self.wfile.write(
            bytes(
                '<meta http-equiv="refresh" content="0; url='\
                f'{self.server.url_handler.handle(self)}" />',
                'utf-8'
            )
        )

class RedirectServer(HTTPServer):
    '''
    Simple server to handle incoming requests. Extended to include a URL
    handler to allow lookups from the SQLite database.
    '''

    def __init__(self,
            url_handler,
            interface,
            port,
            request_handler=SimpleHTTPRequestHandler,
            certfile=None,
            keyfile=None):

        assert url_handler.__class__, (
            'URL handler must be of URLHandler type, not '\
            f'{url_handler.__class__}'
        )

        super().__init__((interface, port), request_handler)
        self.url_handler = url_handler
        self.certfile = certfile
        self.keyfile = keyfile

        ############################################################
        # WRAP THE SOCKET IN SSL IF KEYFILE OR CERTFILE ARE SUPPLIED
        ############################################################
        
        # ASSURE KEYFILE AND CERTFILE ARE BOTH SUPPLIED FOR SSL WRAPPING
        if keyfile or certfile:
    
            assert keyfile and certfile, (
                'Keyfile and certfile arguments are required for ssl wrapping'
            )
    
            assert Path(keyfile).exists(), f'keyfile does not exist ({keyfile})'
            assert Path(certfile).exists(), f'certfile does not exist ({certfile})'
    
            self.ssl_wrap(keyfile, certfile)
            self.ssl = True
        else:
            self.ssl = False

    def ssl_wrap(self,keyfile,certfile):

        sprint('Wrapping the HTTP server socket in TLS1.2')

        self.socket = wrap_socket(self.socket,
            server_side=True,
            certfile=certfile,
            keyfile=keyfile,
            ssl_version=PROTOCOL_TLSv1_2
        )

def run_server(*args,**kwargs):
    '''
    Initialize an HTTP server and run it forever.
    '''

    RedirectServer(*args,**kwargs).serve_forever()

def dump_urls(sess,splash_url,id_param):
    '''
    Dump the URLs to stdout.
    '''

    urls = [
        ru.to_urltuple(splash_url,id_param)
        for ru in sess.query(RedirectURL).all()
    ]

    slen = 0 # splash link length
    for t in urls:
        islen = len(t.splash_link)
        if slen < islen: slen = islen

    for u in urls:

        sep='-'*(slen+17)
        m=  f'{sep}\n- {yellow("Splash Link")}: {u.splash_link}\n'\
            f'- {yellow("Redirect URL")}: {u.redirect_url}\n{sep}\n'
        print(m)

def get_max_len(lst,attr=None):

    l=0
    if attr:

        for i in lst:

            ilen = len(i.__getattribute__(attr))
            if ilen > l: l = ilen

    else:

        for i in lst:

            ilen = len(i)
            if ilen > l: l = ilen

def dump_logs(sess,splash_url,id_param):
    '''
    Dump logs in a simple format to stdout.
    '''

    sep = '-'*60
    for ru in sess.query(RedirectURL).all():

        if ru.access_logs:

            tpl = ru.to_urltuple(splash_url,id_param) 

            m = f'- {yellow("Splash Link")}: {tpl.splash_link}\n'\
                f'- {yellow("Redirect URL")}: {tpl.redirect_url}\n'\
                f'- {yellow("Access Logs")}:\n\n'

            counter = 0
            for al in ru.access_logs:
                counter += 1
                m+=f'[{counter}][{al.time}] {al.source_ip}\n'

            m = m.strip()
    
            print(sep+'\n'+m)

    print(sep)

def url_watcher(sess,redirect_file,splash_url,id_param,suppress_stdout=False):
    '''
    Accept an I/O object expected to contain email addresses and watch it for
    any added lines. Values for each line will be created in the database and
    an updated list of splash links will be printed.
    '''

    sprint(f'Watching URL file: {redirect_file.name}')
    sprint(
        yellow(
            'To avoid having to restart the server, '\
            'append new URLs to the file above for new links '\
            'to be generated and printed to stdout'
        )
    )


    ruf = redirect_file


    try:

        while True:

            ruf.seek(0)
            
            # ITERATE LINES FROM EMAIL FILE....LAZY
            to_add = [
                RedirectURL(value=ru.strip(),identifier=generate_identifier())
                for ru in ruf if ru.strip() and not
                sess.query(RedirectURL).filter(RedirectURL.value == ru.strip()).count()
            ]

    
            # ADD THE NEW URLS TO THE DATABASE
            if to_add:

                m = ''
                for ru in to_add:
                    t = ru.to_urltuple(splash_url,id_param)
                    m += '- '+t.redirect_url+'\n'

                sprint(f'New Redirect URLs detected:\n\n{m}')

                sess.add_all(to_add)
                sess.commit()
   
                if not suppress_stdout:
                    dump_urls(sess,splash_url,id_param) 
                    sprint(
                        yellow(
                            'To avoid having to restart the server, '\
                            'append new URLs to the file above for new links '\
                            'to be generated and printed to stdout'
                        )
                    )

            sleep(1)

    except:

        return
    
def generate_identifier(min=1,max=120000):
    '''
    Generate a random intenger return it to the caller.
    '''

    return randint(min,max)

def colorize(s,code):
    return f'{code}{s}\033[0m'

def yellow(s):
    return colorize(s,'\033[093m')

def green(s):
    return colorize(s,'\033[092m')

def red(s):
    return colorize(s,'\033[091m')

if __name__ == '__main__':

    ######################################
    # DEFINE A BASIC COMMANDLINE INTERFACE
    ######################################

    parser = argparse.ArgumentParser(prog="Redirector thingy",
        description="Redirection, etc.")

    
    subparsers = parser.add_subparsers(help='Sub-command help')
    server_parser = subparsers.add_parser('server', help='Start the server')
    server_parser.set_defaults(cmd='server')
    server_parser.add_argument('--db-file', '-db', default='redirector_db.sqlite',
        help='Path to the appropriate SQLite file')
    server_parser.add_argument('--splash-url', '-su', required=True,
        help='URL which the id_param will be suffixed to.'),
    server_parser.add_argument('--id-param', '-ip', default='sid',
        help='Name of the parameter that will be suffixed to the link URL.')
    server_parser.add_argument('--interface', '-i', default='0.0.0.0',
        help="Interface/IP address the server will bind to.")
    server_parser.add_argument('--port', '-p', default=443, type=int,
        help="Port the server will listen on.")
    server_parser.add_argument('--cert-file', '-c', default=None,
        help="Certificate file for the server to uce")
    server_parser.add_argument('--key-file', '-k', default=None,
        help="Keyfile corresponding to certificate file")
    server_parser.add_argument('--redirect-url', '-ru', required=True,
        help='Single or default url which targets will be redirected')
    server_parser.add_argument('--redirect-url-file', '-ruf', required=False,
        help='Newline delimited file containing origin URLs that will be'\
            ' mapped back to a unique splash link')
    server_parser.add_argument('--suppress-link-output','-sl', action='store_true',
        help='Suppress printing of links to stdout. Run the script again'\
            ' using the --dump-links flag to obtain links when using this'\
            ' option')

    dumper_parser = subparsers.add_parser('dump',
            help='Dump logs and links from the database')
    dumper_parser.set_defaults(cmd='dumper')
    dumper_parser.add_argument('--db-file', '-db', default='redirector_db.sqlite',
        help='Path to the appropriate SQLite file')
    dumper_parser.add_argument('--splash-url', '-su', required=True,
        help='URL which the id_param will be suffixed to.'),
    dumper_parser.add_argument('--id-param', '-ip', default='sid',
        help='Name of the parameter that will be suffixed to the link URL.')
    me_group = dumper_parser.add_mutually_exclusive_group()
    me_group.add_argument('--links', '-dl', action='store_true',
        help='Just dump splash links from the database.')
    me_group.add_argument('--access-logs', '-dal', action='store_true',
        help='Dump access logs from the database')

    args = parser.parse_args()

    print(green('\nInitializing a Simple Redirector\n'))
    
    # Create a factory from which all sessions are created
    engine = create_engine('sqlite:///'+args.db_file)
    Session = sessionmaker()
    Session.configure(bind=engine)
    
    if not Path(args.db_file).exists():
        # CREATE THE DATABASE
         # Derive metadata from engine object
         # Metadata is used to create database tables
         # Sublasses of Base will share this metadata
        Base.metadata.create_all(engine)

    sess = Session()

    if args.cmd == 'dumper':
    
        if args.links:
            sprint('Dumping links to stdout\n')
            dump_urls(sess, args.splash_url, args.id_param)
            close_all_sessions()
            sprint(red('Exiting'))
            exit()
    
        if args.access_logs:
            sprint('Dumping access logs to stdout')
            dump_logs(sess, args.splash_url, args.id_param)
            close_all_sessions()
            sprint(red('Exiting'))
            exit()

    ##############################
    # HANDLE THE REDIRECT_URL_FILE
    ##############################

    if args.redirect_url_file:

        assert Path(args.redirect_url_file).exists(), (
            'Redirect URL file not found'
        )

        ru_file = open(args.redirect_url_file)

        # GET NEW REDIRECT URLS.....LAZY
        to_add = [
                    ru.strip() for ru in ru_file
                    if ru.strip()
                    and not sess.query(RedirectURL.value).filter(
                            RedirectURL.value == ru.strip()
                        ).count()
                ]


        ru_file.seek(0)

        # GENERATE AN IDENTIFIER AND ADD THE URL
        if to_add:
            
            # GENERATE THE IDENTIFIERS WHILE ASSURING UNIQUENESS
            identifiers = []
            for n in range(0,len(to_add)):
                while True:
                    i = generate_identifier()
                    if not sess.query(RedirectURL).filter(
                            RedirectURL.identifier==i).all():
                        identifiers.append(i)
                        break
    
            # BUILD REDIRECT URLS AND ADD THEM TO THE DATABASE
            sess.add_all(
                [
                    RedirectURL(value=ru,identifier=identifiers.pop())
                    for ru in to_add
                ]
            )
    
            sess.commit()

    else:

        # Set to none if no file is provided
        ru_file = None


    # CREATE THE URL HANDLER
    handler = URLHandler(sess,
            args.redirect_url,
            args.id_param,
            args.splash_url)

    # CREATE A URL WATCHER PROCESS
    if ru_file:

        url_watcher_session = Session()
        watcher = Process(target=url_watcher,
            args=(url_watcher_session, ru_file, args.splash_url,
                args.id_param,),
            kwargs={'suppress_stdout':args.suppress_link_output}
        )

    else:

        watcher = None

    # START THE REDIRECTION SERVER
    try:

        if watcher:


            sprint('Starting URL watcher process')
            watcher.start()

        else:

            sprint(f'Beginning static redirection to > {args.redirect_url}')
            sprint('Access logging will not occur')

        if not args.suppress_link_output:
            dump_urls(sess,args.splash_url,args.id_param)

        sprint('Dumping known URLS and Starting the HTTP server')
        run_server(url_handler=handler,
            interface=args.interface,
            port=args.port,
            certfile=args.cert_file,
            keyfile=args.key_file)

    except KeyboardInterrupt as e:

        print()
        sprint('Catching keyboard interrupt')
        sprint('Joining URL watcher process')
        sprint('Closing database connections')
        close_all_sessions()

        if watcher:
            watcher.join(1)
            sprint('Closing file connections')
            ru_file.close()

        sprint(red('Exiting'))
