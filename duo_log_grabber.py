'''
Grabs the administration and authentication logs from the Duo Security
API and sends CEF-compliant syslog messages.

Error/Debug Logs:
Setting the 'DEBUG' flag in the conf.ini file prints all the
CEF messages to a file specified in 'DEBUG_FILE'. By default,
this is written to 'debug.log'. All exceptions  are logged to
'exceptions.log'.

Logging format (CEF):
This is the ArcSight log format and is comprised of a syslog prefix,
a header, and an extension, as shown here:

    Jan 18 11:07:53 host CEF:Version|Device Vendor|
    Device Product|Device Version|Signature ID|Name|Severity|[Extension]

    Sep 19 08:26:10 host CEF:0|Security|threatmanager|1.0|100|worm
    successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232

'''
from __future__ import print_function
from datetime import datetime
import calendar
import ConfigParser
import duo_client
from loggerglue.emitter import UDPSyslogEmitter
import socket

def print_cef(func):
    '''
    Decorator which wraps send_syslog() and prints all CEF
    messages to the file specified in conf.ini.
    '''
    def wrapper(*args, **kwargs):
        if DEBUG:
            with open(DEBUG_FILE, 'a+') as debug_file:
                print(*args, file=debug_file)
            func(*args, **kwargs)
        else:
            func(*args, **kwargs)
    return wrapper


@print_cef
def send_syslog(cef):
    '''
    Sends syslog messages to the server specified in conf.ini.
    '''
    l.emit(cef)

def log_to_cef(eventtype, action, **kwargs):
    '''
    Args are formatted as a CEF-compliant message and then
    passed to send_syslog().
    '''
    header = '|'.join([CEF_VERSION, VENDOR, PRODUCT, VERSION,
                      eventtype, action, SEVERITY]) + '|'
    extension = []
    for key in kwargs:
        extension.extend([key + kwargs[key]])
    
    msg = header + ' '.join(extension)
    cef = ' '.join([syslog_header, msg])
    
    send_syslog(cef)


def get_logs(proxy=None, proxy_port=None):
    '''
    Connects to the DuoSecurity API and grabs the admin
    and auth logs, which are then parsed and passed to
    log)to_cef().
    '''
    admin_api = duo_client.Admin(
        ikey=INTEGRATION_KEY,
        skey=SECRET_KEY,
        host=API_HOST)
    
    if proxy and proxy_port:
        admin_api.set_proxy(proxy, proxy_port)

    # Check to see if DELTA is 0. If so, retrieve all logs.
    if mintime == utc_date:
        admin_log = admin_api.get_administrator_log()
        auth_log = admin_api.get_authentication_log()
    else:
        admin_log = admin_api.get_administrator_log(mintime=mintime)
        auth_log = admin_api.get_authentication_log(mintime=mintime)

    for entry in admin_log:
        # timestamp is converted to milliseconds for CEF
        # repr is used to keep '\\' in the domain\username
        extension = {
            'duser=': repr(entry['username']).strip("u'"),
            'rt=': str(entry['timestamp']*1000),
            'description=': str(entry.get('description')),
            'dhost=': entry['host'],
        }

        log_to_cef(entry['eventtype'], entry['action'], **extension)

    for entry in auth_log:
        # timestamp is converted to milliseconds for CEF
        # repr is used to keep '\\' in the domain\username
        extension = {
            'rt=': str(entry['timestamp']*1000),
            'src=': entry['ip'],
            'dhost=': entry['host'],
            'duser=': repr(entry['username']).strip("u'"),
            'outcome=': entry['result'],
            'cs1Label=': 'new_enrollment',
            'cs1=': str(entry['new_enrollment']),
            'cs2Label=': 'factor',
            'cs2=': entry['factor'],
            'ca3Label=': 'integration',
            'cs3=': entry['integration'],
        }

        log_to_cef(entry['eventtype'], entry['eventtype'], **extension)

if __name__ == "__main__":
    try:
        config = ConfigParser.ConfigParser()
        config.read('conf.ini')

        INTEGRATION_KEY = config.get('api', 'INTEGRATION_KEY')
        SECRET_KEY = config.get('api', 'SECRET_KEY')
        API_HOST = config.get('api', 'API_HOST')
        DELTA = config.getint('api', 'DELTA')

        PROXY_ENABLE = config.getboolean('proxy', 'PROXY_ENABLE')

        if PROXY_ENABLE:
            PROXY_SERVER = config.get('proxy', 'PROXY_SERVER')
            PROXY_PORT = config.getint('proxy', 'PROXY_PORT')

        VENDOR = config.get('cef', 'VENDOR')
        PRODUCT = config.get('cef', 'PRODUCT')
        VERSION = config.get('cef', 'VERSION')
        SEVERITY = config.get('cef', 'SEVERITY')
        CEF_VERSION = config.get('cef', 'CEF_VERSION')
        HOSTNAME = socket.gethostname()

        SYSLOG_SERVER = config.get('syslog', 'SYSLOG_SERVER')
        SYSLOG_PORT = config.getint('syslog', 'SYSLOG_PORT')

        DEBUG = config.getboolean('debug', 'DEBUG')
        DEBUG_FILE = config.get('debug', 'DEBUG_FILE')

        date = datetime.utcnow()
        utc_date = calendar.timegm(date.utctimetuple())
        mintime = utc_date - DELTA

        syslog_date = datetime.now()
        syslog_date_time = syslog_date.strftime("%b %d %I:%M:%S")
        syslog_header = ' '.join([syslog_date_time, HOSTNAME])
        
        l = UDPSyslogEmitter(address=(SYSLOG_SERVER, SYSLOG_PORT))

        if PROXY_ENABLE:
            get_logs(proxy=PROXY_SERVER, proxy_port=PROXY_PORT)
        else:
            get_logs()

    except Exception, e:
        with open('exceptions.log', 'a+') as exception_file:
            print(datetime.utcnow(), e, file=exception_file)
