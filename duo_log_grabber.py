"""
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

Logging format (TSV):
For other systems that parse and store syslog, a simple line of TSV is easy
to parse out. The way fields are tab separated assume that there won't be
any commas in the fields.

Fields are laid out as follows for a TSV log line - auth_logs:

    timestamp\tduo_event_type\tsrcip\tfactor\tusername\tresult\tintegration

Example auth_log:

    Jul 02 08:59:44\tduo_auth_log\t129.21.206.5\tDuo Push\tsapt\tSUCCESS\tVPN

NOTE -
Auth_logs are completely built out - work still needs to be done for admim
logs. I (RyPeck) am switching to using LEEF format for QRadar however, so
someone else will have to pick that up if they want it.
"""


from __future__ import print_function
from datetime import datetime
import calendar
import ConfigParser
import duo_client
from loggerglue.emitter import UDPSyslogEmitter
import socket
import time


def print_msg(func):
    '''
    Decorator which wraps send_syslog() and prints all
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


@print_msg
def send_syslog(msg):
    '''
    Sends syslog messages to the server specified in conf.ini.
    '''
    l.emit(msg)


def log_to_cef(entry, entry_type):
    '''
    Args are formatted as a CEF-compliant message and then
    passed to send_syslog().
    '''
    eventtype = entry['eventtype']

    # For auth logs these are the same for some reason...
    if entry_type == "admin_log":
        action = entry['action']

        # timestamp is converted to milliseconds for CEF
        # repr is used to keep '\\' in the domain\username
        extension = {
            'duser=': repr(entry['username']).lstrip("u").strip("'"),
            'rt=': str(entry['timestamp']*1000),
            'description=': str(entry.get('description')),
            'dhost=': entry['host'],
        }

    elif entry_type == "auth_log":
        action = entry['eventtype']

        # timestamp is converted to milliseconds for CEF
        # repr is used to keep '\\' in the domain\username
        extension = {
            'rt=': str(entry['timestamp']*1000),
            'src=': entry['ip'],
            'dhost=': entry['host'],
            'duser=': repr(entry['username']).lstrip("u").strip("'"),
            'outcome=': entry['result'],
            'cs1Label=': 'new_enrollment',
            'cs1=': str(entry['new_enrollment']),
            'cs2Label=': 'factor',
            'cs2=': entry['factor'],
            'ca3Label=': 'integration',
            'cs3=': entry['integration'],
        }

    header = '|'.join([CEF_VERSION, VENDOR, PRODUCT, VERSION,
                      eventtype, action, SEVERITY]) + '|'

    extension_list = []
    for key in extension:
        extension_list.extend([key + extension[key]])

    msg = header + ' '.join(extension_list)
    cef = ' '.join([syslog_header, msg])

    send_syslog(cef)


def log_to_tsv(entry, entry_type):
    """
    Log an event in tab separated values.

    Order for each event is as specified by the order variable
    """
    # Send timestamp for the entry to syslog
    timestamp = time.strftime('%b %d %H:%M:%S',
                              time.localtime(entry['timestamp']))

    if entry_type == "admin_log":
        data = {
            'duser': repr(entry['username']).lstrip("u").strip("'"),
            'description': str(entry.get('description')),
            'dhost': entry['host'],
            'action': entry['action'],
        }

        order = [
            'duser',
            'dhost',
            'description',
            'action',
            ]

    elif entry_type == "auth_log":
        data = {
            'ip': entry['ip'],
            'factor': entry['factor'],
            'user': repr(entry['username']).lstrip("u").strip("'"),
            'result': entry['result'],
            'integration': entry['integration'],
            }

        order = [
            'ip',
            'factor',
            'user',
            'result',
            'integration',
            ]

    syslog_line = timestamp + ' ' + HOSTIP + '\tduo_' + entry_type + '\t' + \
        '\t'.join([data[x] for x in order])

    send_syslog(syslog_line)


def log_event(entry, entry_type):
    """
    Log an individual entry
    """
    if LOG_METHOD == "cef":
        log_to_cef(entry, entry_type)
    elif LOG_METHOD == "tsv":
        log_to_tsv(entry, entry_type)


def get_logs(proxy=None, proxy_port=None):
    '''
    Connects to the DuoSecurity API and grabs the admin
    and auth logs, which are then parsed and passed to
    log_to_cef().
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
        log_event(entry, 'admin_log')

    for entry in auth_log:
        log_event(entry, 'auth_log')

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
        HOSTIP = socket.gethostbyname(HOSTNAME)

        SYSLOG_SERVER = config.get('syslog', 'SYSLOG_SERVER')
        SYSLOG_PORT = config.getint('syslog', 'SYSLOG_PORT')

        LOG_METHOD = config.get('logging', 'LOG_METHOD')

        DEBUG = config.getboolean('debug', 'DEBUG')
        DEBUG_FILE = config.get('debug', 'DEBUG_FILE')

        date = datetime.utcnow()
        utc_date = calendar.timegm(date.utctimetuple())
        mintime = utc_date - DELTA

        syslog_date = datetime.now()
        syslog_date_time = syslog_date.strftime("%b %d %H:%M:%S")
        syslog_header = ' '.join([syslog_date_time, HOSTNAME])

        l = UDPSyslogEmitter(address=(SYSLOG_SERVER, SYSLOG_PORT))

        if PROXY_ENABLE:
            get_logs(proxy=PROXY_SERVER, proxy_port=PROXY_PORT)
        else:
            get_logs()
        if DEBUG:
            with open(DEBUG_FILE, 'a+') as debug_file:
                print("Ran at %s" % date, file=debug_file)

    except Exception as e:
        with open('exceptions.log', 'a+') as exception_file:
            print(datetime.utcnow(), e, file=exception_file)
