# About

This is a utility that will leverage the Duo Security API (https://www.duosecurity.com/docs) and pulls both the admin and authentication logs and then write CEF-compliant syslog messages to an arbitrary server.

This could used used to with a scheduled job to import Duo Security logs into
a SIEM or log management solution.

# Installation

1. Download the zip archive: https://github.com/libresec/duo_log_grabber/archive/master.zip
2. pip install -r requirements.txt
3. update the conf.ini file

# Notes

Pay attention to the conf.ini file. Many important value are set, including:

- syslog destination
- timeframe for log retrieval 
- API authentication credentials
- rudimentary debugging

# Dependencies

The following modules are used:

- duo_client (2.1) - https://github.com/duosecurity/duo_client_python
- loggerglue (1.0) - https://pypi.python.org/pypi/loggerglue/1.0

Only tested on Python 2.7.6. 

# Resources

Common Event Format (CEF) - https://protect724.arcsight.com/docs/DOC-1613