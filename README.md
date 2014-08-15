# About

This utility leverages the Duo Security API (https://www.duosecurity.com/docs) to consume both the admin and authentication logs, and write CEF-compliant syslog messages to an arbitrary server. Use this incombination with a scheduled job to import Duo Security logs into a SIEM or log management solution.

# Installation

1. download the zip archive
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
This is the most current CEF definition, but requires a Protect724 login.
- https://protect724.arcsight.com/docs/DOC-1613

This is slightly older, but good enough:
- http://mita-tac.wikispaces.com/file/view/CEF+White+Paper+071709.pdf
