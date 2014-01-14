from distutils.core import setup
from Duo_Log_Grabber import __version__

setup(
    name='Duo_Log_Grabber',
    version=__version__,
    description='Retrieves logs from Duo Security API and sends CEF-compliant syslog messages.',
    author='Joe Aguirre',
    url='https://github.com/libresec/duo_log_grabber/',
    license='GPLv3+',
    install_requires=['duo_client', 'netsyslog'],
    dependency_links=[
        'https://github.com/duosecurity/duo_client_python/tarball/master',
        'https://github.com/gma/python-netsyslog/tarball/master'
    ]
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Topic :: Utilities'
    ],
)
