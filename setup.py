from setuptools import setup

setup(
    name='duo_log_grabber',
    description='Retrieves logs from Duo Security API and sends CEF-compliant syslog messages.',
    author='Joe Aguirre',
    url='https://github.com/libresec/duo_log_grabber/',
    license='GPLv3+',
    install_requires=['loggerglue', 'duo_client_python'],
    dependency_links=['https://github.com/duosecurity/duo_client_python/tarball/master#egg=duo_client_python-2.1'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Topic :: Utilities'
    ],
)
