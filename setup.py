# -*- coding: utf-8 -*-
"""

- Contributors
Elliann Marks <elian.markes@gmail.com>

"""

# libraries
from setuptools import setup

setup(
    name="Abuse Automation",
    version="2.0b",
    packages=["abuse_automation"],
    include_package_data=True,
    entry_points={"console_scripts": ["abuse = abuse_automation.abuse:main"]},
    install_requires=['python-dateutil==2.7.5', 'whois', 'PyYAML', 'cachetools==3.1.0', 'certifi==2018.11.29', 'configparser==3.7.1',
                      'mysql-connector-python==8.0.17', 'pika==1.1.0',
                      'python-dateutil==2.7.5', 'requests==2.21.0', 'tld==0.9.2', 'urllib3==1.24.1', 'zenpy==2.0.8',
                      'dnspython==2.0.0',
                      'py3dns==3.2.0', 'imgkit==1.0.2', 'validate-email==1.3', 'ipwhois==1.1.0', 'python-whois==0.7.1',
                      'futures==3.1.1', 'future==0.17.1', 'sgqlc==7.0',
                      'GitPython==2.1.11', 'scikit-learn==0.21.3', 'scipy==1.3.1', 'pandas==0.25.1', 'numpy==1.17.2',
                      'ipinfo==2.0.0', 'python-geoip-python3==1.3', 'python-geoip-geolite2==2015.303',
                      'bitmath==1.3.3.1', 'PyYAML==5.1.1', 'requests==2.21.0', 'ansible==2.8.3', 'selinux==0.1.6'],
    data_files=[('/opt/abuse', []), ('/opt/abuse/bin', []), ('/opt/abuse/prints', []), ('/opt/abuse/action', []), ('/opt/abuse/generate_model', []),
                ('/opt/abuse/files', []), ('/opt/abuse/logs', []), ('/opt/abuse/reports', []), ('/opt/abuse/logs/ia', []),
                ('/opt/abuse/sigs', []), ('/opt/abuse/files', ['abuse_automation_files/model.mia']), ('/opt/abuse/logs/analyze', []),
                ('/opt/abuse/sigs', ['abuse_scan_sigs/clamav-64bit.tar.gz']), ('/opt/abuse/logs/vt', []), ('/opt/abuse/logs/main', []),
                ('/opt/abuse/sigs', ['abuse_scan_sigs/phishing.ndb']), ('/opt/abuse/logs/zenapply', []),
                ('/opt/abuse/sigs', ['abuse_scan_sigs/malware.ndb']),
                ('/opt/abuse/bin', ['abuse_automation/abuse.py']),
                ('/opt/abuse/files/', ['abuse_automation_files/regex.yaml']),
                ('/opt/abuse/files/', ['abuse_automation_files/network.yaml'])],
    platforms="linux",
    zip_safe=False,
    author="Elliann Marks",
    author_email="elian.markes@gmail.com",
    description="Abuse Automation",
    license="BSD",
    keywords="abuse, automation",
    url="https://github.com/elianmarks/abuse_automation",
)

setup(
    name="Abuse Automation Analyze",
    version="2.0b",
    packages=["abuse_automation_analyze"],
    include_package_data=True,
    entry_points={"console_scripts": ["analyze = abuse_automation_analyze.analyze:main"]},
    data_files=[('/opt/abuse/bin', ['abuse_automation_analyze/analyze.py'])],
    platforms="linux",
    zip_safe=False,
    author="Elliann Marks",
    author_email="elian.markes@gmail.com",
    description="Abuse Automation Analyze",
    license="BSD",
    keywords="abuse, automation, analyze",
    url="https://github.com/elianmarks/abuse_automation",
)

setup(
    name="Abuse Automation VT",
    version="2.0b",
    packages=["abuse_automation_vt"],
    include_package_data=True,
    entry_points={"console_scripts": ["vt = abuse_automation_vt.vt:main"]},
    data_files=[('/opt/abuse/bin', ['abuse_automation_vt/vt.py'])],
    platforms="linux",
    zip_safe=False,
    author="Elliann Marks",
    author_email="elian.markes@gmail.com",
    description="Abuse Automation VT",
    license="BSD",
    keywords="abuse, automation, vt",
    url="https://github.com/elianmarks/abuse_automation",
)

setup(
    name="Abuse Automation IA",
    version="2.0b",
    packages=["abuse_automation_ia"],
    include_package_data=True,
    entry_points={"console_scripts": ["ia = abuse_automation_ia.ia:main"]},
    data_files=[('/opt/abuse/bin', ['abuse_automation_ia/ia.py'])],
    platforms="linux",
    zip_safe=False,
    author="Elliann Marks",
    author_email="elian.markes@gmail.com",
    description="Abuse Automation IA",
    license="BSD",
    keywords="abuse, automation, ia",
    url="https://github.com/elianmarks/abuse_automation",
)

setup(
    name="Abuse Automation Zenapply",
    version="2.0b",
    packages=["abuse_automation_zenapply"],
    include_package_data=True,
    entry_points={"console_scripts": ["zenapply = abuse_automation_zenapply.zenapply:main"]},
    data_files=[('/opt/abuse/bin', ['abuse_automation_zenapply/zenapply.py'])],
    platforms="linux",
    zip_safe=False,
    author="Elliann Marks",
    author_email="elian.markes@gmail.com",
    description="Abuse Automation Zenapply",
    license="BSD",
    keywords="abuse, automation, zenapply",
    url="https://github.com/elianmarks/abuse_automation"
)
