## Abuse Automation
#### Require Python >= 3.7

#### Installation
    python3.7 -m pip install virtualenv
    su - abuse
    virtualenv venv
    source venv/bin/activate
    git clone https://github.com/elianmarks/abuse_automation.git
    cd abuse_automation
    git clone https://github.com/rthalley/dnspython.git
    cd dnspython && python setup.py install && cd ..
    python setup.py install

#### Copy playbooks and roles to /etc/ansible (only for services analyze and IA)
    -- Example --
    mkdir -p /etc/ansible/playbooks
    mkdir -p /etc/ansible/roles
    cp abuse_automation_playbooks/*.yaml /etc/ansible/playbooks
    cp -r abuse_automation_playbooks/scan_check /etc/ansible/roles
    cp -r abuse_automation_playbooks/domain_check /etc/ansible/roles
    cp -r abuse_automation_playbooks/block_execute /etc/ansible/roles
    cp -r abuse_automation_playbooks/abuse_upload /etc/ansible/roles

#### Create symbolic link of the abuse/bin/python in /opt/abuse/bin/pythonAbuse
    -- Example --
    ln -s /home/abuse/venv/bin/python3.7 /opt/abuse/bin/pythonAbuse

#### Copy the services to /usr/lib/systemd/system (only for services analyze and IA)
    -- Example --
    cp abuse_systemd_services/analyze.service /usr/lib/systemd/system
    cp abuse_systemd_services/ia.service /usr/lib/systemd/system
    systemctl daemon-reload
    systemctl start analyze
    systemctl start ia

#### Copy the services to /usr/lib/systemd/system (only for services abuse, zenapply and VT)
    -- Example --
    cp abuse_systemd_services/abuse.service /usr/lib/systemd/system
    cp abuse_systemd_services/zenapply.service /usr/lib/systemd/system
    cp abuse_systemd_services/vt.service /usr/lib/systemd/system
    systemctl daemon-reload
    systemctl start abuse
    systemctl start zenapply
    systemctl start vt
 