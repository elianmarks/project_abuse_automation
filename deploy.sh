#!/bin/bash

# roles
ansible_roles="/etc/ansible/roles/"
r_abuse_upload="abuse_upload"
r_backup_generate="backup_generate"
r_block_execute="block_execute"
r_domain_check="domain_check"
r_scan_check="scan_check"
r_check_ssh="check_ssh"

# playbooks
ansible_playbooks="/etc/ansible/playbooks/"
p_abuse_upload="abuse.yaml"
p_backup_generate="backup.yaml"
p_block_execute="block.yaml"
p_domain_check="check.yaml"
p_scan_check="scan.yaml"

# variables
venv_path="/home/abuse/venv_abuse/bin/activate"
app_path="/home/abuse/abuse_automation"
playbooks_path="/home/abuse/abuse_automation/abuse_automation_playbooks"

_git_pull() {
  echo "[INFO] Executing pull..."
  cd $app_path
  _check_execution $?
  git pull
  _check_execution $?
  chown -R abuse. $app_path
  _check_execution $?
  echo "[INFO] Executing install..."
  # active venv
  su abuse -c "source $venv_path && python3.7 setup.py install && python3.7 setup.py install"
  _check_execution $?
}

_copy_roles() {
  echo "[INFO] Executing copy roles..."
  cd $playbooks_path
  # delete all roles
  rm -vrf $ansible_roles$r_abuse_upload
  rm -vrf $ansible_roles$r_backup_generate
  rm -vrf $ansible_roles$r_block_execute
  rm -vrf $ansible_roles$r_domain_check
  rm -vrf $ansible_roles$r_scan_check
  # copy all roles
  cp -vr $r_abuse_upload $ansible_roles
  _check_execution $?
  cp -vr $r_backup_generate $ansible_roles
  _check_execution $?
  cp -vr $r_block_execute $ansible_roles
  _check_execution $?
  cp -vr $r_domain_check $ansible_roles
  _check_execution $?
  cp -vr $r_scan_check $ansible_roles
  _check_execution $?
  if [ -d "$ansible_roles$r_check_ssh" ]; then
    cp -vr $r_check_ssh $ansible_roles
    _check_execution $?
  fi
}

_copy_playbooks() {
  echo "[INFO] Executing copy playbooks..."
  cd $playbooks_path
  # delete all playbooks
  rm -vrf $ansible_playbooks$p_abuse_upload
  rm -vrf $ansible_playbooks$p_backup_generate
  rm -vrf $ansible_playbooks$p_block_execute
  rm -vrf $ansible_playbooks$p_domain_check
  rm -vrf $ansible_playbooks$p_scan_check
  # copy all playbooks
  cp -v $p_abuse_upload $ansible_playbooks
  _check_execution $?
  cp -v $p_backup_generate $ansible_playbooks
  _check_execution $?
  cp -v $p_block_execute $ansible_playbooks
  _check_execution $?
  cp -v $p_domain_check $ansible_playbooks
  _check_execution $?
  cp -v $p_scan_check $ansible_playbooks
  _check_execution $?
}

_check_execution() {
    if [ "$1" != "0" ]
    then
        echo -e "[ERROR] :: Require checking..."
        exit 1
    fi
}

_services() {
  service analyze $1
  service ia $1
}

echo "Initializing deploy..."
_services "stop"
_git_pull
_copy_roles
_copy_playbooks
_services "start"
echo "Deploy completed..."