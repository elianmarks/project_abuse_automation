# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 2.0 - 11/07/2019**

**- Version 3.0 - 18/12/2019**

"""

# custom libraries
from ansible.inventory.manager import InventoryManager
from ansible.vars.manager import VariableManager
from ansible.parsing.dataloader import DataLoader
from ansible.executor import playbook_executor
from ansible import context
from ansible.module_utils.common.collections import ImmutableDict


class ModuleAnsible(object):

    def __init__(self, module_log, module_configuration, abuse_server=False, user_ansible="root", verbosity=0):
        try:
            self._log = module_log
            self.module_configuration = module_configuration
            if abuse_server:
                private_key_path = self.module_configuration.private_key_path_abuse
            else:
                private_key_path = self.module_configuration.private_key_path_all
            context.CLIARGS = ImmutableDict(connection='ssh', remote_user=user_ansible, forks=10,
                                            private_key_file=private_key_path, verbosity=verbosity, check=False, diff=False, host_key_checking=False,
                                            timeout=30, log_path=None, connect_timeout=30, connect_retries=30, connect_interval=30, become_method=None,
                                            roles_path=self.module_configuration.ansible_roles, become_user=None, start_at_task=None, module_path=None, listhosts=None, subset=None,
                                            ask_vault_pass=None, vault_password_files=None, new_vault_password_file=None, output_file=None,
                                            one_line=None, tree=None, ask_sudo_pass=None, ask_su_pass=None, sudo=None, sudo_user=None,
                                            become=None, become_ask_pass=None, ask_pass=None, ssh_common_args=None, sftp_extra_args=None,
                                            scp_extra_args=None, ssh_extra_args=None, poll_interval=None, seconds=None, syntax=None, force_handlers=None,
                                            flush_cache=None, listtasks=None, listtags=None)
            self._passwords = {}
            self._loader = DataLoader()

        except Exception as er:
            # generate a error log
            self._log.error("run playbook - {} - {}".format(__name__, er))

    def execute(self, playbook, extra_vars, server_ip):
        try:
            server_ip = str(server_ip) + ","
            inventory = InventoryManager(loader=self._loader, sources=server_ip)
            variable_manager = VariableManager(loader=self._loader, inventory=inventory)
            variable_manager.extra_vars.update(extra_vars)
            playbook_execution = playbook_executor.PlaybookExecutor(
                playbooks=[playbook],
                inventory=inventory,
                variable_manager=variable_manager,
                loader=self._loader,
                passwords=self._passwords)
            playbook_execution.run()
            stats = playbook_execution._tqm._stats
            if stats is not None and stats is not False:
                result_hosts = stats.processed.keys()
                if result_hosts is not None and result_hosts is not False:
                    for result_host in result_hosts:
                        summary = stats.summarize(result_host)
                        if summary['unreachable'] > 0 or summary['failures'] > 0:
                            return False
                        else:
                            return summary
                else:
                    return False
            else:
                return False

        except Exception as er:
            # generate a error log
            self._log.error("execute - {} - {}".format(self.__class__.__name__, er))
            return False
