# -*- coding: utf-8 -*-
"""


- Contributors
Elliann Marks <elian.markes@gmail.com>

**- Version 01 - 08/02/2019**

**- Version 2.0 - 11/07/2019**

**- Version 3.0 - 18/12/2019**

- Documentation zenpy library
https://github.com/facetoe/zenpy
http://docs.facetoe.com.au/zenpy.html
"""

# libraries
from zenpy import Zenpy
from zenpy.lib.api_objects import Ticket, Comment, User
import time
from abuse_automation.module_exceptions import BrandFailed, ZenFailed, ZenConnectionFailed


class ModuleZen:

    def __init__(self, module_log, module_configuration):
        """
        :param module_log: Instance of the log class
        :type module_log: object
        """
        self._log = module_log
        self.module_configuration = module_configuration
        self._domain = self.module_configuration.domain
        self._token = self.module_configuration.token
        self._domain_es = self.module_configuration.domain_es
        self._token_es = self.module_configuration.token_es
        # production
        if self.module_configuration.application == "production":
            self.group_abuse = 11111111111
            self.group_abuse_es = 11111111111
            self.group_financial_3 = 11111111111
            self.group_financial_3_es = 11111111111
            self.submitter_support = 11111111111
            self.submitter_support_es = 11111111111
        # sandbox
        elif self.module_configuration.application == "development":
            self.group_abuse = 11111111111
            self.group_abuse_es = 11111111111
            self.group_financial_3 = 11111111111
            self.group_financial_3_es = 11111111111
            self.submitter_support = 11111111111
            self.submitter_support_es = 11111111111
        # values in zendesk
        self.tag_search = "abuse_221b_not_checked"
        self.tag_checking = "abuse_221b_checking"
        self.tag_false = "abuse_221b_false"
        self.tag_closed = "assunto-encerrado"
        self.tag_duplicated = "abuse_221b_duplicated"
        self.tag_true = "abuse_221b_true"
        self.tag_handled = "abuse_221b_handled"
        self.tag_phishing = "abuse_221b_phishing"
        self.tag_phishing_intentional = "abuse_221b_phishing_intentional"
        self.tag_true_error = "abuse_221b_true_with_error"
        self.hold_two_days = "48_horas"
        self.new_ticket = "abuse_221b_new_ticket"
        # variables
        self.brand = "br"

    @property
    def connect_zen(self):
        """
        Return object with connection of the zendesk
        """
        try:

            if self.brand == "br":
                email = "apizendesk_es@example.com"
                credentials = {
                    "email": email,
                    "token": self._token,
                    "subdomain": self._domain
                }
                return Zenpy(**credentials)
            elif self.brand == "es":
                email = "apizendesk_es@example.com"
                credentials = {
                    "email": email,
                    "token": self._token_es,
                    "subdomain": self._domain_es
                }
                return Zenpy(** credentials)
            else:
                raise BrandFailed

        except Exception as er:
            # generate a error log
            self._log.error("connect_zen - {} - {}".format(self.__class__.__name__, er))
            return ZenConnectionFailed

    def macro_false(self, brand):
        if self.module_configuration.application == "production":
            if brand == "br":
                return 360096974774
            elif brand == "es":
                return 360129331371
            else:
                raise BrandFailed
        elif self.module_configuration.application == "development":
            if brand == "br":
                return 360105067674
            elif brand == "es":
                return 360130399711
            else:
                raise BrandFailed
        else:
            raise Exception("Invalid application environemnt.")


    @staticmethod
    def duplicated_comment(brand):
        if brand == "br":
            return "Olá,\n\nNosso sistema identificou duplicidade nessa denúncia, de modo que a anterior " \
                   "já está sendo tratada. Por isso estamos encerrando esta!"
        elif brand == "es":
            return "Hola,\n\nNuestro sistema identificó que esta denuncia está duplicada, " \
                   "de modo que la anterior ya está siendo tratada, y por eso, estamos cerrando esta!"
        else:
            raise BrandFailed

    @staticmethod
    def return_comment(brand):
        if brand == "br":
            return "Olá,\n\nAgradecemos por essa informação!"
        elif brand == "es":
            return "Hola,\n\nMuchas gracias por enviarnos esta información!"
        else:
            raise BrandFailed

    def update_ticket(self, update_object, type_macro=None, brand="br"):
        try:
            self.brand = brand
            if type_macro:
                update_object = update_object.ticket
            else:
                update_object = update_object
            return self.connect_zen.tickets.update(update_object)

        except ZenConnectionFailed:
            raise ZenFailed

        except BrandFailed:
            raise ZenFailed

        except Exception as er:
            # generate a error log
            self._log.error("update_ticket - {} - {}".format(self.__class__.__name__, er))
            raise ZenFailed

    def create_ticket(self, subject, email, submitter_id, description=None, comment=None, public=True, upload=None, assignee_id=None, group_id=None,
            organization_id=None, priority=None, problem_id=None, status=None, tags=None, type_zen=None, brand="br"):
        try:
            self.brand = brand
            if description is not None and subject is not None and email is not None:
                create_ticket_object = self.connect_zen.tickets.create([Ticket(subject=subject,
                    description=description, submitter_id=submitter_id, assignee_id=assignee_id,
                    group_id=group_id, organization_id=organization_id, priority=priority,
                    problem_id=problem_id, status=status, tags=tags, type=type_zen,
                    requester=User(name=email.split("@")[0], email=email))])
                return create_ticket_object
            elif comment is not None and subject is not None and upload is not None and email is not None:
                create_ticket_object = self.connect_zen.tickets.create([Ticket(subject=subject,
                    comment=Comment(body=comment, public=public, uploads=upload), assignee_id=assignee_id,
                    group_id=group_id, submitter_id=submitter_id, organization_id=organization_id, priority=priority,
                    problem_id=problem_id, status=status, tags=tags, type=type_zen,
                    requester=User(name=email.split("@")[0], email=email))])
                return create_ticket_object
            elif comment is not None and subject is not None and email is not None:
                create_ticket_object = self.connect_zen.tickets.create([Ticket(subject=subject,
                    comment=Comment(body=comment, public=public), assignee_id=assignee_id,
                    group_id=group_id, submitter_id=submitter_id, organization_id=organization_id, priority=priority,
                    problem_id=problem_id, status=status, tags=tags, type=type_zen,
                    requester=User(name=email.split("@")[0], email=email))])
                return create_ticket_object
            else:
                raise ZenFailed

        except ZenConnectionFailed:
            raise ZenFailed

        except BrandFailed:
            raise ZenFailed

        except Exception as er:
            self._log.error("create_ticket - {} - {}".format(self.__class__.__name__, er))
            raise ZenFailed

    def job_status(self, job_id, brand="br"):
        try:
            self.brand = brand
            count_job_status = 0
            while count_job_status <= 10:
                time.sleep(5)
                result_job_status = self.connect_zen.job_status(id=job_id)
                if result_job_status.status == "completed":
                    return result_job_status.results[0].id
                count_job_status += 1
            return False

        except ZenConnectionFailed:
            raise ZenFailed

        except BrandFailed:
            raise ZenFailed

        except Exception as er:
            self._log.error("job_status - {} - {}".format(self.__class__.__name__, er))
            raise ZenFailed

    def comment_ticket(self, ticket_id, body, public=True, upload=None, brand="br"):
        try:
            self.brand = brand
            update_object = self.search_id(ticket_id, brand=self.brand)
            if update_object is not False:
                if upload is not None and len(upload) > 0:
                    update_object.comment = Comment(body=body, public=public, uploads=upload)
                else:
                    update_object.comment = Comment(body=body, public=public)
                self.update_ticket(update_object, brand=brand)
                return True
            else:
                raise ZenFailed

        except Exception as er:
            self._log.error("comment_ticket - {} - {}".format(self.__class__.__name__, er))
            raise ZenFailed

    def upload_file(self, file_path, target_name=None, brand="br"):
        """
        Create object for make a comment with upload of some file
        """
        try:
            self.brand = brand
            if target_name is None:
                upload_return = self.connect_zen.attachments.upload(file_path)
                return upload_return.token
            else:
                upload_return = self.connect_zen.attachments.upload(file_path, target_name=target_name)
                return upload_return.token

        except ZenConnectionFailed:
            raise ZenFailed

        except BrandFailed:
            raise ZenFailed

        except Exception as er:
            # generate a error log
            self._log.error("upload_file - {} - {}".format(self.__class__.__name__, er))
            raise ZenFailed

    # ticket.comment.html_body = t.comment.html_body.replace("OLD_STRING", "NEW_STRING")
    # ticket.comment.body = t.comment.body.replace("OLD_STRING", "NEW_STRING")
    def macro(self, ticket_id, macro_id, brand="br"):
        try:
            self.brand = brand
            return self.connect_zen.tickets.show_macro_effect(ticket_id, macro_id)

        except ZenConnectionFailed:
            raise ZenFailed

        except BrandFailed:
            raise ZenFailed

        except Exception as er:
            # generate a error log
            self._log.error("macro - {} - {}".format(self.__class__.__name__, er))
            raise ZenFailed

    def search_abuse(self, search_status, search_group_id, search_tags, brand="br"):
        """
        Search by status, group ID and tag
        """
        try:
            self.brand = brand
            return self.connect_zen.search(type="ticket", status=search_status, group_id=search_group_id, tags=search_tags)

        except ZenConnectionFailed:
            raise ZenFailed

        except BrandFailed:
            raise ZenFailed

        except Exception as er:
            # generate a error log
            self._log.error("search_abuse - {} - {}".format(self.__class__.__name__, er))
            raise ZenFailed

    def search_id(self, ticket_id, brand="br"):
        """
        Search for ID of the ticket
        """
        try:
            self.brand = brand
            return self.connect_zen.tickets(id=ticket_id)

        except ZenConnectionFailed:
            raise ZenFailed

        except BrandFailed:
            raise ZenFailed

        except Exception as er:
            # generate a error log
            self._log.error("search_id - {} - {}".format(self.__class__.__name__, er))
            raise ZenFailed

    def handle_tag(self, current_tags, add_tag, remove_tag=None):
        try:
            if isinstance(current_tags, list) and len(current_tags) > 0 and remove_tag is not None:
                if remove_tag in current_tags:
                    current_tags.remove(remove_tag)
            if isinstance(current_tags, list):
                current_tags.append(add_tag)
            else:
                current_tags = add_tag
            return current_tags

        except Exception as er:
            # generate a error log
            self._log.error("handle_tag - {} - {}".format(self.__class__.__name__, er))
            raise ZenFailed
