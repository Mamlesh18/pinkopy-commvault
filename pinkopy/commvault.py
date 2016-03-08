import logging

from .base_session import BaseSession
from .clients import ClientSession
from .jobs import JobSession
from .subclients import SubclientSession

log = logging.getLogger(__name__)


class CommvaultSession(BaseSession):
    """Session wrapper for Commvault.

    See the BaseSession for greater detail. This class will provide the
    other sessions. It will also provide a shim for how it was used in
    the past.
    """
    def __init__(self, *args, **kwargs):
        self.clients = ClientSession(*args, **kwargs)
        self.subclients = SubclientSession(*args, **kwargs)
        self.jobs = JobSession(*args, **kwargs)

        # shim for backwards compatibility
        self.get_client = self.clients.get_client
        self.get_client_properties = self.clients.get_client_properties
        self.get_clients = self.clients.get_clients

        self.get_subclients = self.subclients.get_subclients

        self.get_job_details = self.jobs.get_job_details
        self.get_job_vmstatus = self.jobs.get_job_vmstatus
        self.get_jobs = self.jobs.get_jobs
        self.get_subclient_jobs = self.jobs.get_subclient_jobs


    def logout(self):
        """End session."""
        path = 'Logout'
        self.request('POST', path)
        self.headers['Authtoken'] = None
        return None
