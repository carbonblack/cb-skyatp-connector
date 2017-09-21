import logging
from enum import Enum

# /v1/skyatp/infected_hosts/{list_type}

log = logging.getLogger(__name__)


class ListType(Enum):
    WHITELIST = 0
    BLACKLIST = 1


class JuniperSkyAtpClient(object):
    def __init__(self, session=None, api_token=None, url=None, log_level=None):
        self.session = session
        self.api_token = api_token
        self.url = url if url else "https://api.sky.junipersecurity.net"
        self.headers = {
            "Authorization": "Bearer " + self.api_token,
            "content-type" : "application/json"
        }
        log.setLevel(logging.INFO if not log_level else log_level)

    # /v1/skyatp/infected_hosts/
    def infected_hosts_wlbl(self, listtype=None):
        if not listtype:
            listtype = ListType.BLACKSLIT
        uri = "/v1/skyatp/infected_hosts/" + listtype.name.lower()

        response = self.session.get(url=self.url + uri, headers=self.headers)
        log.debug("get_report: response = %s " % response)
        return response.json()

    def get_infected_hosts(self):
        uri = "/v1/skatp/infected_hosts"
        response = self.session.get(url=self.url + uri,headers=self.headers)
        return response.json()

    def update_infected_hosts_wlbl(self, update, listtype=None):
        if not listtype:
            listtype = ListType.BLACKLIST
        uri = "/v1/skyatp/infected_hosts/" + listtype.name.lower()
        response = self.session.patch(url=self.url + uri, headers=self.headers, data=update)
        return response.json()

    def remove_infected_hosts_wlbl(self, remove, listtype=None):
        if not listtype:
            listtype = ListType.BLACKLIST
        uri = "/v1/skyatp/infected_hosts/" + listtype.name.lower()
        response = self.session.delete(url=self.url + uri, headers=self.headers, data=remove)
        return response.json()
