import json
import logging
import sys
import time
from datetime import (datetime, timedelta, tzinfo)
from logging.handlers import RotatingFileHandler

import cbint
from cbapi.connection import CbAPISessionAdapter
from cbapi.response import *
from cbint.utils.daemon import CbIntegrationDaemon
from requests import Session

from skyatp_api import JuniperSkyAtpClient

log = logging.getLogger(__name__)

ZERO = timedelta(0)
HOUR = timedelta(hours=1)


class UTC(tzinfo):
    """UTC"""

    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO


TZ_UTC = UTC()
mintime_utc = datetime(year=1900, month=1, day=1).replace(tzinfo=TZ_UTC)


class SkyAtpBridge(CbIntegrationDaemon):
    def __init__(self, name, configfile, work_directory=None, logfile=None):
        CbIntegrationDaemon.__init__(self, name, configfile=configfile, logfile=logfile)
        self.validate_config()
        self.logfile = logfile
        self.log_level = logging.DEBUG if self.bridge_options['debug'] is "1" else logging.INFO
        self.initialize_logging()
        self.cb = CbResponseAPI(url=self.bridge_options['carbonblack_server_url'],
                                token=self.bridge_options['carbonblack_server_token'],
                                ssl_verify=self.bridge_options['carbonblack_server_sslverify'])
        self.session = Session()
        tls_adapter = CbAPISessionAdapter(force_tls_1_2=True)
        self.session.mount("https://", tls_adapter)
        self.juniper_apikey = self.get_config_string("juniper_apikey", None)
        self.juniper_client = JuniperSkyAtpClient(session=self.session, api_token=self.juniper_apikey,
                                                  log_level=self.log_level)
        self.watchlists = self.bridge_options['watchlists'].split(",")
        specs = {"M": "minutes", "W": "weeks", "D": "days", "S": "seconds", "H": "hours"}

        time_increment = self.bridge_options.get('time_increment',"5M")
        spec = specs[time_increment[-1].upper()]
        val = int(time_increment[:-1])
        self.TIME_INCREMENT = timedelta(**{spec:val})


    def initialize_logging(self):
        log.debug("intializing logging subsystem")
        if not self.logfile:
            log_path = "/var/log/cb/integrations/%s/" % self.name
            cbint.utils.filesystem.ensure_directory_exists(log_path)
            self.logfile = "%s%s.log" % (log_path, self.name)

        root_logger = logging.getLogger()
        log.debug("self.log_level is {}".format(self.log_level))
        root_logger.setLevel(self.log_level)
        root_logger.handlers = []

        rlh = RotatingFileHandler(self.logfile, maxBytes=524288, backupCount=10)
        rlh.setFormatter(logging.Formatter(fmt="%(asctime)s: %(module)s: %(levelname)s: %(message)s"))
        root_logger.addHandler(rlh)

    def run(self):

        log.info("starting Carbon Black <-> SkyATP Bridge ")

        where_clause = " or ".join(("watchlist_name: " + wl for wl in self.watchlists))

        blacklist  = []

        while True:
            alerts = list(self.cb.select(Alert).where(where_clause).all())
            resolved_alerts = filter(lambda a: a.status is "Resolved", alerts)
            unresolved_alerts = filter(lambda a: a.status is not "Resolved",alerts)
            resolved_ips = set(map(lambda a: a.interface_ip.encode(sys.stdout.encoding) ,resolved_alerts))
            unresolved_ips = set(map(lambda a: a.interface_ip.encode(sys.stdout.encoding) ,unresolved_alerts))
            log.info("alerts = {}".format(alerts))
            log.info("resolved_alerts = {}".format(resolved_alerts))
            log.info("unresolved_alerts = {}".format(unresolved_alerts))
            log.info("resolved_ips = {}".format(resolved_ips))
            log.info("unresolved_ips = {}".format(unresolved_ips))

            resolved_ips = resolved_ips.difference(unresolved_ips)

            log.info("Resolved ips final = {}",resolved_ips)

            if len(unresolved_ips):
                update = {"ipv4": list(unresolved_ips)}
                log.debug("info = {}".format(update))
                self.juniper_client.update_infected_hosts_wlbl(update=json.dumps(update))
            if len(resolved_ips):
                remove = {"ipv4": list(resolved_ips)}
                self.juniper_client.remove_infected_hosts_wlbl(remove=json.dumps(remove))


            cur_time = datetime.utcnow()
            next_time = cur_time + self.TIME_INCREMENT
            time.sleep((next_time - cur_time).total_seconds())


    # index_types == modules then it's binary events = process

    def validate_config(self):
        if 'bridge' in self.options:
            self.bridge_options = self.options['bridge']
        else:
            log.error("configuration does not contain a [bridge] section")
            return False

        config_valid = True
        msgs = []

        if 'carbonblack_server_url' not in self.bridge_options:
            msgs.append('the config option carbonblack_server_url is required')
            config_valid = False
        if 'carbonblack_server_token' not in self.bridge_options:
            msgs.append('the config option carbonblack_server_token is required')
            config_valid = False
        if 'juniper_apikey' not in self.bridge_options:
            msgs.append('the config option juniper_apikey is required')
            config_valid = False
        if not config_valid:
            for msg in msgs:
                sys.stderr.write("%s\n" % msg)
                log.error(msg)
            return False
        else:
            return True


if __name__ == '__main__':

    import os

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/skyatp"

    config_path = os.path.join(my_path, "testing.conf")
    daemon = SkyAtpBridge(name='skyatptest', configfile=config_path, work_directory=temp_directory,
                          logfile=os.path.join(temp_directory, 'test.log') )

    logging.getLogger().setLevel(logging.DEBUG)

    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        else:
            print "Unknown command: %s" % sys.argv[1]
            sys.exit(2)

    else:
        print "Usage: %s start|stop|restart|version" % sys.argv[0]
        sys.exit(2)
