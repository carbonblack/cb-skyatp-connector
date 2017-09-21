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
        self.watchlists = {wl: [mintime_utc, self.cb.select(Watchlist).where("name:" + wl).first()] for wl in
                           self.bridge_options['watchlists'].split(",")}
        specs = {"M": "minutes", "W": "weeks", "D": "days", "S": "seconds", "H": "hours"}

        time_delta = self.bridge_options.get('time_delta',"1M")
        spec = specs[time_delta[-1].upper()]
        val = int(time_delta[:-1])
        self.TIME_DELTA = timedelta(**{spec:val})

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

        while True:
            for wlname in self.watchlists:
                entry = self.watchlists[wlname]
                wl = entry[1]
                wlid = int(wl.id)
                last_checked = entry[0]
                last_hit = wl.last_hit
                log.info(
                    "WL monitor: name = {} , last_checked = {} , last_hit= {}".format(wlname, last_checked, last_hit))
                log.info("Self.TIME_INCREMENT = {} , (last_checked - last_hit) = {}".format(self.TIME_DELTA,
                                                                                            (last_checked - last_hit)))

                if last_hit - last_checked >= self.TIME_DELTA:

                    format_spec = "%Y-%m-%dT%I:%M:%S"

                    now = datetime.utcnow().replace(tzinfo=TZ_UTC)

                    ''' [YYYY-MM-DDThh:mm:ss TO YYYY-MM-DDThh:mm:ss] '''

                    search_res = wl.search()

                    search_res = search_res.where(
                        "watchlist_{}: [ {} TO {} ]".format(wlid, last_checked.strftime(format_spec),
                                                            now.strftime(format_spec)))

                    log.debug("serach_res = {}".format(list(search_res.all())))

                    sensors = []
                    for endpoints in map(lambda p: p.sensor, search_res):
                        sensors.append(endpoints)

                    log.debug("sensors = {}".format(sensors))

                    nics = []
                    for interfaces in map(lambda s: s.network_interfaces, sensors):
                        nics.extend(interfaces)

                    log.debug("nics = {}".format(nics))

                    entry[0] = now

                    ipaddrs = []
                    for nic in nics:
                        ip = nic.ipaddr.encode("ASCII")
                        if ip not in ipaddrs:
                            ipaddrs.append(ip)
                    update = {"ipv4": ipaddrs}
                    log.debug("info = {}".format(update))
                    self.juniper_client.update_infected_hosts_wlbl(update=json.dumps(update))
                else:
                    log.info("Last hit not within time_increment")
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
