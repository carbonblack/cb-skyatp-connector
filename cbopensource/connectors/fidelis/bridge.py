import os
import sys
import json
import time
import flask
import struct
import socket
import logging
import threading
import requests
from datetime import datetime, timedelta

from . import version
import cbapi
import cbint.utils.json
import cbint.utils.feed
import cbint.utils.flaskfeed
import cbint.utils.cbserver
from cbint.utils.daemon import CbIntegrationDaemon


class CarbonBlackFidelisBridge(CbIntegrationDaemon):

    def __init__(self, name, configfile):
        CbIntegrationDaemon.__init__(self, name, configfile=configfile)
        self.flask_feed = cbint.utils.flaskfeed.FlaskFeed(__name__)
        self.bridge_options = {}
        self.debug = False
        self.cb = None
        self.feed_name = "Fidelis"
        self.display_name = self.feed_name
        self.feed = {}
        self.feed_synchronizer = None
        self.directory = os.path.dirname(os.path.realpath(__file__))
        self.cb_image_path = "/content/carbonblack.png"
        self.full_cb_image_path = "/usr/share/cb/integrations/carbonblack_fidelis_bridge/carbonblack.png"
        self.integration_image_path = "/usr/share/cb/integrations/carbonblack_fidelis_bridge/fidelis.png"
        self.json_feed_path = "/fidelis/json"

        self.flask_feed.app.add_url_rule(self.cb_image_path, view_func=self.handle_cb_image_request)
        self.flask_feed.app.add_url_rule(self.integration_image_path, view_func=self.handle_integration_image_request)
        self.flask_feed.app.add_url_rule(self.json_feed_path, view_func=self.handle_json_feed_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/", view_func=self.handle_index_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/feed.html", view_func=self.handle_html_feed_request, methods=['GET'])
        self.flask_feed.app.add_url_rule("/fidelis/echo", view_func=self.handle_fidelis_echo, methods=['POST', 'GET'])
        self.flask_feed.app.add_url_rule("/fidelis/upstream/check", view_func=self.handle_fidelis_upstream_check, methods=['GET'])
        self.flask_feed.app.add_url_rule("/fidelis/register", view_func=self.handle_fidelis_registration, methods=['POST'])
        self.flask_feed.app.add_url_rule("/fidelis/poll", view_func=self.handle_fidelis_poll, methods=['POST'])
        self.flask_feed.app.add_url_rule("/fidelis/deregister", view_func=self.handle_fidelis_deregistration, methods=['POST'])

        self.registrations = []
        self.registrations_lock = threading.RLock()
        self.alert_hits = []
        self.alert_hits_lock = threading.RLock()
        requests.get('http://localhost')


    def on_start(self):
        self.debug = self.bridge_options.get('debug', "0") != "0"
        if self.debug:
            self.logger.setLevel(logging.DEBUG)

    def on_stopping(self):
        self.debug = self.bridge_options.get('debug', "0") != "0"
        if self.debug:
            self.logger.setLevel(logging.DEBUG)

    def run(self):
        self.debug = self.bridge_options.get('debug', "0") != "0"
        if self.debug:
            self.logger.setLevel(logging.DEBUG)

        self.logger.info("starting Carbon Black <-> Fidelis Bridge | version %s" % version.__version__)

        self.logger.debug("initializing cbapi")
        sslverify = False if self.bridge_options.get('carbonblack_server_sslverify', "0") == "0" else True
        self.cb = cbapi.CbApi(self.bridge_options['carbonblack_server_url'],
                              token=self.bridge_options['carbonblack_server_token'],
                              ssl_verify=sslverify)

        self.logger.debug("generating feed metadata")
        self.feed = cbint.utils.feed.generate_feed(self.feed_name, summary="Fidelis on-premise IOC feed",
                    tech_data="There are no requirements to share any data with Carbon Black to use this feed.  The underlying IOC data is provided by an on-premise Fidelis device",
                    provider_url="http://www.fidelissecurity.com/",
                    icon_path="%s" % (self.integration_image_path),
                    display_name=self.display_name, category="Connectors")

        self.logger.debug("starting maintenance thread")
        work_thread = threading.Thread(target=self.perform_maintenance)
        work_thread.setDaemon(True)
        work_thread.start()

        self.logger.debug("starting feed synchronizer")
        self.feed_synchronizer = cbint.utils.feed.FeedSyncRunner(self.cb, self.feed_name,
                                                                 self.bridge_options.get('feed_sync_interval', 15))
        if not self.feed_synchronizer.sync_supported:
            self.logger.warn("feed synchronization is not supported by the associated Carbon Black enterprise server")

        self.logger.debug("starting flask")
        self.serve()

    def serve(self):
        address = self.bridge_options.get('listener_address', '0.0.0.0')
        port = self.bridge_options['listener_port']
        self.logger.info("starting flask server: %s:%s" % (address, port))
        self.flask_feed.app.run(port=port, debug=self.debug,
                                host=address, use_reloader=False)

    def handle_json_feed_request(self):
        return self.flask_feed.generate_json_feed(self.feed)

    def handle_html_feed_request(self):
        return self.flask_feed.generate_html_feed(self.feed, self.display_name)

    def handle_index_request(self):
        return self.flask_feed.generate_html_index(self.feed, self.bridge_options, self.display_name,
                                                   self.cb_image_path, self.integration_image_path,
                                                   self.json_feed_path)

    def handle_cb_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s" % self.full_cb_image_path)

    def handle_integration_image_request(self):
        return self.flask_feed.generate_image_response(image_path="%s" % self.integration_image_path)

    def handle_fidelis_echo(self):
        """
        provide a simple confirmation of availability to the Fidelis Device
        """
        # authenticate
        #
        self.authenticate_api_user(flask.request.headers)

        ver = {'Version': version.__version__, 'Product': 'Carbon Black Fidelis Bridge'}
        return flask.Response(response=cbint.utils.json.json_encode(ver), mimetype='application/json')

    def handle_fidelis_upstream_check(self):
        """
        provide a simple indicator as to if the upstream connection to the
        CBENT server is available
        """
        # authenticate
        #
        self.authenticate_api_user(flask.request.headers)

        return flask.Response(response=json.dumps(self.cb.info()), mimetype='application/json')

    def handle_fidelis_registration(self):
        """
        accept a registration request from a Fidelis Command Post (CP)

        the registration request describes a Fidelis alert.  It is encoded using JSON.
        the following maps the JSON field names to the registration spec provided in
        the specification document provided by Fidels in collaboration with Carbon Black.

          cp_ip              : Command Post Ip <REQUIRED>
          alert_id           : Alert UUID <REQUIRED>
          alert_md5          : md5 of target 'innermost' file <REQUIRED>
          alert_filetype     : type of file specified by alert_md5, such as PE or PDF <REQUIRED>
          alert_severity     : severity, on a 1-4 scale, of the suspected malware <REQUIRED>
          alert_description  : human-consumable name and/or type of malware <REQUIRED>
          alert_related_md5s : list of zero or more MD5s that wrapped the 'innermost' file <OPTIONAL>
          ttl                : ttl, in seconds, of this registration before self-deletion <REQUIRED>
          endpoint_ip        : ipv4 address of endpoint, or 0.0.0.0 for network-wide <REQUIRED>

        logic flow

          this routine first attempts to map the endpoint_ip, if provided, to a Carbon Black sensor
          instance, as identified by a SensorId.  If this fails, HTTP error 412 (precondition fails)
          is returned.  the caller, at it's discretion, may choose to re-issue the registration
          request with "0.0.0.0" as the endpoint ipv4 address to search network-wide.

          the alert 'recv' timestamp is calculated and added to the registration.  the natural expiration
          timestamp of the registration can be calculated by adding the ttl to the received timestamp

          the alert will be added to an internal list of live registrations, and the
          Carbon Black Enterprise Server (CBENT) will be queried regularly until such time as the ttl
          expires or a 'delete' or 'deregistration' call is made.  Any matches of the alert against
          CBENT data will be exposed via the 'poll' API.

          The sensor id and hostname are stored in the alert registration record, as they are used
          to bound subsequent searches of the CBENT data store

        return value

          this routine will return HTTP 200 to indicate a successful registration.  the caller is
          responsible for de-registering, if needed, prior to natural de-registration due to ttl
          expiration.

          this routine will return HTTP 412 (preconditon fails) if the provided endpoint_ip cannot
          be mapped back to a CBENT SensorId. this is expected to occur if the Carbon Black sensor
          is not installed or not active on the specified endpoint.

          this routine will return HTTP 429 if too many existing registrations exist.  this is a
          means of avoiding excessively large alert registration rates.

          this routine may return HTTP 500 to indicate catastrophic internal error.  this is not
          an expected return code.

        """
        # authenticate
        #
        self.authenticate_api_user(flask.request.headers)

        # decode the raw registration request
        #
        registration = cbint.utils.json.json_decode(flask.request.data)

        # ensure that the required registration fields are present
        #
        required_fields = ['cp_ip', 'alert_id', 'alert_md5', 'endpoint_ip', 'ttl',
                           'alert_type', 'alert_severity', 'alert_description']
        for field in required_fields:
            if not registration.has_key(field):
                raise ValueError('Missing field %s' % field)

        # do a endpoint ipv4 -> CBENT SensorId lookup
        #
        # @todo - use cbapi to perform this action
        #         in the meantime, specify 1.1.1.1 to see failure
        #
        if "0.0.0.0" != registration['endpoint_ip']:
            self.logger.debug("looking up endpoint IP '%s'..." % registration['endpoint_ip'])
            sensors = self.cb.sensors({'ip': registration['endpoint_ip']})
            if 0 == len(sensors):
                flask.abort(412)
            registration['sensor_id'] = sensors[0]['id']
            registration['computer_name'] = sensors[0]['computer_name']
            self.logger.debug("mapped '%s' to SensorId %d" % (registration['endpoint_ip'], registration['sensor_id']))
        else:
            self.logger.debug("no endpoint IP specified [this is ok]")

        # verify that the current number of active registrations is within range
        # @todo make this a confg file option
        #
        if len(self.registrations) > 512:
            flask.abort(429)

        # add in received and expire timestamp
        #
        if not str(registration['ttl']).isdigit():
            registration['ttl'] = "600"

        registration['recv_timestamp'] = datetime.now()
        registration['expire_timestamp'] = datetime.now() + timedelta(seconds=int(registration['ttl']))

        # enable the registration
        # registrations are enabled at 'register' time
        # enabled registrations are searched by the searcher thread
        #
        # when the searcher thread finds matches, the registration is disabled
        # but kept on the registration list to provide for feed
        # when the TTL expires, it is removed altogether
        #
        registration['enabled'] = True

        # append this new registration to the global list of registrations
        #
        with self.registrations_lock:
            self.registrations.append(registration)
            self.logger.debug("registered a new alert from Fidelis device with Id %s" % (registration['alert_id']))
            self.alertregistration_to_report(registration)

        return flask.make_response("Thanks!")

    def handle_fidelis_poll(self):
        """
        accept a poll request

        a poll request queries for any alert hits, based on prior registrations,
        for the given cp_ip.  it is important to limit returned alert hits by cp_ip
        as there may be more than one fidelis command post (cp) associated with a
        single carbon black enterprise server instance

        a single JSON-encoded dictionary is accepted as a parameter.  The following
        keys are expected parameters:

            cp_ip : fidelis command post IP <REQUIRED>

        return value

            the endpoint will return HTTP 200 with a JSON-encoded list of zero or
            more matching alerts

            this routine may return HTTP 500 to indicate catastrophic internal error.  this is not
            an expected return code.
        """
        # authenticate
        #
        self.authenticate_api_user(flask.request.headers)

        # decode the raw poll request
        #
        poll = cbint.utils.json.json_decode(flask.request.data)

        # ensure that the required poll fields are present
        #
        required_fields = ['cp_ip']
        for field in required_fields:
            if not poll.has_key(field):
                raise ValueError('Missing field %s' % field)

        alert_hits_local = []

        with self.alert_hits_lock:
            for alert_hit in self.alert_hits:
                if alert_hit['cp_ip'] == poll['cp_ip']:
                    alert_hits_local.append(alert_hit)

            for alert_hit in alert_hits_local:
                self.alert_hits.remove(alert_hit)

            return flask.Response(response=json.dumps(alert_hits_local), mimetype='application/json')

    def handle_fidelis_deregistration(self):
        """
        accept a deregistration request from a Fidelis Command Post (CP)

        the deregistration request describes a previously-registered  Fidelis alert.
        it is encoded using JSON.

        the following maps the JSON field names to the deregistration spec provided in
        the specification document provided by Fidels in collaboration with Carbon Black.

          cp_ip              : Command Post Ip <REQUIRED>
          alert_id           : Alert UUID <REQUIRED>

        logic flow

            the list of active registrations is searched for any that match both the cp_ip and
            the alert_id.  multiple Fidelis command posts (cps) may be configured to post
            alerts to the same Carbon Black bridge device, so the cp_ip provides uniqueness in
            space and helps protect agianst an inadvertent de-registration of an alert not
            registered by the same command post.

            if a matching cp_ip:alert_id pair is found, that registration is removed from the
            list of active registrations.  the alert indicators (iocs) will no longer be searched.

        return value

            this routine will return HTTP 200 to indicate a successful deregistration.  the bridge
            server will no longer search the Carbon Black Enterprise Server data store for IOCs
            associated with this alert.  note that it is possible that an existing alert match has
            been queued since the last call to the 'poll' endpoint.

            this routine will return HTTP 404 (not found) if the provided cp_ip:alert_id pair could
            not be found in the active registration list.  this is the expected return code if the
            registration has already been removed through a previous call to deregister, or if the
            registration timed out naturally

            this routine may return HTTP 500 to indicate catastrophic internal error.  this is not
            an expected return code.
        """
        # authenticate
        #
        self.authenticate_api_user(flask.request.headers)

        # decode the raw deregistration request
        #
        deregistration = cbint.utils.json.json_decode(flask.request.data)

        # ensure that the required registration fields are present
        #
        required_fields = ['cp_ip', 'alert_id']
        for field in required_fields:
            if not deregistration.has_key(field):
                raise ValueError('Missing field %s' % field)

        registration_to_remove = None
        with self.registrations_lock:
            for registration in self.registrations:
                if registration['cp_ip'] == deregistration['cp_ip'] and registration['alert_id'] == deregistration['alert_id']:
                    registration_to_remove = registration

            if None == registration_to_remove:
                self.logger.debug("no such registration [%s {%s}]" % (deregistration['cp_ip'], deregistration['alert_id']))
                flask.abort(404)

            # disable (rather than wholly remove) the registration
            # this allows us to provide a feed with the de-registered reports
            # until the ttl expires
            #
            registration_to_remove['enabled'] = False

        self.logger.debug("removed alert {%s}" % deregistration['alert_id'])

        return flask.make_response("Thanks!")

    def perform_maintenance(self):
        """
        performs background housekeeping, including searching Carbon Black
        datastore for active Fidelis alert registrations and garbage-collecting
        expired Fidelis alert registrations
        """
        time_to_sleep = 1

        while True:

            try:
                # walk the list of registrations, searching CB for IOCs as appropriate
                self.search_registrations()

                # remove any existing registrations with ttls that have expired
                #
                self.expire_registrations()
            except Exception as e:
                self.logger.warn("Error during maintenance loop: %s" % e)

            # increase the time to sleep by 1 second on each iteration, ultimately
            # stopping at 60s in total.  this makes debugging a lot easier :)
            #
            if time_to_sleep < 60:
                time_to_sleep += 1

            time.sleep(time_to_sleep)

    def translate_score(self, severity):
        """
        translate a Fidelis severity rating to a numeric Carbon Black score
        Carbon Black scores are in the range of [0,100]
        Fidlis severities are in the range of [1,4]
        """

        if '4' == severity or 4 == severity:
            return 100
        elif '3' == severity or 3 == severity:
            return 75
        elif '2' == severity or 2 == severity:
            return 50
        elif '1' == severity or 1 == severity:
            return 25
        else:
            return 0

    def alertregistration_to_report(self, alert_reg):
        """
        translate a Fidels alert registration object into a Carbon Black feed
        report object
        """

        report = {}
        report['iocs'] = {}
        report['iocs']['md5'] = []
        report['iocs']['md5'].append(alert_reg['alert_md5'])
        if alert_reg.has_key('alert_related_md5s'):
            report['iocs']['md5'] += alert_reg['alert_related_md5s']
        report['timestamp'] = alert_reg['recv_timestamp']
        report['link'] = "https://%s/j/alert.html?$(%s)" % (alert_reg['cp_ip'], alert_reg['alert_id'])
        report['title'] = alert_reg['alert_description']
        report['score'] = self.translate_score(alert_reg['alert_severity'])
        report['id'] = alert_reg['alert_id']

        self.feed['reports'].append(report)
        self.feed_synchronizer.sync_needed = True

    def authenticate_api_user(self, headers):
        """
        verifies that the http request is properly authenticated

        raises a http 403 flask exception if not authenticated
        """
        # authentication is not required
        # determine if the api token is provided in the configuration
        # if not, no authentication is required
        #
        if not self.bridge_options.has_key('listener_api_token'):
            return

        # verify that the Fidelis auth token is present in the HTTP headers
        #
        if not 'X-Fidelis-Token' in headers:
            flask.abort(401)

        # finally, verify that the token matches
        #
        if self.bridge_options['listener_api_token'] != headers['X-Fidelis-Token']:
            flask.abort(401)

        return

    def expire_registrations(self):
        """
        checks active sensor registrations list for any that are expired, and
        removes them.
        """
        now = datetime.now()

        with self.registrations_lock:
            registrations_to_remove = []
            for registration in self.registrations:
                if registration['expire_timestamp'] < now:
                    self.logger.debug("Removing registration [%s] due to expired ttl" % registration['alert_id'])
                    registrations_to_remove.append(registration)

            for registration in registrations_to_remove:
                self.registrations.remove(registration)

    def translate_filetype(self, filetype):
        """
        translate a Carbon Black numeric filetype enumeration value
        to a human-readable string representation of file type
        """
        #define FILE_TYPE_UNKNOWN           0x0000
        #define FILE_TYPE_BINARY            0x0001  // Windows
        #define FILE_TYPE_ELF               0x0002  // Unix
        #define FILE_TYPE_UNIVERSAL_BIN     0x0003  // OSX
        #define FILE_TYPE_EICAR             0x0008
        #define FILE_TYPE_OFFICE_LEGACY     0x0010
        #define FILE_TYPE_OFFICE_OPENXML    0x0011
        #define FILE_TYPE_PDF               0x0030
        #define FILE_TYPE_ARCHIVE_PKZIP     0x0040
        #define FILE_TYPE_ARCHIVE_LZH       0x0041
        #define FILE_TYPE_ARCHIVE_LZW       0x0042
        #define FILE_TYPE_ARCHIVE_RAR       0x0043
        #define FILE_TYPE_ARCHIVE_TAR       0x0044
        #define FILE_TYPE_ARCHIVE_7ZIP      0x0045

        if 0x1 == filetype:
            return "PE"
        elif 0x2 == filetype:
            return "Elf"
        elif 0x3 == filetype:
           return "Universal Binary"
        elif 0x8 == filetype:
           return "EICAR"
        elif 0x10 == filetype:
            return "Microsoft Office Legacy"
        elif 0x11 == filetype:
            return "Microsoft Office OpenXML"
        elif 0x30 == filetype:
            return "PDF"
        elif 0x40 == filetype:
            return "zip"
        elif 0x41 == filetype:
            return "lzh"
        elif 0x42 == filetype:
            return "lzw"
        elif 0x43 == filetype:
            return "rar"
        elif 0x44 == filetype:
            return "tar"
        elif 0x45 == filetype:
            return "7zip"
        else:
            return "<UNKNOWN>"

    def search_registration(self, registration):
        """
        search CB data set for iocs found in the caller-supplied alert registration
        if and when found, the registration is removed from the global registration
        list and a summary of the match stored in the global alerts list

        returns True to indicate that a match was found.  This means the registration
        should be removed from the list of active registrations.

        returns False to indicate no match was found
        """

        if not registration.get('enabled', False):
            return False

        query = "(process_md5:%s or filewrite_md5:%s)" % (registration['alert_md5'], registration['alert_md5'])
        if registration.has_key('computer_name'):
            query += " and hostname:\"%s\"" % (registration['computer_name'],)

        # todo: consider adding alternate md5s from the registration
        # todo: consider modload_md5 or process_md5, rather than only process_md5

        search_results = self.cb.process_search(query)
        if len(search_results['results']) < 1:
            # no matches
            return False

        matching_processes = []

        # loop over all the returned documents
        # a fidelis-specific summary of each will be provided
        #
        for search_result in search_results['results']:

            process_id = search_result['id']
            segment_id = search_result['segment_id']

            process = self.cb.process_events(process_id, segment_id)['process']
            processed_netconns = []
            raw_netconns = process.get('netconn_complete', [])
            for raw_netconn in raw_netconns:
                timestamp, ip, port, proto, domain, direction = raw_netconn.split('|')

                processed_netconn = {}

                # the ip may not be present if the netconn was observed talking via
                # a web proxy.  as of this writing, the key ('ip') itself is present,
                # but the value is an empty string.
                #
                try:
                     processed_netconn['ip'] = socket.inet_ntoa(struct.pack("!i", int(ip)))
                except Exception, e:
                    pass

                processed_netconn['port'] = port
                processed_netconn['protocol'] = proto
                processed_netconn['dns_name'] = domain
                processed_netconn['outbound'] = direction
                processed_netconn['timestamp'] = timestamp

                processed_netconns.append(processed_netconn)

            processed_filewrites = []
            raw_filewrites = process.get('filemod_complete', [])
            for raw_filewrite in raw_filewrites:

                processed_filewrite = {}

                raw_fields = raw_filewrite.split('|')

                # avoid processing any older SOLR data (pre-4.1 server)
                #
                if len(raw_fields) != 5:
                    continue

                # avoid processing any non-filewrite-complete events
                #
                if '8' != raw_fields[0]:
                    continue

                # avoid reporting any unrelated filewrites
                #
                if raw_fields[3].lower() != registration['alert_md5'].lower():
                    continue

                processed_filewrite['filename'] = self.normalize_file_path(raw_fields[2])
                processed_filewrite['md5'] = raw_fields[3]
                processed_filewrite['type'] = self.translate_filetype(int(raw_fields[4])) if str(raw_fields[4]).isdigit() else "<UNKNOWN>"
                processed_filewrite['timestamp'] = raw_fields[1]

                processed_filewrites.append(processed_filewrite)

            matching_process = {}
            matching_process['endpoint_ip'] = [registration['endpoint_ip']]
            matching_process['hostname'] = process.get('hostname', '<UNKNOWN>')
            matching_process['segment_id'] = process.get('segment_id', 0)
            if process.has_key("unique_id"):
                id = process["unique_id"]
            elif process.has_key("id"):
                id = process["id"]
            else:
                self.logger.critical("The process doc has no unique_id nor id.")
                self.logger.info("The bridge has stopped.")
                sys.exit(1)

            matching_process['id'] = id
            matching_process['process_name'] = process.get('process_name', '<UNKNOWN>')
            matching_process['process_md5'] = process.get('process_md5', '<UNKNOWN>')
            matching_process['relative_url'] = "/#/analyze/%s/%s" % (str(id), str(process['segment_id']))
            matching_process['absolute_url'] = "%s/#/analyze/%s/%s" % (self.bridge_options['carbonblack_server_url'],
                                                                       str(id), str(process['segment_id']))
            matching_process['start'] = process.get('start', '<UNKNOWN>')
            matching_process['netconns'] = processed_netconns
            matching_process['filewrites'] = processed_filewrites
            matching_process['last_update'] = process.get('last_update', '<UNKNOWN>')

            # the endpoint IP is 'special' in two ways:
            #  (1) the endpoint IP may not have been explicitly specified in the orignal
            #      registration (0.0.0.0)
            #  (2) the endpoint IP may have changed since the time of the registration.
            #      for example, the Fidelis device 'saw' traffic to a particular endpoint
            #      IP, then the endpoint IP changed, then the traffic seen by Fidelis was
            #      executed.
            #
            # default to the IP provided in the alert registration
            # if possible, find the current IP(s) for the sensor associated with the
            # original endpoints
            #
            try:
                sensor = self.cb.sensor(process['sensor_id'])
                ips = []
                for ip_mac_pair in sensor['network_adapters'].rstrip('|').split('|'):
                    ips.append(ip_mac_pair.split(',')[0])
                matching_process['endpoint_ip'] = ips
            except:
                # endpoint_ip has already been populated with the IP used during
                # registration
                #
                pass

            matching_processes.append(matching_process)

        # check to see if the search results contain new records.  If there are new records, create an alert.
        last_search_results = registration['last_search_results'] if registration.has_key('last_search_results') else []
        current_search_results = matching_processes

        if len(last_search_results) == len(current_search_results):
            last_set = set((x['id'], x['last_update'], len(x['filewrites'])) for x in last_search_results)
            diff_set = [x for x in current_search_results if (x['id'], x['last_update'], len(x['filewrites'])) not in last_set]
            if not diff_set or len(diff_set) < 1:
                self.logger.debug("Dropping search results for registration [%s] due to having no new results." %
                                  registration['alert_id'])
                return False

        self.logger.debug("Adding search results for registration [%s] to alerts" % registration['alert_id'])
        registration['last_search_results'] = matching_processes

        alert = {}
        alert['cp_ip'] = registration['cp_ip']
        alert['alert_id'] = registration['alert_id']
        alert['md5'] = registration['alert_md5']
        alert['processes'] = matching_processes

        with self.alert_hits_lock:
            self.alert_hits.append(alert)

        return True

    def search_registrations(self):
        """
        search CB data set for IOCs found in registrations
        if found, update global list of matches and remove the registration
        """

        # make a copy of the list so that we don't hold the lock while searching
        with self.registrations_lock:
            registrations_to_search = list(self.registrations)

        for registration in registrations_to_search:
            self.search_registration(registration)

        return

    def normalize_file_path(self, path):
        """
        performs configuration based normalization of file paths
        """
        return path.replace('\\', '/')

    def validate_config(self):
        if 'bridge' in self.options:
            self.bridge_options = self.options['bridge']
        else:
            self.logger.error("configuration does not contain a [bridge] section")
            return False

        config_valid = True
        msgs = []
        if not 'listener_port' in self.bridge_options or not self.bridge_options['listener_port'].isdigit():
            msgs.append('the config option listener_port is required and must be a valid port number')
            config_valid = False
        if not 'carbonblack_server_url' in self.bridge_options:
            msgs.append('the config option carbonblack_server_url is required')
            config_valid = False
        if not 'carbonblack_server_token' in self.bridge_options:
            msgs.append('the config option carbonblack_server_token is required')
            config_valid = False

        if not config_valid:
            for msg in msgs:
                sys.stderr.write("%s\n" % msg)
                self.logger.error(msg)
            return False
        else:
            return True
