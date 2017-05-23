import logging
import logging.handlers
import json
import hashlib
import subprocess
from time import sleep
from virus_total_apis import PublicApi as VirusTotalPublicApi
from virus_total_apis import PrivateApi as VirusTotalPrivateApi

__author__ = 'Davide Tampellini'
__copyright__ = '2017 Davide Tampellini - FabbricaBinaria'
__license__ = 'GNU GPL version 3 or later'


class VTMonitor:
    def __init__(self):
        self.settings = None
        self.version = '1.0.0'
        self.api_key = None
        self.private_api = None
        self.args = []

        # Logging information
        vt_logger = logging.getLogger('vtmonitor')
        vt_logger.setLevel(logging.DEBUG)

        # Create a rotation logging, so we won't have and endless file
        rotate = logging.handlers.RotatingFileHandler('vtmonitor.log', maxBytes=(5 * 1024 * 1024), backupCount=3)
        rotate.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s|%(levelname)-8s| %(message)s', '%Y-%m-%d %H:%M:%S')
        rotate.setFormatter(formatter)

        vt_logger.addHandler(rotate)

        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)

        formatter = logging.Formatter('%(asctime)s|%(levelname)-8s| %(message)s', '%Y-%m-%d %H:%M:%S')
        console.setFormatter(formatter)
        vt_logger.addHandler(console)

        # Let's silence the requests package logger
        logging.getLogger("requests").setLevel(logging.WARNING)

    def banner(self):
        print("VTMonitor " + self.version + " - Watch and report")
        print("Copyright (C) 2017 FabbricaBinaria - Davide Tampellini")
        print("===============================================================================")
        print("VTMonitor is Free Software, distributed under the terms of the GNU General")
        print("Public License version 3 or, at your option, any later version.")
        print("This program comes with ABSOLUTELY NO WARRANTY as per sections 15 & 16 of the")
        print("license. See http://www.gnu.org/licenses/gpl-3.0.html for details.")
        print("===============================================================================")

    def checkenv(self):
        try:
            with open('settings.json', 'rb') as handle:
                settings = json.load(handle)
                self.api_key = settings['api_key']
        except IOError:
            raise Exception('Please rename settings-dist.json to settings.json and fill the required value')
        except AttributeError:
            raise Exception('Please add your Virus Total API key to the settings.json file')

        if not self.api_key:
            raise Exception('Please add your Virus Total API key to the settings.json file')

        self.private_api = settings['private']

    def check_updates(self):
        pass

    def run(self):
        vt_logger = logging.getLogger('vtmonitor')

        self.banner()

        # Perform some sanity checks
        try:
            self.checkenv()
        except Exception as error:
            vt_logger.critical(error)
            return

        self.check_updates()

        vt_logger.debug('==================================================')
        vt_logger.debug('Application restart')
        vt_logger.debug('==================================================')

        if self.private_api:
            vt = VirusTotalPrivateApi(self.api_key)
        else:
            vt = VirusTotalPublicApi(self.api_key)

        # Create baseline of processes
        vt_logger.info('Creating base list of allowed process')
        wmic = subprocess.check_output("wmic process get ExecutablePath", shell=True)
        wmic = wmic.replace('\r', '\n')

        base_list = set([])

        for process in wmic.split('\n'):
            process = process.strip()

            if not process:
                continue

            base_list.add(process)

        vt_logger.info("Starting main loop to watch for new processes")

        while True:
            sleep(1)

            wmic = subprocess.check_output("wmic process get ExecutablePath", shell=True)
            wmic = wmic.replace('\r', '\n')

            for process in wmic.split('\n'):
                process = process.strip()

                if not process:
                    continue

                if process in base_list:
                    continue

                vt_logger.debug("Unknown process %s, checking the hash on Virus Total" % process)

                # New process, let's submit to VT for details
                with open(process, 'rb') as handle:
                    data = handle.read()

                signature = hashlib.md5(data).hexdigest()
                response = vt.get_file_report(signature)

                if response['results'].get('response_code') == 0:
                    vt_logger.warn("Process %s is unknown on Virus Total" % process)
                else:
                    vt_logger.info("Process %s has a known signature on Virus Total" % process)

                # and add it to the base list, otherwise it will keep pinging VT all the time
                base_list.add(process)

try:
    scraper = VTMonitor()
    scraper.run()
except KeyboardInterrupt:
    print("")
    print ("Operation aborted")
