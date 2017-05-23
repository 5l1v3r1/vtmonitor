import argparse
import logging
import json
import hashlib
import subprocess
from datetime import datetime
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

        parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)

        self.args = parser.parse_args()

        # Let's silence the requests package logger
        logging.getLogger("requests").setLevel(logging.WARNING)

    def banner(self):
        now = datetime.now()

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
        self.banner()

        # Perform some sanity checks
        try:
            self.checkenv()
        except Exception as error:
            print "[!] " + str(error)
            return

        self.check_updates()

        if self.private_api:
            vt = VirusTotalPrivateApi(self.api_key)
        else:
            vt = VirusTotalPublicApi(self.api_key)

        # Create baseline of processes
        print "[*] Creating base list of allowed process"
        wmic = subprocess.check_output("wmic process get ExecutablePath", shell=True)
        wmic = wmic.replace('\r', '\n')

        base_list = set([])

        for process in wmic.split('\n'):
            process = process.strip()

            if not process:
                continue

            base_list.add(process)

        print "[*] Starting main loop to watch for new processes"

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

                print "[+] Unknown process %s, checking the hash on Virus Total" % process

                # New process, let's submit to VT for details
                with open(process, 'rb') as handle:
                    data = handle.read()

                signature = hashlib.md5(data).hexdigest()
                response = vt.get_file_report(signature)

                msg = "[-] Process %s has a known signature on Virus Total" % process

                if response['results'].get('response_code') == 0:
                    msg = "[!] Process %s is unknown on Virus Total" % process

                print msg

                # and add it to the base list, otherwise it will keep pinging VT all the time
                base_list.add(process)

                # print json.dumps(response, indent=4)

try:
    scraper = VTMonitor()
    scraper.run()
except KeyboardInterrupt:
    print("")
    print ("[*] Operation aborted")
