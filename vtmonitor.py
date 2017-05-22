import argparse
import logging
import json
import hashlib
from datetime import datetime
from virus_total_apis import PublicApi as VirusTotalPublicApi

__author__ = 'Davide Tampellini'
__copyright__ = '2017 Davide Tampellini - FabbricaBinaria'
__license__ = 'GNU GPL version 3 or later'


class VTMonitor:
    def __init__(self):
        self.settings = None
        self.version = '1.0.0'
        self.api_key = None

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
                _ = json.load(handle)
                self.api_key = _['api_key']
        except IOError:
            raise Exception('Please rename settings-dist.json to settings.json and fill the required value')
        except AttributeError:
            raise Exception('Please add your Virus Total API key to the settings.json file')

        if not self.api_key:
            raise Exception('Please add your Virus Total API key to the settings.json file')

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

        vt = VirusTotalPublicApi(self.api_key)

        with open("C:\\\Windows\\system32\\notepad.exe", 'rb') as handle:
            test = handle.read()

        signature = hashlib.md5(test).hexdigest()
        response = vt.get_file_report(signature)

        print json.dumps(response, indent=4)

try:
    scraper = VTMonitor()
    scraper.run()
except KeyboardInterrupt:
    print("")
    print ("[*] Operation aborted")
