import argparse
import logging
from datetime import datetime
from virus_total_apis import PublicApi as VirusTotalPublicApi

__author__ = 'Davide Tampellini'
__copyright__ = '2017 Davide Tampellini - FabbricaBinaria'
__license__ = 'GNU GPL version 3 or later'


class VTMonitor:
    def __init__(self):
        self.settings = None
        self.version = '1.0.0'

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
        pass

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

        vt = VirusTotalPublicApi('')
        vt.get_file_report('')


try:
    scraper = VTMonitor()
    scraper.run()
except KeyboardInterrupt:
    print("")
    print ("[*] Operation aborted")
