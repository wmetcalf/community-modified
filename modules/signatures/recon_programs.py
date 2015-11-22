# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature
import re
class InstalledApps(Signature):
    name = "recon_programs"
    description = "Collects information about installed applications"
    severity = 3
    confidence = 20
    categories = ["recon"]
    authors = ["Optiv"]
    minimum = "1.2"

    def run(self):
        self.office_paths_re = re.compile(r"^[A-Z]\:\\Program Files(?:\s\(x86\))?\\Microsoft Office\\(?:Office\d{2}\\)?(?:WINWORD|OUTLOOK|POWERPNT|EXCEL|WORDVIEW)\.EXE$",re.I)
        # get the path of the initial monitored executable
        self.initialpath = None
        processes = self.results["behavior"]["processtree"]
        if len(processes):
            self.initialpath = processes[0]["module_path"].lower()
        if self.initialpath and self.office_paths_re.match(self.initialpath):
            return False

        if self.check_read_key(pattern= ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall.*", regex=True):
            return True

        return False
