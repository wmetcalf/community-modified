from lib.cuckoo.common.abstracts import Signature
import re
class OfficeSecurity(Signature):
    name = "office_security"
    description = "Attempts to modify Microsoft Office security settings"
    severity = 3
    categories = ["office"]
    authors = ["Kevin Ross"]
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

        reg_indicators = [
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Office\\\\.*\\\\Security\\\\.*",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Policies\\\\Microsoft\\\\Office\\\\.*\\\\Security\\\\.*",    
        ]

        for indicator in reg_indicators:
            if self.check_write_key(pattern=indicator, regex=True):
                return True

        return False
