# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class MimicsIcon(Signature):
    name = "mimics_icon"
    description = "Mimics icon used for popular non-executable file format"
    severity = 3
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "1.3"

    def run(self):
        # Alphanumerica hash list by category
        badhashes = [
            # outlook 2013? icon
            "94c2270400f0e96be89d6d909c8e2485",
            # Office 365 Application Logo
            "4e623298caf36bc642543408fee2fd10",
            # Word 2007+ Application Logo
            "bad3afc82412906dc308db9d96f95e88",
            # Word 2007+
            "ec7e6f5458456dddb2d826bf1b8b03a2",
            # PDF icon
            "059dcdf32e800b5f2fe2aea2d5f045d8",
            "2c45339aea71418c49248aa88ffb2378",
            "6890c8a40c2eb5ff973159eca0428d6e",
            "6b0de9fbca602a637b0580b879904d61",
            "9334967a316ffffd255aaf9224a7da5e",
            "b686a61a6fbd20073faf430128597795",
            "d05e789cb57b150c4315acd350fce088",
            "db2d2c31f0c651217a0ef11aaf8c7796",
            "e52d1e9d64fd9535bf10f6da1091df9d",
            "f25d6693364cba910762c7e1d5149c21",
            # Fake PDF icon
            "f042192565667b350a5056af6ce01d5c",
        ]

        if "static" in self.results and "pe" in self.results["static"]  and "icon_fuzzy" in self.results["static"]["pe"]:
            if self.results["static"]["pe"]["icon_fuzzy"] in badhashes:
                return True
        return False
