#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Vuls Report Import Plugin
Copyright (C) 2016 gleentea
See the file 'doc/LICENSE' for the license information

'''
from __future__ import with_statement
from plugins import core
import re
import os
import sys
import json

try:
    import xml.etree.cElementTree as ET
    import xml.etree.ElementTree as ET_ORIG
    ETREE_VERSION = ET_ORIG.VERSION
except ImportError:
    import xml.etree.ElementTree as ET
    ETREE_VERSION = ET.VERSION

current_path = os.path.abspath(os.getcwd())

__author__ = "gleentea"
__copyright__ = "Copyright (c) 2016, gleentea"
__credits__ = ["gleentea"]
__license__ = ""
__version__ = "1.0.0"
__maintainer__ = "gleentea"
__email__ = "gleentea@gmail.com"
__status__ = "Experimental"


class VulsParser(object):
    def __init__(self, output):
        lists = output.split("\r\n")
        i = 0
        self.items = []
        if re.search("Could not reach", output) is not None:
            self.fail = True
            return

        for line in lists:
            if i > 8:
                item = {'link': line}
                self.items.append(item)
            i = i + 1


class VulsPlugin(core.PluginBase):
    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "Vuls"
        self.name = "Vuls XML Output Plugin"
        self.plugin_version = "0.0.1"
        self.version = "1.0.0"
        self.framework_version = "1.0.0"
        self.options = None
        self._current_output = None
        self._current_path = None
        self._command_regex = re.compile(
            r'^(vuls|sudo vuls|\.\/vuls).*?')
        self.host = None
        self.port = None
        self.protocol = None
        self.fail = None

        global current_path

    def canParseCommandString(self, current_input):
        if self._command_regex.match(current_input.strip()):
            return True
        else:
            return False

    def parseOutputString(self, output, debug=False):
        j = None
        try:
            tree = ET.fromstring(output)
            j = tree.findtext(".//data")
            j = json.loads(j)
        except Exception as e:
            print "Exception - %s" % e

        # TODO: output IP address to json report
        # TODO: output MAC Address to json report
        ip = "127.0.0.1"
        os = j['Family'] + "/" + j["Release"]
        host = j["ServerName"]
        mac = "00:00:00:00:00:00"
        h_id = self.createAndAddHost(ip,os)

        if self._isIPV4(ip):
            i_id = self.createAndAddInterface(h_id, ip, mac, ipv4_address=ip, hostname_resolution=host)
        else:
            i_id = self.createAndAddInterface(h_id, ip, mac, ipv6_address=ip, hostname_resolution=host)

        for k in ['KnownCves','UnknownCves']:
            for v in j[k]:
                severity = self.scoreToString(v['CveDetail']['Nvd']['Score'])

                resolution = ""
                ref = []
                ref.append(v["CveDetail"]["CveID"])
                desc = v["CveDetail"]["Nvd"]["Summary"]
                if v["CveDetail"]["Nvd"]["References"]:
                    for r in v["CveDetail"]["Nvd"]["References"]:
                        ref.append(r["Link"])
                for pkg in v['Packages']:
                    name = pkg['Name']
                    ver = ["Installed:" + pkg['Version'],"Candidate:" + pkg['NewVersion']]
                    if pkg['Release'] != "":
                        ver[0] += "/" + pkg["Release"]
                    if pkg["NewRelease"] != "":
                        ver[1] += "/" + pkg["NewRelease"]
                    self.createAndAddVulnToHost(h_id, name, desc, ref+ver, severity=severity, resolution=resolution)
        return True

    def _isIPV4(self, ip):
        if len(ip.split(".")) == 4:
            return True
        else:
            return False

    def processCommandString(self, username, current_path, command_string):
        return None

    def setHost(self):
        pass

    def resolve(self, host):
        try:
            return socket.gethostbyname(host)
        except:
            pass
        return host

    def scoreToString(self,score):
        if score == 0.0:
            return "info"
        if 0.0 < score and score <= 3.9:
            return "low"
        if 3.9 < score and score <= 6.9:
            return "medium"
        if 6.9 < score and score <= 8.9:
            return "high"
        if 8.9 < score:
            return "critical"
        return "unclassified"

def createPlugin():
    return VulsPlugin()

if __name__ == '__main__':
    parser = VulsParser(sys.argv[1])
    for item in parser.items:
        if item.status == 'up':
            print item
