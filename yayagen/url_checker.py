#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##############################################################################
# __  __   __  __     _____                                                  #
# \ \/ /__ \ \/ /__ _/ ___/__ ___                                            #
#  \  / _ `/\  / _ `/ (_ / -_) _ \                                           #
#  /_/\_,_/ /_/\_,_/\___/\__/_//_/                                           #
#                                                                            #
# (c) 2017 by Andrea Marcelli & Giovanni Squillero                           #
# YaYaGen is distributed under a BSD-style license -- See file LICENSE.md    #
#                                                                            #
##############################################################################

import pickle
import pyjq
import json
import urllib
import re
import sqlite3
from urllib.parse import urlparse
import tldextract

import logging
log = logging.getLogger('yayagen')

VT_URL_TEXT = 'https://www.virustotal.com/vtapi/v2/domain/report'
VT_URL_IPADDR = 'https://www.virustotal.com/vtapi/v2/ip-address/report'


class UrlChecker():
    __min_detections = 1
    __db_connection = None

    def __init__(self, jconfig, vtapikey):
        """
        Load the DOMAINS_WHITELIST and setup the tld-extractor
        """
        try:
            with open(jconfig['DOMAINS_WHITELIST'], 'rb') as f_in:
                UrlChecker.whitelist = pickle.load(f_in)
        except:
            log.error("URL whitelist loading error")
            UrlChecker.whitelist = list()
        cache_file = jconfig['TOP_DOMAINS_CACHE']
        UrlChecker.__tld = tldextract.TLDExtract(cache_file=cache_file)
        UrlChecker.__vtapikey = vtapikey

    def get_sub_domain(self, url):
        """
        Get domain and subdomain from URL
        """
        res = UrlChecker.__tld(url)
        domain = res.domain
        if len(res.suffix):
            domain += '.' + res.suffix
        subdomain = res.subdomain
        if len(res.subdomain) > 0:
            subdomain += '.' + domain
        return domain.lower(), subdomain.lower()

    def detected_VT(self, domain, ipaddr=False, nodb=False):
        """
        Return True if the domain is known and detected by VT
        (that is, it's potentially malicious)
        """
        try:
            if not re.match('.+\..+', domain):
                return False

            if not UrlChecker.__vtapikey:
                return False
                
            detections = self.__fetch(domain)
            # Not in DB
            if (detections is None) or nodb:
                log.debug("querying VT: %s", domain)
                if ipaddr:
                    parameters = {'ip': domain,
                                  'apikey': UrlChecker.__vtapikey}
                    vt_url = VT_URL_IPADDR
                else:
                    parameters = {'domain': domain,
                                  'apikey': UrlChecker.__vtapikey}
                    vt_url = VT_URL_TEXT
                param = urllib.parse.urlencode(parameters)
                vurl = '%s?%s' % (vt_url, param)
                response = urllib.request.urlopen(vurl).read()
                if len(response) == 0:
                    log.error("VT error - (probably API limit exceeded)")
                    return False
                jresponse = json.loads(response)
                if jresponse['response_code'] == 0:
                    # Item not present in VirusTotal's dataset
                    self.__store(domain, [])
                    return False
                detections = pyjq.all(
                    '.detected_urls[] | .positives', jresponse)
                self.__store(domain, detections)

            if len(detections) >= UrlChecker.__min_detections:
                # Domain is detected
                return True
            return False

        except Exception:
            log.error("Error while querying domain: %s", domain)
            return False

    def is_common_url(self, url, nodb):
        """
        Return False if 'url' is potentially malicious,
        True otherwise
        """
        domain, subdomain = self.get_sub_domain(url)
        if len(domain) > 0:
            # Check if the domain is an IP address
            if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                if self.detected_VT(domain, ipaddr=True, nodb=nodb):
                    return False
                return True
            if domain in UrlChecker.whitelist:
                return True
            if len(subdomain) > 0 and self.detected_VT(subdomain, nodb=nodb):
                return False
            if self.detected_VT(domain, nodb=nodb):
                return False
        return True

    def find_url_strings(self, url):
        """
        Return php pages extracted from the urls
        """
        strings = list()
        output = urlparse(url)
        if output.path.endswith(".php"):
            strings.append(output.path)
        return strings

    def __store(self, domain, detections):
        """
        Store VT detection results on a sqlite DB
        """
        query_write = '''INSERT OR REPLACE INTO `detections` VALUES(?, ?)'''
        self.db.execute(query_write, (domain, pickle.dumps(detections)))
        self.db.commit()

    def __fetch(self, domain):
        """
        Get VT detection results from DB
        """
        query_read = 'SELECT `detections` FROM `detections` WHERE `domain` = ?'
        cursor = self.db.cursor()
        cursor.execute(query_read, (domain,))
        data = cursor.fetchone()
        if data:
            return pickle.loads(data[0])
        return None

    @property
    def db(self):
        if not UrlChecker.__db_connection:
            UrlChecker.__db_connection = sqlite3.connect('detections.sqlite3')
            UrlChecker.__db_connection.execute('''
                    CREATE TABLE IF NOT EXISTS `detections` (
                        `domain` TEXT NOT NULL,
                        `detections`   BLOB NOT NULL,
                        PRIMARY KEY(domain)
                    ) WITHOUT ROWID;''')
            # This makes SQLite to run faster, but it could result in database corruption
            UrlChecker.__db_connection.execute('PRAGMA synchronous = OFF')
        return UrlChecker.__db_connection
