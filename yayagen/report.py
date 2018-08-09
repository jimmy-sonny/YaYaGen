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

import sys
import os
import re
import json
import sqlite3
import requests
import pickle
import pyjq

import logging
log = logging.getLogger('yayagen')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

from .rule import YaraRule

KOODOUS_DOWNLOAD_URL = "https://api.koodous.com/apks/%s/analysis"


class Report(object):

    __db_connection = None

    def __init__(self, jreport=None, filename=None, sha256=None):
        """
        (Get Koodous JSON analysis report)
        parse it; process it; store it (sqlite)
        """
        if jreport:
            self.__jreport = jreport
            self.__parse_jreport()
            self.__store()

        if filename:
            # Go lucky -- search the sha256 in the DB
            read_file = True
            fname = os.path.basename(filename).split('.')[0]
            if re.compile('[A-Fa-f0-9]{64}').match(fname):
                self.__sha256 = fname
                self.__yara_rule = self.__fetch(self.__sha256)
                read_file = False
                # Not available in cache
                if not self.__yara_rule or Report.nodb:
                    read_file = True

            # Actually read the file
            if read_file:
                log.debug("reading the file: %s", filename)
                try:
                    with open(filename, encoding='utf-8') as data_report:
                        self.__jreport = json.load(data_report)
                        self.__parse_jreport()
                        self.__store()
                except FileNotFoundError:
                    log.exception("File %s not found", filename)
                    raise SyntaxError('Error building \'Report\' object!')

        if sha256:
            if not re.compile('[A-Fa-f0-9]{64}').match(sha256):
                log.error('sha256 is not valid')
                raise SyntaxError('Error building \'Report\' object!')

            self.__sha256 = sha256
            self.__yara_rule = self.__fetch(self.__sha256)

            # Not available in cache
            if not self.__yara_rule or Report.nodb:
                log.warning("Downloading report from Koodous")
                r = requests.get(url=KOODOUS_DOWNLOAD_URL % sha256)
                self.__jreport = r.json()
                if len(self.__jreport) == 0:
                    log.error('Report not available in Koodous')
                    raise SyntaxError('Error building \'Report\' object!')
                self.__parse_jreport()
                self.__store()

        if not self.__yara_rule:
            log.error('Report is non valid')
            raise SyntaxError('Error building \'Report\' object!')

        self.__filter_rule()

        if len(self.__yara_rule) == 0:
            log.error('Report is empty')
            raise SyntaxError('Error building \'Report\' object!')

    def __parse_jreport(self):
        """
        Parse a report using the KEYWORDS
        from the configuration file
        """
        self.__yara_dict = dict()
        self.__sha256 = pyjq.first('.sha256', self.__jreport)

        for xp in Report.KEYWORDS['XPATH_PATTERNS'].keys():
            cc = self.__convert_XPATH_to_rule(xp)
            self.__yara_dict[cc] = pyjq.first(xp, self.__jreport)

        for xp in Report.KEYWORDS['XPATH_NUMERIC_PATTERNS'].keys():
            tmp = pyjq.first(xp, self.__jreport)
            if tmp:
                cc = self.__convert_XPATH_NUMERIC_to_rule(xp)
                self.__yara_dict[cc] = len(tmp)

        self.__yara_rule = YaraRule()
        for xpath, xval in self.__yara_dict.items():
            if xval is None:
                continue
            elif isinstance(xval, int) or isinstance(xval, str):
                self.__yara_rule.add((xpath, xval))
            elif isinstance(xval, list):
                for element in xval:
                    self.__yara_rule.add((xpath, element))
            elif isinstance(xval, dict):
                for key in xval.keys():
                    new_key = xpath + '-' + key
                    self.__yara_rule.add((new_key, xval[key]))
            else:
                raise TypeError(type(xval))

    def __filter_rule(self):
        """
        Apply rule filtering to self.__yara_rule
        """
        self.__yara_rule.filter_attributes()

    def match(self, rule):
        """
        return True if rule matches self.__yara_rule, that is, if
        all attributes of rule are within self.__yara_rule
        """
        return all([y in self.__yara_rule for y in rule])

    def match_any(self, ruleset):
        """
        return True if at least one rule of ruleset matches
        self.__yara_rule
        """
        return any([self.match(y) for y in ruleset])

    def match_all(self, yara_ruleset):
        """
        return True if all the rules of ruleset matche
        self.__yara_rule
        """
        return all([self.match(y) for y in yara_ruleset])

    def __convert_XPATH_to_rule(self, xpath):
        """
        Converts Koodous Report  syntax to YARA syntax (1)
        """
        if xpath in Report.KEYWORDS['XPATH_PATTERNS'].keys():
            return Report.KEYWORDS['XPATH_PATTERNS'][xpath]
        raise SyntaxError(xpath)

    def __convert_XPATH_NUMERIC_to_rule(self, xpath):
        """
        Converts Koodous Report  syntax to YARA syntax (2)
        """
        if xpath in Report.KEYWORDS['XPATH_NUMERIC_PATTERNS'].keys():
            return Report.KEYWORDS['XPATH_NUMERIC_PATTERNS'][xpath]
        raise SyntaxError(xpath)

    def __store(self):
        """
        Store a report in a local db, using the SHA256 as a key
        """
        query_write = '''INSERT OR REPLACE INTO `reports` VALUES(?, ?)'''
        self.__db.execute(query_write, (self.__sha256,
                                        pickle.dumps(self.__yara_rule)))
        self.__db.commit()

    def __fetch(self, sha256):
        """
        Retrieves a report stored in a local db, given the SHA256
        """
        query_read = 'SELECT `yara_rule` FROM `reports` WHERE `sha256` = ?'
        cursor = self.__db.cursor()
        cursor.execute(query_read, (sha256,))
        data = cursor.fetchone()
        if data:
            return pickle.loads(data[0])
        else:
            return None

    @staticmethod
    def static_initializer(jconfig, nodb):
        """
        Static variables initialization
        """
        Report.nodb = nodb

        if nodb:
            log.warning("Koodous DB disabled")

        with open(jconfig['REPORT_KEYWORDS']) as f_in:
            Report.KEYWORDS = json.load(f_in)

        # Some low level initialization to match Report syntax with YARA modules syntax
        # Very poor SoftEng -- just skip it
        for func in Report.KEYWORDS['FUNCTIONALITIES']:
            for func_pattern in Report.KEYWORDS['FUNCTIONALITIES_XPATH_PATTERNS']:
                key = func_pattern.replace('FUNCTIONALITY', func)
                key_array = key[1:-1].rsplit('.', 2)
                key_array[1] = key_array[1].replace('[]', '')
                value = 'androguard.functionality.'
                if key_array[1] in Report.KEYWORDS['FUNCTIONALITY_CONVERSION_KEYWORDS'].keys():
                    value += Report.KEYWORDS['FUNCTIONALITY_CONVERSION_KEYWORDS'][key_array[1]]
                else:
                    value += key_array[1]
                value += '.'
                value += key_array[2]
                Report.KEYWORDS['XPATH_PATTERNS'][key] = value
        return

    @property
    def __db(self):
        if not Report.__db_connection:
            Report.__db_connection = sqlite3.connect('reports.sqlite3')
            Report.__db_connection.execute('''
                    CREATE TABLE IF NOT EXISTS `reports` (
                        `sha256` TEXT NOT NULL,
                        `yara_rule`   BLOB NOT NULL,
                        PRIMARY KEY(sha256)
                    ) WITHOUT ROWID;''')
            # This makes SQLite to run faster, but it could result in database corruption
            Report.__db_connection.execute('PRAGMA synchronous = OFF')
        return Report.__db_connection


    @property
    def sha256(self):
        return self.__sha256
    

    @property
    def jreport(self):
        return self.__jreport

    @property
    def yara_dict(self):
        return self.__yara_dict

    @property
    def yara_rule(self):
        return self.__yara_rule
