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
import re
import time
import pickle
import json

import editdistance
from math import ceil

from urllib.parse import urlparse
from .url_checker import UrlChecker
from .optimizer import *

import logging
log = logging.getLogger('yayagen')


class YaraRule(set):

    def filter_attributes(self):
        """
        Remove some attributes from the YaraRule object
        e.g., MainActivity, common URLs, ...
        """
        filter_set = set()
        new_set = set()

        def isascii(s): return len(s) == len(s.encode())

        for ypath, yval in self:

            # MainActivity
            if ypath == 'androguard.main_activity' and 'MainActivity' in yval:
                filter_set.add((ypath, yval))

            # intent.action.MAIN
            if ypath == 'androguard.filter' and yval == 'android.intent.action.MAIN':
                filter_set.add((ypath, yval))

            # APP name
            if ypath == 'androguard.app_name' and not isascii(yval):
                filter_set.add((ypath, yval))

            # common URLs
            if ypath == 'androguard.url':
                if YaraRule.UrlChecker.is_common_url(yval, YaraRule.nodb):
                    filter_set.add((ypath, yval))
                else:
                    for string in YaraRule.UrlChecker.find_url_strings(yval):
                        new_set.add(('androguard.url', string))

            if YaraRule.CUCKOO_SUPPORT:
                # common DNS
                if ypath == 'cuckoo.network.dns_lookup':
                    if YaraRule.UrlChecker.is_common_url(yval, YaraRule.nodb):
                        filter_set.add((ypath, yval))

                # common HTTP requests
                if ypath == 'cuckoo.network.http_request':
                    if YaraRule.UrlChecker.is_common_url(yval, YaraRule.nodb):
                        filter_set.add((ypath, yval))
                    else:
                        for string in YaraRule.UrlChecker.find_url_strings(yval):
                            new_set.add(('androguard.url', string))

        t0 = len(self)
        self.difference_update(filter_set)
        self.update(new_set)
        log.debug("Common attributes removed (%d -> %d)", t0, len(self))
        return

    def optimize_rule(self, opt='basic', reports=None,):
        """
        Optimize rule to increase # of detections
        """
        t0 = self.evaluate()
        if opt == 'basic':
            self = basic_optimizer(self)
        elif opt == 'evo':
            self = sgx_optimizer(self, reports)
        else:
            log.critical('Available optimizers: [basic, evo]')
            sys.exit()
        
        log.info("Rule optimization finished. (weight: %d -> %d)", t0, self.evaluate())
        return self

    def rule_coverage(self, reports):
        """
        Returns the number of reports that match the YaraRule object
        """
        return sum([rep.match(self) for rep in reports])

    def get_rule_stat(self, reports):
        """
        Get stats information about a YaraRule object
        Nb. reports could be None
        """
        if reports:
            detections = "%s/%s" % (self.rule_coverage(reports), len(reports))
        else:
            detections = "N/A"

        return {
            "literals": len(self),
            "detections": detections,
            "weight": self.evaluate(),
        }

    def print_rule_stat(self, reports=None):
        """
        Display some stats info about a YaraRule object
        """
        rule_stat = self.get_rule_stat(reports)

        log.info("RULE statistics:")
        log.info("** Number of literals: %d", rule_stat['literals'])
        log.info("** Weight: %.2f", rule_stat['weight'])
        log.info("** detections: %s", rule_stat['detections'])

    @staticmethod
    def print_wrong_permissions():
        """
        Print info about wrong permissions found
        """
        wps = len(YaraRule.WRONG_PERMISSION_DICT)
        if wps == 0:
            log.debug("No wrong permission found")
        else:
            log.debug("YaYaGen found %d wrong permissions: ", wps)
            for permission in YaraRule.WRONG_PERMISSION_DICT:
                log.warning("++%s", YaraRule.WRONG_PERMISSION_DICT[permission])
                log.warning("--%s", permission)

    def __is_wrong_permission(self, permission):
        """
        Return True if the permission contains a typo
        """
        if permission not in YaraRule.PERMISSION_SET:
            if permission in YaraRule.WRONG_PERMISSION_DICT.keys():
                return True
            if permission in YaraRule.CACHE_NNSTD_PERMISSION_DICT:
                return False
            for standard_perm in YaraRule.PERMISSION_SET:
                distance = editdistance.eval(permission, standard_perm)
                if distance > 0 and distance <= 3:
                    YaraRule.WRONG_PERMISSION_DICT[permission] = standard_perm
                    return True
                else:
                    YaraRule.CACHE_NNSTD_PERMISSION_DICT.add(permission)
        return False

    def __evaluate_permission(self, attribute, aval):
        """
        Evaluate permissions within a YaraRule object
        """
        score = 0
        if attribute in YaraRule.PERMISSION_NORMAL_SET:
            score += aval['androguard.permission_normal_value']
        elif attribute in YaraRule.PERMISSION_DANGEROUS_SET:
            score += aval['androguard.permission_dangerous_value']
        elif attribute in YaraRule.PERMISSION_NOT_THIRD_PARTY_SET:
            score += aval['androguard.permission_not_third_party_value']
        elif attribute in YaraRule.PERMISSION_SYSTEM_SET:
            score += aval['androguard.permission_system_value']
        elif self.__is_wrong_permission(attribute):
            score += aval['androguard.permission_wrong_value']
        else:
            score += aval['androguard.permission_non_standard_value']
        return score

    def evaluate(self):
        """
        Evaluate a YaraRule object
        """
        score = 0.0
        aval = YaraRule.values['ATTRIBUTE_VALUES']
        for ypath, yval in self:

            # Evalute a permission
            if ypath.startswith('androguard.permission'):
                score += self.__evaluate_permission(yval, aval)

            # Evaluate an intent filter
            if ypath == 'androguard.filter':
                if ypath in YaraRule.INTENT_SET:
                    score += aval['androguard.filter_standard']
                else:
                    score += aval['androguard.filter']

            # Evaluate the number of permissions
            if ypath.startswith('androguard.number_of_'):
                score += ceil(yval / 2)
            if ypath.startswith('androguard.permissions_number'):
                score += ceil(yval / 2)

            # Evaluate a functionality
            if ypath.startswith('androguard.functionality'):
                score += aval['androguard.functionality']

            # Evaluate an URL
            if ypath == 'androguard.url':
                score += aval['androguard.url']

            # Others
            if ypath in aval.keys():
                score += aval[ypath]

        return score

    def to_yar_format(self, rulename, url=None):
        """
        Convert a YaraRule object into the YARA language
        """
        # HEADER
        if not rulename.lower().startswith('yaya'):
            rulename = 'YaYa' + rulename
        rule = 'import "androguard"\n'
        if YaraRule.CUCKOO_SUPPORT:
            rule += 'import "cuckoo"\n\n'

        rule += ('\nrule %s {' % rulename)
        rule += '\n\tmeta:\n'
        rule += '\t\tauthor = "YaYaGen -- Yet Another Yara Rule Generator (*) %s"\n' % "v0.5_summer18"
        rule += "\t\tdate = \"%s\"\n" % time.strftime("%d %b %Y")
        if url:
            rule += "\t\turl = \"%s\"\n" % url

        # CONDITION section
        rule += '\n\tcondition:'
        conditions = list()
        last_ypath = ''
        for ypath, yval in sorted(self):
            # Manage the vertical spaces between clauses
            begin = ("\n" if last_ypath != ypath else "")
            if ypath.count('.') > 1:
                begin = "\n"
                if last_ypath.count('.') != 1:
                    c1 = last_ypath.rsplit(".", 2)[0]
                    c2 = ypath.rsplit(".", 2)[0]
                    begin = ("\n" if c1 != c2 else "")

            last_ypath = ypath
            # Convert to appropriate encoding
            if ypath.startswith('androguard.functionality'):
                cc = begin + "\t\t%s(/%s/)" % (ypath, re.escape(yval))
                conditions.append(cc)
            elif YaraRule.CUCKOO_SUPPORT and ypath.startswith('androguard.url'):
                url_lit = "\n\t\t(%s(\"%s\") or \n" % (ypath, yval)
                if urlparse(yval).hostname:
                    t_lit = re.escape(urlparse(yval).hostname)
                    url_lit += "\t\tcuckoo.network.dns_lookup(/%s/)  or \n" % t_lit
                    url_lit += "\t\tcuckoo.network.http_request(/%s/))" % t_lit
                else:
                    t_lit = re.escape(yval)
                    url_lit += "\t\tcuckoo.network.http_request(/%s/))" % t_lit
                conditions.append(url_lit)
            elif ypath.startswith('androguard.number_of_'):
                conditions.append(begin + "\t\t%s == %s" % (ypath, yval))
            elif ypath.startswith('androguard.permissions_number'):
                conditions.append(begin + "\t\t%s == %s" % (ypath, yval))
            else:
                conditions.append(begin + "\t\t%s(\"%s\")" % (ypath, yval))
        rule += " and \n".join(conditions)
        rule += '\n}'
        return rule

    @staticmethod
    def static_initializer(jconfig, vtapi, nodb):
        """
        Static variables initialization
        """
        YaraRule.vtapi = vtapi
        YaraRule.nodb = nodb

        if not vtapi:
            log.warning("VTAPI not set")

        if nodb:
            log.warning("VT DB disabled")

        YaraRule.UrlChecker = UrlChecker(jconfig, vtapi)

        YaraRule.CUCKOO_SUPPORT = jconfig['CUCKOO_SUPPORT']
        if not YaraRule.CUCKOO_SUPPORT:
            log.warning("CUCKOO disabled")

        YaraRule.WRONG_PERMISSION_DICT = dict()
        YaraRule.CACHE_NNSTD_PERMISSION_DICT = set()

        # Loading standard Android permissions
        with open(jconfig['PERMISSION_NORMAL_SET'], "rb") as f_in:
            YaraRule.PERMISSION_NORMAL_SET = pickle.load(f_in)
            YaraRule.PERMISSION_SET = YaraRule.PERMISSION_NORMAL_SET
        with open(jconfig['PERMISSION_DANGEROUS_SET'], "rb") as f_in:
            YaraRule.PERMISSION_DANGEROUS_SET = pickle.load(f_in)
            YaraRule.PERMISSION_SET.extend(YaraRule.PERMISSION_DANGEROUS_SET)
        with open(jconfig['PERMISSION_NOT_THIRD_PARTY_SET'], "rb") as f_in:
            YaraRule.PERMISSION_NOT_THIRD_PARTY_SET = pickle.load(f_in)
            YaraRule.PERMISSION_SET.extend(
                YaraRule.PERMISSION_NOT_THIRD_PARTY_SET)
        with open(jconfig['PERMISSION_SYSTEM_SET'], "rb") as f_in:
            YaraRule.PERMISSION_SYSTEM_SET = pickle.load(f_in)
            YaraRule.PERMISSION_SET.extend(YaraRule.PERMISSION_SYSTEM_SET)

        # Loading standard Android intents
        with open(jconfig['INTENT_ACTIVITY_SET'], "rb") as f_in:
            YaraRule.INTENT_ACTIVITY_SET = pickle.load(f_in)
            YaraRule.INTENT_SET = YaraRule.INTENT_ACTIVITY_SET
        with open(jconfig['INTENT_BROADCAST_SET'], "rb") as f_in:
            YaraRule.INTENT_BROADCAST_SET = pickle.load(f_in)
            YaraRule.INTENT_SET.extend(YaraRule.INTENT_BROADCAST_SET)
        with open(jconfig['INTENT_CATEGORIES_SET'], "rb") as f_in:
            YaraRule.INTENT_CATEGORIES_SET = pickle.load(f_in)
            YaraRule.INTENT_SET.extend(YaraRule.INTENT_CATEGORIES_SET)
        with open(jconfig['INTENT_FEATURES_SET'], "rb") as f_in:
            YaraRule.INTENT_FEATURES_SET = pickle.load(f_in)
            YaraRule.INTENT_SET.extend(YaraRule.INTENT_FEATURES_SET)

        with open(jconfig['RULE_VALUES']) as f_in:
            YaraRule.values = json.load(f_in)
