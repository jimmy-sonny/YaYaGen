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

import os
import re
import requests
import pyjq

from .report import Report

import logging
log = logging.getLogger('yayagen')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

KOODOUS_SEARCH_URL = "https://koodous.com/apks?search="
KOODOUS_SEARCH_URL_API = "https://api.koodous.com/apks?search="


def get_reports_from_url(url, filter_list):
    """
    Query Koodous API and get a list of for SHA256.
    """
    reports = list()

    if url.startswith(KOODOUS_SEARCH_URL):
        url = url.replace(KOODOUS_SEARCH_URL, KOODOUS_SEARCH_URL_API)
        try:
            r = requests.get(url=url)
            j = r.json()
            shalist = pyjq.all('.results[] | .sha256', j)
            log.debug("Found %d applications", len(shalist))
            for sha256 in shalist:
                if sha256 not in filter_list:
                    try:
                        log.info("Processing: %s", sha256)
                        reports.append(Report(sha256=sha256))
                    except Exception:
                        log.error('Error while processing: %s', sha256)
        except:
            log.error('Error while processing: %s', url)
    else:
        log.error('Invalid URL: %s', url)
    return reports


def get_reports_from_dir(directory, filter_list):
    """
    Traverse a directory and convert each JSON file in a Report object.
    """
    reports = list()

    for root, _, files in os.walk(directory):
        for basename in files:
            if basename.split('.')[0] not in filter_list:
                fullpath = os.path.join(root, basename)
                try:
                    log.info("Processing: %s", fullpath)
                    reports.append(Report(filename=fullpath))
                except Exception:
                    log.error('Error while processing: %s', fullpath)
    return reports


def get_reports(args):
    """
    Get Koodous reports
    """
    reports = list()
    filter_list = list()

    if args.filter:
        with open(filter_file, 'rt') as fd:
            filter_list = [_.strip().split('.')[0] for _ in fd.readlines()]

    if args.directory:
        reports += get_reports_from_dir(args.directory, filter_list)

    if args.url:
        reports += get_reports_from_url(args.url, filter_list)

    for sha256 in args.sha256:
        if sha256 not in filter_list:
            try:
                log.info("Processing: %s", sha256)
                reports.append(Report(sha256=sha256))
            except Exception:
                log.error('Error while processing: %s', sha256)

    return reports
