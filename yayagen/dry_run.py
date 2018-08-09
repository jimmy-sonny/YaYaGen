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

import logging
log = logging.getLogger('yayagen')


def dry_run(reports, args):
    """
    Transform each report into a YARA rule and print it
    """
    log.warning('DRY run')
    print(" ")
    for report in reports:
        log.info("%s", report.sha256)
        report.yara_rule.print_rule_stat()
        opt = report.yara_rule.optimize_rule()
        print(opt.to_yar_format(args.rulename))
        print(" ")