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

import logging
log = logging.getLogger('yayagen')

from .algorithm_greedy import *
from .algorithm_clot import *
from .rule import YaraRule


def optimize_and_save(reports, rules, outputdir, rulename, comment, args):
    """
    Display and save each YARA rule (optimization included)
    """
    for count, rule in enumerate(rules):
        if rule.evaluate() < YaraRule.values['THRESHOLD']:
            log.critical("YaraRule WEIGHT %d < THRESHOLD!" % rule.evaluate())

        rulename = ": rule%d" % count
        rule.print_rule_stat(reports)
        yar_original = rule.to_yar_format(rulename, comment)
        print(yar_original)
        print(" ")

        optimized_rule = rule.optimize_rule(
            opt=args.optimizer, reports=reports)
        optimized_rule.print_rule_stat(reports)
        yar_optimized = optimized_rule.to_yar_format(rulename, comment)
        print(yar_optimized)
        print(" ")

        if outputdir:
            try:
                if not os.path.isdir(outputdir):
                    os.mkdir(outputdir)
                    log.info("Folder %s created", outputdir)

                fname = "%s_%d.yar" % (rulename, count)
                fpath = os.path.join(outputdir, fname)
                with open(fpath, "w") as f_out:
                    f_out.write(yar_original)

                fname = "%s_opt_%d.yar" % (rulename, count)
                fpath = os.path.join(outputdir, fname)
                with open(fpath, "w") as f_out:
                    f_out.write(yar_optimized)

            except Exception:
                log.error("Error while saving the Yara rule")


def generate_rule(reports, args):
    """
    Automatically generate a new YARA rule
    """
    if len(reports) == 0:
        return

    rules = list()
    if args.algorithm == 'greedy':
        log.info('Greedy run')
        rules = yyg_greedy(reports)

    elif args.algorithm == 'clot':
        log.info('Clot run')
        rules = yyg_clot(reports)

    else:
        log.critical('Available algorithms: [greedy, clot]')
        sys.exit()

    log.info("Generated %d rules", len(rules))
    print(' ')
    optimize_and_save(reports, rules, args.outputdir,
                      args.rulename, args.url, args)
