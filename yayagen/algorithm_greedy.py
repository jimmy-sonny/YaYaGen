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

from .rule import YaraRule
from .util import *

import logging
log = logging.getLogger('yayagen')


def get_best_yara_pair_rule(reports):
    """
    Evaluate the intersection for each pair of reports,
    return the rule (intersection) that gives the highest score
    """
    best_rule = None
    best_val = 0.0
    for rep1, rep2 in itertools.combinations(reports, 2):
        rule = rule_class.YaraRule(rep1.yara_rule & rep2.yara_rule)
        val = rule.evaluate()
        if val > best_val:
            best_val, best_rule = val, rule
    return best_rule


def yyg_greedy(reports):
    """
    Greedy implementation of the algorithm to generate YARA rules
    """
    global_undetected = set(reports)
    yara_ruleset = list()
    yara_rule = None

    while len(global_undetected) > 0:
        # Pick the next best rule
        if yara_rule is None:
            
            if len(global_undetected) > 1:
                yara_rule = get_best_yara_pair_rule(global_undetected)
            else:
                yara_rule = next(iter(global_undetected)).yara_rule
            continue

        # Compute which reports are not covered by the current rule
        log.debug('%d undetected', len(global_undetected))
        local_undetected = {
            c for c in global_undetected if not c.match(yara_rule)
        }
        global_undetected = local_undetected

        new_yara_rule = get_relaxed_rule(yara_rule, local_undetected)
        c1 = not new_yara_rule 
        c2 = new_yara_rule and \
            (new_yara_rule.evaluate() < YaraRule.values['THRESHOLD'])

        if c1 or c2:
            yara_ruleset.append(yara_rule)
            log.debug('YARA rule weight: %f', yara_rule.evaluate())
            yara_rule = None
            continue

        yara_rule = new_yara_rule

    if yara_rule:
        yara_ruleset.append(yara_rule)
        log.debug('YARA rule weight: %f', yara_rule.evaluate())

    log.info("Greedy terminated")
    return yara_ruleset
