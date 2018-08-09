#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##############################################################################
# __  __   __  __     _____                                                  #
# \ \/ /__ \ \/ /__ _/ ___/__ ___                                            #
#  \  / _ `/\  / _ `/ (_ / -_) _ \                                           #
#  /_/\_,_/ /_/\_,_/\___/\__/_//_/                                           #
#                                                                            #
# (c) 2018 by Andrea Marcelli & Giovanni Squillero                           #
# YaYaGen is distributed under a BSD-style license -- See file LICENSE.md    #
#                                                                            #
##############################################################################

import random

import logging
log = logging.getLogger('yayagen')

LISTED_RULE = None
REPORTS = None


def basic_optimizer(rule):
    """
    Randombly remove attributes, until reaching UPPER_THRESHOLD
    """
    from . import rule as rule_class
    if rule.evaluate() < rule_class.YaraRule.values['UPPER_THRESHOLD']:
        return rule

    optimized = False
    opt_rule = rule_class.YaraRule(rule)

    while not optimized:
        candidate = random.sample(opt_rule, 1)[0]
        temp = rule_class.YaraRule(opt_rule - {candidate})
        weight = temp.evaluate()
        c1 = weight > rule_class.YaraRule.values['UPPER_THRESHOLD']
        c2 = weight > rule_class.YaraRule.values['THRESHOLD']
        if c1 and c2:
            opt_rule = temp
        else:
            optimized = True
    return opt_rule


def sgx_optimizer(rule, reports):
    log.critical("sgx_optimizer has not been released yet. Available soon :)")
    return rule