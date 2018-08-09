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

import itertools
from . import rule as rule_class

import logging
log = logging.getLogger('yayagen')


def get_relaxed_rule(yara_rule, candidates):
    best_val = 0.0
    best_rule = None
    for cc in candidates:
        rule = rule_class.YaraRule(yara_rule & cc.yara_rule)
        val = rule.evaluate()
        if val > best_val:
            best_val, best_rule = val, rule
    return best_rule
