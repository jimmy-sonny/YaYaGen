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


import math
import itertools

from .rule import YaraRule
from .util import *

import logging
log = logging.getLogger('yayagen')

MAX_SEARCH_SPACE_SIZE = 500

def yyg_clot(reports):
    heap = [((-rep.yara_rule.rule_coverage(reports), rep.yara_rule.evaluate()), rep.yara_rule) for rep in reports]
    bunch = heap[:]

    while len(heap) > 0:
        # log.debug('CLOT: selected=%s; heap_size=%d; bunch_size=%d', heap[0][0], len(heap), len(bunch))
        heap = sorted(heap)
        yara1 = heap.pop(-1)
        best = None
        for yara2 in bunch:
            new_yara = YaraRule(yara1[1] & yara2[1])
            candidate = ((-new_yara.rule_coverage(reports),
                          new_yara.evaluate()), new_yara)
            if candidate in bunch:
                continue
            if (candidate[0][1] >= YaraRule.values['THRESHOLD'] and
                    best is None):
                best = candidate
            elif (candidate[0][1] >= YaraRule.values['THRESHOLD'] and
                  candidate[0] < best[0]):
                best = candidate
        if best:
            heap.append(best)
            bunch.append(best)

    # log.debug('Generated %d rules', len(bunch))
    yara_ruleset = list()
    uncovered_reports = set(reports)
    while len(uncovered_reports) > 0:
        # find if a report is critical
        critical_set = None
        for rep in uncovered_reports:
            current_set = [y for _, y in bunch if rep.match(y)]
            if critical_set is None or len(current_set) < len(critical_set):
                critical_set = current_set

        candidate = [((-y.rule_coverage(uncovered_reports), y.evaluate()), y)
                     for y in critical_set]
        candidate = sorted(candidate, reverse=True)
        _, yara = candidate.pop(-1)
        yara_ruleset.append(yara)
        uncovered_reports = {c for c in uncovered_reports if not c.match(yara)}

    actual_size = len(yara_ruleset)
    # log.debug('Found a \'reasonable\' solution (size=%d)', actual_size)

    target_size = actual_size
    search_space_size = math.factorial(len(bunch)) // (
        math.factorial(target_size) * math.factorial(len(bunch) - target_size))
    if search_space_size > MAX_SEARCH_SPACE_SIZE:
        target_size -= 1
    run_exact = True

    while run_exact:
        best_solution = None
        best_solution_value = None
        search_space_size = math.factorial(len(bunch)) // (
            math.factorial(target_size) * math.factorial(len(bunch) - target_size))
        if target_size == 0:
            run_exact = False
        elif search_space_size > MAX_SEARCH_SPACE_SIZE:
            run_exact = False
        else:
            # log.debug('Brute force: evaluating %d solutions (target_size=%d)', search_space_size, target_size)
            for solution in itertools.combinations(bunch, target_size):
                ruleset = [r for _, r in solution]
                uncovered_reports = {
                    c for c in reports if not c.match_any(ruleset)}
                if len(uncovered_reports) > 0:
                    continue
                value = (sum([v for (v, _), _ in solution]),
                         sum([v for (_, v), _ in solution]))
                if not best_solution or value < best_solution_value:
                    best_solution = ruleset
                    best_solution_value = value
        if best_solution:
            yara_ruleset = best_solution
            actual_size = len(yara_ruleset)
            target_size = actual_size - 1
            # log.debug('Found the optimal solution (size=%d)', actual_size)
        else:
            run_exact = False

    log.info('Clot terminated')
    return yara_ruleset
