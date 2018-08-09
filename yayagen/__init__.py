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

"""
    YaYaGen
    Generates a sharp set of Yara Rules to detect a set of Koodous reports.
    Fore more details, see the paper: "Countering Android Malware: a Scalable
    Semi-Supervised Approach for Family-Signature Generation" [DOI]
"""

import sys
from .report import Report
from .io import *
from .dry_run import *
from .generate_rule import *

YYG_VERSION = "v0.5_summer18"

if sys.flags.optimize == 0:
    logging.debug("All debug checks are active, performances may be impaired")
