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
assert sys.version_info >= (3, 4)
import os
import argparse
import json
import signal

import coloredlogs
import logging
log = None

import yayagen as yyg

banner = """
__  __   __  __     _____
\ \/ /__ \ \/ /__ _/ ___/__ ___   YaYaGen -- Yet Another Yara Rule Generator
 \  / _ `/\  / _ `/ (_ / -_) _ \  (!) %s
 /_/\_,_/ /_/\_,_/\___/\__/_//_/  by Andrea Marcelli & Giovanni Squillero
"""


def signal_handler(signal, frame):
    log.critical('You pressed Ctrl+C!')
    log.critical('Finishing')
    sys.exit(0)


def load_configuration(configuration_path):
    """
    Load YaYaGen configuration from external file
    """
    try:
        with open(configuration_path) as f_in:
            jconfig = json.load(f_in)
            return jconfig
    except Exception:
        log.critical("Configuration file not found")
        sys.exit()


def set_logger(debug):
    """
    Set logger level and syntax
    """
    global log
    log = logging.getLogger('yayagen')
    if debug:
        loglevel = 'DEBUG'
    else:
        loglevel = 'INFO'
    coloredlogs.install(fmt='%(asctime)s %(levelname)s:: %(message)s',
                        datefmt='%H:%M:%S', level=loglevel, logger=log)


def main():
    example_text = '''example:

 ./yyg.py -d -dry -dir _sample_analysis_json
 ./yyg.py -d -a clot -opt basic -dir _sample_analysis_json
 ./yyg.py -d -name bankbot -o bankbot_rule --url https://koodous.com/apks?search=tag:bankbot%20AND%20date:%3E2018-06-10
 ./yyg.py accd05c00951ef568594efebd5c30bdce2e63cee9b2cdd88cb705776e0a4ca70 e6aba7629608a525b020f4e76e4694d6d478dd9561d934813004b6903d66e44c
 '''

    parser = argparse.ArgumentParser(prog='YaYaGen',
                                     description='Yet another YARA rule Generator',
                                     epilog=example_text,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-d', '--debug', dest='debug',
                        action='store_true', help='log level debug')
    parser.add_argument('-ndb', '--no-db', dest='no_db',
                        action='store_true', help='disable DB')
    # Algorithms
    parser.add_argument('-dry', '--dryrun', dest='dryrun',
                        action='store_true', help='parse inputs and exit')
    parser.add_argument('-a', '--algorithm', default='clot',
                        type=str, help='[greedy, clot]')
    parser.add_argument('-opt', '--optimizer', default='basic',
                        type=str, help='[basic, evo]')
    # Inputs
    parser.add_argument('-u', '--url', type=str,
                        help='koodous URL')
    parser.add_argument('-dir', '--directory', type=str,
                        help='directory with Koodous reports')
    parser.add_argument('sha256', metavar='sha256', type=str,
                        nargs='*', help='sha256 APK list')
    parser.add_argument('-f', '--filter', type=str,
                        help='filter reports in input (one sha256 or filename per line)')
    # Output
    parser.add_argument('-o', '--outputdir', type=str,
                        help='save generated rules to outputdir')
    parser.add_argument('-name', '--rulename', type=str,
                        help='YARA rule name', default='YaYaRule')
    args = parser.parse_args()

    global log
    set_logger(args.debug)

    log.warning("YaYaGen started!")
    jconfig = load_configuration('_config/configuration.json')

    vtapi = os.environ.get('VTAPI')

    yyg.Report.static_initializer(jconfig, args.no_db)
    yyg.YaraRule.static_initializer(jconfig, vtapi, args.no_db)

    reports = yyg.get_reports(args)
    log.info("Found %d reports", len(reports))

    # Read inputs and exit
    if args.dryrun:
        yyg.dry_run(reports, args)
    else:
        yyg.generate_rule(reports, args)

    log.warning("That's all folks")


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    print(banner % yyg.YYG_VERSION)
    main()
