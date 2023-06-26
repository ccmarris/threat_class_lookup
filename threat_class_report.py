#!/usr/bin/env python3
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
"""
------------------------------------------------------------------------
 ABSOLUTELY NO WARRANTY WITH THIS PACKAGE. USE IT AT YOUR OWN RISK.

 Simple script to get threat classes, properties and stats from TIDE

 Requirements:
   Requires bloxone

 Usage: <scriptname> [options] <query>
        -h        help
        -c        Override config file
        -s        suppress all but CSV
        -d        debug output

 Author: Chris Marrison

 ChangeLog:
   20211005    v0.5    Updated to use Bloxone
   20190207    v0.3    Added human readable output
   20181123    v0.2    Create and output threat classes and properties options
   20181122    v0.1    Initial testing

 Todo:

 Copyright (c) 2018 All Rights Reserved.
------------------------------------------------------------------------
"""
__version__ = '0.5'
__author__ = 'Chris Marrison'


import sys
import os
import shutil
import argparse
import collections
import json
import logging
import tqdm

import bloxone

### Functions ###

def parseargs():
    '''
     Parse Arguments Using argparse

        Returns arguments
    '''
    parse = argparse.ArgumentParser(description='Simple script to get threat classes, properties and stats from TIDE')
    parse.add_argument('-c', '--config', type=str, default='config.ini',
                       help="Overide Config file")
    parse.add_argument('-p', '--properties', action='store_true', help="Get properties by threat class")
    parse.add_argument('-o', '--output', type=str, help="CSV Output to <filename>")
    parse.add_argument('-d', '--debug', action='store_true', help="Enable debug messages")

    return parse.parse_args()


def setup_logging(debug):
    '''
    Set up logging

    Returns logging object
    '''
    # Set up formatter for console
    #formatter = logging.Formatter('%(asctime)s: %(levelname)s - %(message)s')
    #fileh = logging.StreamHandler()
    #fileh.setFormatter(formatter)
    #console = logging.StreamHandler()
    #console.setFormatter(formatter)

    # Set debug level
    if debug:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

    # Create logger and add Console handler
    log = logging.getLogger(__name__)
    #log.addHandler(fileh)
    #log.addHandler(console)
    return log

def open_file(filename):
    '''
     Attempt to open logfile
        Returns file handler
    '''
    if os.path.isfile(filename):
        backup = filename+".bak"
        try:
            shutil.move(filename, backup)
            log.info("Outfile exists moved to {}".format(backup))
            try:
                handler = open(filename, mode='w')
                log.info("Successfully opened output file {}.".format(filename))
            except IOError as err:
                log.error("{}".format(err))
                handler = False
        except:
            log.warning("Could not back up existing file {}, exiting.".format(filename))
            handler = False
    else:
        try:
            handler = open(filename, mode='w')
            log.info("Opened file {} for invalid lines.".format(filename))
        except IOError as err:
            log.error("{}".format(err))
            handler = False

    return handler

def output_counter(cc):
    '''
     Output all entries in a counter by value

    Parameters:
        cc is a collection.Counter() obj
        topn is the number of items to print from highest to lowest

    Returns:
        None

    '''
    for key in cc.items():
        print('  {}: {}'.format(key[0], key[1]))
    return


def getkeys(cc):
    '''
     Get keys from collections.Counter object

     Parameters:
        cc = collection.counter
     Returns:
        keys = List of keys
    '''
    keys = []
    for item in cc.items():
        keys.append(item[0])

    return keys


def get_classes(b1td):
    '''
    Call threat_classes from bloxone.b1td and process output

    Parameters:
        b1td (obj) = Instantiated bloxone.b1td class obj

    Returns:
        threat_classes = List of threat class ids

    '''
    threat_classes = []
    response = b1td.threat_classes()

    if response.status_code in b1td.return_codes_ok:
        # Parse json
        parsed_json = json.loads(response.text)

        if 'threat_class' in parsed_json.keys():
            for tclass in parsed_json['threat_class']:
                threat_classes.append(tclass['id'])
        else:
            log.debug('Data format error. Raw data: {}'.format(response.text))
    else:
        log.debug('API error with rcode: {}'.format(response.status_code))

    return threat_classes


def get_properties(b1td, tclass):
    '''
    Call threat_properties from b1td and process output

    Parameters:
        b1td (obj) = Instantiated bloxone.b1td class obj

    Returns:
        threat_classes = List of threat class ids

    '''
    threat_properties = []
    response = b1td.threat_properties(threatclass=tclass)

    if response.status_code in b1td.return_codes_ok:
        # Parse json
        parsed_json = json.loads(response.text)

        if 'property' in parsed_json.keys():
            for property in parsed_json['property']:
                threat_properties.append(property['id'])
        else:
            log.debug('Data format error. Raw data: {}'.format(response.text))
    else:
        log.debug('API error with rcode: {}'.format(response.status_code))

    return threat_properties


def output_report(threat_classes, prop_by_class = []):
    '''
    Output Human Readable Report

    Parameters:
        None

    Returns:
        None

    '''
    if prop_by_class:
        for tclass in threat_classes:
            print()
            print('Threat Class: {}'.format(tclass))
            print(' Associated Threat Properties:')
            for prop in prop_by_class[tclass]:
                print('     {}'.format(prop))
        print()

    else:
        print('Threat Classes:')
        for tclass in threat_classes:
            print('     {}'.format(tclass))
        print()

    return

def main():
    '''
    Core script logic

    '''
    # Local Variables
    exitcode = 0
    threat_classes = []
    prop_by_class = collections.defaultdict()

    # Parse Arguments and configure
    args = parseargs()
    add_properties = args.properties
    outputfile = args.output
    if args.config:
        configfile = args.config
    else:
        configfile = 'config.ini'

    # Initialise bloxone
    b1td = bloxone.b1td(configfile)

    # Set up logging
    debug = args.debug
    log = setup_logging(debug)

    # Set up output file for CSV
    if outputfile:
        outfile = open_file(outputfile)
        if not outfile:
            log.warning('Failed to open output file for CSV.')
    else:
        outfile = False

    log.info('Retreiving Threat Classes')
    threat_classes = get_classes(b1td)
    log.info('{} Threat Classes Returned'.format(len(threat_classes)))

    if add_properties:
        log.info('Retreiving Threat Properies for each Threat Class')
        with tqdm.tqdm(total = len(threat_classes)) as pbar:
            for tc in threat_classes:
                prop_by_class[tc] = get_properties(b1td, tc)
                pbar.update(1)
                #print(prop_by_class)

    # Output Report
    log.info('Generating Report')
    output_report(threat_classes, prop_by_class)

    # Close files
    if outfile:
        outfile.close()

    log.debug("Processing complete.")

    return exitcode


### Main ###
if __name__ == '__main__':
    exitcode = main()
    exit(exitcode)
### End Main ###
