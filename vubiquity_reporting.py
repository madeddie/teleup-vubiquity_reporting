#!/usr/bin/env python

from __future__ import print_function
import argparse
import hashlib
import logging
import os
import sys
import xml.dom.minidom as MD
import xml.etree.cElementTree as ET
from calendar import timegm
from datetime import date, datetime, timedelta
from ftplib import FTP
from logging.config import dictConfig
from StringIO import StringIO
try:
    from urlparse import urljoin
except ImportError:
    from urllib.parse import urljoin

import requests


def read_config(config_file=None):
    """Return config dict with values from config file"""
    config = {}
    if not config_file:
        config_file = os.path.join(sys.path[0], 'config.py')
    try:
        exec(open(config_file).read(), config)
    except IOError:
        logger.error('File {} not found, exiting'.format(config_file))
        sys.exit()

    mandatory = [
        'api_url',
        'api_key',
        'ftp_server',
        'ftp_user',
        'ftp_pass',
        'affiliate_name',
        'system'
    ]

    missing = set(mandatory).difference(list(config.keys()))
    if missing:
        logger.error('Missing config setting(s) {}'.format(','.join(missing)))
        sys.exit()

    return config


def parse_args(argv=None):
    """Return args object

    Parsed from commandline options and arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--config_file',
                        help='Full location of config file to use')
    parser.add_argument('--dry_run', action='store_true',
                        help='Dry run; does not make any actual changes')
    parser.add_argument('--loglevel', default='WARNING',
                        choices=['DEBUG', 'INFO', 'WARNING',
                                 'ERROR', 'CRITICAL'],
                        help='Set log level')

    return parser.parse_args(argv)


def get_purchases(startPeriod=None, endPeriod=None, paging=True, limit=100):
    """Return list of purchases from TeleUP api vod endpoint"""
    api_endpoint = config['api_url']
    api_auth = (config['api_key'], '')
    url = '{}?startPeriod={}&endPeriod={}&limit={}'.format(
        api_endpoint,
        startPeriod,
        endPeriod,
        limit
    )

    sess = requests.Session()
    resp = sess.get(url, auth=api_auth)
    if not resp.ok:
        logger.warning(
            'Something went wrong with the TeleUP API: {}'.format(resp.text)
        )
        return False

    resp_json = resp.json()
    output = []
    output.extend(resp_json.get('data'))

    if paging:
        while 'next' in resp_json.get('paging', {}):
            resp = sess.get(
                urljoin(api_endpoint, resp_json['paging']['next']),
                auth=api_auth
            )
            resp_json = resp.json()
            output.extend(resp_json.get('data'))

    return output


def update_purchases(purchase_ids, transmitted_at, transmitted_filename):
    """Update billing reporting status of purchases in TeleUP api

    :param purchase_ids: list of record ID's from purchase data
    :type purchase_ids: list of ints
    :param transmitted_at: timestamp of XML file creation/transmission
    :type transmitted_at: int
    :param transmitted_filename: name of uploaded XML file
    :type transmitted_filename: str
    """
    api_endpoint = config['api_url']
    api_auth = (config['api_key'], '')

    query = {
        'ids': purchase_ids,
        'transmitted_at': transmitted_at,
        'transmitted_filename': transmitted_filename
    }

    resp = requests.patch(api_endpoint, json=query, auth=api_auth)
    if not resp.ok:
        logger.error('Talking to TeleUP API failed: {}'.format(
            resp.text
        ))
        return False

    if resp.json() is True:
        return True

    if resp.json().get('result') == 'failure':
        logger.error('Updating reporting status failed: {}'.format(
            resp.json().get('reason')
        ))
    else:
        logger.error('Unknown failure updatint reporting status')

    return False


def return_xml(data):
    """Format the input JSON as XML and return doc as string"""

    # These fields will be used from the JSON objects
    valid_records = (
        'asset_id', 'billing_id', 'customer_account_id', 'device', 'lease_id',
        'mac_address', 'postal_code', 'studio', 'system', 'title',
        'transaction_date', 'transaction_price'
    )

    root = ET.Element('BILLING_DATA')
    for rec in data:
        doc = ET.SubElement(root, 'PURCHASE')
        for k, v in rec.items():
            if k not in valid_records:
                continue
            if k == 'transaction_price':
                ET.SubElement(doc, k.upper()).text = '{:.2f}'.format(v)
            else:
                ET.SubElement(doc, k.upper()).text = '{}'.format(v)

    xmldoc = MD.parseString(ET.tostring(root)).toprettyxml(
        indent='  ',
        encoding='utf-8'
    )

    return xmldoc


def test_data(data):
    """Test validity of all records

    Returns 2 lists, one with all correct records, on with all records that
    don't comply.
    """
    valid_records = (
        'asset_id', 'billing_id', 'customer_account_id', 'device', 'lease_id',
        'mac_address', 'postal_code', 'studio', 'system', 'title',
        'transaction_date', 'transaction_price'
    )

    bad_records = []
    good_records = []

    for idx, rec in enumerate(data):
        missing = set(valid_records).difference(list(rec.keys()))
        empty = [x[0] for x in rec.items() if x[1] is None or x[1] == '']
        if missing or empty:
            bad_records.append({
                'rec': rec,
                'missing': list(missing),
                'empty': empty
            })
        else:
            good_records.append(rec)

    return good_records, bad_records


def upload_xml(xmldoc, filename):
    """Upload xmldoc string as filename to FTP server

    Upload integrity is checked by downloading and comparing hashes of before
    and after. If hash compare fails, file is deleted and function returns
    False.
    """
    ftp = FTP(config['ftp_server'], config['ftp_user'], config['ftp_pass'])

    outfile = StringIO(xmldoc)
    outfile_digest = hashlib.md5(outfile.read()).hexdigest()
    outfile.seek(0)
    ftp.storbinary('STOR ' + filename, outfile)

    infile = StringIO()
    ftp.retrbinary('RETR ' + filename, infile.write)
    infile.seek(0)
    infile_digest = hashlib.md5(infile.read()).hexdigest()

    if outfile_digest != infile_digest:
        logger.error('hash of uploaded file is incorrect, upload deleted.')
        ftp.delete(filename)
        return False

    return filename


if __name__ == '__main__':
    args = parse_args()
    config = read_config(args.config_file)

    loglevel = getattr(logging, args.loglevel)
    if args.dry_run:
        print('Not making any actual changes, setting loglevel to DEBUG')
        loglevel = getattr(logging, 'DEBUG')

    logging_config = dict(
        version=1,
        formatters={
            'brief': {'format': '%(asctime)s - %(levelname)s - %(message)s'}
        },
        handlers={
            'console': {'class': 'logging.StreamHandler',
                        'formatter': 'brief',
                        'level': loglevel},
            'file': {'class': 'logging.FileHandler',
                     'formatter': 'brief',
                     'level': logging.INFO,
                     'filename': os.path.join(sys.path[0], 'reporting.log')}
        },
        root={
            'handlers': ['console', 'file'],
            'level': logging.DEBUG
        },
    )

    logging.config.dictConfig(logging_config)
    logger = logging.getLogger()

    # If script is run non-interactive and without dry_run, remove console log
    if not os.isatty(sys.stdout.fileno()) and not args.dry_run:
        logger.removeHandler(
            next(hdl for hdl in logger.handlers if hdl.name == 'console')
        )

    # If run with dry_run flag, do not log to file
    if args.dry_run:
        logger.removeHandler(
            next(hdl for hdl in logger.handlers if hdl.name == 'file')
        )

    end_timestamp = timegm((date.today() - timedelta(1)).timetuple())

    data = get_purchases(endPeriod=end_timestamp)
    good_data, bad_data = test_data(data)
    if bad_data:
        logger.warning('found some bad records:')
        for bad_rec in bad_data:
            bad_output = ['id: {}'.format(bad_rec['rec']['id'])]
            if bad_rec['missing']:
                bad_output.append('missing: ' + ', '.join(bad_rec['missing']))
            if bad_rec['empty']:
                bad_output.append('empty: ' + ','.join(bad_rec['empty']))
            logger.warning(' '.join(bad_output))
    if not good_data:
        logger.info('No new records found')
        if config.get('healthcheck_url'):
            requests.get(config['healthcheck_url'])
        sys.exit()

    now_utc = datetime.utcnow().replace(microsecond=0)
    now_timestamp = timegm(now_utc.timetuple())

    xmldoc = return_xml(data)
    filename = '{0}_{1}_{2}.xml'.format(
        config['affiliate_name'],
        config['system'],
        now_utc.isoformat()
    )

    logger.debug('output XML:\n' + xmldoc)
    logger.debug('filename: ' + filename)

    # If this is not a dry_run, make actual changes
    if not args.dry_run:
        result = upload_xml(xmldoc, filename)
        if not result:
            sys.exit(1)
        else:
            logger.info('Succesfully sent {} records'.format(len(good_data)))

            result = update_purchases(
                [x['id'] for x in good_data],
                now_timestamp,
                filename
            )

            # If we ran succesfully _and_ we have healthcheck set, ping it
            if result and config.get('healthcheck_url'):
                requests.get(config['healthcheck_url'])
