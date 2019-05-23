"""The main entrypoint to vulnture."""

import argparse
import configparser
import json
import logging
from pathlib import Path
import sys
from time import gmtime

from project.modules.models import Asset, EmailNotification, VulnerabilitySource
from project.plugins.assets import dynamodb
from project.plugins.vulnfeeds import cisco_advisories, nvd_feed

# Parse args
parser = argparse.ArgumentParser(description='Kick off the various'
' components of the vulnerability notification tool.')
parser.add_argument('--table-name', help='DynamoDB table name')
parser.add_argument('--vendor-key', help='DynamoDB vendor column name (key)')
parser.add_argument('--product-key', help='DynamoDB product column name (key)')
parser.add_argument('--test', action='store_true',
    help='Test with input data rather than asset DB')
parser.add_argument('-v', '--verbose', action='count',
    help='Set the verbosity level (More v\'s = higher verbosity)')
args = parser.parse_args()


def get_notifications(config):
    """Checks conf.ini for enabled notifications.

    Parameters
    ----------
    config : configparser.ConfigParser
        An instantiated ConfigParser referring to conf/conf.ini

    Returns
    -------
    set
        A set of Notification subclasses representing enabled notifications
    """
    logger = logging.getLogger()
    # Set to store all configured Notifications - in the future can use DB and
    # web GUI instead - for now, updating notification settings requires
    # modifying conf.ini before each runtime
    configured_notifications = set()
    try:
        notifications = config['Notifications']
    except KeyError as KE:
        sys.exit('Failed to parse config section {}!'.format(KE))
    # Check if email notifications enabled
    if notifications.getboolean('email'):
        try:
            email_recipients = json.loads(notifications['EmailRecipients'])
        except KeyError as KE:
            sys.exit('Email notifications enabled, but no recipients set!')
        # ignores numbers (e.g. 1, 2) in keys and just get values we need
        for value in email_recipients.values():
            # list of email recipients
            recipients = value['recipients'].split(',')
            if 'selectors' in value:
                # list of selectors
                selectors = value['selectors'].split(',')
            else:
                # None implies send everything (no limitations)
                selectors = None
            smtp_server = notifications['SMTPServer']
            sender = notifications['SMTPSender']
            configured_notifications.add(
                EmailNotification(
                    smtp_server=smtp_server,
                    sender=sender,
                    recipients=recipients,
                    selectors=selectors
                )
            )
    return configured_notifications


def get_assets(config):
    """Checks conf.ini for enabled asset backends and ingests discovered
    assets.

    Parameters
    ----------
    config : configparser.ConfigParser
        An instantiated ConfigParser referring to conf/conf.ini

    Returns
    -------
    set
        A set of Asset objects representing discovered assets
    """
    logger = logging.getLogger()
    # Set to store all discovered Assets - in the future can use DB and web
    # GUI instead
    discovered_assets = set()
    # Check for configured backend(s) - only one initially, multiple in
    # future release
    try:
        asset_backends = config['Asset Backends']
    except KeyError as KE:
        sys.exit('Failed to parse config section {}!'.format(KE))
    if asset_backends.getboolean('dynamodb'):
        # Get all assets from DynamoDB table and create Asset objects
        logger.debug('Searching DynamoDB for assets...')
        asset_set = dynamodb.retrieve_assets(
            args.table_name, args.vendor_key, args.product_key)
        for asset in asset_set:
            # Get vendor and product names by splitting on colon
            asset_values = asset.split(':')
            vendor_name = asset_values[0]
            raw_product_name = asset_values[1]
            product = asset_values[2]
            # NOTE: A bug will arise if any product names contain a pipe (|)!
            # Get product name and keyword by splitting on pipe
            product_keyword_values = product.split('|')
            normalized_product_name = product_keyword_values[0]
            # Check in case dynamodb.get_keywords() returned None
            if len(product_keyword_values) > 1:
                # keyword is used exclusively to search for false positives in
                # Cisco vuln feed
                # TODO: Find a clean way to seperate this Cisco vuln specific
                # field from Asset creation
                keyword = product_keyword_values[1]
                if keyword == 'keyword':
                    keyword = normalized_product_name
            else:
                # Use product name as keyword if get_keywords() yields None
                keyword = normalized_product_name
            discovered_assets.add(
                Asset(
                    vendor=vendor_name,
                    product=normalized_product_name,
                    raw_name=raw_product_name,
                    keywords=keyword)
            )
    return discovered_assets


def get_vulnerability_sources(config):
    """Checks conf.ini for sources of vulnerability alerts.

    Parameters
    ----------
    config : configparser.ConfigParser
        An instantiated ConfigParser referring to conf/conf.ini

    Returns
    -------
    set
        A set of VulnerabilitySource objects representing configured
        vulnerability alert sources
    """
    logger = logging.getLogger()
    configured_vulnerability_sources = set()
    try:
        vulnerability_sources = config['Vulnerability Data Sources']
    except KeyError as KE:
        sys.exit('Failed to parse config section {}!'.format(KE))
    # Check if Cisco security advisories and alerts service enabled
    if vulnerability_sources.getboolean('Cisco'):
        configured_vulnerability_sources.add(
            VulnerabilitySource(
                applicable_vendors='Cisco',
                url='https://tools.cisco.com/security/center/publicationService.x'
            )
        )
    # Check if NVD feed enabled
    if vulnerability_sources.getboolean('NVD'):
        configured_vulnerability_sources.add(
            VulnerabilitySource(
                applicable_vendors='all',
                url='https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz'
            )
        )
    return configured_vulnerability_sources


def get_vulnerabilities(config, assets):
    """Searches configured vulnerability data sources for vulnerabilities
    related to discovered assets.

    Parameters
    ----------
    config : configparser.ConfigParser
        An instantiated ConfigParser referring to conf/conf.ini
    assets : set(Asset)
        A set of Asset objects representing discovered assets

    Returns
    -------
    set
        A set of Vulnerability objects representing asset vulnerabilities
    """
    logger = logging.getLogger()
    detected_vulnerabilities = set()
    # TODO: this will eventually be removed and only kept in 
    # get_vulnerability_sources once moving to fully object oriented
    try:
        vulnerability_sources = config['Vulnerability Data Sources']
    except KeyError as KE:
        sys.exit('Failed to parse config section {}!'.format(KE))
    # Check if Cisco security advisories and alerts service enabled
    if vulnerability_sources.getboolean('Cisco'):
        # Create dict to act as cache of normalized product names searched
        # paired to Vulnerabilities (set) returned in search
        search_cache = {}
        # Check only Cisco products
        logger.debug('Searching Cisco security advisories and alerts...')
        for asset in assets:
            if asset.vendor.lower() == 'cisco':
                # Cisco vuln feed should be searched once per product
                cisco_advisories.search(
                    asset, search_cache, detected_vulnerabilities
                )
    # Check if NVD feed enabled
    if vulnerability_sources.getboolean('NVD'):
        # Check products by all vendors
        # NVD feed should be downloaded once, then queried once per product
        logger.debug('Searching recently modified NVD vulnerabilities...')
        nvd_feed.search(assets, detected_vulnerabilities)
    return detected_vulnerabilities


# Parameters event and context are sent by the AWS Lambda service
def handler(event, context):
    # Remove AWS Lambda root logger handler
    logger = logging.getLogger()
    if logger.handlers:
        for handler in logger.handlers:
            logger.removeHandler(handler)

    # Get verbosity level from Lambda function event input
    if 'verbosity' in event:
        args.verbose = int(event['verbosity'])
    # Set log verbosity level
    if args.verbose:
        log_level = 50 - min((args.verbose-1) * 10, 50)
        # If log_level is set to NOTSET (0) here, it will delegate to the root
        # logger level, which is WARNING (30) by default. This is not what we
        # want if a user has set log_level to 5+ (highest level), so set to 1
        # instead of 0 to avoid this. Alternatively can set root logger to 0
        # via basicConfig above, but logging everything when a user doesn't
        # request any verbosity is also not desirable.
        log_level = 1 if log_level == 0 else log_level
    else:
        # Log nothing
        log_level = 60
    # Enable logging, use UTC rather than local date/time
    logging.Formatter.converter = gmtime
    logging.basicConfig(
        datefmt='%Y-%m-%dT%H:%M:%S',
        format='%(name)s | %(asctime)s.%(msecs)03dZ | %(levelname)s: %(message)s')
    logger.setLevel(log_level)
    logger.debug('main.py - {}'.format(__name__))

    # Parse config file
    logger.info('Parsing conf.ini...')
    config = configparser.ConfigParser()
    if not config.read('project/conf/conf.ini'):
        sys.exit('Failed to read conf.ini! Make sure that it exists and is '
                'in the right location.')

    # Test, only call get_vulnerabilities() with test data
    TESTING = False
    if args.test:
        TESTING = True
        logger.info('Entering test mode...')
        vendor = input('Enter a vendor name: ')
        product = input('Enter a product name: ')
        keywords = input('Enter keyword (optional): ')
        asset = Asset(vendor, product, product, keywords)
        discovered_assets = {asset}
        get_vulnerabilities(config, discovered_assets)
        print(asset)
        for vuln in asset.vulnerabilities:
            print(vuln)
        for vuln in asset.vulnerabilities_unconfirmed:
            print(vuln)
        sys.exit('Finished testing')

    ### NOTIFICATIONS
    # Set of Notifications configured via conf/conf.ini
    logger.info('Getting configured notifications...')
    configured_notifications = get_notifications(config)

    ### ASSETS
    # Set of Assets discovered via configured Asset Backend(s)
    if not TESTING:
        try:
            # Check if Lambda event data is passed in
            if event and event['table_name'] and event['vendor_key'] and event['product_key']:
                args.table_name = event['table_name']
                args.vendor_key = event['vendor_key']
                args.product_key = event['product_key']
        except KeyError as KE:
            sys.exit('Expected event parameters not found - {}!'.format(KE))
        if not (args.table_name and args.vendor_key and args.product_key):
            sys.exit('You must pass in table name, vendor key, and product '
                    'key if not in test mode!')
        logger.info('Retrieving assets...')
        discovered_assets = get_assets(config)

    ### VULNERABILITY DATA SOURCES
    # Set of enabled VulnerabilitySources
    # TODO: consider this approach in future iteration
    #configured_vulnerability_sources = get_vulnerability_sources(config)

    ### VULNERABILITIES
    # TODO: consider this approach in future iteration
    #vulnerabilities = get_vulnerabilities(
    #    configured_vulnerability_sources,
    #    discovered_assets)
    logger.info('Getting vulnerabilities...')
    discovered_vulnerabilities = get_vulnerabilities(config, discovered_assets)

    # Relevant vulnerabilities found, send notification(s)
    if discovered_vulnerabilities:
        logger.info('Preparing notifications to send...')
        for configured_notification in configured_notifications:
            for vuln in discovered_vulnerabilities:
                configured_notification.message += str(vuln)
            configured_notification.send()
    # No relevant vulnerabilities discovered, do nothing
    else:
        logger.info('No relevant vulnerabilities discovered, exiting.')


def main():
    handler(dict(), None)


if __name__ == '__main__':
    try:
        # Parameters event and context are sent by the AWS Lambda service
        main()
    except KeyboardInterrupt:
        print()
