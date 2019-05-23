"""Vulnerability feed plugin that allows vulnture to search Cisco Security
Advisories and Alerts for vulnerabilities associated with particular assets
and then attempt to validate whether or not they're genuinely vulnerable.
"""

from datetime import datetime, timedelta
import logging
import re
from time import sleep
from urllib.parse import quote_plus

try:
    import requests
except ImportError:
    from botocore.vendored import requests

from ...modules.models import Vulnerability
from ...modules.vulnerable_product_checker import VulnerableProductChecker

# Initialize logger
LOGGER = logging.getLogger()
LOGGER.debug('cisco_advisories.py - {}'.format(__name__))

### Global variables (for this module)
# Get today's date (UTC)
today = datetime.utcnow()
# Get yesterday's date (UTC)
yesterday = today - timedelta(days=1)
# Get yesterday's date in string format
# We search only yesterday for vulnerabilities so we don't get duplicates
yesterday_string = quote_plus(yesterday.strftime('%Y/%m/%d'))
# Query parameter skeleton
query_parameters = {
    # Cisco Bug ID
    'ciscoBugs': '',
    # Keyword match logic (e.g. exact, or, and)
    'criteria': 'and',
    # CVE (can be exact or partial, e.g. CVE-2018-0369 or 0369)
    'cves': '',
    # Minimum base CVSS score
    'cvssBaseScoreMin': '',
    # Non-functional? No obvious GUI counterpart
    'cwe': '',
    # Format: 2018%2F07%2F01 (YYYY/MM/DD, URL encoded)
    'firstPublishedEndDate': '',
    # NOTE: Requires firstPublishedEndDate, format: 2016%2F08%2F01
    'firstPublishedStartDate': '',
    # Publication ID
    'identifiers': '',
    # Keyword search
    'keyword': '',
    # Format: 2018%2F07%2F01 (YYYY/MM/DD, URL encoded)
    'lastPublishedEndDate': yesterday_string,
    # NOTE: Requires lastPublishedEndDate
    'lastPublishedStartDate': yesterday_string,
    'last_published_date': '',
    # 20 / 50 / 100
    'limit': '100',
    # 0 (default)
    'offset': '0',
    # 1,6,9,10 (default)
    'publicationTypeIDs': '1,6,9,10',
    # Number or comma-separated numbers representing specific product or vendor
    'resourceIDs': '',
    # String or comma-separated strings (e.g. high or critical,high,low)
    'securityImpactRatings': '',
    # %2Blast_published (+ URL encoded) or -last_published (default, blank)
    'sort': '',
    # Title of vulnerability, URL encoded (%20 for space, not +)
    'title': ''
}
# dict to store discovered Cisco vulnerabilities to prevent re-creating vulns
created_vulnerabilities = {}


def search(asset, search_cache, detected_vulnerabilities):
    """Searches Cisco Security Advisories and Alerts for vulnerabilities
    related to passed assets.

    Parameters
    ----------
    asset : Asset
        An Asset object representing a Cisco asset
    search_cache : dict
        A dict acting as a cache of product names to vulnerabilities
    detected_vulnerabilities: set(Vulnerability)
        A set of Vulnerability objects representing discovered vulnerabilities
    """
    product_name = asset.product
    LOGGER.debug('Product name is {}'.format(product_name))
    # Already searched this normalized product name before
    if product_name in search_cache:
        # Add Vulnerabilities associated with this search to this Asset
        asset.vulnerabilities.update(search_cache[product_name])
        # Add this Asset to impacted for all related Vulnerabilities
        for vuln in search_cache[product_name]:
            vuln.impacted.add(asset)
    # First time searching for this normalized product name
    else:
        # Create empty set for this product in search_cache
        search_cache[product_name] = set()
        global query_parameters
        # Set keyword to search to normalized product name
        encoded_product_name = quote_plus(product_name)
        query_parameters['keyword'] = encoded_product_name
        LOGGER.debug('Set keyword search to {}'.format(encoded_product_name))
        # Requests automatically URL encodes parameters which breaks certain
        # searches so send query parameters as string rather than dictionary
        payload_string = '&'.join('{}={}'.format(k, v) for k, v in query_parameters.items())
        # Service URL to search
        SERVICE_URL = 'https://tools.cisco.com/security/center/publicationService.x'
        # Make HTTP GET request
        search_response = requests.get(
            SERVICE_URL,
            params=payload_string,
        )
        # If received ok, non-empty response...
        if search_response.ok and search_response.text:
            for vuln in search_response.json():
                vuln_id = vuln['identifier']
                LOGGER.debug('Found vuln {} for asset {}'.format(vuln_id, asset.product))
                # First validate that it's actually vulnerable
                vuln_checker = VulnerableProductChecker(asset.keywords, vuln['url'])
                LOGGER.debug('Vuln {} vulnerable status: {}'.format(vuln_id, vuln_checker.vulnerable))
                global created_vulnerabilities
                # TODO: Once moving to fully object oriented and have a
                # VulnerabilitySource object for Cisco vulnerability service
                # can use a class variable (similar to static variable in Java)
                # and take advantage of mutable characteristic of list or dict
                # in order to track Cisco vulnerabilities already found in the
                # service to then associate with new Asset
                # We've already seen this vuln (affects multiple keywords), update product set
                if vuln_id in created_vulnerabilities:
                    old_vulnerability = created_vulnerabilities[vuln_id]
                    # Maybe vulnerable
                    if vuln_checker.vulnerable is None:
                        # Add Asset to Vulnerability and vice versa
                        old_vulnerability.impacted_unconfirmed.add(asset)
                        asset.vulnerabilities_unconfirmed.add(old_vulnerability)
                    # Confirmed vulnerable
                    elif vuln_checker.vulnerable:
                        # Add Asset to Vulnerability and vice versa
                        old_vulnerability.impacted.add(asset)
                        asset.vulnerabilities.add(old_vulnerability)
                # Create new Vulnerability, not previously created
                else:
                    # Only create Vulnerability if vulnerable
                    if vuln_checker.vulnerable or vuln_checker.vulnerable is None:
                        new_vulnerability = Vulnerability()
                        new_vulnerability.title = vuln['title']
                        new_vulnerability.summary = vuln['summary']
                        new_vulnerability.severity = vuln['severity']
                        new_vulnerability.cve = vuln['cve']
                        new_vulnerability.reference_urls.add(vuln['url'])
                        detected_vulnerabilities.add(new_vulnerability)
                        # Maybe vulnerable
                        if vuln_checker.vulnerable is None:
                            # Add Asset to Vulnerability and vice versa
                            new_vulnerability.impacted_unconfirmed.add(asset)
                            asset.vulnerabilities_unconfirmed.add(new_vulnerability)
                        # Confirmed vulnerable
                        elif vuln_checker.vulnerable:
                            # Add Asset to Vulnerability and vice versa
                            new_vulnerability.impacted.add(asset)
                            asset.vulnerabilities.add(new_vulnerability)
                        # Add Vulnerability to dict to prevent duplicating
                        created_vulnerabilities[vuln_id] = new_vulnerability
                        # Add Vulnerability to search_cache to avoid duplicate search
                        search_cache[product_name].add(new_vulnerability)

                # Print all details from Cisco vulnerability
                for key in vuln:
                    LOGGER.debug(key + ': ' + str(vuln[key]))
        # Search unsuccessful, check formatting of queries (e.g. URL quoting)
        else:
            print(
                'Received HTTP {} while searching Cisco vulnerability '
                'publication service'.format(search_response.status_code)
            )

        # Short delay to prevent too many rapid requests
        sleep(1)
