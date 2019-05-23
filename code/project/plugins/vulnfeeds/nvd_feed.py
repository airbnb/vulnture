"""Vulnerability feed plugin that allows vulnture to search the NVD (National
Vulnerability Database) for vulnerabilities associated with particular assets.
"""

from datetime import datetime, timedelta
import gzip
from io import BytesIO
import json
import logging

try:
    import requests
except ImportError:
    from botocore.vendored import requests

from ...modules.models import Vulnerability

# Initialize logger
LOGGER = logging.getLogger()
LOGGER.debug('nvd_feed.py - {}'.format(__name__))

### Global variables (for this module)
# CPE part mapping
part_map = {
    'a': 'application',
    'o': 'operating system',
    'h': 'hardware'
}

# CVSS impact mapping
impact_map = {
    'AV': {'description': 'attack vector',
           'ratings': {'N': 'network',
                       'A': 'adjacent network',
                       'L': 'local',
                       'P': 'physical'}},
    'AC': {'description': 'attack complexity',
           'ratings': {'L': 'low',
                       'M': 'medium',
                       'H': 'high'}},
    'PR': {'description': 'privilege required',
           'ratings': {'N': 'none',
                       'L': 'low',
                       'H': 'high'}},
    'UI': {'description': 'user interaction',
           'ratings': {'N': 'none',
                       'R': 'required'}},
    'S': {'description': 'scope',
          'ratings': {'U': 'unchanged',
                      'C': 'changed'}},
    'C': {'description': 'confidentiality impact',
          'ratings': {'N': 'none',
                      'L': 'low',
                      'H': 'high',
                      'P': 'partial',
                      'C': 'complete'}},
    'I': {'description': 'integrity impact',
          'ratings': {'N': 'none',
                      'L': 'low',
                      'H': 'high',
                      'P': 'partial',
                      'C': 'complete'}},
    'A': {'description': 'availability impact',
          'ratings': {'N': 'none',
                      'L': 'low',
                      'H': 'high',
                      'P': 'partial',
                      'C': 'complete'}},
    'Au': {'description': 'authentication',
           'ratings': {'M': 'multiple',
                       'S': 'single',
                       'N': 'none'}},
}

# CPE index numbers
PART_INDEX = 2
VENDOR_INDEX = 3
PRODUCT_INDEX = 4
VERSION_INDEX = 5
UPDATE_INDEX = 6
EDITION_INDEX = 7
SW_EDITION_INDEX = 8
TARGET_SW_INDEX = 9
TARGET_HW_INDEX = 10
LANGUAGE_INDEX = 11
OTHER_INDEX = 12

# CPE/CVSS attribute lengths
CPE_22_LENGTH = 5
CPE_23_LENGTH = 13
CVSSV2_LENGTH = 6
CVSSV3_LENGTH = 9

# dict to store created vulnerabilities to prevent re-creating vulns
created_vulnerabilities = {}


def search(assets, detected_vulnerabilities):
    """Searches the NVD JSON data feed for vulnerabilities related to
    discovered assets.

    Parameters
    ----------
    assets : set(Asset)
        A set of Asset objects representing discovered assets
    detected_vulnerabilities: set(Vulnerability)
        A set of Vulnerability objects representing discovered vulnerabilities
    """
    # Use global variable created_vulnerabilities to pair CVEs to Vulnerability
    global created_vulnerabilities
    # dict to store normalized product names (with _) paired to set of Assets
    product_asset_mapping = {}
    for asset in assets:
        underscored_product_name = asset.product.lower().replace(' ', '_')
        if underscored_product_name in product_asset_mapping:
            product_asset_mapping[underscored_product_name].add(asset)
        else:
            # First time seeing this product name, sole value is Asset
            product_asset_mapping[underscored_product_name] = {asset}
    LOGGER.debug('product_asset_mapping = {}'.format(product_asset_mapping))
    # Service URL to search
    SERVICE_URL = 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz'
    # Gets recently modified entries (last 8 days)
    r = requests.get(SERVICE_URL)
    bytes_file_object = BytesIO(r.content)

    with gzip.open(bytes_file_object) as f:
        text = f.read()
    json_text = json.loads(text)
    # Attempt to free up memory (not guaranteed)
    del text

    # Loop through list of CVE items
    for cve_item in json_text['CVE_Items']:
        # Clear variables each iteration to avoid printing wrong CVE value on error
        description = ''
        cvss_info = None
        cvss_base_score = 0
        cvss_vector_string = ''
        references_set = set()

        # Get published/updated date
        published_date = cve_item['publishedDate']
        updated_date = cve_item['lastModifiedDate']
        # Get today's date (UTC)
        today = datetime.utcnow()
        # Get yesterday's date (UTC)
        yesterday = today - timedelta(days=1)
        # Get yesterday's date in string format
        yesterday_string = yesterday.strftime('%Y-%m-%d')
        if updated_date.startswith(yesterday_string):
            # Get CVE information
            cve_id = cve_item['cve']['CVE_data_meta']['ID']
            LOGGER.debug('Parsing CVE {} from NVD...'.format(cve_id))
            # Get CVE description
            cve_description_list = cve_item['cve']['description']['description_data']
            for description in cve_description_list:
                # TODO: Should consider other languages
                if description['lang'] == 'en':
                    description = description['value']
            # Get CVSS impact information
            cvss_impact = cve_item['impact']
            # Get CVSS base score and vector string
            if 'baseMetricV3' in cvss_impact:
                cvss_info = cvss_impact['baseMetricV3']['cvssV3']
                cvss_base_score = cvss_info['baseScore']
                cvss_vector_string = cvss_info['vectorString']
            elif 'baseMetricV2' in cvss_impact:
                cvss_info = cvss_impact['baseMetricV2']['cvssV2']
                cvss_base_score = cvss_info['baseScore']
                cvss_vector_string = cvss_info['vectorString']
            # Parse CVSS details if discovered
            if cvss_info:
                # Parse CVSS vector string
                cvss_details = parse_cvss(cvss_vector_string)
            # Get reference URLs
            cve_references = cve_item['cve']['references']['reference_data']
            if cve_references:
                for reference in cve_references:
                    # Add reference URL to set
                    references_set.add(reference['url'])
            # Get vendor/product/version/etc. information
            cve_nodes = cve_item['configurations']['nodes']
            # Create list to accumulate all CPEs
            cpe_list = []
            for cve_node in cve_nodes:
                interim_cpe_list = cve_node.get('cpe_match')
                # CPE node has "cpe" key
                if interim_cpe_list:
                    cpe_list.extend(interim_cpe_list)
                # No "cpe" key in CPE node, check for children CPE nodes
                else:
                    # Should be list of CPE dictionary nodes (which also contain lists)
                    cpe_children = cve_node.get('children')
                    if cpe_children:
                        for child in cpe_children:
                            # Add CPE dictionary objects to list to make one big list
                            cpe_list.extend(child.get('cpe_match'))
            # Iterate over CPEs accumulated in list and process them
            for cpe in cpe_list:
                cpe_details = parse_cpe(cpe)
                if cpe_details:
                    # Get product name
                    vendor_name = cpe_details['vendor']
                    LOGGER.debug('Parsed vendor name is {}'.format(vendor_name))
                    product_name = cpe_details['product'].split('-')[0]
                    LOGGER.debug('Parsed product name is {}'.format(product_name))
                    # Only get details if it's a relevant product
                    if product_name in product_asset_mapping:
                        LOGGER.info('Found relevant vulnerability for {}'.format(product_name))
                        # Already created Vulnerability object for this vuln
                        if cve_id in created_vulnerabilities:
                            # Should be 1:1, no need to iterate with for loop
                            # Add all Assets associated with this name to this Vulnerability
                            created_vulnerabilities[cve_id].impacted.update(
                                product_asset_mapping[product_name])
                        # Haven't created a Vulnerability for this vuln yet
                        else:
                            new_vulnerability = Vulnerability()
                            new_vulnerability.title = 'None (from NVD)'
                            new_vulnerability.summary = description
                            new_vulnerability.severity = determine_severity_rating(
                                cvss_base_score)
                            new_vulnerability.cve = cve_id
                            new_vulnerability.reference_urls.update(references_set)
                            # Add all Assets associated with this name to this Vulnerability
                            new_vulnerability.impacted.update(
                                product_asset_mapping[product_name])
                            # Add Vulnerability to created_vulnerabilities dict
                            created_vulnerabilities[cve_id] = new_vulnerability
                            detected_vulnerabilities.add(new_vulnerability)
                            LOGGER.debug('New Vulnerability created:\n{}'.format(new_vulnerability))
                        # Add this Vulnerability to each Asset associated with this name
                        for asset in product_asset_mapping[product_name]:
                            asset.vulnerabilities.add(
                                created_vulnerabilities[cve_id])
                else:
                    LOGGER.warning('Failed to find valid CPE information for {}'.format(cve_id))


def parse_cpe(cpe):
    # Prefer version 2.3
    if 'cpe23Uri' in cpe:
        cpe_info = cpe['cpe23Uri']
        cpe_version = 2.3
    else:
        cpe_info = cpe.get('cpe22Uri')
        cpe_version = 2.2
    if cpe_info:
        cpe_parsed = cpe_info.split(':')
        if cpe_version == 2.2 and len(cpe_parsed) == CPE_22_LENGTH:
            part = cpe_parsed[PART_INDEX-1]
            vendor = cpe_parsed[VENDOR_INDEX-1]
            product = cpe_parsed[PRODUCT_INDEX-1]
            version = cpe_parsed[VERSION_INDEX-1]
            cpe_details = {
                'type': part_map[part],
                'vendor': vendor,
                'product': product,
                'version': version,
            }
        elif cpe_version == 2.3 and len(cpe_parsed) == CPE_23_LENGTH:
            part = cpe_parsed[PART_INDEX]
            vendor = cpe_parsed[VENDOR_INDEX]
            product = cpe_parsed[PRODUCT_INDEX]
            version = cpe_parsed[VERSION_INDEX]
            update = cpe_parsed[UPDATE_INDEX]
            edition = cpe_parsed[EDITION_INDEX]
            sw_edition = cpe_parsed[SW_EDITION_INDEX]
            target_sw = cpe_parsed[TARGET_SW_INDEX]
            target_hw = cpe_parsed[TARGET_HW_INDEX]
            language = cpe_parsed[LANGUAGE_INDEX]
            other = cpe_parsed[OTHER_INDEX]
            cpe_details = {
                'type': part_map[part],
                'vendor': vendor,
                'product': product,
                'version': version,
                'update': update,
                'edition': edition,
                'sw_edition': sw_edition,
                'target_sw': target_sw,
                'target_hw': target_hw,
                'language': language,
                'other': other
            }
        else:
            # CPE length didn't match expected value for version
            return None
        # Return tuple formed after parsing CPE information
        return cpe_details
    # Didn't find valid CPE info
    else:
        return None


def parse_cvss(cvss_vector_string):
    cvss_vector_list = cvss_vector_string.split('/')
    # Check version of CVSS being used
    if len(cvss_vector_list) == CVSSV2_LENGTH:
        # Strip out parantheses
        cvss_vector_list[0] = cvss_vector_list[0].replace('(', '')
        cvss_vector_list[-1] = cvss_vector_list[-1].replace(')', '')
    elif len(cvss_vector_list) == CVSSV3_LENGTH:
        # Remove CVSS version
        if not cvss_vector_list.pop(0) == 'CVSS:3.0':
            print('Unusual CVSSv3 vector string syntax found')
    else:
        print('CVSS vector string is not expected length (V2 or V3)')
    # Iterate through attributes of CVSS vector string
    cvss_details = {}
    for item in cvss_vector_list:
        metric_score_list = item.split(':')
        metric = metric_score_list[0]
        value = metric_score_list[1]
        cvss_details[impact_map[metric]['description']] = impact_map[metric]['ratings'][value]
    return cvss_details


def determine_severity_rating(cvss_score):
    if type(cvss_score) is str:
        cvss_score = float(cvss_score)
    if cvss_score < 4:
        rating = 'Low'
    elif cvss_score < 7:
        rating = 'Medium'
    elif cvss_score < 9:
        rating = 'High'
    else:
        rating = 'Critical'
    return rating
