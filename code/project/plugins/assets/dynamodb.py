"""Asset plugin that allows vulnture to retrieve assets (identified by vendor
and product name) from a DynamoDB table.
"""

import re
import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from . import product_patterns


def get_keywords(product_name):
    """Provided a product name or model number, generates human-friendly
    keywords that are more likely to return results from vulnerability feeds.

    This funtion relies on regex and other values defined in the
    product_patterns.py file. If none of the regex provided match product_name
    this function will return None and the raw product_name value will be used
    as the value for Asset.product and Asset.raw_name

    The value appended after the pipe is used solely to double check Cisco
    vulnerability announcements to prevent false positives.

    NOTE: This function should be "deterministic" - it should always yield the
    same keywords given a product name, so regex patterns must match ONLY ONE
    product.

    Parameters
    ----------
    product_name : str
        The product model or name to be normalized

    Returns
    -------
    str
        A string containing the normalized product name and keyword to verify
        results separated by the | (pipe) character
    """
    keywords = None
    for pair in product_patterns.pattern_to_keywords:
        # TODO: Consider doing product_name.lower() and only using lowercase
        match = re.findall(pair[product_patterns.PATTERN], product_name)
        # We only want this to return something if a pattern is matched
        if match:
            keywords = pair[product_patterns.KEYWORDS]
            if pair[product_patterns.APPEND_MATCH]:
                keywords += ' ' + match.pop()
            # Add verification string to search after keywords (with | delimiter)
            keywords += '|' + pair[product_patterns.VERIFICATION_STRING]
            # Only one pattern should match, so break out of for loop
            break
    return keywords


def retrieve_assets(table_name, vendor_key, product_key):
    """Retrieves vendor and product information from the database.

    Parameters
    ----------
    table_name : str
        The name of the DynamoDB table containing the vendor and product data
    vendor_key : str
        The name of the column header holding the vendor value
    product_key : str
        The name of the column header holding the product name/model value

    Returns
    -------
    set
        A set of vendor:raw_product_name:normalized_product_name|keyword pairs
        (colon-separated strings)
    """
    # List to keep track of DB items/assets
    asset_list = []
    # Comma-separate vendor and product column titles/keys
    projection_expression = vendor_key + ', ' + product_key

    # Get keywords from DynamoDB table/asset DB
    try:
        dynamodb_client = boto3.client('dynamodb')
        all_db_items = dynamodb_client.scan(
            TableName=table_name,
            ProjectionExpression=projection_expression,
            ConsistentRead=True)
        asset_list = all_db_items['Items']
    except ClientError as CE:
        if CE.response['Error']['Code'] == 'ExpiredTokenException':
            sys.exit('{}\nEnsure that your AWS session token is valid!'
                    .format(CE))
    except NoCredentialsError as NCE:
        sys.exit('{}\nDid you set AWS credentials in env vars or '
                '~/.aws/credentials?'.format(NCE))

    # Scan again while more results
    while 'LastEvaluatedKey' in all_db_items and all_db_items['LastEvaluatedKey']:
        all_db_items = dynamodb_client.scan(
            TableName=table_name,
            ProjectionExpression=projection_expression,
            ConsistentRead=True,
            ExclusiveStartKey=all_db_items['LastEvaluatedKey'])
        asset_list.extend(all_db_items['Items'])

    asset_set = set()
    # For each product/asset from DynamoDB table...
    for asset in asset_list:
        vendor_name = asset[vendor_key]['S']
        product_name = asset[product_key]['S']
        # Get keywords based on product name
        keywords = get_keywords(product_name)
        # If our regex matched a product from DynamoDB, store normalized name,
        # otherwise, just store raw name (as both product_name and keywords)
        if not keywords:
            keywords = product_name
        asset_set.add('{}:{}:{}'.format(vendor_name, product_name, keywords))
    return asset_set
