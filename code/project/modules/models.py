"""The object-oriented "models" (classes) used by vulnture."""

import re
import sys
import uuid

from .send_email import send as send_email


class VulnerabilitySource:
    """A source of vulnerabilities (e.g. vulnerability feed)"""

    def __init__(self, applicable_vendors, url):
        self.applicable_vendors = applicable_vendors
        self.url = url


class Asset:
    """An asset"""

    def __init__(self, vendor, product, raw_name, keywords=None):
        self.uuid = uuid.uuid4()
        self.vendor = vendor
        # Normalized product name (see main.get_assets)
        self.product = product
        # Currently keyword is exclusively used to check for false positives
        # in Cisco vuln feeds
        self.keywords = keywords
        # The raw product name found in the configured asset backend
        self.raw_name = raw_name
        self.version = None
        self.quantity = None
        # Set of Vulnerabilities affecting this asset
        self.vulnerabilities = set()
        self.vulnerabilities_unconfirmed = set()

    def __str__(self):
        # Human-readable string summarizing this asset
        relevant_vulns = {
            vuln.cve for vuln in self.vulnerabilities
            } if self.vulnerabilities else 'None'
        relevant_vulns_unconfirmed = {
            vuln.cve for vuln in self.vulnerabilities_unconfirmed
            } if self.vulnerabilities_unconfirmed else 'None'
        return('UUID: {}\n'
            'Vendor: {}\n'
            'Product: {}\n'
            'Keywords: {}\n'
            'Raw Name: {}\n'
            'Version: {}\n'
            'Quantity: {}\n'
            'Vulnerabilities: {}\n'
            'Vulnerabilities Unconfirmed: {}\n\n'.format(
                self.uuid,
                self.vendor,
                self.product,
                self.keywords,
                self.raw_name,
                self.version,
                self.quantity,
                relevant_vulns,
                relevant_vulns_unconfirmed))


class Notification:
    """A notification "abstract" class"""

    def __init__(self, recipients, selectors):
        self.message = ''
        # e.g. sev > low, vendor == Acme, date < 1 week, etc. (under what
        # condition(s) to send this alert) - should be list of comma-separated
        # selectors
        if selectors:
            self.selectors = set()
            pattern = r'(\w+)(\W+)(\w+)'
            for selector in selectors:
                matches = re.match(pattern, selector)
                if len(matches.groups()) == 3:
                    selector_key = matches.group(1)
                    comparator = matches.group(2)
                    selector_value = matches.group(3)
                    selector_tuple = (selector_key, comparator, selector_value)
                    self.selectors.add(selector_tuple)
                else:
                    sys.exit('Detected improperly formatted selector ({}) in '
                            'conf.ini!'.format(selector))
        else:
            self.selectors = None
        # should be list of recipients, e.g. email addresses
        self.recipients = recipients
        # Store list of Vulnerabilities to notify on
        self.vuln_list = []

    # TODO: Complete implementation (not functional)
    # Goal: Call this method, passing in set of all detected vulnerabilities,
    # call send method to generate message of all vulns and send to recipients
    def add_applicable(self, vulnerability):
        if self.selectors is None:
            self.vuln_list.append(vulnerability)
        else:
            for selector in self.selectors:
                vuln_attr = getattr(vulnerability, selector[0])
                comparator = selector[1]
                value = selector[2]
                #eval(vuln_attr + ' ' + comparator + ' ' + value)

    def send(self):
        # Raise exception if subclass hasn't implemented send method
        raise NotImplementedError("Please implement this method!")


class EmailNotification(Notification):
    """An email notification"""

    def __init__(self, smtp_server, sender, **kwargs):
        self.smtp_server = smtp_server
        self.sender = sender
        self.notification_type = 'email'
        # Pass kwargs (recipients, selectors) to Notification base class init
        super().__init__(**kwargs)

    def send(self):
        # Once add_applicable method is implemented this check can be removed
        if not self.message:
            # Add vulnerabilities to message to send
            self.message = ''
            for vuln in self.vuln_list:
                self.message += '{}\n\n'.format(str(vuln))
        # Only attempt to send if there's a message to send
        if self.message:
            for recipient in self.recipients:
                send_email(
                    self.smtp_server,
                    self.sender,
                    self.message,
                    recipient
                )


class Vulnerability:
    """A vulnerability"""

    def __init__(self):
        # Not necessary if all vulnerabilities have a CVE
        self.uuid = uuid.uuid4()
        self.title = None
        self.summary = None
        self.severity = None
        self.cve = None
        # Set of reference URLs
        self.reference_urls = set()
        # Set of impacted Assets
        self.impacted = set()
        self.impacted_unconfirmed = set()
        self.date = None
        # Source of vulnerability alert (e.g. NVD, Cisco, etc.)
        self.alert_source = None
        self.product = None
        self.vendor = None
        self.version = None

    def __str__(self):
        # Human-readable string summarizing this vulnerability
        impacted_assets = ', '.join({
            asset.product for asset in self.impacted
            }) if self.impacted else 'None'
        impacted_assets_unconfirmed = ', '.join({
            asset.product for asset in self.impacted_unconfirmed
            }) if self.impacted_unconfirmed else 'None'
        return('Title: {}\n'
            'Summary: {}...\n'
            'Severity: {}\n'
            'CVE: {}\n'
            'URL(s): {}\n'
            'Impacted Assets: {}\n'
            'Potentially Impacted Assets: {}\n\n'.format(
                self.title,
                self.summary,
                self.severity,
                self.cve,
                ', '.join(self.reference_urls),
                impacted_assets,
                impacted_assets_unconfirmed))
