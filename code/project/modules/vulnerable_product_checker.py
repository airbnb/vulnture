"""Helper module that parses through a Cisco vulnerability announcement web
page in an attempt to validate whether or not a particular Cisco product is
vulnerable.
"""

from html.parser import HTMLParser
import logging

from botocore.vendored import requests

# Initialize logger
LOGGER = logging.getLogger()
LOGGER.debug('vulnerable_product_checker.py - {}'.format(__name__))

### Global variables
# Name of HTML attribute
NAME = 0
# Value of HTML attribute
VALUE = 1
# Line number from HTMLParser getpos function
LINE_NUM = 0


class VulnerableProductChecker(HTMLParser):
    def __init__(self, keywords, vulnerability_url):
        super().__init__()
        self.keywords = keywords
        self.vulnerability_url = vulnerability_url
        self.vulnerable = None
        # Line of HTML code marked by div with id="vulnerableproducts"
        self.vuln_start_line = 0
        # Line of HTML code that appears to close the div
        self.vuln_end_line = 0
        # Line of HTML code marked by id="productsconfirmednotvulnerable"
        self.not_vuln_start_line = 0
        # Line of HTML code that appears to close the div
        self.not_vuln_end_line = 0
        # Count of divs found between open and closing divs of interest
        self.div_count = 0
        # Index of start of line containing div with id="vulnerableproducts"
        self.vuln_start_index = 0
        # Index of start of line that appears to close the div
        self.vuln_end_index = 0
        # Index of start of line containing div with
        # id="productsconfirmednotvulnerable"
        self.not_vuln_start_index = 0
        # Index of start of line that appears to close the div
        self.not_vuln_end_index = 0
        # Retrieve and parse HTML text
        if self.keywords and self.vulnerability_url:
            if self.vulnerability_url.startswith('https://tools.cisco.com/'):
                r = requests.get(vulnerability_url)
                self.html_text = r.text
                self.feed(r.text)
                self.lines_to_indexes()
                self.determine_if_vulnerable()
            else:
                LOGGER.error('VulnerableProductChecker is only compatible '
                            'with Cisco Security Advisories and Alerts')

    def handle_starttag(self, tag, attrs):
        if tag == 'div':
            # If we've already seen section start, start counting other divs
            if (self.vuln_start_line and not self.vuln_end_line) or \
                (self.not_vuln_start_line and not self.not_vuln_end_line):
                self.div_count += 1
            # Save line numbers of vuln and not_vuln section starts
            for attr in attrs:
                if attr[NAME] == 'id' and attr[VALUE] == 'vulnerableproducts':
                    self.vuln_start_line = self.getpos()[LINE_NUM]
                    LOGGER.debug(
                        'vuln start = {}'.format(self.vuln_start_line)
                    )
                elif attr[NAME] == 'id' and \
                    attr[VALUE] == 'productsconfirmednotvulnerable':
                    self.not_vuln_start_line = self.getpos()[LINE_NUM]
                    LOGGER.debug(
                        'not vuln start = {}'.format(self.not_vuln_start_line)
                    )

    def handle_endtag(self, tag):
        # If div and already passed section start
        if tag == 'div' and ((self.vuln_start_line and not self.vuln_end_line)
            or (self.not_vuln_start_line and not self.not_vuln_end_line)):
            self.div_count -= 1
            # We've closed more div tags than seen since section start,
            # so must be end of section
            if self.div_count == -1:
                if not self.vuln_end_line:
                    self.vuln_end_line = self.getpos()[LINE_NUM]
                    # Reset div_count so we can find not_vuln start/end
                    self.div_count = 0
                    LOGGER.debug(
                        'vuln end = {}'.format(self.vuln_end_line)
                    )
                elif not self.not_vuln_end_line:
                    self.not_vuln_end_line = self.getpos()[LINE_NUM]
                    self.div_count = 0
                    LOGGER.debug(
                        'not vuln end = {}'.format(self.not_vuln_end_line)
                    )

    def lines_to_indexes(self):
        # Convert line numbers to character positional/character indexes
        curr_pos = 0
        line_count = 0
        # Iterate through HTML file character-by-character
        for char in self.html_text:
            # Start on line 1 (HTML files don't have line 0...)
            curr_pos += 1
            # If we hit a newline character, we've hit the end of a line
            if char == '\n':
                line_count += 1
                # Use previous line to ensure we include line that contains
                # start of div
                if line_count == self.vuln_start_line - 1:
                    self.vuln_start_index = curr_pos
                # Use line itself to ensure we include entire end div line
                elif line_count == self.vuln_end_line:
                    self.vuln_end_index = curr_pos
                # Use previous line to ensure we include line that contains
                # start of div
                elif line_count == self.not_vuln_start_line - 1:
                    self.not_vuln_start_index = curr_pos
                # Use line itself to ensure we include entire end div line
                elif line_count == self.not_vuln_end_line:
                    self.not_vuln_end_index = curr_pos

        LOGGER.debug(
            'vuln range = {} - {}'.format(
                self.vuln_start_index,
                self.vuln_end_index
            )
        )
        LOGGER.debug(
            'not vuln range = {} - {}'.format(
                self.not_vuln_start_index,
                self.not_vuln_end_index
            )
        )

    def determine_if_vulnerable(self):
        # Keep track of all instances of keyword found in text via set
        keyword_indexes = set()
        # Find first instance of keyword in text
        keyword_index = self.html_text.lower().find(self.keywords.lower())
        if keyword_index != -1:
            keyword_indexes.add(keyword_index)
            LOGGER.debug('keyword index = {}'.format(keyword_index))
        # Look for all other instances of keyword in text
        while keyword_index != -1:
            keyword_index = self.html_text.lower().find(
                self.keywords.lower(),
                keyword_index + 1
            )
            if keyword_index != -1:
                keyword_indexes.add(keyword_index)
                LOGGER.debug('keyword index = {}'.format(keyword_index))

        for keyword_index in keyword_indexes:
            try:
                if self.vuln_start_index < keyword_index < self.vuln_end_index:
                    if self.vulnerable == None or self.vulnerable == True:
                        self.vulnerable = True
                    else:
                        raise Warning(
                            'Status switched from NOT VULNERABLE to '
                            'VULNERABLE which is unexpected!'
                        )
                elif self.not_vuln_start_index < keyword_index < self.not_vuln_end_index:
                    if self.vulnerable == None or self.vulnerable == False:
                        self.vulnerable = False
                    else:
                        raise Warning(
                            'Status switched from VULNERABLE to '
                            'NOT VULNERABLE which is unexpected!'
                        )
            except Warning as W:
                LOGGER.warning(W)

        if self.vulnerable == True:
            LOGGER.debug(
                '{} VULNERABLE to {}'.format(
                    self.keywords,
                    self.vulnerability_url
                )
            )
        elif self.vulnerable == False:
            LOGGER.debug(
                '{} NOT VULNERABLE to {}'.format(
                    self.keywords,
                    self.vulnerability_url
                )
            )
        # self.vulnerable was never set, still None, we can't be sure
        else:
            LOGGER.debug(
                '{} *MAY BE* VULNERABLE to {}'.format(
                    self.keywords,
                    self.vulnerability_url
                )
            )
