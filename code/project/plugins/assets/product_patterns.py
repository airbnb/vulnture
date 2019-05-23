"""Asset plugin that allows vulnture to translate product model numbers to
product names and keywords.
"""

# Tuple index numbers, defined to avoid magic number usage
PATTERN = 0
KEYWORDS = 1
VERIFICATION_STRING = 2
APPEND_MATCH = 3

# Tuple of tuples coupling regex patterns and keyword search strings
# The second-from-last string is what should be searched in the vulnerability
#   HTML page to determine whether or not a product is vulnerable
# The boolean value at the end of the tuple determines whether or not the
#   matched string value from the regex is added to the keywords to search
pattern_to_keywords = ()
