import importlib.metadata as pkg_resources  # For Python 3.8+

from .tldextract import extract, TLDExtract

# For Python versions older than 3.8, you may need to use:
# import importlib_metadata as pkg_resources

try:
    __version__ = pkg_resources.version('tldextract')
except pkg_resources.PackageNotFoundError:
    __version__ = '(local)'
