# """Export tldextract's public interface."""
#
# import pkg_resources
#
# from .tldextract import extract, TLDExtract
#
# try:
#     __version__ = pkg_resources.get_distribution('tldextract').version # pylint: disable=no-member
# except pkg_resources.DistributionNotFound as _:
#     __version__ = '(local)'
import importlib.metadata as pkg_resources  # For Python 3.8+
# For Python versions older than 3.8, you may need to use:
# import importlib_metadata as pkg_resources

from .tldextract import extract, TLDExtract

try:
    __version__ = pkg_resources.version('tldextract')
except pkg_resources.PackageNotFoundError:
    __version__ = '(local)'