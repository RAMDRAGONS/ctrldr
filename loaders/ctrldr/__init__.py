"""
Nintendo 3DS (CTR) executable reading, independent of IDA.

A raw ExeFS .code carries no section table. The layout comes from an ExHeader
when one is available; otherwise it is recovered from the image itself using
the CTR-SDK scatter layout and the ZI clear loop in the SDK crt0.
"""

from .exheader import ExHeader
from .formats import FORMATS, Image, detect_format, load_image
from .layout import LayoutInference, Section
from .util import CODE_BASE, LoaderError, Source

__all__ = ["CODE_BASE", "ExHeader", "FORMATS", "Image", "LayoutInference", "LoaderError",
           "Section", "Source", "detect_format", "load_image"]
