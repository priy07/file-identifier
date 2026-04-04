"""
File Type Identifier using Magic Numbers
Reads file headers (magic bytes) to identify file types - no extensions needed.
"""

from .core import identify_file, identify_many, read_header, print_report

__version__ = "0.1.0"
__all__ = ["identify_file", "identify_many", "read_header", "print_report"]
