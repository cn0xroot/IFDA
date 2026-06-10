"""Interpreted-script static analysis (FR-INV-3 + FR-VUL).

Most IoT command-injection lives in shell/CGI scripts, not ELF binaries. This
package analyzes scripts the way EMBA's S20-series modules do, starting with
shell (the dominant case); Lua/PHP/Python analyzers slot in as sibling modules.
"""

from .shell import scan_scripts
from .langs import scan_lang_scripts

__all__ = ["scan_scripts", "scan_lang_scripts"]
