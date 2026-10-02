"""Test-session setup: keep log files out of the working directory and make
sure a stray SWIFTSCAN_TOKEN in the developer's shell can't change results."""
import os
import tempfile

os.environ["SWIFTSCAN_LOG_DIR"] = tempfile.mkdtemp(prefix="swiftscan_testlogs_")
for _var in ("SWIFTSCAN_TOKEN", "SWIFTSCAN_ALLOW_INTERNAL", "SWIFTSCAN_REPORTS_DIR"):
    os.environ.pop(_var, None)
