#!/usr/bin/env python3
"""Helper script for manual debugging using parse_email package."""
from parse_email.debug_utils import debug_email_structure

if __name__ == "__main__":
    debug_email_structure("email.eml")
