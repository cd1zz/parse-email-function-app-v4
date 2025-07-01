#!/usr/bin/env python3
"""
Entry point for running phishing_email_parser as a module.
This allows: python -m phishing_email_parser <email_file>
"""

from .main_parser import main

if __name__ == "__main__":
    main()
