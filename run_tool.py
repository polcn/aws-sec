#!/usr/bin/env python3
"""
Runner script for AWS Security Tool
This script sets up the proper Python path and runs the CLI
"""

import sys
import os

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'aws-security-tool', 'src'))

# Import and run the main CLI
from cli import main

if __name__ == '__main__':
    main()