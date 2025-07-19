#!/usr/bin/env python3
"""
Runner script for AWS Security Tool
This script sets up the proper Python path and runs the CLI
"""

import sys
import os

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import and run the main CLI
from src.cli import cli as main

if __name__ == '__main__':
    main()