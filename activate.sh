#!/bin/bash
# Activation script for aws-sec virtual environment

echo "Activating aws-sec virtual environment..."
source /home/ec2-user/aws-sec/venv/bin/activate

# Add the aws-security-tool src directory to PYTHONPATH
export PYTHONPATH="/home/ec2-user/aws-sec/aws-security-tool/src:$PYTHONPATH"

echo "Virtual environment activated!"
echo "Python: $(which python)"
echo "pip: $(which pip)"
echo ""
echo "To run aws-security-tool, use:"
echo "  python -m cli --help"
echo ""
echo "Or navigate to the tool directory first:"
echo "  cd /home/ec2-user/aws-sec/aws-security-tool/src"
echo "  python cli.py --help"