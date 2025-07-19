# AWS Security Tool Tests

This directory contains unit tests for the AWS Security Analysis Tool.

## Running Tests

### Basic Test Execution
```bash
# Activate virtual environment
source venv/bin/activate

# Run all tests
PYTHONPATH=/home/ec2-user/aws-sec python -m pytest

# Run specific test file
PYTHONPATH=/home/ec2-user/aws-sec python -m pytest tests/test_s3_scanner.py

# Run with verbose output
PYTHONPATH=/home/ec2-user/aws-sec python -m pytest -v
```

### Running Tests with Coverage
```bash
# Run tests with coverage report
PYTHONPATH=/home/ec2-user/aws-sec python -m pytest --cov=src --cov-report=term-missing

# Generate HTML coverage report
PYTHONPATH=/home/ec2-user/aws-sec python -m pytest --cov=src --cov-report=html
# View coverage report in browser: open htmlcov/index.html
```

## Test Structure

### Current Test Coverage

- **S3 Scanner Tests** (`test_s3_scanner.py`)
  - 23 comprehensive unit tests
  - 85% code coverage
  - Tests all security checks including:
    - Bucket encryption (SSE-S3, SSE-KMS)
    - Public access controls
    - Versioning
    - Logging
    - Lifecycle policies
    - Bucket policies
    - ACLs
    - Object Lock

### Test Conventions

- Test files are named `test_<module_name>.py`
- Test classes are named `Test<ClassName>`
- Test methods are named `test_<what_is_being_tested>`
- Use fixtures for common setup
- Mock AWS API calls to avoid actual AWS interactions

### Writing New Tests

When adding new scanners or features:

1. Create a corresponding test file in the `tests/` directory
2. Mock all AWS API calls using `unittest.mock`
3. Test both successful scenarios and error handling
4. Aim for at least 80% code coverage
5. Include integration tests for complex workflows

### Test Dependencies

Required packages (included in requirements.txt):
- pytest>=8.0.0
- pytest-mock>=3.14.0
- pytest-cov>=6.0.0
- boto3-stubs[s3]>=1.34.0

## Continuous Integration

Tests should be run:
- Before committing code changes
- As part of CI/CD pipeline
- After major dependency updates

## Future Test Improvements

- [ ] Add integration tests for multi-service scanning
- [ ] Create performance benchmarks
- [ ] Add tests for CLI commands
- [ ] Implement test fixtures for common AWS resources
- [ ] Add tests for report generation