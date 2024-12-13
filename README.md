# har_analyzer

A Python tool for analyzing HTTP Archive (HAR) files with a focus on transaction analysis and security assessment.

## Overview

This tool analyzes HAR files to extract useful information about web transactions, with particular emphasis on:
- Communication patterns
- Security headers
- Payment-related activities
- Card number transmissions
- DNS dependencies

## Features

- **Website Communications Analysis**
  - Tracks domains contacted
  - Categorizes resources (JS, CSS, images, etc.)
  - Maps all communication endpoints

- **Security Analysis**
  - Monitors card number transmissions
  - Evaluates security headers
  - Checks HTTPS/TLS usage
  - Analyzes transport security

- **Transaction Monitoring**
  - Identifies payment-related URLs
  - Detects checkout processes
  - Monitors POST request data
  - Tracks order-related activities

## Installation

1. Clone the repository
2. Install all required dependencies using pip:
```bash
pip install -r requirements.txt
```

This will install:
- cached-property (2.0.1)
- haralyzer (2.4.0)
- python-dateutil (2.9.0.post0)
- six (1.17.0)

## Usage

Basic usage:

```bash
python har_analyzer.py -i <input_file.har>
```
Analyze a specific page:
```bash
python har_analyzer.py -i <input_file.har> -p <page_number>
```
Command Line Arguments
- `-i`: Input HAR file path (default: "transaction.har")
- `-p`: Page number to analyze in detail (0-based index)

## Output

The analyzer provides detailed information about:
- Page summaries
- Domain communications
- Security header presence
- Card number transmissions
- DNS dependencies

## Requirements

- Python 3.x
- Dependencies listed in requirements.txt:
  ```
  cached-property==2.0.1
  haralyzer==2.4.0
  python-dateutil==2.9.0.post0
  six==1.17.0
  ```

## Security Note

This tool is designed for security analysis and debugging purposes. When analyzing HAR files containing sensitive information:
- Ensure proper data handling
- Follow security protocols
- Comply with privacy regulations
- Handle card number data securely
