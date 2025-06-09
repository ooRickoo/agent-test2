# Security Agent Testing Framework

This repository contains a security agent testing framework that allows you to test and evaluate security agents' capabilities in various scenarios. The framework provides tools for domain information gathering, host information analysis, and security testing.

## Features

- Domain Information Analysis
- Host Information Gathering
- IP Geolocation
- Security Testing Capabilities
- Integration with Anthropic's Claude API

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- An Anthropic API key

## Installation

1. Clone this repository:
```bash
git clone <your-repository-url>
cd <repository-name>
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory and add your Anthropic API key:
```
ANTHROPIC_API_KEY=your_api_key_here
```

## Project Structure

```
.
├── README.md
├── requirements.txt
├── test_agent/
│   ├── test_agent.py          # Main testing agent implementation
│   ├── domaininformation.py   # Domain information gathering module
│   ├── hostinformation.py     # Host information gathering module
│   ├── ip_geolocation.py      # IP geolocation utilities
│   ├── epoch_converter.py     # Time conversion utilities
│   └── tools.csv              # Tool definitions and configurations
```

## Usage

1. Ensure your virtual environment is activated and dependencies are installed.

2. Run the test agent:
```bash
python test_agent/test_agent.py
```

## Components

### Domain Information Module
The domain information module (`domaininformation.py`) provides capabilities for:
- WHOIS lookups
- DNS record analysis
- Domain registration information
- SSL certificate information

### Host Information Module
The host information module (`hostinformation.py`) provides capabilities for:
- Port scanning
- Service detection
- Operating system detection
- Network service analysis

### IP Geolocation
The IP geolocation module (`ip_geolocation.py`) provides:
- IP address location information
- ASN information
- Network block information

## Security Considerations

- Always use this framework in a controlled environment
- Ensure you have proper authorization before testing any systems
- Follow responsible disclosure practices
- Keep your API keys secure and never commit them to the repository

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository. 