# Contributing to VaultGuard

First off, thanks for taking the time to contribute to Web3 security! 🛡️🎉

The following is a set of guidelines for contributing to VaultGuard. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. We're committed to making Web3 safer for everyone.

## How Can I Contribute?

### Reporting Security Vulnerabilities

**🚨 IMPORTANT**: If you discover a security vulnerability, please do NOT open a public issue. Instead, email us directly or use GitHub's private vulnerability reporting feature. Security issues require special handling to protect users.

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

- Use a clear and descriptive title
- Describe the exact steps which reproduce the problem
- Include the specific blockchain network (Solana mainnet/devnet)
- Provide transaction signatures or wallet addresses (if safe to share)
- Describe the security analysis behavior you observed
- Explain which security behavior you expected to see instead
- Include log outputs and error messages
- Specify your Python version and OS

**Template:**


**Bug Description:**
[Clear description of the bug]

**Steps to Reproduce:**
1. 
2. 
3. 

**Expected Security Behavior:**
[What should have happened]

**Actual Behavior:**
[What actually happened]

**Environment:**
- Python version:
- OS:
- Network: [Solana mainnet/devnet]
- AI Model: [Claude/OpenAI/etc.]

**Logs:**
[Paste relevant log output]


### Suggesting Security Enhancements

Security enhancement suggestions are especially welcome! When creating an enhancement suggestion, please include:

- Use a clear and descriptive title
- Explain the security problem this enhancement would solve
- Describe the potential threat vectors it would address
- Provide examples of attacks it could prevent
- Explain implementation approach if you have ideas
- Consider performance impact on real-time analysis

**Security Enhancement Areas:**

- New threat detection patterns
- Improved AI analysis algorithms
- Better community intelligence sharing
- Enhanced quarantine mechanisms
- Performance optimizations for real-time analysis
- New blockchain network support

### Contributing Threat Intelligence

We welcome contributions of threat intelligence data:

- **New scam patterns** - Submit patterns you've discovered
- **Malicious contract signatures** - Help build our detection database
- **False positive reports** - Help us improve accuracy
- **Community intelligence** - Share threat data responsibly

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added security analysis code, include test cases with safe sample data
3. If you've changed APIs, update the documentation
4. Ensure all security tests pass
5. Test with real blockchain data on devnet/testnet when possible
6. Make sure your code follows security best practices
7. Update relevant analysis modules if needed
8. Issue that pull request!

**Security-Specific PR Guidelines:**

- Never include real private keys or sensitive data in code
- Test security analysis with known safe/malicious samples
- Document any new threat detection capabilities
- Consider edge cases and potential bypasses
- Ensure backward compatibility with existing analysis modules

## Development Setup

### Prerequisites

- Python 3.12+
- Docker & Docker Compose
- Access to Solana RPC (Helius, QuickNode, etc.)
- AI API keys (Anthropic Claude, OpenAI, etc.)

### Local Development

```bash
# Clone your fork
git clone https://github.com/ticketguy/vaultguard.git
cd vaultguard

# Setup Python environment
python -m venv agent-venv
source agent-venv/bin/activate

# Install dependencies
cd agent
pip install -e .

# Copy and configure environment
cp .env.example .env
# Edit .env with your API keys

# Run security agent
python -m scripts.starter


### Testing Security Analysis


# Test with safe sample transactions
python -m scripts.test_security_analysis

# Run analysis module tests
python -m pytest tests/analysis/

# Test edge learning engine
python -m pytest tests/intelligence/


## Styleguides

### Git Commit Messages

- Use the present tense ("Add threat detection" not "Added threat detection")
- Use the imperative mood ("Improve analysis speed" not "Improves analysis speed")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line
- Use security-focused prefixes:
  - `security:` for security improvements
  - `analysis:` for analysis module changes
  - `intelligence:` for threat intelligence updates
  - `fix:` for bug fixes
  - `docs:` for documentation

**Examples:**

security: Add MEV sandwich attack detection
analysis: Improve contract drain risk scoring
intelligence: Update scam token black
