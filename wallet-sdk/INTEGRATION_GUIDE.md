# Wallet Provider Integration Guide

## Quick Start

```python
from wallet_security_sdk import WalletSecuritySDK

# Initialize for your wallet
sdk = WalletSecuritySDK("your_wallet_provider_id")
await sdk.initialize()

# Check incoming transactions
result = await sdk.check_incoming_transaction(transaction_data)

if result['action'] == 'quarantine':
    # Show quarantine notification to user
    show_notification(result['user_message'])
else:
    # Add to main wallet
    add_to_main_wallet(transaction_data)