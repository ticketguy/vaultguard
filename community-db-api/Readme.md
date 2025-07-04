# Hybrid Onchain Community Intelligence System

A decentralized threat intelligence network that combines the speed of offchain processing with the trustlessness of blockchain consensus.

## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Edge Agents   │───▶│  Offchain API    │───▶│ Onchain Registry│
│                 │    │  (Fast Queries)  │    │  (Consensus)    │
│ • Instant Cache │    │                  │    │                 │
│ • Real-time     │    │ • Evidence Store │    │ • Reputation    │
│   Analysis      │    │ • Private Intel  │    │ • Staking       │
│ • Local Intel   │    │ • Query Cache    │    │ • Governance    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## System Components

### Layer 1: Edge Agents (Client Layer)

**Purpose**: Instant transaction analysis with cached intelligence

Edge agents run locally at each wallet provider and perform:

- Real-time transaction analysis using cached threat intelligence
- Instant security decisions (ALLOW/WARN/BLOCK) without network delays
- Background learning from user decisions and transaction patterns
- Local intelligence caching for sub-millisecond response times

**Key Features**:

- Zero-latency security decisions
- Offline-capable threat detection
- Continuous learning from user behavior
- Privacy-preserving local analysis

### Layer 2: Offchain API (Intelligence Layer)

**Purpose**: Centralized intelligence aggregation and detailed evidence storage

The offchain layer handles:

- Detailed threat evidence collection and storage
- Real-time intelligence sharing between edge agents
- Private investigation data that shouldn't be public
- High-frequency query caching for performance
- Complex analysis that requires significant compute resources

**Database Schema**:

```sql
-- Detailed threat reports with evidence
reports (
  address, token_symbol, report_type, 
  evidence_json, description, reporter_id
)

-- Aggregated consensus data
consensus_data (
  threat_key, confidence_score, 
  vote_count, last_updated
)
```

### Layer 3: Onchain Registry (Consensus Layer)

**Purpose**: Decentralized consensus and economic incentives

The blockchain layer provides:

- Immutable reputation scores for addresses and tokens
- Economic incentives for accurate threat reporting
- Governance mechanisms for disputed classifications
- Cross-ecosystem threat intelligence sharing
- Cryptographic proof of intelligence authenticity

**Smart Contract Interface**:

```solidity
contract CommunityThreatRegistry {
    struct ReputationData {
        uint8 score;           // 0-255 reputation score
        uint32 reportCount;    // Number of reports
        uint32 lastUpdated;    // Timestamp of last update
        bytes32 evidenceHash;  // IPFS hash of evidence
    }
    
    mapping(address => ReputationData) public reputation;
    
    function reportThreat(address target, bytes32 evidence) external;
    function updateReputation(address target, uint8 newScore) external;
    function getReputation(address target) external view returns (ReputationData);
}
```

## Data Flow

### 1. Threat Detection Flow

```
User Transaction → Edge Agent Analysis → Local Cache Check
                                              ↓
                                         Instant Decision
                                              ↓
                                    Background: Report to API
                                              ↓
                                    API: Aggregate Evidence  
                                              ↓
                                    High Confidence? → Onchain
```

### 2. Intelligence Propagation

```
Threat Discovered → Offchain API → Community Validation → Onchain Registry
                                        ↓
                                 Edge Agent Sync ← API Cache Update
                                        ↓
                                 All Agents Protected
```

### 3. Reputation Query Flow

```
Need Reputation → Check Local Cache → Check API Cache → Query Onchain
     (0ms)              (5ms)             (50ms)          (500ms)
```

## Economic Model

### Staking & Rewards

- **Threat Reporters**: Stake tokens to submit reports, earn rewards for accuracy
- **Validators**: Stake to validate reports, earn fees from reputation queries
- **Consumers**: Pay small fees for reputation queries, funding the reward pool

### Reputation Scoring

```javascript
// Onchain reputation calculation
function calculateReputation(reports) {
    const totalStaked = reports.reduce((sum, r) => sum + r.stake, 0);
    const weightedScore = reports.reduce((sum, r) => 
        sum + (r.score * r.stake), 0
    );
    return Math.floor(weightedScore / totalStaked);
}
```

### Incentive Alignment

- **False positives** result in stake slashing
- **Missed threats** reduce reporter reputation
- **Accurate reports** earn compounding rewards
- **Community consensus** determines truth through economic votes

## Integration Guide

### For Wallet Providers

```javascript
// Initialize edge agent with hybrid intelligence
const edgeAgent = new EdgeAgent({
    offchainAPI: "https://api.community-intel.xyz",
    onchainProgram: "ThreatRegistryProgram123...",
    localCache: true,
    stakingEnabled: true
});

// Analyze transaction (instant response)
const analysis = await edgeAgent.analyzeTransaction(txData);
// Returns: { action: "ALLOW", riskScore: 0.1, confidence: 0.95 }
```

### For DeFi Protocols

```javascript
// Query reputation before interaction
const reputation = await ThreatRegistry.getReputation(userAddress);
if (reputation.score < 50) {
    requireAdditionalVerification();
}
```

### For Security Researchers

```javascript
// Submit threat intelligence with stake
await ThreatRegistry.reportThreat(
    suspiciousAddress,
    evidenceIPFSHash,
    { stake: "100 SOL" }
);
```

## Network Effects

### Cross-Ecosystem Protection

When Phantom Wallet's edge agent discovers a threat:

1. **Immediate**: Phantom users are protected
2. **5 minutes**: Offchain API aggregates the intelligence
3. **1 hour**: High-confidence threats move onchain
4. **Next sync**: All wallet providers receive the update
5. **Result**: Solflare, Backpack, and other wallets protect their users

### Ecosystem Growth

```
More Wallets → More Threat Data → Better Intelligence → Safer Ecosystem
     ↑                                                         ↓
Better Protection ← Higher Accuracy ← More Validators ← More Value
```

## Technical Implementation

### Phase 1: Offchain Foundation

- Deploy centralized API for intelligence aggregation
- Implement edge agent local caching
- Build evidence collection and validation system
- Establish basic economic incentives

### Phase 2: Onchain Integration

- Deploy smart contracts for reputation registry
- Implement staking and reward mechanisms
- Build governance system for disputed cases
- Enable cross-ecosystem reputation queries

### Phase 3: Full Decentralization

- Migrate high-confidence intelligence onchain
- Implement decentralized governance
- Enable permissionless validator participation
- Launch community-driven threat bounty program

## Security Considerations

### Privacy Protection

- **Detailed evidence** stays offchain in encrypted storage
- **Investigation techniques** remain private to security teams
- **User transaction patterns** never leave local edge agents
- **Only reputation scores** are published onchain

### Attack Resistance

- **Economic staking** prevents spam and false reports
- **Multi-layer validation** ensures accuracy before onchain publication
- **Reputation decay** ensures outdated intelligence expires
- **Governance override** handles edge cases and appeals

## Getting Started

### For Developers

```bash
# Install the hybrid intelligence SDK
npm install @community-intel/hybrid-sdk

# Initialize with your configuration
const intel = new HybridIntelligence({
    network: "mainnet",
    stakeAmount: "10 SOL",
    validatorMode: true
});
```

### For Wallet Providers

```bash
# Deploy your edge agent
git clone https://github.com/community-intel/edge-agent
cd edge-agent
npm install && npm run deploy
```

### For Security Teams

```bash
# Access the threat intelligence dashboard
curl -X POST https://api.community-intel.xyz/auth \
  -d '{"role": "security_researcher", "stake": "100 SOL"}'
```

---

**The Hybrid Onchain Community Intelligence System represents the evolution of Web3 security - combining the speed users demand with the trustlessness they deserve.**
