# solidity-security-research

> Smart contract security research — vulnerability library, exploit PoCs, wargame solutions.

![Forge](https://img.shields.io/badge/Forge-passing-brightgreen)
![Vulns](https://img.shields.io/badge/Vulnerabilities-1%2F30-blue)
![Exploits](https://img.shields.io/badge/Exploit_PoCs-0%2F43-orange)
![Wargames](https://img.shields.io/badge/Wargames-0%2F71-purple)

## Structure

```
solidity-security-research/
├── vuln-library/         ← 30 vulnerability patterns (broken + exploit + fix)
├── exploit-pocs/         ← 43 real-world hack recreations
├── wargames/
│   ├── ethernaut/        ← 34 levels
│   ├── capture-the-ether/← 19 challenges
│   └── damn-vulnerable-defi/ ← 18 levels
├── foundry.toml
└── SETUP.md
```

## Vulnerability Library

Each pattern has: `Vulnerable.sol` → `Attacker.sol` → `Safe.sol` → forge test → README

| Pattern | Description | Status |
|---------|-------------|--------|
| [Reentrancy](vuln-library/01-reentrancy/) | CEI pattern violation — ETH sent before state update | ![](https://img.shields.io/badge/-DONE-brightgreen) |
| [AccessControl](vuln-library/02-access-control/) | tx.origin vs msg.sender — ownership bypass | ![](https://img.shields.io/badge/-TODO-lightgrey) |
| [IntegerOverflow](vuln-library/03-integer-overflow/) | Pre-0.8.0 wrap-around — SafeMath history | ![](https://img.shields.io/badge/-TODO-lightgrey) |
| [Delegatecall](vuln-library/04-delegatecall/) | Storage collision — proxy context abuse | ![](https://img.shields.io/badge/-TODO-lightgrey) |
| [OracleManipulation](vuln-library/05-oracle-manipulation/) | Spot price oracle — flash loan price attack | ![](https://img.shields.io/badge/-TODO-lightgrey) |
| [FlashLoans](vuln-library/06-flash-loans/) | AAVE v3 callback — atomic borrow and exploit | ![](https://img.shields.io/badge/-TODO-lightgrey) |
| [SignatureReplay](vuln-library/07-signature-replay/) | ecrecover replay — EIP-712 missing nonce | ![](https://img.shields.io/badge/-TODO-lightgrey) |
| [GasDOS](vuln-library/08-gas-dos/) | Unbounded loops — block gas limit griefing | ![](https://img.shields.io/badge/-TODO-lightgrey) |
| [BridgeAttack](vuln-library/09-bridge-attacks/) | Message validation bypass — cross-chain exploit | ![](https://img.shields.io/badge/-TODO-lightgrey) |
| [UpgradeBug](vuln-library/10-upgrade-bugs/) | Uninitialized impl — storage collision in proxy | ![](https://img.shields.io/badge/-TODO-lightgrey) |
| [ReentrancyAdvanced](vuln-library/11-reentrancy-advanced/) | Cross-function reentrancy — read-only reentrancy | ![](https://img.shields.io/badge/-TODO-lightgrey) |
| [EIP712Deep](vuln-library/12-eip712-deep/) | Permit() abuse — gasless approval exploit | ![](https://img.shields.io/badge/-TODO-lightgrey) |

## Real-World Exploit PoCs

| Hack | Lost | Root Cause |
|------|------|-----------|
| [TheDAO 2016](exploit-pocs/2016-the-dao/) | $60M | Reentrancy in withdraw() — ETH sent before balance... |
| [Parity 2017](exploit-pocs/2017-parity-multisig/) | $30M | Unprotected initWallet() callable by anyone... |
| [bZx 2020](exploit-pocs/2020-bzx-flash-loan/) | $350k | Spot price oracle from AMM — flash loan manipulati... |
| [Compound 2021](exploit-pocs/2021-compound-governance/) | $90M | COMP distribution double-claim bug... |
| [Harvest 2020](exploit-pocs/2020-harvest-finance/) | $34M | Curve spot oracle — 7-step flash loan attack... |
| [Euler 2023](exploit-pocs/2023-euler-finance/) | $197M | donateToReserves() bypassed health check... |
| [Wintermute 2022](exploit-pocs/2022-wintermute-profanity/) | $160M | Weak vanity address — GPU brute force... |
| [Ronin 2022](exploit-pocs/2022-ronin-bridge/) | $625M | 5/9 validator keys compromised... |
| ... | | |

## Wargames

| Platform | Levels | Status |
|----------|--------|--------|
| Ethernaut | 34 | 0 / 34 |
| Capture The Ether | 19 | 0 / 19 |
| DamnVulnerableDeFi | 18 | 0 / 18 |

## Run

```bash
git clone --recursive https://github.com/protamoghna-dev/solidity-security-research.git
cd solidity-security-research && forge test -vv
```
