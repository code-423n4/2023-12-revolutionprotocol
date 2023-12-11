# Repo setup


- [ ] Optional / nice to have: pre-record a high-level overview of your protocol (not just specific smart contract functions). This saves wardens a lot of time wading through documentation.

- [ ] Remove any part of this template that's not relevant to the final version of the README (e.g. instructions in brackets and italic)
- [ ] Delete this checklist and all text above the line below when you're ready.

---

# Revolution audit details

- Total Prize Pool: $36,500 USDC
  - HM awards: $24,250 USDC
  - Analysis awards: $1,250 USDC
  - QA awards: $750 USDC
  - Bot Race awards: $2,250 USDC
  - Gas awards: $1,500 USDC
  - Judge awards: $3,600 USDC
  - Lookout awards: $2,400 USDC
  - Scout awards: $500 USD
- Join [C4 Discord](https://discord.gg/code4rena) to register
- Submit findings [using the C4 form](https://code4rena.com/2023-12-revolution-protocol/submit)
- [Read our guidelines for more details](https://docs.code4rena.com/roles/wardens)
- Starts December 13, 20:00 UTC
- Ends December 21, 20:00 UTC

## Automated Findings

The 4naly3er report can be found [here](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/4naly3er-report.md).

Automated findings output for the audit can be found [here](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/bot-report.md) within 24 hours of audit opening.

_Note for C4 wardens: Anything included in this `Automated Findings / Publicly Known Issues` section is considered a publicly known issue and is ineligible for awards._

### Publicly Known Issues

The AuctionHouse will fail to create a new auction if the CultureIndex is empty. Not too worried about this.

VerbsToken mint can fail if the top voted piece in the CultureIndex has not met quorum. Potential attack vector here.

If you create the VRGDA with shoddy parameters you can get bad outputs and errors. Will add checks on the deployer/manager contract to ensure valid params.

# the Revolution protocol ⌐◨-◨

Revolution is a set of contracts that improve on [Nouns DAO](https://github.com/nounsDAO/nouns-monorepo). Nouns is a generative avatar collective that auctions off one ERC721, every day, forever. 100% of the proceeds of each auction (the winning bid) go into a shared treasury, and owning an NFT gets you 1 vote over the treasury.

<img width="377" alt="noun" src="https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/readme-img/noun.png">

Compared to Nouns, Revolution seeks to make governance token ownership more accessible to creators and builders, and balance the scales between culture and capital while committing to a constant governance inflation schedule.

The ultimate goal of Revolution is fair ownership distribution over a community movement where anyone can earn decision making power over the energy of the movement. If this excites you, [build with us](mailto:rocketman@collective.xyz).

# Developer guide

## Setup

```
git clone https://github.com/code-423n4/2023-12-revolutionprotocol.git && cd 2023-12-revolutionprotocol
```

#### Node.js and pnpm

```
npm install -g pnpm
```

#### Turbo

```
npm install turbo --global
```

#### Foundry

[Installation guide](https://book.getfoundry.sh/getting-started/installation)

## Install dependencies

```
pnpm install
```

## Run tests

Run tests for both Protocol Rewards and Revolution Contracts

```
turbo run test
```

Run tests in dev mode for a package w/gas logs

```
cd packages/revolution && pnpm run dev
```

## Gas reports

Gas reports are located in [gas-reports](https://github.com/code-423n4/2023-12-revolutionprotocol/tree/main/gas-reports)

Run the tests with and generate a gas report.

```
cd packages/revolution && pnpm run write-gas-report
```

Gas optimizations around the CultureIndex `createPiece` and `vote` functionality, the [MaxHeap](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/MaxHeap.sol) and [`buyToken`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol) should be prioritized.

## Slither

#### Revolution contracts

```
cd packages/revolution && slither src --solc-remaps "ds-test/=node_modules/ds-test/src/,forge-std/=node_modules/forge-std/src/,@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/,@openzeppelin/contracts-upgradeable/=node_modules/@openzeppelin/contracts-upgradeable,solmate=node_modules/solmate/src,@collectivexyz/protocol-rewards/src/=node_modules/@collectivexyz/protocol-rewards/src/" --checklist --show-ignored-findings --filter-paths "@openzeppelin|ERC721|Votes.sol" --config-file="../../.github/config/slither.config.json"
```

#### Protocol rewards

```
cd packages/protocol-rewards && slither src --solc-remaps "ds-test/=../../node_modules/ds-test/src/,forge-std/=../../node_modules/forge-std/src/,@openzeppelin/contracts/=../../node_modules/@openzeppelin/contracts/,@openzeppelin/contracts-upgradeable/=../../node_modules/@openzeppelin/contracts-upgradeable,solmate=../../node_modules/solmate/src" --checklist --show-ignored-findings --filter-paths "@openzeppelin"
```

# revolution overview

Instead of [auctioning](https://nouns.wtf/) off a generative PFP like Nouns, anyone can upload art pieces to the [CultureIndex](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/CultureIndex.sol) contract, and the community votes on their favorite art pieces.

The top piece is auctioned off every day as an ERC721 [VerbsToken](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/VerbsToken.sol) via the [AuctionHouse](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol).

The auction proceeds are split with the creator(s) of the art piece, and the rest is sent to the owner of the auction contract. The winner of the auction receives an ERC721 of the art piece. The creator receives an amount of ERC20 governance tokens and a share of the winning bid.

The ERC20 tokens the creator receives is calculated by the [ERC20TokenEmitter](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol). Both the ERC721 and the ERC20 governance token have voting power to vote on art pieces in the **CultureIndex**.

# relevant contracts

## CultureIndex

[**CultureIndex.sol**](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/CultureIndex.sol) is a directory of uploaded art pieces that anyone can add media to. Owners of an ERC721 or ERC20 can vote weighted by their balance on any given art piece.

<img width="817" alt="culture index" src="https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/readme-img/culture-index.png">

The art piece votes data is stored in [**MaxHeap.sol**](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/MaxHeap.sol), a heap datastructure that enables efficient lookups of the highest voted art piece.

The contract has a function called **dropTopVotedPiece**, only callable by the owner, which pops (removes) the top voted item from the **MaxHeap** and returns it.

## VerbsToken

[**VerbsToken.sol**](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/VerbsToken.sol) is a fork of the [NounsToken](https://github.com/nounsDAO/nouns-monorepo/blob/master/packages/nouns-contracts/contracts/NounsToken.sol) contract. **VerbsToken** owns the **CultureIndex**. When calling **mint()** on the **VerbsToken**, the contract calls **dropTopVotedPiece** on **CultureIndex**, and creates an ERC721 with metadata based on the dropped art piece data from the **CultureIndex**.

## AuctionHouse

[**AuctionHouse.sol**](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol) is a fork of the [NounsAuctionHouse](https://github.com/nounsDAO/nouns-monorepo/blob/master/packages/nouns-contracts/contracts/NounsAuctionHouse.sol) contract, that mints **VerbsToken**s. Additionally, the **AuctionHouse** splits auction proceeds (the winning bid) with the creator(s) of the art piece that is minted.

<img width="882" alt="Screenshot 2023-12-06 at 11 25 27 AM" src="https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/readme-img/vrb-auction.png">

### Creator payment

The **creatorRateBps** defines the proportion (in basis points) of the auction proceeds that is reserved for the creator(s) of the art piece, called the _creator's share_.

```
creator_share = (msg.value * creatorRateBps) / 10_000
```

The **entropyRateBps** defines the proportion of the _creator's share_ that is sent to the creator directly in ether.

```
direct creator payment = (creator_share * entropyRateBps) / 10_000
```

The remaining amount of the _creator's share_ is sent to the [ERC20TokenEmitter](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol) contract's **buyToken** function to buy the creator ERC20 governance tokens, according to a linear token emission schedule.

## ERC20TokenEmitter

**[ERC20TokenEmitter.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol)** is a linear [VRGDA](https://www.paradigm.xyz/2022/08/vrgda) that mints an ERC20 token when the payable **buyToken** function is called, and enables anyone to purchase the ERC20 governance token at any time. A portion of value spent on buying the ERC20 tokens is paid to creators and to a protocol rewards contract.

### Creator payment

The ERC20TokenEmitter has a **creatorRateBps** and **entropyRateBps** that function the same as the **AuctionHouse** contract's. Whenever a **buyToken** purchase of governance tokens is made, a **creatorRateBps** portion of the proceeds is reserved for the **creatorsAddress** set in the contract, with direct payment calculated according to the **entropyRateBps**.

### Protocol rewards

A fixed percentage of the value sent to the **buyToken** function is paid to the **TokenEmitterRewards** contract. The rewards setup is modeled after Zora's _fixed_ [protocol rewards](https://github.com/ourzora/zora-protocol/tree/main/packages/protocol-rewards). The key difference is that instead of a _fixed_ amount of ETH being split between the builder, referrer, deployer, and architect, the **TokenEmitterRewards** system splits a percentage of the value to relevant parties.

## VRGDA

The ERC20TokenEmitter utilizes a VRGDA to emit ERC20 tokens at a predictable rate. You can read more about VRGDA's [here](https://www.paradigm.xyz/2022/08/vrgda), and view the implementation for selling NFTs [here](https://github.com/transmissions11/VRGDAs). Basically, a VRGDA contract dynamically adjusts the price of a token to adhere to a specific issuance schedule. If the emission is ahead of schedule, the price increases exponentially. If it is behind schedule, the price of each token decreases by some constant decay rate.

<img width="903" alt="Screenshot 2023-12-05 at 8 31 54 PM" src="https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/readme-img/vrgda.png">

You can read more about the implementation on [Paradigm's site](https://www.paradigm.xyz/2022/08/vrgda). Additional information located in the Additional Context section of the README.

## Links

- **Previous Nouns DAO audits:**
- [NounsDAOV2](https://github.com/code-423n4/2022-08-nounsdao)
- [NounsDAOV3 (fork)](https://github.com/code-423n4/2023-07-nounsdao)
- **Twitter:**
  [@collectivexyz](https://twitter.com/collectivexyz) and [@vrbsdao](https://twitter.com/vrbsdao)

# Scope

_List all files in scope in the table below (along with hyperlinks) -- and feel free to add notes here to emphasize areas of focus._

The ERC20TokenEmitter and flow of action from CultureIndex `drop` -> VerbsToken `mint` -> AuctionHouse `createAuction` are likely the most complex and prone to attack.

| Contract | Purpose | Libraries used |  External contract calls
| ----------- | ----------- | ----------- | ----------- |
| [MaxHeap.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/MaxHeap.sol) | Implements a [MaxHeap](https://www.geeksforgeeks.org/introduction-to-max-heap-data-structure/) data structure for O(1) max value retrieval | [`@openzeppelin/contracts`](https://openzeppelin.com/contracts/) |  |
| [CultureIndex.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/CultureIndex.sol) | Creation and weighted token voting of community art pieces | [`@openzeppelin/contracts`](https://openzeppelin.com/contracts/) [`ERC20Votes`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/base/erc20/ERC20Votes.sol) [`ERC721Checkpointable`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/base/ERC721Checkpointable.sol) | [`ERC721Checkpointable`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/base/ERC721Checkpointable.sol) / [`ERC20Votes`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/base/erc20/ERC20Votes.sol) / [`MaxHeap`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/MaxHeap.sol) |
| [NontransferableERC20Votes.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/NontransferableERC20Votes.sol) | A nontransferable ERC20 Votes token | [`@openzeppelin/contracts`](https://openzeppelin.com/contracts/) [`ERC20Votes`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/base/erc20/ERC20Votes.sol) |  |
| [TokenEmitter.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/TokenEmitter.sol) | Continuous linear VRGDA for purchasing ERC20 tokens with ether | [`@openzeppelin/contracts`](https://openzeppelin.com/contracts/) [`SignedWadMath`](https://github.com/transmissions11/solmate/blob/main/src/utils/SignedWadMath.sol)  | [`NontransferableERC20Votes`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/NontransferableERC20Votes.sol) / [`TokenEmitterRewards`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol) / [`VRGDAC`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/libs/VRGDAC.sol) |
| [VerbsAuctionHouse.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/VerbsAuctionHouse.sol) | AuctionHouse for selling ERC721s and paying creators | [`@openzeppelin/contracts-upgradeable`](https://openzeppelin.com/contracts/)| [`TokenEmitter`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/TokenEmitter.sol) / [`VerbsToken`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/VerbsToken.sol) | |
| [VerbsToken.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/VerbsToken.sol) | The ERC721 that mints from the top *CultureIndex* art piece | [`@openzeppelin/contracts`](https://openzeppelin.com/contracts/) [`ERC721Checkpointable`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/base/ERC721Checkpointable.sol) | [`CultureIndex`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/CultureIndex.sol) |
| [libs/VRGDAC.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/libs/VRGDAC.sol) | The continuous linear VRGDA used for ERC20 token emission | [`SignedWadMath`](https://github.com/transmissions11/solmate/blob/main/src/utils/SignedWadMath.sol) ||  |
||
| [TokenEmitterRewards.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol) | Compute rewards and deposit for the *TokenEmitter* |  | |
| [RewardSplits.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/protocol-rewards/src/abstract/RewardSplits.sol) | Compute and deposit rewards based on splits |  | [`RevolutionProtocolRewards`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/protocol-rewards/src/RevolutionProtocolRewards.sol) |


### Protocol rewards SLOC

| Type | File                                          | Logic Contracts | Interfaces | Lines   | nLines  | nSLOC  | Comment Lines | Complex. Score | Capabilities                                  |
| ---- | --------------------------------------------- | --------------- | ---------- | ------- | ------- | ------ | ------------- | -------------- | --------------------------------------------- |
| 🎨   | abstract/TokenEmitter/TokenEmitterRewards.sol | 1               | \*\*\*\*   | 22      | 17      | 12     | 1             | 11             | **<abbr title='Payable Functions'>💰</abbr>** |
| 🎨   | abstract/RewardSplits.sol                     | 1               | \*\*\*\*   | 93      | 88      | 64     | 7             | 33             | **<abbr title='Payable Functions'>💰</abbr>** |
| 🎨   | **Totals**                                    | **2**           | \*\*\*\*   | **115** | **105** | **76** | **8**         | **44**         | **<abbr title='Payable Functions'>💰</abbr>** |

### Revolution contracts SLOC

| Type | File   | Logic Contracts | Interfaces | Lines | nLines | nSLOC | Comment Lines | Complex. Score | Capabilities |
| ---- | ------ | --------------- | ---------- | ----- | ------ | ----- | ------------- | -------------- | ------------ | 
| 📝 | CultureIndex.sol | 1 | **** | 547 | 516 | 224 | 197 | 215 | **<abbr title='Payable Functions'>💰</abbr><abbr title='Uses Hash-Functions'>🧮</abbr><abbr title='Handles Signatures: ecrecover'>🔖</abbr>** |
| 📝 | MaxHeap.sol | 1 | **** | 185 | 185 | 88 | 66 | 68 | **<abbr title='Payable Functions'>💰</abbr>** |
| 📝 | VerbsToken.sol | 1 | **** | 332 | 324 | 139 | 125 | 125 | **<abbr title='Payable Functions'>💰</abbr><abbr title='TryCatch Blocks'>♻️</abbr>** |
| 📝 | AuctionHouse.sol | 1 | **** | 434 | 428 | 201 | 147 | 192 | **<abbr title='Uses Assembly'>🖥</abbr><abbr title='Payable Functions'>💰</abbr><abbr title='Initiates ETH Value Transfer'>📤</abbr><abbr title='TryCatch Blocks'>♻️</abbr>** |
| 📝 | ERC20TokenEmitter.sol | 1 | **** | 314 | 304 | 150 | 102 | 155 | **<abbr title='Payable Functions'>💰</abbr>** |
| 📝 | NontransferableERC20Votes.sol | 1 | **** | 158 | 151 | 56 | 71 | 48 | **<abbr title='Payable Functions'>💰</abbr>** |
| 📝 | libs/VRGDAC.sol | 1 | **** | 97 | 97 | 61 | 21 | 34 | **<abbr title='Unchecked Blocks'>Σ</abbr>** |
| 📝 | **Totals** | **7** | **** | **2067**  | **2005** | **919** | **729** | **837** | **<abbr title='Uses Assembly'>🖥</abbr><abbr title='Payable Functions'>💰</abbr><abbr title='Initiates ETH Value Transfer'>📤</abbr><abbr title='Uses Hash-Functions'>🧮</abbr><abbr title='Handles Signatures: ecrecover'>🔖</abbr><abbr title='TryCatch Blocks'>♻️</abbr><abbr title='Unchecked Blocks'>Σ</abbr>** |

## Out of scope

All the contracts not mentioned in scope including all test files.

Any issues or improvements on how we integrate with the out of scope contracts is in scope.

## Main invariants

(properties that should NEVER EVER be broken).

Only the RevolutionBuilder instance should be able to initialize the 7 in-scope contracts in the revolution-contracts package. Only the initialized owner should be able to upgrade (via [UUPS](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/libs/proxy/UUPS.sol)) the CultureIndex, MaxHeap, Descriptor, and AuctionHouse, VerbsToken contracts.

### NontransferableERC20Votes

- Only the owner should be able to directly mint tokens.

- Tokens cannot be transferred between addresses (except to mint by the owner). This includes direct transfers, transfers from, and any other mechanisms that might move tokens between different addresses.

- No address should be able to approve another address to spend tokens on its behalf, as there should be no transfer of tokens.

- Only authorized entities (owner) should be able to mint new tokens. Minted tokens should correctly increase the recipient's balance and the total supply.

- Voting power and delegation work as intended according to [Votes](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/governance/utils/Votes.sol) without enabling any form of transferability.

### Creator payments

- The ERC20TokenEmitter and AuctionHouse should always pay creators (ETH or ERC20) in accordance with the creatorRateBps and entropyRateBps calculation.

- The AuctionHouse should always pay only creator(s) of the CultureIndex art piece being auctioned and the owner.

- The ERC20TokenEmitter should always pay the `creatorsAddress`.

- ETH and ERC20 transfer functions are secure and protected with reentrancy checks / math errors.

### CultureIndex

- Anything uploaded to the CultureIndex should always be mintable by the VerbsToken contract and not disrupt the VerbsToken contract in any way.

- The voting weights calculated must be solely based on the ERC721 and ERC20 balance of the account that casts the vote.

- Accounts should not be able to vote more than once on the same art piece with the same ERC721 token in the CultureIndex.

- Accounts can not vote twice on the same art piece.

- `voteWithSig` signatures should only be valid for a one-time use.

- Only snapshotted (at art piece creation block) vote weights should be able to update the total vote weight of the art piece. eg: If you received votes after snapshot date on the art piece, you should have 0 votes.

- CultureIndex and MaxHeap, must be resilient to DoS attacks that could significantly hinder voting, art creation, or auction processes.

- An art piece that has not met quorum cannot be dropped.

### VerbsToken

- VerbsToken should only mint art pieces from the CultureIndex.

- VerbsToken should always mint the top voted art piece in the CultureIndex.

### AuctionHouse

- AuctionHouse should only auction off tokens from the VerbsToken.
- The owner of the auction should always receive it's share of ether (minus creatorRateBps share).

### MaxHeap

- The MaxHeap should always maintain the property of being a binary tree in which the value in each internal node is greater than or equal to the values in the children of that node.

### VRGDA

- The VRGDAC should always exponentially increase the price of tokens if the supply is ahead of schedule.

### ERC20TokenEmitter

- The treasury and creatorsAddress should not be able to buy tokens.

- The distribution of ERC20 governance tokens should be in accordance with the defined linear emission schedule.

- The ERC20TokenEmitter should always pay protocol rewards assuming enough ETH was paid to the buyToken function.

- The treasury should always receive it's share of ether (minus creatorRateBps and protocol rewards share).

# Additional Context

### VRGDAC

The Token Emitter utilizes a continuous VRGDA ([VRGDAC.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/libs/VRGDAC.sol)) to facilitate ERC20 token purchases. Given an amount of ether to pay, it will return the number of tokens to sell (`YtoX`), and given an amount of tokens to buy, will return the cost (`XtoY`) where X is the ERC20 token and Y is ether. The original VRGDAC implementation is [here](https://gist.github.com/transmissions11/485a6e2deb89236202bd2f59796262fd).

In order to get the amount of tokens to emit given a payment of ether (`YtoX` in [VRGDAC.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/libs/VRGDAC.sol)), we first take the integral of the linear VRGDA pricing function [p(x)](https://www.paradigm.xyz/2022/08/vrgda).

<img width="487" alt="Screenshot 2023-12-05 at 9 21 59 PM" src="https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/readme-img/vrgda-c-integral.png">

Then - we can get the cost of a specific number of tokens (`XtoY` in [VRGDAC.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/libs/VRGDAC.sol)) by doing `p_integral(x_start+x_bought) - p_integral(x_start)` where `x_start` is the current supply of the ERC20 and `x_bought` is the amount of tokens you wish to purchase.

We can then solve for `x_bought` using a handy python [solver](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/script/solve.py) to find `YtoX`, allowing us to pass in an amount of ether and receive an amount of tokens to sell.

<img width="1727" alt="Screenshot 2023-12-05 at 8 34 22 PM" src="https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/readme-img/vrgdac-graph.png">

The green line is the pricing function p(x) for a linear VRGDA. The red line is the integral of p(x), and the purple line signifies the amount of ERC20 tokens you'd receive given a payment in ether (YtoX). The relevant functions and integrals for the VRGDAC are available here: https://www.desmos.com/calculator/im67z1tate.

## Attack ideas (Where to look for bugs)

Compared to Nouns DAO, complexity arises from the auction of community created/voted art, and direct payments to creators. So - focusing on ways in which the `CultureIndex` -> `VerbsToken` -> `AuctionHouse` flow can be attacked, or DOS'd to prevent community intent from manifesting is a good start. Additionally, exploring creator governance token accumulation attack vectors is a solid start.

### Where to start

Begin by examining the access control and permissions for contracts that make up the art piece to AuctionHouse flow, such as the CultureIndex. It’s essential to ensure that access is tightly constrained and locked down to prevent unauthorized or malicious activities. Next, ensure the logic and flow of the system does not have any gaps or unexpected edge cases. This step is foundational to the system’s security and continued operation. Also, review the ERC20TokenEmitter contract's ownership and permissions to prevent governance takeover.

### [CultureIndex](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/CultureIndex.sol) attacks

Checking that the CultureIndex or the MaxHeap can not be DOS'd where voting or creating art becomes prohibitively expensive, within a reasonable attack cost (~50 ETH). Keep in mind the CultureIndex can be reset by the VerbsToken to potentially relieve some pressure.

Ensuring nothing uploaded to CultureIndex could break or otherwise disrupt the minting functionality of the VerbsToken.

Any replay attacks on `voteWithSig` signatures.

### [AuctionHouse](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol) attacks

Ensuring gas passed to the settleAndCreateNewAuction functions or other nefarious interactions with AuctionSettlement cannot brick/pause the auction.

Ensuring anything submitted to the CultureIndex cannot brick the auction by being minted. Look for large numbers of creators on art pieces as a potential attack vector.

Ensuring anything nefarious in the minting functionality of the VerbsToken contract cannot brick the auction.

### [ERC20TokenEmitter](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol) attacks

Another large distinction from Nouns is that there are 2 classes of governance shares, the ERC721 auction item (VerbsToken) and the nontransferable ERC20. These two tokens are used to vote on the CultureIndex and choose the next auction item, and in the future will be used to govern a DAO with a treasury. It is essential to explore potential ways in which the ERC20 emission from the ERC20TokenEmitter can be exploited to gain an outsized governance share.

### Creator rate attacks

The system is further complicated by the creator payments on both the AuctionHouse and the ERC20TokenEmitter. The DAO is able to unilaterally set both the `creatorRateBps` and `entropyRateBps` on both the Auction and ERC20TokenEmitter. The CultureIndex voting setup and quorum determins the creator(s) paid as part of the Auction. The DAO can set the `creatorsAddress` on the ERC20TokenEmitter. Given creators will be paid directly, ensure malicious creator contracts or a large number of creators cannot disrupt the system by eg: bricking the auction.

## Tokens used on launch and anticipated to interact with.

### ERC20

USDC, and the [NontransferableERC20Votes](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/NontransferableERC20Votes.sol)

### ERC721

[VerbsToken](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/VerbsToken.sol)

## Blockchains

Ethereum

## Trusted roles

- Trusted roles (e.g. operators, slashers, pausers, etc.), the privileges they hold, and any conditions under which privilege escalation is expected/allowable

[RevolutionBuilder](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/builder/RevolutionBuilder.sol) manages upgrades and deployments for the set of 7 contracts in the scope. Only the RevolutionBuilder instance should be able to initialize the 7 contracts in the revolution-contracts package scope. Privilege escalation is not allowed, everything should be managed by the RevolutionBuilder contract.

VerbsToken has a descriptor, minter, and CultureIndex. The minter is assumed to be always set to the AuctionHouse contract, and should have complete and sole control over the token minting functionality.

CultureIndex has a `dropperAdmin` address set on initialize that has exclusive and locked control of dropping pieces from the CultureIndex. 

MaxHeap has an `admin` address set on initialize that has exclusive and locked control of updating the MaxHeap data structure.

VerbsDAOLogicV1 (outside scope) is assumed to be the owner of all contracts (CultureIndex, MaxHeap, Descriptor, ERC20TokenEmitter, NontransferableERC20Votes, and VerbsToken) and is able to upgrade via [UUPS](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/libs/proxy/UUPS.sol) the CultureIndex, MaxHeap, Descriptor, AuctionHouse, and VerbsToken.

## DOS

Minimum duration after which we would consider a DOS finding to be valid?

DOS on CultureIndex: 20m

## EIP conformity

- [VerbsToken](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/VerbsToken.sol): Should comply with `ERC721`
- [NontransferableERC20Votes](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/NontransferableERC20Votes.sol): Should comply with `ERC20`

## Scoping Details

```
- If you have a public code repo, please share it here: https://github.com/code-423n4/2023-12-revolutionprotocol/tree/main/packages/revolution, https://github.com/code-423n4/2023-12-revolutionprotocol/tree/main/packages/protocol-rewards
- How many contracts are in scope?: 9
- Total SLoC for these contracts?: 1000
- How many external imports are there?: 14
- How many separate interfaces and struct definitions are there for the contracts within scope?: 13
- Does most of your code generally use composition or inheritance?: Inheritance
- How many external calls?: 4
- What is the overall line coverage percentage provided by your tests?: 88
- Is this an upgrade of an existing system?:

True - We're upgrading Nouns DAO so that the auction item is a piece of community created art, voted on by the community. Additionally, we are issuing an ERC20 governance token to the creator and splitting the auction proceeds with the creator of the art.

- Check all that apply (e.g. timelock, NFT, AMM, ERC20, rollups, etc.): NFT, Uses L2, ERC-20 Token
- Is there a need to understand a separate part of the codebase / get context in order to audit this part of the protocol?: RevolutionBuilder for a look at the deployment and upgrade lifecycle
- Please describe required context:
- Does it use an oracle?: No
- Describe any novel or unique curve logic or mathematical models your code uses: We use a continuous VRGDA function, built by Paradigm (https://www.paradigm.xyz/2022/08/vrgda). It enables a linear emission of ERC20 tokens over time.
- Is this either a fork of or an alternate implementation of another project?: True
- Does it use a side-chain?:
- Describe any specific areas you would like addressed:
```
