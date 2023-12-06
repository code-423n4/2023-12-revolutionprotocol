
# Repo setup

## ⭐️ Sponsor: Add code to this repo

- [ ] Create a PR to this repo with the below changes:
- [ ] Provide a self-contained repository with working commands that will build (at least) all in-scope contracts, and commands that will run tests producing gas reports for the relevant contracts.
- [ ] Make sure your code is thoroughly commented using the [NatSpec format](https://docs.soliditylang.org/en/v0.5.10/natspec-format.html#natspec-format).
- [ ] Please have final versions of contracts and documentation added/updated in this repo **no less than 48 business hours prior to audit start time.**
- [ ] Be prepared for a 🚨code freeze🚨 for the duration of the audit — important because it establishes a level playing field. We want to ensure everyone's looking at the same code, no matter when they look during the audit. (Note: this includes your own repo, since a PR can leak alpha to our wardens!)


---

## ⭐️ Sponsor: Edit this `README.md` file

- [ ] Modify the contents of this `README.md` file. Describe how your code is supposed to work with links to any relevent documentation and any other criteria/details that the C4 Wardens should keep in mind when reviewing. ([Here's a well-constructed example.](https://github.com/code-423n4/2022-08-foundation#readme))
- [ ] Review the Gas award pool amount. This can be adjusted up or down, based on your preference - just flag it for Code4rena staff so we can update the pool totals across all comms channels.
- [ ] Optional / nice to have: pre-record a high-level overview of your protocol (not just specific smart contract functions). This saves wardens a lot of time wading through documentation.
- [ ] [This checklist in Notion](https://code4rena.notion.site/Key-info-for-Code4rena-sponsors-f60764c4c4574bbf8e7a6dbd72cc49b4#0cafa01e6201462e9f78677a39e09746) provides some best practices for Code4rena audits.

## ⭐️ Sponsor: Final touches
- [ ] Review and confirm the details in the section titled "Scoping details" and alert Code4rena staff of any changes.
- [ ] Check that images and other files used in this README have been uploaded to the repo as a file and then linked in the README using absolute path (e.g. `https://github.com/code-423n4/yourrepo-url/filepath.png`)
- [ ] Ensure that *all* links and image/file paths in this README use absolute paths, not relative paths
- [ ] Check that all README information is in markdown format (HTML does not render on Code4rena.com)
- [ ] Remove any part of this template that's not relevant to the final version of the README (e.g. instructions in brackets and italic)
- [ ] Delete this checklist and all text above the line below when you're ready.

---

# Collective audit details
- Total Prize Pool: $36,500 USDC
  - HM awards: $24,750 USDC
  - Analysis awards: $1,500 USDC
  - QA awards: $750 USDC
  - Bot Race awards: $2,250 USDC
  - Gas awards: $750 USDC
  - Judge awards: $3,600 USDC
  - Lookout awards: $2,400 USDC
  - Scout awards: $500 USD
- Join [C4 Discord](https://discord.gg/code4rena) to register
- Submit findings [using the C4 form](https://code4rena.com/2023-12-collective/submit)
- [Read our guidelines for more details](https://docs.code4rena.com/roles/wardens)
- Starts December 11, 20:00 UTC
- Ends December 20, 20:00 UTC

## Automated Findings / Publicly Known Issues

The 4naly3er report can be found [here](https://github.com/code-423n4/2023-12-collective/blob/main/4naly3er-report.md).

Automated findings output for the audit can be found [here](https://github.com/code-423n4/2023-12-collectiveblob/main/bot-report.md) within 24 hours of audit opening.

_Note for C4 wardens: Anything included in this `Automated Findings / Publicly Known Issues` section is considered a publicly known issue and is ineligible for awards._

[ ⭐️ SPONSORS: Are there any known issues or risks deemed acceptable that shouldn't lead to a valid finding? If so, list them here. ]


# Overview
# the Revolution protocol ⌐◨-◨

## intro
Revolution is a set of contracts that improve on [Nouns DAO](https://github.com/nounsDAO/nouns-monorepo). Nouns is a generative avatar collective that auctions off one ERC721, every day, forever. 100% of the proceeds of each auction (the winning bid) go into a shared treasury, and owning an NFT gets you 1 vote over the treasury. 

Compared to Nouns, Revolution seeks to make governance token ownership more accessible to creators and builders, and balance the scales between culture and capital while committing to a constant governance inflation schedule. 

The ultimate goal of Revolution is fair ownership distribution over a community movement where anyone can earn decision making power over the energy of the movement.

## overview
In Revolution, instead of [auctioning](https://nouns.wtf/) off a generative PFP, anyone can upload art pieces to the [CultureIndex](https://github.com/code-423n4/2023-12-collective/blob/main/packages/revolution-contracts/src/CultureIndex.sol) contract, and the community votes on their favorite art pieces. The top piece is auctioned off every day via the [AuctionHouse](https://github.com/collectivexyz/revolution-protocol/blob/main/packages/revolution-contracts/src/VerbsAuctionHouse.sol). 

A portion of the auction proceeds is split with the creator(s) of the art piece, and the rest is sent to the DAO treasury. The winner of the auction receives an ERC721 of the art piece, and the creator receives an amount of ERC20 governance tokens and ether. Both the ERC721 and the ERC20 governance token have voting power to vote on art pieces in the **CultureIndex**. 

## relevant contracts

### CultureIndex
[**CultureIndex.sol**](https://github.com/collectivexyz/revolution-protocol/blob/main/packages/revolution-contracts/src/CultureIndex.sol) is a directory of uploaded art pieces that anyone can add media to. Owners of a specific ERC721 or ERC20 can vote on any given art piece. The art piece votes data is stored in [**MaxHeap.sol**](https://github.com/collectivexyz/revolution-protocol/blob/main/packages/revolution-contracts/src/MaxHeap.sol), a heap datastructure that enables O(1) lookups of the highest voted art piece. 

The contract has a function called **dropTopVotedPiece**, only callable by the owner, which pops (removes) the top voted item from the **MaxHeap** and returns it. 

### VerbsToken
[**VerbsToken.sol**](https://github.com/collectivexyz/revolution-protocol/blob/main/packages/revolution-contracts/src/VerbsToken.sol) is a fork of the [NounsToken](https://github.com/nounsDAO/nouns-monorepo/blob/master/packages/nouns-contracts/contracts/NounsToken.sol) contract. **VerbsToken** owns the **CultureIndex**. When calling **mint()** on the **VerbsToken**, the contract calls **dropTopVotedPiece** on **CultureIndex**, and creates the ERC721 metadata based on the returned data from the CultureIndex. 

### AuctionHouse
[**VerbsAuctionHouse.sol**](https://github.com/collectivexyz/revolution-protocol/blob/main/packages/revolution-contracts/src/VerbsAuctionHouse.sol) is a fork of the [NounsAuctionHouse](https://github.com/nounsDAO/nouns-monorepo/blob/master/packages/nouns-contracts/contracts/NounsAuctionHouse.sol) contract, that mints **VerbsToken**s. Additionally, the **AuctionHouse** splits proceeds of the auction (the amount paid by the winning bidder) with the creator(s) of the art piece that is minted.

#### Creator payment
The **creatorRateBps** defines the proportion (in basis points) of the auction proceeds that is reserved for the creator(s) of the art piece, called the _creator's share_. The **entropyRateBps** defines the proportion of the _creator's share_ that is sent to the creator directly in ether. The remaining amount of the _creator's share_ is sent to the [TokenEmitter](https://github.com/collectivexyz/revolution-protocol/blob/main/packages/revolution-contracts/src/TokenEmitter.sol) contract's **buyToken** function to buy the creator ERC20 governance tokens, according to a linear token emission schedule.

### TokenEmitter
**[TokenEmitter.sol](https://github.com/collectivexyz/revolution-protocol/blob/main/packages/revolution-contracts/src/TokenEmitter.sol)** is a linear VRGDA that mints an ERC20 token when the payable **buyToken** function is called, and enables anyone to purchase the ERC20 governance token at any time.

You can read more about VRGDA's [here](https://www.paradigm.xyz/2022/08/vrgda), and view the implementation for NFTs [here](https://github.com/transmissions11/VRGDAs). Basically, a VRGDA contract dynamically adjusts the price of a token to adhere to a specific issuance schedule. 

<img width="903" alt="Screenshot 2023-12-05 at 8 31 54 PM" src="https://github.com/code-423n4/2023-12-revolutionprotocol/assets/20303031/86b23fbf-3095-41bd-b0f5-f885c46d1772">

You can read more about the implementation on [Paradigm's site](https://www.paradigm.xyz/2022/08/vrgda). 

The Token Emitter utilizes a continuous VRGDA (VRGDAC) to facilitate ERC20 token purchases. Given an amount of ether to pay, it will return the number of tokens to sell (YtoX), and given an amount of tokens to buy, will return the cost (XtoY) where x is the ERC20 token and Y is ether as defined in [VRGDAC.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/libs/VRGDAC.sol). The original VRGDAC implementation is [here](https://gist.github.com/transmissions11/485a6e2deb89236202bd2f59796262fd). 

In order to get the amount of tokens to emit given a payment of ether (YtoX in [VRGDAC.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/libs/VRGDAC.sol)), we first take the integral of the linear VRGDA pricing function p(x). Then - we can get the cost of a specific number of tokens (XtoY in [VRGDAC.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/libs/VRGDAC.sol)) by doing p_integral(x_start+x_bought) - p_integral(x_start) where x_start is the current supply of the ERC20 and x_bought is the amount of tokens you wish to purchase. We can then solve for x_bought using a handy python [solver](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/script/solve.py) to find YtoX, allowing us to pass in an amount of ether and receive an amount of tokens to sell.

<img width="1727" alt="Screenshot 2023-12-05 at 8 34 22 PM" src="https://github.com/code-423n4/2023-12-revolutionprotocol/assets/20303031/d38b7e81-9c7f-4210-a146-65dcfab933b1">
The green line is the pricing function p(x) for a linear VRGDA. The red line is the integral of p(x), and the purple line signifies the amount of ERC20 tokens you'd receive given a payment in ether. The relevant functions and integrals for the VRGDAC are available [here.](https://www.desmos.com/calculator/im67z1tate) 


#### Creator payment
The contract has a **creatorRateBps** and **entropyRateBps** that function the same as the **AuctionHouse** contract's. Whenever a **buyToken** purchase of governance tokens is made, a **creatorRateBps** portion of the proceeds is reserved for the **creatorsAddress** set in the contract, with direct payment calculated according to the **entropyRateBps**.

#### Protocol rewards
A fixed percentage of the value sent to the **buyToken** function is paid to the **TokenEmitterRewards** contract. The rewards setup is modeled after Zora's _fixed_ [protocol rewards](https://github.com/ourzora/zora-protocol/tree/main/packages/protocol-rewards). The key difference is that instead of a _fixed_ amount of ETH being split between the creator, builder, referrer, deployer, and architect, the **TokenEmitterRewards** system splits a percentage of the value to relevant parties. 


## Links

- **Previous audits:** 
N/A
- **Twitter:**
[@collectivexyz](https://twitter.com/collectivexyz) and [@vrbsdao](https://twitter.com/vrbsdao)


# Scope

[ ⭐️ SPONSORS: add scoping and technical details here ]

- [ ] In the table format shown below, provide the name of each contract and:
  - [ ] source lines of code (excluding blank lines and comments) in each *For line of code counts, we recommend running prettier with a 100-character line length, and using [cloc](https://github.com/AlDanial/cloc).* 
  - [ ] external contracts called in each
  - [ ] libraries used in each

*List all files in scope in the table below (along with hyperlinks) -- and feel free to add notes here to emphasize areas of focus.*

| Contract | SLOC | Purpose | Libraries used |  
| ----------- | ----------- | ----------- | ----------- |
| [MaxHeap.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/MaxHeap.sol) | 68 | Implements a [MaxHeap](https://www.geeksforgeeks.org/introduction-to-max-heap-data-structure/) data structure for O(1) max value retrieval | [`@openzeppelin/contracts`](https://openzeppelin.com/contracts/) |
| [CultureIndex.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/CultureIndex.sol) | 203 | Creation and weighted token voting of community art pieces | [`@openzeppelin/contracts`](https://openzeppelin.com/contracts/) [`ERC20Votes`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/base/erc20/ERC20Votes.sol) [`ERC721Checkpointable`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/base/ERC721Checkpointable.sol) |
| [NontransferableERC20Votes.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/NontransferableERC20Votes.sol) | 41 | A nontransferable ERC20 Votes token | [`@openzeppelin/contracts`](https://openzeppelin.com/contracts/) [`ERC20Votes`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/base/erc20/ERC20Votes.sol) |
| [TokenEmitter.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/TokenEmitter.sol) | 120 | Continuous linear VRGDA for purchasing ERC20 tokens with ether | [`@openzeppelin/contracts`](https://openzeppelin.com/contracts/) [`VRGDAC`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/libs/VRGDAC.sol) [`TokenEmitterRewards`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol) [`SignedWadMath`](https://github.com/transmissions11/solmate/blob/main/src/utils/SignedWadMath.sol)  |
| [VerbsAuctionHouse.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/VerbsAuctionHouse.sol) | 167 | AuctionHouse for selling ERC721s and paying creators | [`@openzeppelin/contracts-upgradeable`](https://openzeppelin.com/contracts/)|
| [VerbsDescriptor.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/VerbsDescriptor.sol) | 63 | Token metadata library | [`@openzeppelin/contracts`](https://openzeppelin.com/contracts/) |
| [VerbsToken.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/VerbsToken.sol) | 131 | The ERC721 that mints from the top *CultureIndex* art piece | [`@openzeppelin/contracts`](https://openzeppelin.com/contracts/) [`ERC721Checkpointable`](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/base/ERC721Checkpointable.sol) |
| [libs/VRGDAC.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution-contracts/src/libs/VRGDAC.sol) | 49 | The continuous linear VRGDA used for ERC20 token emission | [`SignedWadMath`](https://github.com/transmissions11/solmate/blob/main/src/utils/SignedWadMath.sol) ||
| [RevolutionProtocolRewards.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/protocol-rewards/src/RevolutionProtocolRewards.sol) | 108 | Manager of deposits and rewards for protocol rewards | [`@openzeppelin/contracts`](https://openzeppelin.com/contracts/) ||
| [TokenEmitterRewards.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol) | 11 | Compute rewards and deposit for the *TokenEmitter* | N/A |
| [RewardSplits.sol](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/protocol-rewards/src/abstract/RewardSplits.sol) | 68 | Compute and deposit rewards based on splits | N/A |


## Out of scope

All the contracts not mentioned in scope including all test files


# Additional Context

- [ ] Describe any novel or unique curve logic or mathematical models implemented in the contracts
- [ ] Please list specific ERC20 that your protocol is anticipated to interact with. Could be "any" (literally anything, fee on transfer tokens, ERC777 tokens and so forth) or a list of tokens you envision using on launch.
- [ ] Please list specific ERC721 that your protocol is anticipated to interact with.
- [ ] Which blockchains will this code be deployed to, and are considered in scope for this audit?
- [ ] Please list all trusted roles (e.g. operators, slashers, pausers, etc.), the privileges they hold, and any conditions under which privilege escalation is expected/allowable
- [ ] In the event of a DOS, could you outline a minimum duration after which you would consider a finding to be valid? This question is asked in the context of most systems' capacity to handle DoS attacks gracefully for a certain period.
- [ ] Is any part of your implementation intended to conform to any EIP's? If yes, please list the contracts in this format: 
  - `Contract1`: Should comply with `ERC/EIPX`
  - `Contract2`: Should comply with `ERC/EIPY`

## Attack ideas (Where to look for bugs)
*List specific areas to address - see [this blog post](https://medium.com/code4rena/the-security-council-elections-within-the-arbitrum-dao-a-comprehensive-guide-aa6d001aae60#9adb) for an example*

## Main invariants
*Describe the project's main invariants (properties that should NEVER EVER be broken).*

## Scoping Details 
[ ⭐️ SPONSORS: please confirm/edit the information below. ]

```
- If you have a public code repo, please share it here: https://github.com/collectivexyz/revolution-protocol/tree/main/packages/revolution-contracts, https://github.com/collectivexyz/revolution-protocol/tree/main/packages/protocol-rewards 
- How many contracts are in scope?: 11   
- Total SLoC for these contracts?: 1000  
- How many external imports are there?: 13  
- How many separate interfaces and struct definitions are there for the contracts within scope?: 13  
- Does most of your code generally use composition or inheritance?: Inheritance   
- How many external calls?: 1   
- What is the overall line coverage percentage provided by your tests?: 73
- Is this an upgrade of an existing system?: True - We're upgrading Nouns DAO so that the auction item is a piece of community created media, voted on by the community. Additionally, we are issuing an ERC20 governance token to the creator and splitting the auction proceeds with the creator.
- Check all that apply (e.g. timelock, NFT, AMM, ERC20, rollups, etc.): NFT, Uses L2, ERC-20 Tokeen
- Is there a need to understand a separate part of the codebase / get context in order to audit this part of the protocol?: False  
- Please describe required context:   
- Does it use an oracle?: No
- Describe any novel or unique curve logic or mathematical models your code uses: We use a continuous VRGDA function, built by Paradigm (https://www.paradigm.xyz/2022/08/vrgda). It enables a linear emission of ERC20 tokens over time. 
- Is this either a fork of or an alternate implementation of another project?: True  
- Does it use a side-chain?:
- Describe any specific areas you would like addressed:
```

# Tests

*Provide every step required to build the project from a fresh git clone, as well as steps to run the tests with a gas report.* 

*Note: Many wardens run Slither as a first pass for testing.  Please document any known errors with no workaround.* 
