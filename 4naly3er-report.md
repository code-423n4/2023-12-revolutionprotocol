# Nothing to see here… *yet*

# Report


## Gas Optimizations


| |Issue|Instances|
|-|:-|:-:|
| [GAS-1](#GAS-1) | Using bools for storage incurs overhead | 7 |
| [GAS-2](#GAS-2) | Cache array length outside of loop | 11 |
| [GAS-3](#GAS-3) | Use calldata instead of memory for function arguments that do not get mutated | 6 |
| [GAS-4](#GAS-4) | For Operations that will not overflow, you could use unchecked | 519 |
| [GAS-5](#GAS-5) | Use Custom Errors | 136 |
| [GAS-6](#GAS-6) | Don't initialize variables with default value | 19 |
| [GAS-7](#GAS-7) | Long revert strings | 82 |
| [GAS-8](#GAS-8) | Functions guaranteed to revert when called by normal users can be marked `payable` | 31 |
| [GAS-9](#GAS-9) | `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too) | 16 |
| [GAS-10](#GAS-10) | Using `private` rather than `public` for constants, saves gas | 26 |
| [GAS-11](#GAS-11) | Use shift Right/Left instead of division/multiplication if possible | 4 |
| [GAS-12](#GAS-12) | Splitting require() statements that use && saves gas | 7 |
| [GAS-13](#GAS-13) | Use != 0 instead of > 0 for unsigned integer comparison | 32 |
### <a name="GAS-1"></a>[GAS-1] Using bools for storage incurs overhead
Use uint256(1) and uint256(2) for true/false to avoid a Gwarmaccess (100 gas), and to avoid Gsset (20000 gas) when changing from ‘false’ to ‘true’, after having been ‘true’ in the past. See [source](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/58f635312aa21f947cae5f8578638a85aa2519f5/contracts/security/ReentrancyGuard.sol#L23-L27).

*Instances (7)*:
```solidity
File: CultureIndex.sol

22:     bool public isERC721VotingTokenLocked;

```

```solidity
File: VerbsDescriptor.sol

34:     bool public override isDataURIEnabled = true;

```

```solidity
File: VerbsToken.sol

41:     bool public isMinterLocked;

44:     bool public isCultureIndexLocked;

47:     bool public isDescriptorLocked;

```

```solidity
File: base/ERC721.sol

68:     mapping(address => mapping(address => bool)) private _operatorApprovals;

```

```solidity
File: governance/VerbsDAOExecutor.sol

49:     mapping(bytes32 => bool) public queuedTransactions;

```

### <a name="GAS-2"></a>[GAS-2] Cache array length outside of loop
If not cached, the solidity compiler will always read the length of the array during each iteration. That is, if it is a storage array, this is an extra sload operation (100 additional extra gas for each iteration except for the first) and if it is a memory array, this is an extra mload operation (3 additional gas for each iteration except for the first).

*Instances (11)*:
```solidity
File: CultureIndex.sol

150:         for (uint i = 0; i < creatorArray.length; i++) {

193:         for (uint i = 0; i < creatorArray.length; i++) {

211:         for (uint i = 0; i < creatorArray.length; i++) {

305:         for (uint256 i = 0; i < pieceIds.length; ++i) {

397:             for (uint i = 0; i < pieces[pieceId].creators.length; i++) {

```

```solidity
File: TokenEmitter.sol

120:             for (uint i = 0; i < _addresses.length; i++) {

```

```solidity
File: VerbsToken.sol

264:             for (uint i = 0; i < artPiece.creators.length; i++) {

```

```solidity
File: governance/VerbsDAOLogicV1.sol

277:         for (uint256 i = 0; i < proposal.targets.length; i++) {

300:         for (uint256 i = 0; i < proposal.targets.length; i++) {

348:         for (uint256 i = 0; i < proposal.targets.length; i++) {

375:         for (uint256 i = 0; i < proposal.targets.length; i++) {

```

### <a name="GAS-3"></a>[GAS-3] Use calldata instead of memory for function arguments that do not get mutated
Mark data types as `calldata` instead of `memory` where possible. This makes it so that the data is not automatically loaded into memory. If the data passed into the function does not need to be changed (like updating values in an array), it can be passed in as `calldata`. The one exception to this is if the argument must later be passed into another function that takes an argument that specifies `memory` storage.

*Instances (6)*:
```solidity
File: governance/VerbsDAOExecutor.sol

94:     function cancelTransaction(address target, uint256 value, string memory signature, bytes memory data, uint256 eta) public {

94:     function cancelTransaction(address target, uint256 value, string memory signature, bytes memory data, uint256 eta) public {

104:         require(msg.sender == admin, "VerbsDAOExecutor::executeTransaction: Call must come from admin.");

104:         require(msg.sender == admin, "VerbsDAOExecutor::executeTransaction: Call must come from admin.");

109:         require(getBlockTimestamp() <= eta + GRACE_PERIOD, "VerbsDAOExecutor::executeTransaction: Transaction is stale.");

109:         require(getBlockTimestamp() <= eta + GRACE_PERIOD, "VerbsDAOExecutor::executeTransaction: Transaction is stale.");

```

### <a name="GAS-4"></a>[GAS-4] For Operations that will not overflow, you could use unchecked

*Instances (519)*:
```solidity
File: CultureIndex.sol

4: import { ERC20Votes } from "./base/erc20/ERC20Votes.sol";

4: import { ERC20Votes } from "./base/erc20/ERC20Votes.sol";

4: import { ERC20Votes } from "./base/erc20/ERC20Votes.sol";

5: import { MaxHeap } from "./MaxHeap.sol";

6: import { ICultureIndex } from "./interfaces/ICultureIndex.sol";

6: import { ICultureIndex } from "./interfaces/ICultureIndex.sol";

7: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

7: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

7: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

8: import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

8: import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

8: import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

9: import { ERC721Checkpointable } from "./base/ERC721Checkpointable.sol";

9: import { ERC721Checkpointable } from "./base/ERC721Checkpointable.sol";

28:     uint256 public constant MIN_QUORUM_VOTES_BPS = 200; // 200 basis points or 2%

28:     uint256 public constant MIN_QUORUM_VOTES_BPS = 200; // 200 basis points or 2%

31:     uint256 public constant MAX_QUORUM_VOTES_BPS = 4_000; // 4,000 basis points or 40%

31:     uint256 public constant MAX_QUORUM_VOTES_BPS = 4_000; // 4,000 basis points or 40%

150:         for (uint i = 0; i < creatorArray.length; i++) {

150:         for (uint i = 0; i < creatorArray.length; i++) {

152:             totalBps += creatorArray[i].bps;

178:         uint256 pieceId = _currentPieceId++;

178:         uint256 pieceId = _currentPieceId++;

191:         newPiece.quorumVotes = (quorumVotesBPS * newPiece.totalVotesSupply) / 10_000;

191:         newPiece.quorumVotes = (quorumVotesBPS * newPiece.totalVotesSupply) / 10_000;

193:         for (uint i = 0; i < creatorArray.length; i++) {

193:         for (uint i = 0; i < creatorArray.length; i++) {

211:         for (uint i = 0; i < creatorArray.length; i++) {

211:         for (uint i = 0; i < creatorArray.length; i++) {

252:         return erc20Balance + (erc721Balance * erc721VotingTokenWeight * 1e18);

252:         return erc20Balance + (erc721Balance * erc721VotingTokenWeight * 1e18);

252:         return erc20Balance + (erc721Balance * erc721VotingTokenWeight * 1e18);

278:         totalVoteWeights[pieceId] += weight;

305:         for (uint256 i = 0; i < pieceIds.length; ++i) {

305:         for (uint256 i = 0; i < pieceIds.length; ++i) {

380:         return (quorumVotesBPS * _calculateVoteWeight(erc20VotingToken.totalSupply(), erc721VotingToken.totalSupply())) / 10_000;

380:         return (quorumVotesBPS * _calculateVoteWeight(erc20VotingToken.totalSupply(), erc721VotingToken.totalSupply())) / 10_000;

397:             for (uint i = 0; i < pieces[pieceId].creators.length; i++) {

397:             for (uint i = 0; i < pieces[pieceId].creators.length; i++) {

403:             string memory reason // Catch known revert reason

403:             string memory reason // Catch known revert reason

408:             revert(reason); // Revert with the original error if not matched

408:             revert(reason); // Revert with the original error if not matched

410:             bytes memory /*lowLevelData*/ // Catch any other low-level failures

410:             bytes memory /*lowLevelData*/ // Catch any other low-level failures

410:             bytes memory /*lowLevelData*/ // Catch any other low-level failures

410:             bytes memory /*lowLevelData*/ // Catch any other low-level failures

410:             bytes memory /*lowLevelData*/ // Catch any other low-level failures

410:             bytes memory /*lowLevelData*/ // Catch any other low-level failures

410:             bytes memory /*lowLevelData*/ // Catch any other low-level failures

```

```solidity
File: MaxHeap.sol

4: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

4: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

4: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

5: import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

5: import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

5: import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

31:         return (pos - 1) / 2;

31:         return (pos - 1) / 2;

46:         uint256 left = 2 * pos + 1;

46:         uint256 left = 2 * pos + 1;

47:         uint256 right = 2 * pos + 2;

47:         uint256 right = 2 * pos + 2;

53:         if (pos >= (size / 2) && pos <= size) return;

72:         valueMapping[itemId] = value; // Update the value mapping

72:         valueMapping[itemId] = value; // Update the value mapping

73:         positionMapping[itemId] = size; // Update the position mapping

73:         positionMapping[itemId] = size; // Update the position mapping

80:         size++;

80:         size++;

101:         } else if (newValue < oldValue) maxHeapify(position); // Downwards heapify  

101:         } else if (newValue < oldValue) maxHeapify(position); // Downwards heapify  

111:         heap[0] = heap[--size];

111:         heap[0] = heap[--size];

```

```solidity
File: NontransferableERC20Votes.sol

20: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

20: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

20: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

21: import { ERC20Votes } from "./base/erc20/ERC20Votes.sol";

21: import { ERC20Votes } from "./base/erc20/ERC20Votes.sol";

21: import { ERC20Votes } from "./base/erc20/ERC20Votes.sol";

22: import { ERC20 } from "./base/erc20/ERC20.sol";

22: import { ERC20 } from "./base/erc20/ERC20.sol";

22: import { ERC20 } from "./base/erc20/ERC20.sol";

23: import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

23: import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

23: import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

23: import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

```

```solidity
File: TokenEmitter.sol

4: import { VRGDAC } from "./libs/VRGDAC.sol";

4: import { VRGDAC } from "./libs/VRGDAC.sol";

5: import { toDaysWadUnsafe } from "./libs/SignedWadMath.sol";

5: import { toDaysWadUnsafe } from "./libs/SignedWadMath.sol";

6: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

6: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

6: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

7: import { NontransferableERC20Votes } from "./NontransferableERC20Votes.sol";

8: import { ITokenEmitter } from "./interfaces/ITokenEmitter.sol";

8: import { ITokenEmitter } from "./interfaces/ITokenEmitter.sol";

9: import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

9: import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

9: import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

10: import { TokenEmitterRewards } from "@collectivexyz/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol";

10: import { TokenEmitterRewards } from "@collectivexyz/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol";

10: import { TokenEmitterRewards } from "@collectivexyz/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol";

10: import { TokenEmitterRewards } from "@collectivexyz/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol";

10: import { TokenEmitterRewards } from "@collectivexyz/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol";

10: import { TokenEmitterRewards } from "@collectivexyz/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol";

11: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

11: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

11: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

42:         int _targetPrice, // The target price for a token if sold on pace, scaled by 1e18.

42:         int _targetPrice, // The target price for a token if sold on pace, scaled by 1e18.

43:         int _priceDecayPercent, // The percent price decays per unit of time with no sales, scaled by 1e18.

43:         int _priceDecayPercent, // The percent price decays per unit of time with no sales, scaled by 1e18.

44:         int _tokensPerTimeUnit // The number of tokens to target selling in 1 full unit of time, scaled by 1e18.

44:         int _tokensPerTimeUnit // The number of tokens to target selling in 1 full unit of time, scaled by 1e18.

88:         uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;

88:         uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;

88:         uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;

92:         uint256 creatorDirectPayment = ((msgValueRemaining - toPayTreasury) * entropyRateBps) / 10_000;

92:         uint256 creatorDirectPayment = ((msgValueRemaining - toPayTreasury) * entropyRateBps) / 10_000;

92:         uint256 creatorDirectPayment = ((msgValueRemaining - toPayTreasury) * entropyRateBps) / 10_000;

94:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0 ? getTokenQuoteForEther((msgValueRemaining - toPayTreasury) - creatorDirectPayment) : int(0);

94:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0 ? getTokenQuoteForEther((msgValueRemaining - toPayTreasury) - creatorDirectPayment) : int(0);

94:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0 ? getTokenQuoteForEther((msgValueRemaining - toPayTreasury) - creatorDirectPayment) : int(0);

94:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0 ? getTokenQuoteForEther((msgValueRemaining - toPayTreasury) - creatorDirectPayment) : int(0);

100:         emittedTokenWad += totalTokensForBuyers;

101:         if (totalTokensForCreators > 0) emittedTokenWad += totalTokensForCreators;

120:             for (uint i = 0; i < _addresses.length; i++) {

120:             for (uint i = 0; i < _addresses.length; i++) {

122:                 _mint(_addresses[i], uint((totalTokensForBuyers * int(_bps[i])) / 10_000));

122:                 _mint(_addresses[i], uint((totalTokensForBuyers * int(_bps[i])) / 10_000));

123:                 sum += _bps[i];

133:             msg.value - msgValueRemaining,

146:         return xToY({ timeSinceStart: toDaysWadUnsafe(block.timestamp - startTime), sold: emittedTokenWad, amount: int(amount) });

153:         return yToX({ timeSinceStart: toDaysWadUnsafe(block.timestamp - startTime), sold: emittedTokenWad, amount: int(etherAmount) });

162:                 timeSinceStart: toDaysWadUnsafe(block.timestamp - startTime),

164:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)

164:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)

164:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)

164:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)

```

```solidity
File: VerbsAuctionHouse.sol

26: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

26: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

26: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

26: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

27: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

27: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

27: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

27: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

28: import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

28: import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

28: import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

28: import { OwnableUpgradeable } from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

29: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

29: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

29: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

29: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

30: import { IVerbsAuctionHouse } from "./interfaces/IVerbsAuctionHouse.sol";

30: import { IVerbsAuctionHouse } from "./interfaces/IVerbsAuctionHouse.sol";

31: import { IVerbsToken } from "./interfaces/IVerbsToken.sol";

31: import { IVerbsToken } from "./interfaces/IVerbsToken.sol";

32: import { IWETH } from "./interfaces/IWETH.sol";

32: import { IWETH } from "./interfaces/IWETH.sol";

33: import { ITokenEmitter } from "./interfaces/ITokenEmitter.sol";

33: import { ITokenEmitter } from "./interfaces/ITokenEmitter.sol";

34: import { ICultureIndex } from "./interfaces/ICultureIndex.sol";

34: import { ICultureIndex } from "./interfaces/ICultureIndex.sol";

138:         require(msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100), "Must send more than last bid by minBidIncrementPercentage amount");

138:         require(msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100), "Must send more than last bid by minBidIncrementPercentage amount");

138:         require(msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100), "Must send more than last bid by minBidIncrementPercentage amount");

146:         bool extended = _auction.endTime - block.timestamp < timeBuffer;

147:         if (extended) auction.endTime = _auction.endTime = block.timestamp + timeBuffer;

261:             uint256 endTime = startTime + duration;

295:             uint256 auctioneerPayment = (_auction.amount * (10_000 - creatorRateBps)) / 10_000;

295:             uint256 auctioneerPayment = (_auction.amount * (10_000 - creatorRateBps)) / 10_000;

295:             uint256 auctioneerPayment = (_auction.amount * (10_000 - creatorRateBps)) / 10_000;

298:             uint256 creatorPayment = _auction.amount - auctioneerPayment;

301:             uint256 creatorDirectPayment = (creatorPayment * entropyRateBps) / 10_000;

301:             uint256 creatorDirectPayment = (creatorPayment * entropyRateBps) / 10_000;

304:             uint256 creatorGovernancePayment = creatorPayment - creatorDirectPayment;

317:             for (uint256 i = 0; i < numCreators; i++) {

317:             for (uint256 i = 0; i < numCreators; i++) {

323:                 uint256 etherAmount = (creatorPayment * entropyRateBps * creator.bps) / (10_000 * 10_000);

323:                 uint256 etherAmount = (creatorPayment * entropyRateBps * creator.bps) / (10_000 * 10_000);

323:                 uint256 etherAmount = (creatorPayment * entropyRateBps * creator.bps) / (10_000 * 10_000);

323:                 uint256 etherAmount = (creatorPayment * entropyRateBps * creator.bps) / (10_000 * 10_000);

```

```solidity
File: VerbsDescriptor.sol

20: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

20: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

20: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

21: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

21: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

21: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

22: import { IVerbsDescriptor } from "./interfaces/IVerbsDescriptor.sol";

22: import { IVerbsDescriptor } from "./interfaces/IVerbsDescriptor.sol";

23: import { Base64 } from "@openzeppelin/contracts/utils/Base64.sol";

23: import { Base64 } from "@openzeppelin/contracts/utils/Base64.sol";

23: import { Base64 } from "@openzeppelin/contracts/utils/Base64.sol";

24: import { ICultureIndex } from "./interfaces/ICultureIndex.sol";

24: import { ICultureIndex } from "./interfaces/ICultureIndex.sol";

71:         return string(abi.encodePacked("data:application/json;base64,", Base64.encode(bytes(json))));

```

```solidity
File: VerbsToken.sol

20: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

20: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

20: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

21: import { ERC721Checkpointable } from "./base/ERC721Checkpointable.sol";

21: import { ERC721Checkpointable } from "./base/ERC721Checkpointable.sol";

22: import { IVerbsDescriptorMinimal } from "./interfaces/IVerbsDescriptorMinimal.sol";

22: import { IVerbsDescriptorMinimal } from "./interfaces/IVerbsDescriptorMinimal.sol";

23: import { ICultureIndex } from "./interfaces/ICultureIndex.sol";

23: import { ICultureIndex } from "./interfaces/ICultureIndex.sol";

24: import { IVerbsToken } from "./interfaces/IVerbsToken.sol";

24: import { IVerbsToken } from "./interfaces/IVerbsToken.sol";

25: import { ERC721 } from "./base/ERC721.sol";

25: import { ERC721 } from "./base/ERC721.sol";

26: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

26: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

26: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

26: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

27: import { IProxyRegistry } from "./external/opensea/IProxyRegistry.sol";

27: import { IProxyRegistry } from "./external/opensea/IProxyRegistry.sol";

27: import { IProxyRegistry } from "./external/opensea/IProxyRegistry.sol";

28: import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

28: import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

28: import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

113:         return string(abi.encodePacked("ipfs://", _contractURIHash));

113:         return string(abi.encodePacked("ipfs://", _contractURIHash));

252:             uint256 verbId = _currentVerbId++;

252:             uint256 verbId = _currentVerbId++;

264:             for (uint i = 0; i < artPiece.creators.length; i++) {

264:             for (uint i = 0; i < artPiece.creators.length; i++) {

```

```solidity
File: base/ERC721.sol

35: import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

35: import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

35: import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

35: import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

36: import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

36: import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

36: import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

36: import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

37: import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";

37: import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";

37: import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";

37: import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";

37: import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";

38: import "@openzeppelin/contracts/utils/Address.sol";

38: import "@openzeppelin/contracts/utils/Address.sol";

38: import "@openzeppelin/contracts/utils/Address.sol";

39: import "@openzeppelin/contracts/utils/Context.sol";

39: import "@openzeppelin/contracts/utils/Context.sol";

39: import "@openzeppelin/contracts/utils/Context.sol";

40: import "@openzeppelin/contracts/utils/Strings.sol";

40: import "@openzeppelin/contracts/utils/Strings.sol";

40: import "@openzeppelin/contracts/utils/Strings.sol";

41: import "@openzeppelin/contracts/utils/introspection/ERC165.sol";

41: import "@openzeppelin/contracts/utils/introspection/ERC165.sol";

41: import "@openzeppelin/contracts/utils/introspection/ERC165.sol";

41: import "@openzeppelin/contracts/utils/introspection/ERC165.sol";

291:         _balances[to] += 1;

316:         _balances[owner] -= 1;

342:         _balances[from] -= 1;

343:         _balances[to] += 1;

```

```solidity
File: base/ERC721Checkpointable.sol

37: import "./ERC721Enumerable.sol";

126:         require(nonce == nonces[signatory]++, "ERC721Checkpointable::delegateBySig: invalid nonce");

126:         require(nonce == nonces[signatory]++, "ERC721Checkpointable::delegateBySig: invalid nonce");

138:         return nCheckpoints > 0 ? checkpoints[account][nCheckpoints - 1].votes : 0;

157:         if (checkpoints[account][nCheckpoints - 1].fromBlock <= blockNumber) {

158:             return checkpoints[account][nCheckpoints - 1].votes;

167:         uint32 upper = nCheckpoints - 1;

169:             uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow

169:             uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow

169:             uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow

169:             uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow

169:             uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow

176:                 upper = center - 1;

199:                 uint96 srcRepOld = srcRepNum > 0 ? checkpoints[srcRep][srcRepNum - 1].votes : 0;

206:                 uint96 dstRepOld = dstRepNum > 0 ? checkpoints[dstRep][dstRepNum - 1].votes : 0;

216:         if (nCheckpoints > 0 && checkpoints[delegatee][nCheckpoints - 1].fromBlock == blockNumber) {

217:             checkpoints[delegatee][nCheckpoints - 1].votes = newVotes;

220:             numCheckpoints[delegatee] = nCheckpoints + 1;

227:         require(n < 2 ** 32, errorMessage);

227:         require(n < 2 ** 32, errorMessage);

232:         require(n < 2 ** 96, errorMessage);

232:         require(n < 2 ** 96, errorMessage);

237:         uint96 c = a + b;

244:         return a - b;

```

```solidity
File: base/ERC721Enumerable.sol

30: import "./ERC721.sol";

31: import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol";

31: import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol";

31: import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol";

31: import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol";

31: import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol";

143:         uint256 lastTokenIndex = ERC721.balanceOf(from) - 1;

150:             _ownedTokens[from][tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token

150:             _ownedTokens[from][tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token

150:             _ownedTokens[from][tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token

151:             _ownedTokensIndex[lastTokenId] = tokenIndex; // Update the moved token's index

151:             _ownedTokensIndex[lastTokenId] = tokenIndex; // Update the moved token's index

168:         uint256 lastTokenIndex = _allTokens.length - 1;

176:         _allTokens[tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token

176:         _allTokens[tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token

176:         _allTokens[tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token

177:         _allTokensIndex[lastTokenId] = tokenIndex; // Update the moved token's index

177:         _allTokensIndex[lastTokenId] = tokenIndex; // Update the moved token's index

```

```solidity
File: base/Votes.sol

5: import { IERC5805 } from "@openzeppelin/contracts/interfaces/IERC5805.sol";

5: import { IERC5805 } from "@openzeppelin/contracts/interfaces/IERC5805.sol";

5: import { IERC5805 } from "@openzeppelin/contracts/interfaces/IERC5805.sol";

6: import { Context } from "@openzeppelin/contracts/utils/Context.sol";

6: import { Context } from "@openzeppelin/contracts/utils/Context.sol";

6: import { Context } from "@openzeppelin/contracts/utils/Context.sol";

7: import { Nonces } from "@openzeppelin/contracts/utils/Nonces.sol";

7: import { Nonces } from "@openzeppelin/contracts/utils/Nonces.sol";

7: import { Nonces } from "@openzeppelin/contracts/utils/Nonces.sol";

8: import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

8: import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

8: import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

8: import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

9: import { Checkpoints } from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

9: import { Checkpoints } from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

9: import { Checkpoints } from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

9: import { Checkpoints } from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

10: import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";

10: import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";

10: import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";

10: import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";

11: import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

11: import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

11: import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

11: import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

12: import { Time } from "@openzeppelin/contracts/utils/types/Time.sol";

12: import { Time } from "@openzeppelin/contracts/utils/types/Time.sol";

12: import { Time } from "@openzeppelin/contracts/utils/types/Time.sol";

12: import { Time } from "@openzeppelin/contracts/utils/types/Time.sol";

215:         return a + b;

219:         return a - b;

```

```solidity
File: base/erc20/ERC20.sol

6: import { Context } from "@openzeppelin/contracts/utils/Context.sol";

6: import { Context } from "@openzeppelin/contracts/utils/Context.sol";

6: import { Context } from "@openzeppelin/contracts/utils/Context.sol";

7: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

7: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

7: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

7: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

8: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

8: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

8: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

8: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

8: import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

9: import { IERC20Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

9: import { IERC20Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

9: import { IERC20Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

9: import { IERC20Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";

191:             _totalSupply += value;

199:                 _balances[from] = fromBalance - value;

206:                 _totalSupply -= value;

211:                 _balances[to] += value;

312:                 _approve(owner, spender, currentAllowance - value, false);

```

```solidity
File: base/erc20/ERC20Votes.sol

6: import { ERC20 } from "./ERC20.sol";

7: import { Votes } from "../Votes.sol";

8: import { Checkpoints } from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

8: import { Checkpoints } from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

8: import { Checkpoints } from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

8: import { Checkpoints } from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

```

```solidity
File: governance/VerbsDAOExecutor.sol

85:         require(eta >= getBlockTimestamp() + delay, "VerbsDAOExecutor::queueTransaction: Estimated execution block must satisfy delay.");

109:         require(getBlockTimestamp() <= eta + GRACE_PERIOD, "VerbsDAOExecutor::executeTransaction: Transaction is stale.");

```

```solidity
File: governance/VerbsDAOLogicV1.sol

55: import "./VerbsDAOInterfaces.sol";

62:     uint256 public constant MIN_PROPOSAL_THRESHOLD_BPS = 1; // 1 basis point or 0.01%

62:     uint256 public constant MIN_PROPOSAL_THRESHOLD_BPS = 1; // 1 basis point or 0.01%

65:     uint256 public constant MAX_PROPOSAL_THRESHOLD_BPS = 1_000; // 1,000 basis points or 10%

65:     uint256 public constant MAX_PROPOSAL_THRESHOLD_BPS = 1_000; // 1,000 basis points or 10%

68:     uint256 public constant MIN_VOTING_PERIOD = 5_760; // About 24 hours

68:     uint256 public constant MIN_VOTING_PERIOD = 5_760; // About 24 hours

71:     uint256 public constant MAX_VOTING_PERIOD = 80_640; // About 2 weeks

71:     uint256 public constant MAX_VOTING_PERIOD = 80_640; // About 2 weeks

77:     uint256 public constant MAX_VOTING_DELAY = 40_320; // About 1 week

77:     uint256 public constant MAX_VOTING_DELAY = 40_320; // About 1 week

80:     uint256 public constant MIN_QUORUM_VOTES_BPS_LOWER_BOUND = 200; // 200 basis points or 2%

80:     uint256 public constant MIN_QUORUM_VOTES_BPS_LOWER_BOUND = 200; // 200 basis points or 2%

83:     uint256 public constant MIN_QUORUM_VOTES_BPS_UPPER_BOUND = 2_000; // 2,000 basis points or 20%

83:     uint256 public constant MIN_QUORUM_VOTES_BPS_UPPER_BOUND = 2_000; // 2,000 basis points or 20%

86:     uint256 public constant MAX_QUORUM_VOTES_BPS_UPPER_BOUND = 6_000; // 4,000 basis points or 60%

86:     uint256 public constant MAX_QUORUM_VOTES_BPS_UPPER_BOUND = 6_000; // 4,000 basis points or 60%

89:     uint256 public constant MAX_QUORUM_VOTES_BPS = 2_000; // 2,000 basis points or 20%

89:     uint256 public constant MAX_QUORUM_VOTES_BPS = 2_000; // 2,000 basis points or 20%

92:     uint256 public constant proposalMaxOperations = 10; // 10 actions

92:     uint256 public constant proposalMaxOperations = 10; // 10 actions

206:         require(getTotalVotes(msg.sender, block.number - 1) > temp.proposalThreshold, "VerbsDAO::propose: proposer votes below proposal threshold");

221:         temp.startBlock = block.number + votingDelay;

222:         temp.endBlock = temp.startBlock + votingPeriod;

224:         proposalCount++;

224:         proposalCount++;

276:         uint256 eta = block.timestamp + timelock.delay();

277:         for (uint256 i = 0; i < proposal.targets.length; i++) {

277:         for (uint256 i = 0; i < proposal.targets.length; i++) {

300:         for (uint256 i = 0; i < proposal.targets.length; i++) {

300:         for (uint256 i = 0; i < proposal.targets.length; i++) {

316:         return (erc721TokenVotes * 1e18 * verbsTokenVotingWeight) + erc20PointsVotesWad;

316:         return (erc721TokenVotes * 1e18 * verbsTokenVotingWeight) + erc20PointsVotesWad;

316:         return (erc721TokenVotes * 1e18 * verbsTokenVotingWeight) + erc20PointsVotesWad;

343:             msg.sender == proposal.proposer || getTotalVotes(proposal.proposer, block.number - 1) <= proposal.proposalThreshold,

348:         for (uint256 i = 0; i < proposal.targets.length; i++) {

348:         for (uint256 i = 0; i < proposal.targets.length; i++) {

375:         for (uint256 i = 0; i < proposal.targets.length; i++) {

375:         for (uint256 i = 0; i < proposal.targets.length; i++) {

429:         } else if (block.timestamp >= proposal.eta + timelock.GRACE_PERIOD()) {

559:             proposal.againstVotes = proposal.againstVotes + votes;

561:             proposal.forVotes = proposal.forVotes + votes;

563:             proposal.abstainVotes = proposal.abstainVotes + votes;

836:             return proposal.startBlock - votingDelay;

867:         uint256 againstVotesBPS = (10000 * againstVotes) / totalSupply;

867:         uint256 againstVotesBPS = (10000 * againstVotes) / totalSupply;

868:         uint256 quorumAdjustmentBPS = (params.quorumCoefficient * againstVotesBPS) / 1e6;

868:         uint256 quorumAdjustmentBPS = (params.quorumCoefficient * againstVotesBPS) / 1e6;

869:         uint256 adjustedQuorumBPS = params.minQuorumVotesBPS + quorumAdjustmentBPS;

889:         if (quorumParamsCheckpoints[len - 1].fromBlock <= blockNumber) {

890:             return quorumParamsCheckpoints[len - 1].params;

898:         uint256 upper = len - 1;

900:             uint256 center = upper - (upper - lower) / 2;

900:             uint256 center = upper - (upper - lower) / 2;

900:             uint256 center = upper - (upper - lower) / 2;

907:                 upper = center - 1;

916:         if (pos > 0 && quorumParamsCheckpoints[pos - 1].fromBlock == blockNumber) {

917:             quorumParamsCheckpoints[pos - 1].params = params;

930:             uint256 gasPrice = min(tx.gasprice, basefee + MAX_REFUND_PRIORITY_FEE);

931:             uint256 gasUsed = min(startGas - gasleft() + REFUND_BASE_GAS, MAX_REFUND_GAS_USED);

931:             uint256 gasUsed = min(startGas - gasleft() + REFUND_BASE_GAS, MAX_REFUND_GAS_USED);

932:             uint256 refundAmount = min(gasPrice * gasUsed, balance);

957:         return (number * bps) / 10000;

957:         return (number * bps) / 10000;

```

```solidity
File: governance/VerbsDAOProxyV1.sol

41: import "./VerbsDAOInterfaces.sol";

```

```solidity
File: interfaces/ICultureIndex.sol

5: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

5: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

5: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

5: import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

6: import { ERC721Checkpointable } from "../base/ERC721Checkpointable.sol";

6: import { ERC721Checkpointable } from "../base/ERC721Checkpointable.sol";

```

```solidity
File: interfaces/IVerbsDescriptor.sol

20: import { IVerbsDescriptorMinimal } from "./IVerbsDescriptorMinimal.sol";

21: import { ICultureIndex } from "./ICultureIndex.sol";

```

```solidity
File: interfaces/IVerbsDescriptorMinimal.sol

20: import { ICultureIndex } from "./ICultureIndex.sol";

```

```solidity
File: interfaces/IVerbsToken.sol

20: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

20: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

20: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

20: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

21: import { IVerbsDescriptorMinimal } from "./IVerbsDescriptorMinimal.sol";

22: import { ICultureIndex } from "./ICultureIndex.sol";

```

```solidity
File: libs/SignedWadMath.sol

69:     return wadExp((wadLn(x) * y) / 1e18); // Using ln(x) means x must be greater than 0.

69:     return wadExp((wadLn(x) * y) / 1e18); // Using ln(x) means x must be greater than 0.

69:     return wadExp((wadLn(x) * y) / 1e18); // Using ln(x) means x must be greater than 0.

69:     return wadExp((wadLn(x) * y) / 1e18); // Using ln(x) means x must be greater than 0.

76:         if (x <= -42139678854452767551) return 0;

85:         x = (x << 78) / 5 ** 18;

85:         x = (x << 78) / 5 ** 18;

85:         x = (x << 78) / 5 ** 18;

90:         int256 k = ((x << 96) / 54916777467707473351141471128 + 2 ** 95) >> 96;

90:         int256 k = ((x << 96) / 54916777467707473351141471128 + 2 ** 95) >> 96;

90:         int256 k = ((x << 96) / 54916777467707473351141471128 + 2 ** 95) >> 96;

90:         int256 k = ((x << 96) / 54916777467707473351141471128 + 2 ** 95) >> 96;

91:         x = x - k * 54916777467707473351141471128;

91:         x = x - k * 54916777467707473351141471128;

97:         int256 y = x + 1346386616545796478920950773328;

98:         y = ((y * x) >> 96) + 57155421227552351082224309758442;

98:         y = ((y * x) >> 96) + 57155421227552351082224309758442;

99:         int256 p = y + x - 94201549194550492254356042504812;

99:         int256 p = y + x - 94201549194550492254356042504812;

100:         p = ((p * y) >> 96) + 28719021644029726153956944680412240;

100:         p = ((p * y) >> 96) + 28719021644029726153956944680412240;

101:         p = p * x + (4385272521454847904659076985693276 << 96);

101:         p = p * x + (4385272521454847904659076985693276 << 96);

104:         int256 q = x - 2855989394907223263936484059900;

105:         q = ((q * x) >> 96) + 50020603652535783019961831881945;

105:         q = ((q * x) >> 96) + 50020603652535783019961831881945;

106:         q = ((q * x) >> 96) - 533845033583426703283633433725380;

106:         q = ((q * x) >> 96) - 533845033583426703283633433725380;

107:         q = ((q * x) >> 96) + 3604857256930695427073651918091429;

107:         q = ((q * x) >> 96) + 3604857256930695427073651918091429;

108:         q = ((q * x) >> 96) - 14423608567350463180887372962807573;

108:         q = ((q * x) >> 96) - 14423608567350463180887372962807573;

109:         q = ((q * x) >> 96) + 26449188498355588339934803723976023;

109:         q = ((q * x) >> 96) + 26449188498355588339934803723976023;

127:         r = int256((uint256(r) * 3822833074963236453042738258902158003155416615667) >> uint256(195 - k));

127:         r = int256((uint256(r) * 3822833074963236453042738258902158003155416615667) >> uint256(195 - k));

154:         int256 k = r - 96;

155:         x <<= uint256(159 - k);

160:         int256 p = x + 3273285459638523848632254066296;

161:         p = ((p * x) >> 96) + 24828157081833163892658089445524;

161:         p = ((p * x) >> 96) + 24828157081833163892658089445524;

162:         p = ((p * x) >> 96) + 43456485725739037958740375743393;

162:         p = ((p * x) >> 96) + 43456485725739037958740375743393;

163:         p = ((p * x) >> 96) - 11111509109440967052023855526967;

163:         p = ((p * x) >> 96) - 11111509109440967052023855526967;

164:         p = ((p * x) >> 96) - 45023709667254063763336534515857;

164:         p = ((p * x) >> 96) - 45023709667254063763336534515857;

165:         p = ((p * x) >> 96) - 14706773417378608786704636184526;

165:         p = ((p * x) >> 96) - 14706773417378608786704636184526;

166:         p = p * x - (795164235651350426258249787498 << 96);

166:         p = p * x - (795164235651350426258249787498 << 96);

170:         int256 q = x + 5573035233440673466300451813936;

171:         q = ((q * x) >> 96) + 71694874799317883764090561454958;

171:         q = ((q * x) >> 96) + 71694874799317883764090561454958;

172:         q = ((q * x) >> 96) + 283447036172924575727196451306956;

172:         q = ((q * x) >> 96) + 283447036172924575727196451306956;

173:         q = ((q * x) >> 96) + 401686690394027663651624208769553;

173:         q = ((q * x) >> 96) + 401686690394027663651624208769553;

174:         q = ((q * x) >> 96) + 204048457590392012362485061816622;

174:         q = ((q * x) >> 96) + 204048457590392012362485061816622;

175:         q = ((q * x) >> 96) + 31853899698501571402653359427138;

175:         q = ((q * x) >> 96) + 31853899698501571402653359427138;

176:         q = ((q * x) >> 96) + 909429971244387300277376558375;

176:         q = ((q * x) >> 96) + 909429971244387300277376558375;

194:         r *= 1677202110996718588342820967067443963516166;

196:         r += 16597577552685614221487285958193947469193820559219878177908093499208371 * k;

196:         r += 16597577552685614221487285958193947469193820559219878177908093499208371 * k;

198:         r += 600920179829731861736702779321621459595472258049074101567377883020018308;

```

```solidity
File: libs/VRGDAC.sol

4: import { wadExp, wadLn, wadMul, wadDiv, unsafeWadDiv, wadPow } from "./SignedWadMath.sol";

35:         decayConstant = wadLn(1e18 - _priceDecayPercent);

49:             return pIntegral(timeSinceStart, sold + amount) - pIntegral(timeSinceStart, sold);

49:             return pIntegral(timeSinceStart, sold + amount) - pIntegral(timeSinceStart, sold);

55:         int256 soldDifference = wadMul(perTimeUnit, timeSinceStart) - sold;

64:                                 wadMul(targetPrice, wadMul(perTimeUnit, wadPow(1e18 - priceDecayPercent, wadDiv(soldDifference, perTimeUnit)))) -

64:                                 wadMul(targetPrice, wadMul(perTimeUnit, wadPow(1e18 - priceDecayPercent, wadDiv(soldDifference, perTimeUnit)))) -

78:                 -wadMul(

80:                     wadPow(1e18 - priceDecayPercent, timeSinceStart - unsafeWadDiv(sold, perTimeUnit)) - wadPow(1e18 - priceDecayPercent, timeSinceStart)

80:                     wadPow(1e18 - priceDecayPercent, timeSinceStart - unsafeWadDiv(sold, perTimeUnit)) - wadPow(1e18 - priceDecayPercent, timeSinceStart)

80:                     wadPow(1e18 - priceDecayPercent, timeSinceStart - unsafeWadDiv(sold, perTimeUnit)) - wadPow(1e18 - priceDecayPercent, timeSinceStart)

80:                     wadPow(1e18 - priceDecayPercent, timeSinceStart - unsafeWadDiv(sold, perTimeUnit)) - wadPow(1e18 - priceDecayPercent, timeSinceStart)

```

### <a name="GAS-5"></a>[GAS-5] Use Custom Errors
[Source](https://blog.soliditylang.org/2021/04/21/custom-errors/)
Instead of using error strings, to reduce deployment and runtime cost, you should use Custom Errors. This would save both deployment and runtime cost.

*Instances (136)*:
```solidity
File: CultureIndex.sol

71:         require(quorumVotesBPS_ >= MIN_QUORUM_VOTES_BPS && quorumVotesBPS_ <= MAX_QUORUM_VOTES_BPS, "CultureIndex::constructor: invalid quorum bps");

72:         require(erc721VotingTokenWeight_ > 0, "CultureIndex::constructor: invalid erc721 voting token weight");

73:         require(erc721VotingToken_ != address(0), "CultureIndex::constructor: invalid erc721 voting token");

74:         require(erc20VotingToken_ != address(0), "CultureIndex::constructor: invalid erc20 voting token");

92:         require(!isERC721VotingTokenLocked, "ERC721VotingToken is locked");

125:         require(uint8(metadata.mediaType) > 0 && uint8(metadata.mediaType) <= 5, "Invalid media type");

128:             require(bytes(metadata.image).length > 0, "Image URL must be provided");

130:             require(bytes(metadata.animationUrl).length > 0, "Animation URL must be provided");

132:             require(bytes(metadata.text).length > 0, "Text must be provided");

147:         require(creatorArray.length <= 100, "Creator array must not be > 100");

151:             require(creatorArray[i].creator != address(0), "Invalid creator address");

173:         require(totalBps == 10_000, "Total BPS must sum up to 10,000");

272:         require(weight > 0, "Weight must be greater than zero");

273:         require(!(votes[pieceId][msg.sender].voterAddress != address(0)), "Already voted");

274:         require(!pieces[pieceId].isDropped, "Piece has already been dropped");

275:         require(pieceId < _currentPieceId, "Invalid piece ID");

294:         require(pieceId < _currentPieceId, "Invalid piece ID");

306:             require(pieceIds[i] < _currentPieceId, "Invalid piece ID");

317:         require(pieceId < _currentPieceId, "Invalid piece ID");

327:         require(pieceId < _currentPieceId, "Invalid piece ID");

389:         require(totalVoteWeights[pieceId] >= pieces[pieceId].quorumVotes, "Piece must have quorum votes in order to be dropped.");

406:                 revert("No pieces available to drop");

412:             revert("Unknown error extracting top piece");

```

```solidity
File: MaxHeap.sol

30:         require(pos != 0, "Position should not be zero");

108:         require(size > 0, "Heap is empty");

121:         require(size > 0, "Heap is empty");

```

```solidity
File: TokenEmitter.sol

46:         require(_treasury != address(0), "Invalid treasury address");

80:         require(msg.value > 0, "Must send ether");

82:         require(_addresses.length == _bps.length, "Parallel arrays required");

103:         require(success, "Transfer failed.");

108:             require(success, "Transfer failed.");

127:         require(sum == 10_000, "bps must add up to 10_000");

143:         require(amount > 0, "Amount must be greater than 0");

150:         require(etherAmount > 0, "Ether amount must be greater than 0");

157:         require(paymentAmount > 0, "Payment amount must be greater than 0");

174:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");

186:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");

197:         require(_creatorsAddress != address(0), "Invalid address");

```

```solidity
File: VerbsAuctionHouse.sol

94:         require(_creatorRateBps >= _minCreatorRateBps, "Creator rate must be greater than or equal to the creator rate");

95:         require(_WETH != address(0), "WETH cannot be zero address");

134:         require(_auction.verbId == verbId, "Verb not up for auction");

136:         require(block.timestamp < _auction.endTime, "Auction expired");

137:         require(msg.value >= reservePrice, "Must send at least reservePrice");

138:         require(msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100), "Must send more than last bid by minBidIncrementPercentage amount");

173:         require(_creatorRateBps >= minCreatorRateBps, "Creator rate must be greater than or equal to minCreatorRateBps");

174:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");

186:         require(_minCreatorRateBps <= creatorRateBps, "Min creator rate must be less than or equal to creator rate");

187:         require(_minCreatorRateBps <= 10_000, "Min creator rate must be less than or equal to 10_000");

190:         require(_minCreatorRateBps > minCreatorRateBps, "Min creator rate must be greater than previous minCreatorRateBps");

203:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");

278:         require(_auction.startTime != 0, "Auction hasn't begun");

279:         require(!_auction.settled, "Auction has already been settled");

281:         require(block.timestamp >= _auction.endTime, "Auction hasn't completed");

340:         if (address(this).balance < _amount) revert("Insufficient balance");

360:             if (!wethSuccess) revert("WETH transfer failed");

```

```solidity
File: VerbsToken.sol

65:         require(!isMinterLocked, "Minter is locked");

73:         require(!isCultureIndexLocked, "CultureIndex is locked");

81:         require(!isDescriptorLocked, "Descriptor is locked");

89:         require(msg.sender == minter, "Sender is not the minter");

102:         require(_minter != address(0), "Minter cannot be zero address");

155:         require(_exists(tokenId), "VerbsToken: URI query for nonexistent token");

164:         require(_exists(tokenId), "VerbsToken: URI query for nonexistent token");

173:         require(_minter != address(0), "Minter cannot be zero address");

235:         require(verbId <= _currentVerbId, "Invalid piece ID");

247:         require(artPiece.creators.length <= 100, "Creator array must not be > 100");

275:             revert("dropTopVotedPiece failed");

```

```solidity
File: base/ERC721.sol

89:         require(owner != address(0), "ERC721: balance query for the zero address");

98:         require(owner != address(0), "ERC721: owner query for nonexistent token");

120:         require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");

140:         require(to != owner, "ERC721: approval to current owner");

142:         require(_msgSender() == owner || isApprovedForAll(owner, _msgSender()), "ERC721: approve caller is not owner nor approved for all");

151:         require(_exists(tokenId), "ERC721: approved query for nonexistent token");

160:         require(operator != _msgSender(), "ERC721: approve to caller");

178:         require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

194:         require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

218:         require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");

241:         require(_exists(tokenId), "ERC721: operator query for nonexistent token");

268:         require(_checkOnERC721Received(address(0), to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");

286:         require(to != address(0), "ERC721: mint to the zero address");

287:         require(!_exists(tokenId), "ERC721: token already minted");

334:         require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer of token that is not own");

335:         require(to != address(0), "ERC721: transfer to the zero address");

375:                     revert("ERC721: transfer to non ERC721Receiver implementer");

```

```solidity
File: base/ERC721Checkpointable.sol

125:         require(signatory != address(0), "ERC721Checkpointable::delegateBySig: invalid signature");

126:         require(nonce == nonces[signatory]++, "ERC721Checkpointable::delegateBySig: invalid nonce");

127:         require(block.timestamp <= expiry, "ERC721Checkpointable::delegateBySig: signature expired");

149:         require(blockNumber < block.number, "ERC721Checkpointable::getPriorVotes: not yet determined");

```

```solidity
File: base/ERC721Enumerable.sol

62:         require(index < ERC721.balanceOf(owner), "ERC721Enumerable: owner index out of bounds");

77:         require(index < ERC721Enumerable.totalSupply(), "ERC721Enumerable: global index out of bounds");

```

```solidity
File: governance/VerbsDAOExecutor.sol

52:         require(delay_ >= MINIMUM_DELAY, "VerbsDAOExecutor::constructor: Delay must exceed minimum delay.");

53:         require(delay_ <= MAXIMUM_DELAY, "VerbsDAOExecutor::setDelay: Delay must not exceed maximum delay.");

60:         require(msg.sender == address(this), "VerbsDAOExecutor::setDelay: Call must come from VerbsDAOExecutor.");

61:         require(delay_ >= MINIMUM_DELAY, "VerbsDAOExecutor::setDelay: Delay must exceed minimum delay.");

62:         require(delay_ <= MAXIMUM_DELAY, "VerbsDAOExecutor::setDelay: Delay must not exceed maximum delay.");

69:         require(msg.sender == pendingAdmin, "VerbsDAOExecutor::acceptAdmin: Call must come from pendingAdmin.");

77:         require(msg.sender == address(this), "VerbsDAOExecutor::setPendingAdmin: Call must come from VerbsDAOExecutor.");

84:         require(msg.sender == admin, "VerbsDAOExecutor::queueTransaction: Call must come from admin.");

85:         require(eta >= getBlockTimestamp() + delay, "VerbsDAOExecutor::queueTransaction: Estimated execution block must satisfy delay.");

95:         require(msg.sender == admin, "VerbsDAOExecutor::cancelTransaction: Call must come from admin.");

104:         require(msg.sender == admin, "VerbsDAOExecutor::executeTransaction: Call must come from admin.");

107:         require(queuedTransactions[txHash], "VerbsDAOExecutor::executeTransaction: Transaction hasn't been queued.");

108:         require(getBlockTimestamp() >= eta, "VerbsDAOExecutor::executeTransaction: Transaction hasn't surpassed time lock.");

109:         require(getBlockTimestamp() <= eta + GRACE_PERIOD, "VerbsDAOExecutor::executeTransaction: Transaction is stale.");

123:         require(success, "VerbsDAOExecutor::executeTransaction: Transaction execution reverted.");

```

```solidity
File: governance/VerbsDAOLogicV1.sol

146:         require(address(timelock) == address(0), "VerbsDAO::initialize: can only initialize once");

150:         require(timelock_ != address(0), "VerbsDAO::initialize: invalid timelock address");

151:         require(verbs_ != address(0), "VerbsDAO::initialize: invalid verbs address");

152:         require(verbsPoints_ != address(0), "VerbsDAO::initialize: invalid verbs points address");

153:         require(votingPeriod_ >= MIN_VOTING_PERIOD && votingPeriod_ <= MAX_VOTING_PERIOD, "VerbsDAO::initialize: invalid voting period");

154:         require(votingDelay_ >= MIN_VOTING_DELAY && votingDelay_ <= MAX_VOTING_DELAY, "VerbsDAO::initialize: invalid voting delay");

159:         require(verbsTokenVotingWeight_ > 0, "VerbsDAO::initialize: invalid verbs token voting weight");

206:         require(getTotalVotes(msg.sender, block.number - 1) > temp.proposalThreshold, "VerbsDAO::propose: proposer votes below proposal threshold");

211:         require(targets.length != 0, "VerbsDAO::propose: must provide actions");

212:         require(targets.length <= proposalMaxOperations, "VerbsDAO::propose: too many actions");

217:             require(proposersLatestProposalState != ProposalState.Active, "VerbsDAO::propose: one live proposal per proposer, found an already active proposal");

218:             require(proposersLatestProposalState != ProposalState.Pending, "VerbsDAO::propose: one live proposal per proposer, found an already pending proposal");

274:         require(state(proposalId) == ProposalState.Succeeded, "VerbsDAO::queue: proposal can only be queued if it is succeeded");

297:         require(state(proposalId) == ProposalState.Queued, "VerbsDAO::execute: proposal can only be executed if it is queued");

413:         require(proposalCount >= proposalId, "VerbsDAO::state: invalid proposal id");

537:         require(signatory != address(0), "VerbsDAO::castVoteBySig: invalid signature");

549:         require(state(proposalId) == ProposalState.Active, "VerbsDAO::castVoteInternal: voting is closed");

550:         require(support <= 2, "VerbsDAO::castVoteInternal: invalid vote type");

553:         require(receipt.hasVoted == false, "VerbsDAO::castVoteInternal: voter already voted");

581:         require(newVotingDelay >= MIN_VOTING_DELAY && newVotingDelay <= MAX_VOTING_DELAY, "VerbsDAO::_setVotingDelay: invalid voting delay");

596:         require(newVotingPeriod >= MIN_VOTING_PERIOD && newVotingPeriod <= MAX_VOTING_PERIOD, "VerbsDAO::_setVotingPeriod: invalid voting period");

638:         require(newMinQuorumVotesBPS <= params.maxQuorumVotesBPS, "VerbsDAO::_setMinQuorumVotesBPS: min quorum votes bps greater than max");

660:         require(newMaxQuorumVotesBPS <= MAX_QUORUM_VOTES_BPS_UPPER_BOUND, "VerbsDAO::_setMaxQuorumVotesBPS: invalid max quorum votes bps");

661:         require(params.minQuorumVotesBPS <= newMaxQuorumVotesBPS, "VerbsDAO::_setMaxQuorumVotesBPS: min quorum votes bps greater than max");

747:         require(msg.sender == admin, "VerbsDAO::_setPendingAdmin: admin only");

765:         require(msg.sender == pendingAdmin && msg.sender != address(0), "VerbsDAO::_acceptAdmin: pending admin only");

815:         require(msg.sender == vetoer, "VerbsDAO::_burnVetoPower: vetoer only");

```

```solidity
File: governance/VerbsDAOProxyV1.sol

82:         require(msg.sender == admin, "VerbsDAOProxy::_setImplementation: admin only");

83:         require(implementation_ != address(0), "VerbsDAOProxy::_setImplementation: invalid implementation address");

```

```solidity
File: libs/SignedWadMath.sol

80:         if (x >= 135305999368893231589) revert("EXP_OVERFLOW");

133:         require(x > 0, "UNDEFINED");

```

```solidity
File: libs/VRGDAC.sol

38:         require(decayConstant < 0, "NON_NEGATIVE_DECAY_CONSTANT");

```

### <a name="GAS-6"></a>[GAS-6] Don't initialize variables with default value

*Instances (19)*:
```solidity
File: CultureIndex.sol

149:         uint256 totalBps = 0;

150:         for (uint i = 0; i < creatorArray.length; i++) {

193:         for (uint i = 0; i < creatorArray.length; i++) {

211:         for (uint i = 0; i < creatorArray.length; i++) {

305:         for (uint256 i = 0; i < pieceIds.length; ++i) {

397:             for (uint i = 0; i < pieces[pieceId].creators.length; i++) {

```

```solidity
File: MaxHeap.sol

14:     uint256 public size = 0;

```

```solidity
File: TokenEmitter.sol

116:         uint sum = 0;

120:             for (uint i = 0; i < _addresses.length; i++) {

```

```solidity
File: VerbsAuctionHouse.sol

285:         uint256 creatorTokensEmitted = 0;

317:             for (uint256 i = 0; i < numCreators; i++) {

```

```solidity
File: VerbsToken.sol

264:             for (uint i = 0; i < artPiece.creators.length; i++) {

```

```solidity
File: base/ERC721Checkpointable.sol

41:     uint8 public constant decimals = 0;

166:         uint32 lower = 0;

```

```solidity
File: governance/VerbsDAOLogicV1.sol

277:         for (uint256 i = 0; i < proposal.targets.length; i++) {

300:         for (uint256 i = 0; i < proposal.targets.length; i++) {

348:         for (uint256 i = 0; i < proposal.targets.length; i++) {

375:         for (uint256 i = 0; i < proposal.targets.length; i++) {

897:         uint256 lower = 0;

```

### <a name="GAS-7"></a>[GAS-7] Long revert strings

*Instances (82)*:
```solidity
File: CultureIndex.sol

71:         require(quorumVotesBPS_ >= MIN_QUORUM_VOTES_BPS && quorumVotesBPS_ <= MAX_QUORUM_VOTES_BPS, "CultureIndex::constructor: invalid quorum bps");

72:         require(erc721VotingTokenWeight_ > 0, "CultureIndex::constructor: invalid erc721 voting token weight");

73:         require(erc721VotingToken_ != address(0), "CultureIndex::constructor: invalid erc721 voting token");

74:         require(erc20VotingToken_ != address(0), "CultureIndex::constructor: invalid erc20 voting token");

389:         require(totalVoteWeights[pieceId] >= pieces[pieceId].quorumVotes, "Piece must have quorum votes in order to be dropped.");

```

```solidity
File: TokenEmitter.sol

150:         require(etherAmount > 0, "Ether amount must be greater than 0");

157:         require(paymentAmount > 0, "Payment amount must be greater than 0");

174:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");

186:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");

```

```solidity
File: VerbsAuctionHouse.sol

94:         require(_creatorRateBps >= _minCreatorRateBps, "Creator rate must be greater than or equal to the creator rate");

138:         require(msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100), "Must send more than last bid by minBidIncrementPercentage amount");

173:         require(_creatorRateBps >= minCreatorRateBps, "Creator rate must be greater than or equal to minCreatorRateBps");

174:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");

186:         require(_minCreatorRateBps <= creatorRateBps, "Min creator rate must be less than or equal to creator rate");

187:         require(_minCreatorRateBps <= 10_000, "Min creator rate must be less than or equal to 10_000");

190:         require(_minCreatorRateBps > minCreatorRateBps, "Min creator rate must be greater than previous minCreatorRateBps");

203:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");

```

```solidity
File: VerbsToken.sol

155:         require(_exists(tokenId), "VerbsToken: URI query for nonexistent token");

164:         require(_exists(tokenId), "VerbsToken: URI query for nonexistent token");

```

```solidity
File: base/ERC721.sol

89:         require(owner != address(0), "ERC721: balance query for the zero address");

98:         require(owner != address(0), "ERC721: owner query for nonexistent token");

120:         require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");

140:         require(to != owner, "ERC721: approval to current owner");

142:         require(_msgSender() == owner || isApprovedForAll(owner, _msgSender()), "ERC721: approve caller is not owner nor approved for all");

151:         require(_exists(tokenId), "ERC721: approved query for nonexistent token");

178:         require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

194:         require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

218:         require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");

241:         require(_exists(tokenId), "ERC721: operator query for nonexistent token");

268:         require(_checkOnERC721Received(address(0), to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");

334:         require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer of token that is not own");

335:         require(to != address(0), "ERC721: transfer to the zero address");

```

```solidity
File: base/ERC721Checkpointable.sol

125:         require(signatory != address(0), "ERC721Checkpointable::delegateBySig: invalid signature");

126:         require(nonce == nonces[signatory]++, "ERC721Checkpointable::delegateBySig: invalid nonce");

127:         require(block.timestamp <= expiry, "ERC721Checkpointable::delegateBySig: signature expired");

149:         require(blockNumber < block.number, "ERC721Checkpointable::getPriorVotes: not yet determined");

```

```solidity
File: base/ERC721Enumerable.sol

62:         require(index < ERC721.balanceOf(owner), "ERC721Enumerable: owner index out of bounds");

77:         require(index < ERC721Enumerable.totalSupply(), "ERC721Enumerable: global index out of bounds");

```

```solidity
File: governance/VerbsDAOExecutor.sol

52:         require(delay_ >= MINIMUM_DELAY, "VerbsDAOExecutor::constructor: Delay must exceed minimum delay.");

53:         require(delay_ <= MAXIMUM_DELAY, "VerbsDAOExecutor::setDelay: Delay must not exceed maximum delay.");

60:         require(msg.sender == address(this), "VerbsDAOExecutor::setDelay: Call must come from VerbsDAOExecutor.");

61:         require(delay_ >= MINIMUM_DELAY, "VerbsDAOExecutor::setDelay: Delay must exceed minimum delay.");

62:         require(delay_ <= MAXIMUM_DELAY, "VerbsDAOExecutor::setDelay: Delay must not exceed maximum delay.");

69:         require(msg.sender == pendingAdmin, "VerbsDAOExecutor::acceptAdmin: Call must come from pendingAdmin.");

77:         require(msg.sender == address(this), "VerbsDAOExecutor::setPendingAdmin: Call must come from VerbsDAOExecutor.");

84:         require(msg.sender == admin, "VerbsDAOExecutor::queueTransaction: Call must come from admin.");

85:         require(eta >= getBlockTimestamp() + delay, "VerbsDAOExecutor::queueTransaction: Estimated execution block must satisfy delay.");

95:         require(msg.sender == admin, "VerbsDAOExecutor::cancelTransaction: Call must come from admin.");

104:         require(msg.sender == admin, "VerbsDAOExecutor::executeTransaction: Call must come from admin.");

107:         require(queuedTransactions[txHash], "VerbsDAOExecutor::executeTransaction: Transaction hasn't been queued.");

108:         require(getBlockTimestamp() >= eta, "VerbsDAOExecutor::executeTransaction: Transaction hasn't surpassed time lock.");

109:         require(getBlockTimestamp() <= eta + GRACE_PERIOD, "VerbsDAOExecutor::executeTransaction: Transaction is stale.");

123:         require(success, "VerbsDAOExecutor::executeTransaction: Transaction execution reverted.");

```

```solidity
File: governance/VerbsDAOLogicV1.sol

146:         require(address(timelock) == address(0), "VerbsDAO::initialize: can only initialize once");

150:         require(timelock_ != address(0), "VerbsDAO::initialize: invalid timelock address");

151:         require(verbs_ != address(0), "VerbsDAO::initialize: invalid verbs address");

152:         require(verbsPoints_ != address(0), "VerbsDAO::initialize: invalid verbs points address");

153:         require(votingPeriod_ >= MIN_VOTING_PERIOD && votingPeriod_ <= MAX_VOTING_PERIOD, "VerbsDAO::initialize: invalid voting period");

154:         require(votingDelay_ >= MIN_VOTING_DELAY && votingDelay_ <= MAX_VOTING_DELAY, "VerbsDAO::initialize: invalid voting delay");

159:         require(verbsTokenVotingWeight_ > 0, "VerbsDAO::initialize: invalid verbs token voting weight");

206:         require(getTotalVotes(msg.sender, block.number - 1) > temp.proposalThreshold, "VerbsDAO::propose: proposer votes below proposal threshold");

211:         require(targets.length != 0, "VerbsDAO::propose: must provide actions");

212:         require(targets.length <= proposalMaxOperations, "VerbsDAO::propose: too many actions");

217:             require(proposersLatestProposalState != ProposalState.Active, "VerbsDAO::propose: one live proposal per proposer, found an already active proposal");

218:             require(proposersLatestProposalState != ProposalState.Pending, "VerbsDAO::propose: one live proposal per proposer, found an already pending proposal");

274:         require(state(proposalId) == ProposalState.Succeeded, "VerbsDAO::queue: proposal can only be queued if it is succeeded");

297:         require(state(proposalId) == ProposalState.Queued, "VerbsDAO::execute: proposal can only be executed if it is queued");

413:         require(proposalCount >= proposalId, "VerbsDAO::state: invalid proposal id");

537:         require(signatory != address(0), "VerbsDAO::castVoteBySig: invalid signature");

549:         require(state(proposalId) == ProposalState.Active, "VerbsDAO::castVoteInternal: voting is closed");

550:         require(support <= 2, "VerbsDAO::castVoteInternal: invalid vote type");

553:         require(receipt.hasVoted == false, "VerbsDAO::castVoteInternal: voter already voted");

581:         require(newVotingDelay >= MIN_VOTING_DELAY && newVotingDelay <= MAX_VOTING_DELAY, "VerbsDAO::_setVotingDelay: invalid voting delay");

596:         require(newVotingPeriod >= MIN_VOTING_PERIOD && newVotingPeriod <= MAX_VOTING_PERIOD, "VerbsDAO::_setVotingPeriod: invalid voting period");

638:         require(newMinQuorumVotesBPS <= params.maxQuorumVotesBPS, "VerbsDAO::_setMinQuorumVotesBPS: min quorum votes bps greater than max");

660:         require(newMaxQuorumVotesBPS <= MAX_QUORUM_VOTES_BPS_UPPER_BOUND, "VerbsDAO::_setMaxQuorumVotesBPS: invalid max quorum votes bps");

661:         require(params.minQuorumVotesBPS <= newMaxQuorumVotesBPS, "VerbsDAO::_setMaxQuorumVotesBPS: min quorum votes bps greater than max");

747:         require(msg.sender == admin, "VerbsDAO::_setPendingAdmin: admin only");

765:         require(msg.sender == pendingAdmin && msg.sender != address(0), "VerbsDAO::_acceptAdmin: pending admin only");

815:         require(msg.sender == vetoer, "VerbsDAO::_burnVetoPower: vetoer only");

```

```solidity
File: governance/VerbsDAOProxyV1.sol

82:         require(msg.sender == admin, "VerbsDAOProxy::_setImplementation: admin only");

83:         require(implementation_ != address(0), "VerbsDAOProxy::_setImplementation: invalid implementation address");

```

### <a name="GAS-8"></a>[GAS-8] Functions guaranteed to revert when called by normal users can be marked `payable`
If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as `payable` will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided.

*Instances (31)*:
```solidity
File: CultureIndex.sol

100:     function setERC721VotingToken(ERC721Checkpointable _ERC721VotingToken) external override onlyOwner nonReentrant whenERC721VotingTokenNotLocked {

110:     function lockERC721VotingToken() external override onlyOwner whenERC721VotingTokenNotLocked {

364:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {

387:     function dropTopVotedPiece() public nonReentrant onlyOwner returns (ArtPiece memory) {

```

```solidity
File: MaxHeap.sol

45:     function maxHeapify(uint256 pos) public onlyOwner {

70:     function insert(uint256 itemId, uint256 value) public onlyOwner {

87:     function updateValue(uint256 itemId, uint256 newValue) public onlyOwner {

107:     function extractMax() external onlyOwner returns (uint256, uint256) {

```

```solidity
File: NontransferableERC20Votes.sol

94:     function mint(address account, uint256 amount) public onlyOwner {

```

```solidity
File: TokenEmitter.sol

173:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {

185:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {

196:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {

```

```solidity
File: VerbsAuctionHouse.sol

163:     function pause() external override onlyOwner {

172:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {

185:     function setMinCreatorRateBps(uint256 _minCreatorRateBps) external onlyOwner {

202:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {

214:     function unpause() external override onlyOwner {

226:     function setTimeBuffer(uint256 _timeBuffer) external override onlyOwner {

236:     function setReservePrice(uint256 _reservePrice) external override onlyOwner {

246:     function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {

```

```solidity
File: VerbsDescriptor.sol

79:     function toggleDataURIEnabled() external override onlyOwner {

92:     function setBaseURI(string calldata _baseURI) external override onlyOwner {

```

```solidity
File: VerbsToken.sol

120:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {

138:     function mint() public override onlyMinter nonReentrant returns (uint256) {

145:     function burn(uint256 verbId) public override onlyMinter nonReentrant {

172:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {

183:     function lockMinter() external override onlyOwner whenMinterNotLocked {

193:     function setDescriptor(IVerbsDescriptorMinimal _descriptor) external override onlyOwner nonReentrant whenDescriptorNotLocked {

203:     function lockDescriptor() external override onlyOwner whenDescriptorNotLocked {

213:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {

223:     function lockCultureIndex() external override onlyOwner whenCultureIndexNotLocked {

```

### <a name="GAS-9"></a>[GAS-9] `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too)
*Saves 5 gas per loop*

*Instances (16)*:
```solidity
File: CultureIndex.sol

150:         for (uint i = 0; i < creatorArray.length; i++) {

178:         uint256 pieceId = _currentPieceId++;

193:         for (uint i = 0; i < creatorArray.length; i++) {

211:         for (uint i = 0; i < creatorArray.length; i++) {

397:             for (uint i = 0; i < pieces[pieceId].creators.length; i++) {

```

```solidity
File: MaxHeap.sol

80:         size++;

```

```solidity
File: TokenEmitter.sol

120:             for (uint i = 0; i < _addresses.length; i++) {

```

```solidity
File: VerbsAuctionHouse.sol

317:             for (uint256 i = 0; i < numCreators; i++) {

```

```solidity
File: VerbsToken.sol

252:             uint256 verbId = _currentVerbId++;

264:             for (uint i = 0; i < artPiece.creators.length; i++) {

```

```solidity
File: base/ERC721Checkpointable.sol

126:         require(nonce == nonces[signatory]++, "ERC721Checkpointable::delegateBySig: invalid nonce");

```

```solidity
File: governance/VerbsDAOLogicV1.sol

224:         proposalCount++;

277:         for (uint256 i = 0; i < proposal.targets.length; i++) {

300:         for (uint256 i = 0; i < proposal.targets.length; i++) {

348:         for (uint256 i = 0; i < proposal.targets.length; i++) {

375:         for (uint256 i = 0; i < proposal.targets.length; i++) {

```

### <a name="GAS-10"></a>[GAS-10] Using `private` rather than `public` for constants, saves gas
If needed, the values can be read from the verified contract source code, or if there are multiple values there can be a single getter function that [returns a tuple](https://github.com/code-423n4/2022-08-frax/blob/90f55a9ce4e25bceed3a74290b854341d8de6afa/src/contracts/FraxlendPair.sol#L156-L178) of the values of all currently-public constants. Saves **3406-3606 gas** in deployment gas due to the compiler not having to create non-payable getter functions for deployment calldata, not having to store the bytes of the value outside of where it's used, and not adding another entry to the method ID table

*Instances (26)*:
```solidity
File: CultureIndex.sol

28:     uint256 public constant MIN_QUORUM_VOTES_BPS = 200; // 200 basis points or 2%

31:     uint256 public constant MAX_QUORUM_VOTES_BPS = 4_000; // 4,000 basis points or 40%

```

```solidity
File: base/ERC721Checkpointable.sol

41:     uint8 public constant decimals = 0;

59:     bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");

62:     bytes32 public constant DELEGATION_TYPEHASH = keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)");

```

```solidity
File: governance/VerbsDAOExecutor.sol

41:     uint256 public constant GRACE_PERIOD = 14 days;

42:     uint256 public constant MINIMUM_DELAY = 2 days;

43:     uint256 public constant MAXIMUM_DELAY = 30 days;

```

```solidity
File: governance/VerbsDAOLogicV1.sol

59:     string public constant name = "Vrbs DAO";

62:     uint256 public constant MIN_PROPOSAL_THRESHOLD_BPS = 1; // 1 basis point or 0.01%

65:     uint256 public constant MAX_PROPOSAL_THRESHOLD_BPS = 1_000; // 1,000 basis points or 10%

68:     uint256 public constant MIN_VOTING_PERIOD = 5_760; // About 24 hours

71:     uint256 public constant MAX_VOTING_PERIOD = 80_640; // About 2 weeks

74:     uint256 public constant MIN_VOTING_DELAY = 1;

77:     uint256 public constant MAX_VOTING_DELAY = 40_320; // About 1 week

80:     uint256 public constant MIN_QUORUM_VOTES_BPS_LOWER_BOUND = 200; // 200 basis points or 2%

83:     uint256 public constant MIN_QUORUM_VOTES_BPS_UPPER_BOUND = 2_000; // 2,000 basis points or 20%

86:     uint256 public constant MAX_QUORUM_VOTES_BPS_UPPER_BOUND = 6_000; // 4,000 basis points or 60%

89:     uint256 public constant MAX_QUORUM_VOTES_BPS = 2_000; // 2,000 basis points or 20%

92:     uint256 public constant proposalMaxOperations = 10; // 10 actions

95:     uint256 public constant MAX_REFUND_PRIORITY_FEE = 2 gwei;

98:     uint256 public constant REFUND_BASE_GAS = 36000;

101:     uint256 public constant MAX_REFUND_GAS_USED = 200_000;

104:     uint256 public constant MAX_REFUND_BASE_FEE = 200 gwei;

107:     bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");

110:     bytes32 public constant BALLOT_TYPEHASH = keccak256("Ballot(uint256 proposalId,uint8 support)");

```

### <a name="GAS-11"></a>[GAS-11] Use shift Right/Left instead of division/multiplication if possible

*Instances (4)*:
```solidity
File: MaxHeap.sol

31:         return (pos - 1) / 2;

53:         if (pos >= (size / 2) && pos <= size) return;

```

```solidity
File: base/ERC721Checkpointable.sol

169:             uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow

```

```solidity
File: governance/VerbsDAOLogicV1.sol

900:             uint256 center = upper - (upper - lower) / 2;

```

### <a name="GAS-12"></a>[GAS-12] Splitting require() statements that use && saves gas

*Instances (7)*:
```solidity
File: CultureIndex.sol

71:         require(quorumVotesBPS_ >= MIN_QUORUM_VOTES_BPS && quorumVotesBPS_ <= MAX_QUORUM_VOTES_BPS, "CultureIndex::constructor: invalid quorum bps");

125:         require(uint8(metadata.mediaType) > 0 && uint8(metadata.mediaType) <= 5, "Invalid media type");

```

```solidity
File: governance/VerbsDAOLogicV1.sol

153:         require(votingPeriod_ >= MIN_VOTING_PERIOD && votingPeriod_ <= MAX_VOTING_PERIOD, "VerbsDAO::initialize: invalid voting period");

154:         require(votingDelay_ >= MIN_VOTING_DELAY && votingDelay_ <= MAX_VOTING_DELAY, "VerbsDAO::initialize: invalid voting delay");

581:         require(newVotingDelay >= MIN_VOTING_DELAY && newVotingDelay <= MAX_VOTING_DELAY, "VerbsDAO::_setVotingDelay: invalid voting delay");

596:         require(newVotingPeriod >= MIN_VOTING_PERIOD && newVotingPeriod <= MAX_VOTING_PERIOD, "VerbsDAO::_setVotingPeriod: invalid voting period");

765:         require(msg.sender == pendingAdmin && msg.sender != address(0), "VerbsDAO::_acceptAdmin: pending admin only");

```

### <a name="GAS-13"></a>[GAS-13] Use != 0 instead of > 0 for unsigned integer comparison

*Instances (32)*:
```solidity
File: CultureIndex.sol

72:         require(erc721VotingTokenWeight_ > 0, "CultureIndex::constructor: invalid erc721 voting token weight");

125:         require(uint8(metadata.mediaType) > 0 && uint8(metadata.mediaType) <= 5, "Invalid media type");

128:             require(bytes(metadata.image).length > 0, "Image URL must be provided");

130:             require(bytes(metadata.animationUrl).length > 0, "Animation URL must be provided");

132:             require(bytes(metadata.text).length > 0, "Text must be provided");

272:         require(weight > 0, "Weight must be greater than zero");

```

```solidity
File: MaxHeap.sol

108:         require(size > 0, "Heap is empty");

121:         require(size > 0, "Heap is empty");

```

```solidity
File: TokenEmitter.sol

80:         require(msg.value > 0, "Must send ether");

94:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0 ? getTokenQuoteForEther((msgValueRemaining - toPayTreasury) - creatorDirectPayment) : int(0);

97:         int totalTokensForBuyers = toPayTreasury > 0 ? getTokenQuoteForEther(toPayTreasury) : int(0);

101:         if (totalTokensForCreators > 0) emittedTokenWad += totalTokensForCreators;

106:         if (creatorDirectPayment > 0) {

112:         if (totalTokensForCreators > 0 && creatorsAddress != address(0)) {

119:         if (totalTokensForBuyers > 0) {

143:         require(amount > 0, "Amount must be greater than 0");

150:         require(etherAmount > 0, "Ether amount must be greater than 0");

157:         require(paymentAmount > 0, "Payment amount must be greater than 0");

```

```solidity
File: VerbsAuctionHouse.sol

293:         if (_auction.amount > 0) {

```

```solidity
File: base/ERC721.sol

123:         return bytes(baseURI).length > 0 ? string(abi.encodePacked(baseURI, tokenId.toString())) : "";

370:         if (to.code.length > 0) {

```

```solidity
File: base/ERC721Checkpointable.sol

138:         return nCheckpoints > 0 ? checkpoints[account][nCheckpoints - 1].votes : 0;

196:         if (srcRep != dstRep && amount > 0) {

199:                 uint96 srcRepOld = srcRepNum > 0 ? checkpoints[srcRep][srcRepNum - 1].votes : 0;

206:                 uint96 dstRepOld = dstRepNum > 0 ? checkpoints[dstRep][dstRepNum - 1].votes : 0;

216:         if (nCheckpoints > 0 && checkpoints[delegatee][nCheckpoints - 1].fromBlock == blockNumber) {

```

```solidity
File: base/Votes.sol

184:         if (from != to && amount > 0) {

```

```solidity
File: governance/VerbsDAOLogicV1.sol

159:         require(verbsTokenVotingWeight_ > 0, "VerbsDAO::initialize: invalid verbs token voting weight");

513:         if (votes > 0) {

916:         if (pos > 0 && quorumParamsCheckpoints[pos - 1].fromBlock == blockNumber) {

```

```solidity
File: libs/SignedWadMath.sol

2: pragma solidity >=0.8.22;

133:         require(x > 0, "UNDEFINED");

```


## Non Critical Issues


| |Issue|Instances|
|-|:-|:-:|
| [NC-1](#NC-1) | Missing checks for `address(0)` when assigning values to address state variables | 2 |
| [NC-2](#NC-2) | Return values of `approve()` not checked | 4 |
| [NC-3](#NC-3) | Event is missing `indexed` fields | 24 |
| [NC-4](#NC-4) | Constants should be defined rather than using magic numbers | 5 |
| [NC-5](#NC-5) | Functions not used internally could be marked external | 6 |
### <a name="NC-1"></a>[NC-1] Missing checks for `address(0)` when assigning values to address state variables

*Instances (2)*:
```solidity
File: governance/VerbsDAOExecutor.sol

69:         require(msg.sender == pendingAdmin, "VerbsDAOExecutor::acceptAdmin: Call must come from pendingAdmin.");

88:         queuedTransactions[txHash] = true;

```

### <a name="NC-2"></a>[NC-2] Return values of `approve()` not checked
Not all IERC20 implementations `revert()` when there's a failure in `approve()`. The function signature has a boolean return value and they indicate errors that way instead. By not checking the return value, operations that should have marked as failed, may potentially go through without actually approving anything

*Instances (4)*:
```solidity
File: base/ERC721.sol

144:         _approve(to, tokenId);

```

```solidity
File: base/erc20/ERC20.sol

134:         _approve(owner, spender, value);

264:         _approve(owner, spender, value, true);

312:                 _approve(owner, spender, currentAllowance - value, false);

```

### <a name="NC-3"></a>[NC-3] Event is missing `indexed` fields
Index event fields make the field more quickly accessible to off-chain tools that parse events. However, note that each index field costs extra gas during emission, so it's not necessarily best to index the maximum allowed per event (three fields). Each event should use three indexed fields if there are three or more fields, and gas usage is not particularly of concern for the events in question. If there are fewer than three fields, all of the fields should be indexed.

*Instances (24)*:
```solidity
File: governance/VerbsDAOExecutor.sol

45:     address public admin;

51:     constructor(address admin_, uint256 delay_) {

52:         require(delay_ >= MINIMUM_DELAY, "VerbsDAOExecutor::constructor: Delay must exceed minimum delay.");

```

```solidity
File: governance/VerbsDAOInterfaces.sol

55:         uint256 startBlock,

65:     /// @param support Support value for the vote. 0=against, 1=for, 2=abstain

80:     event ProposalVetoed(uint256 id);

85:     /// @notice An event emitted when the voting period is set

88:     /// @notice Emitted when implementation is changed

91:     /// @notice Emitted when proposal threshold basis points is set

92:     event ProposalThresholdBPSSet(uint256 oldProposalThresholdBPS, uint256 newProposalThresholdBPS);

94:     /// @notice Emitted when quorum votes basis points is set

97:     /// @notice Emitted when pendingAdmin is changed

100:     /// @notice Emitted when pendingAdmin is accepted, which means admin is updated

104:     event NewVetoer(address oldVetoer, address newVetoer);

107:     event MinQuorumVotesBPSSet(uint16 oldMinQuorumVotesBPS, uint16 newMinQuorumVotesBPS);

110:     event MaxQuorumVotesBPSSet(uint16 oldMaxQuorumVotesBPS, uint16 newMaxQuorumVotesBPS);

113:     event QuorumCoefficientSet(uint32 oldQuorumCoefficient, uint32 newQuorumCoefficient);

116:     event RefundableVote(address indexed voter, uint256 refundAmount, bool refundSent);

118:     /// @notice Emitted when admin withdraws the DAO's balance.

122:     event NewPendingVetoer(address oldPendingVetoer, address newPendingVetoer);

127:     address public admin;

133:     address public implementation;

138:  * @notice For future upgrades, do not change VerbsDAOStorageV1. Create a new

140:  * VerbsDAOStorageVX.

```

### <a name="NC-4"></a>[NC-4] Constants should be defined rather than using magic numbers

*Instances (5)*:
```solidity
File: VerbsAuctionHouse.sol

348:             success := call(50000, _to, _amount, 0, 0, 0, 0)

```

```solidity
File: libs/SignedWadMath.sol

101:         p = p * x + (4385272521454847904659076985693276 << 96);

127:         r = int256((uint256(r) * 3822833074963236453042738258902158003155416615667) >> uint256(195 - k));

155:         x <<= uint256(159 - k);

166:         p = p * x - (795164235651350426258249787498 << 96);

```

### <a name="NC-5"></a>[NC-5] Functions not used internally could be marked external

*Instances (6)*:
```solidity
File: governance/VerbsDAOExecutor.sol

69:         require(msg.sender == pendingAdmin, "VerbsDAOExecutor::acceptAdmin: Call must come from pendingAdmin.");

83:     function queueTransaction(address target, uint256 value, string memory signature, bytes memory data, uint256 eta) public returns (bytes32) {

85:         require(eta >= getBlockTimestamp() + delay, "VerbsDAOExecutor::queueTransaction: Estimated execution block must satisfy delay.");

90:         emit QueueTransaction(txHash, target, value, signature, data, eta);

103:     function executeTransaction(address target, uint256 value, string memory signature, bytes memory data, uint256 eta) public returns (bytes memory) {

108:         require(getBlockTimestamp() >= eta, "VerbsDAOExecutor::executeTransaction: Transaction hasn't surpassed time lock.");

```


## Low Issues


| |Issue|Instances|
|-|:-|:-:|
| [L-1](#L-1) |  `abi.encodePacked()` should not be used with dynamic types when passing the result to a hash function such as `keccak256()` | 4 |
| [L-2](#L-2) | Use of `tx.origin` is unsafe in almost every context | 2 |
| [L-3](#L-3) | Empty Function Body - Consider commenting why | 6 |
| [L-4](#L-4) | Initializers could be front-run | 7 |
| [L-5](#L-5) | Unsafe ERC20 operation(s) | 2 |
| [L-6](#L-6) | Unspecific compiler version pragma | 1 |
| [L-7](#L-7) | Use of ecrecover is susceptible to signature malleability | 2 |
### <a name="L-1"></a>[L-1]  `abi.encodePacked()` should not be used with dynamic types when passing the result to a hash function such as `keccak256()`
Use `abi.encode()` instead which will pad items to 32 bytes, which will [prevent hash collisions](https://docs.soliditylang.org/en/v0.8.13/abi-spec.html#non-standard-packed-mode) (e.g. `abi.encodePacked(0x123,0x456)` => `0x123456` => `abi.encodePacked(0x1,0x23456)`, but `abi.encode(0x123,0x456)` => `0x0...1230...456`). "Unless there is a compelling reason, `abi.encode` should be preferred". If there is only one argument to `abi.encodePacked()` it can often be cast to `bytes()` or `bytes32()` [instead](https://ethereum.stackexchange.com/questions/30912/how-to-compare-strings-in-solidity#answer-82739).
If all arguments are strings and or bytes, `bytes.concat()` should be used instead

*Instances (4)*:
```solidity
File: CultureIndex.sol

405:             if (keccak256(abi.encodePacked(reason)) == keccak256(abi.encodePacked("Heap is empty"))) {

405:             if (keccak256(abi.encodePacked(reason)) == keccak256(abi.encodePacked("Heap is empty"))) {

```

```solidity
File: base/ERC721Checkpointable.sol

123:         bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

```

```solidity
File: governance/VerbsDAOLogicV1.sol

535:         bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

```

### <a name="L-2"></a>[L-2] Use of `tx.origin` is unsafe in almost every context
According to [Vitalik Buterin](https://ethereum.stackexchange.com/questions/196/how-do-i-make-my-dapp-serenity-proof), contracts should _not_ `assume that tx.origin will continue to be usable or meaningful`. An example of this is [EIP-3074](https://eips.ethereum.org/EIPS/eip-3074#allowing-txorigin-as-signer-1) which explicitly mentions the intention to change its semantics when it's used with new op codes. There have also been calls to [remove](https://github.com/ethereum/solidity/issues/683) `tx.origin`, and there are [security issues](solidity.readthedocs.io/en/v0.4.24/security-considerations.html#tx-origin) associated with using it for authorization. For these reasons, it's best to completely avoid the feature.

*Instances (2)*:
```solidity
File: governance/VerbsDAOLogicV1.sol

933:             (bool refundSent, ) = tx.origin.call{ value: refundAmount }("");

934:             emit RefundableVote(tx.origin, refundAmount, refundSent);

```

### <a name="L-3"></a>[L-3] Empty Function Body - Consider commenting why

*Instances (6)*:
```solidity
File: MaxHeap.sol

24:     constructor(address _owner) Ownable(_owner) {}

```

```solidity
File: NontransferableERC20Votes.sol

32:     constructor(address _initialOwner, string memory name_, string memory symbol_) Ownable(_initialOwner) ERC20(name_, symbol_) EIP712(name_, "1") {}

```

```solidity
File: base/ERC721.sol

401:     function _beforeTokenTransfer(address from, address to, uint256 tokenId) internal virtual {}

```

```solidity
File: governance/VerbsDAOExecutor.sol

135:     receive() external payable {}

137:     fallback() external payable {}

```

```solidity
File: governance/VerbsDAOLogicV1.sol

980:     receive() external payable {}

```

### <a name="L-4"></a>[L-4] Initializers could be front-run
Initializers could be front-run, allowing an attacker to either set their own values, take ownership of the contract, and in the best case forcing a re-deployment

*Instances (7)*:
```solidity
File: VerbsAuctionHouse.sol

75:     function initialize(

87:     ) external initializer {

88:         __Pausable_init();

89:         __ReentrancyGuard_init();

90:         __Ownable_init(_founder);

```

```solidity
File: governance/VerbsDAOLogicV1.sol

135:     function initialize(

```

```solidity
File: governance/VerbsDAOProxyV1.sol

61:                 "initialize(address,address,address,uint256,uint256,uint256,(uint16,uint16,uint32))",

```

### <a name="L-5"></a>[L-5] Unsafe ERC20 operation(s)

*Instances (2)*:
```solidity
File: VerbsAuctionHouse.sol

291:         else verbs.transferFrom(address(this), _auction.bidder, _auction.verbId);

357:             bool wethSuccess = IWETH(WETH).transfer(_to, _amount);

```

### <a name="L-6"></a>[L-6] Unspecific compiler version pragma

*Instances (1)*:
```solidity
File: libs/SignedWadMath.sol

2: pragma solidity >=0.8.22;

```

### <a name="L-7"></a>[L-7] Use of ecrecover is susceptible to signature malleability
The built-in EVM precompile ecrecover is susceptible to signature malleability, which could lead to replay attacks.Consider using OpenZeppelin’s ECDSA library instead of the built-in function.

*Instances (2)*:
```solidity
File: base/ERC721Checkpointable.sol

124:         address signatory = ecrecover(digest, v, r, s);

```

```solidity
File: governance/VerbsDAOLogicV1.sol

536:         address signatory = ecrecover(digest, v, r, s);

```


## Medium Issues


| |Issue|Instances|
|-|:-|:-:|
| [M-1](#M-1) | Centralization Risk for trusted owners | 47 |
### <a name="M-1"></a>[M-1] Centralization Risk for trusted owners

#### Impact:
Contracts have owners with privileged rights to perform admin tasks and need to be trusted to not perform malicious updates or drain funds.

*Instances (47)*:
```solidity
File: CultureIndex.sol

7: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

11: contract CultureIndex is ICultureIndex, Ownable, ReentrancyGuard {

70:     ) Ownable(initialOwner_) {

100:     function setERC721VotingToken(ERC721Checkpointable _ERC721VotingToken) external override onlyOwner nonReentrant whenERC721VotingTokenNotLocked {

110:     function lockERC721VotingToken() external override onlyOwner whenERC721VotingTokenNotLocked {

364:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {

387:     function dropTopVotedPiece() public nonReentrant onlyOwner returns (ArtPiece memory) {

```

```solidity
File: MaxHeap.sol

4: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

10: contract MaxHeap is Ownable, ReentrancyGuard {

24:     constructor(address _owner) Ownable(_owner) {}

45:     function maxHeapify(uint256 pos) public onlyOwner {

70:     function insert(uint256 itemId, uint256 value) public onlyOwner {

87:     function updateValue(uint256 itemId, uint256 newValue) public onlyOwner {

107:     function extractMax() external onlyOwner returns (uint256, uint256) {

```

```solidity
File: NontransferableERC20Votes.sol

20: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

25: contract NontransferableERC20Votes is Ownable, ERC20Votes {

32:     constructor(address _initialOwner, string memory name_, string memory symbol_) Ownable(_initialOwner) ERC20(name_, symbol_) EIP712(name_, "1") {}

94:     function mint(address account, uint256 amount) public onlyOwner {

```

```solidity
File: TokenEmitter.sol

11: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

13: contract TokenEmitter is VRGDAC, ITokenEmitter, ReentrancyGuard, TokenEmitterRewards, Ownable {

45:     ) TokenEmitterRewards(_protocolRewards, _protocolFeeRecipient) VRGDAC(_targetPrice, _priceDecayPercent, _tokensPerTimeUnit) Ownable(_initialOwner) {

173:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {

185:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {

196:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {

```

```solidity
File: VerbsAuctionHouse.sol

163:     function pause() external override onlyOwner {

172:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {

185:     function setMinCreatorRateBps(uint256 _minCreatorRateBps) external onlyOwner {

202:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {

214:     function unpause() external override onlyOwner {

226:     function setTimeBuffer(uint256 _timeBuffer) external override onlyOwner {

236:     function setReservePrice(uint256 _reservePrice) external override onlyOwner {

246:     function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {

```

```solidity
File: VerbsDescriptor.sol

20: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

26: contract VerbsDescriptor is IVerbsDescriptor, Ownable {

50:     constructor(address _initialOwner, string memory _tokenNamePrefix) Ownable(_initialOwner) {

79:     function toggleDataURIEnabled() external override onlyOwner {

92:     function setBaseURI(string calldata _baseURI) external override onlyOwner {

```

```solidity
File: VerbsToken.sol

20: import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

30: contract VerbsToken is IVerbsToken, Ownable, ERC721Checkpointable, ReentrancyGuard {

101:     ) ERC721(_tokenName, _tokenSymbol) Ownable(_initialOwner) {

120:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {

172:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {

183:     function lockMinter() external override onlyOwner whenMinterNotLocked {

193:     function setDescriptor(IVerbsDescriptorMinimal _descriptor) external override onlyOwner nonReentrant whenDescriptorNotLocked {

203:     function lockDescriptor() external override onlyOwner whenDescriptorNotLocked {

213:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {

223:     function lockCultureIndex() external override onlyOwner whenCultureIndexNotLocked {

```

