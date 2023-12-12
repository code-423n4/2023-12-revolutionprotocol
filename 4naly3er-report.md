# Report

## Gas Optimizations

| |Issue|Instances|
|-|:-|:-:|
| [GAS-1](#GAS-1) | Using bools for storage incurs overhead | 3 |
| [GAS-2](#GAS-2) | Cache array length outside of loop | 2 |
| [GAS-3](#GAS-3) | For Operations that will not overflow, you could use unchecked | 283 |
| [GAS-4](#GAS-4) | Use Custom Errors | 73 |
| [GAS-5](#GAS-5) | Don't initialize variables with default value | 7 |
| [GAS-6](#GAS-6) | Long revert strings | 16 |
| [GAS-7](#GAS-7) | Functions guaranteed to revert when called by normal users can be marked `payable` | 30 |
| [GAS-8](#GAS-8) | `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too) | 13 |
| [GAS-9](#GAS-9) | Using `private` rather than `public` for constants, saves gas | 6 |
| [GAS-10](#GAS-10) | Use shift Right/Left instead of division/multiplication if possible | 2 |
| [GAS-11](#GAS-11) | Splitting require() statements that use && saves gas | 2 |
| [GAS-12](#GAS-12) | Use != 0 instead of > 0 for unsigned integer comparison | 21 |

### <a name="GAS-1"></a>[GAS-1] Using bools for storage incurs overhead

Use uint256(1) and uint256(2) for true/false to avoid a Gwarmaccess (100 gas), and to avoid Gsset (20000 gas) when changing from ‘false’ to ‘true’, after having been ‘true’ in the past. See [source](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/58f635312aa21f947cae5f8578638a85aa2519f5/contracts/security/ReentrancyGuard.sol#L23-L27).

*Instances (3)*:

```solidity
File: packages/revolution/src/VerbsToken.sol

51:     bool public isMinterLocked;

54:     bool public isCultureIndexLocked;

57:     bool public isDescriptorLocked;

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/VerbsToken.sol)

### <a name="GAS-2"></a>[GAS-2] Cache array length outside of loop

If not cached, the solidity compiler will always read the length of the array during each iteration. That is, if it is a storage array, this is an extra sload operation (100 additional extra gas for each iteration except for the first) and if it is a memory array, this is an extra mload operation (3 additional gas for each iteration except for the first).

*Instances (2)*:

```solidity
File: packages/revolution/src/ERC20TokenEmitter.sol

209:         for (uint256 i = 0; i < addresses.length; i++) {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol)

```solidity
File: packages/revolution/src/VerbsToken.sol

306:             for (uint i = 0; i < artPiece.creators.length; i++) {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/VerbsToken.sol)

### <a name="GAS-3"></a>[GAS-3] For Operations that will not overflow, you could use unchecked

*Instances (283)*:

```solidity
File: packages/protocol-rewards/src/abstract/RewardSplits.sol

4: import { IRevolutionProtocolRewards } from "../interfaces/IRevolutionProtocolRewards.sol";

4: import { IRevolutionProtocolRewards } from "../interfaces/IRevolutionProtocolRewards.sol";

44:             (paymentAmountWei * BUILDER_REWARD_BPS) /

44:             (paymentAmountWei * BUILDER_REWARD_BPS) /

45:             10_000 +

46:             (paymentAmountWei * PURCHASE_REFERRAL_BPS) /

46:             (paymentAmountWei * PURCHASE_REFERRAL_BPS) /

47:             10_000 +

48:             (paymentAmountWei * DEPLOYER_REWARD_BPS) /

48:             (paymentAmountWei * DEPLOYER_REWARD_BPS) /

49:             10_000 +

50:             (paymentAmountWei * REVOLUTION_REWARD_BPS) /

50:             (paymentAmountWei * REVOLUTION_REWARD_BPS) /

57:                 builderReferralReward: (paymentAmountWei * BUILDER_REWARD_BPS) / 10_000,

57:                 builderReferralReward: (paymentAmountWei * BUILDER_REWARD_BPS) / 10_000,

58:                 purchaseReferralReward: (paymentAmountWei * PURCHASE_REFERRAL_BPS) / 10_000,

58:                 purchaseReferralReward: (paymentAmountWei * PURCHASE_REFERRAL_BPS) / 10_000,

59:                 deployerReward: (paymentAmountWei * DEPLOYER_REWARD_BPS) / 10_000,

59:                 deployerReward: (paymentAmountWei * DEPLOYER_REWARD_BPS) / 10_000,

60:                 revolutionReward: (paymentAmountWei * REVOLUTION_REWARD_BPS) / 10_000

60:                 revolutionReward: (paymentAmountWei * REVOLUTION_REWARD_BPS) / 10_000

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/protocol-rewards/src/abstract/RewardSplits.sol)

```solidity
File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

4: import { RewardSplits } from "../RewardSplits.sol";

20:         return msgValue - _depositPurchaseRewards(msgValue, builderReferral, purchaseReferral, deployer);

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol)

```solidity
File: packages/revolution/src/AuctionHouse.sol

26: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

26: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

26: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

26: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

27: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

27: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

27: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

27: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

28: import { IAuctionHouse } from "./interfaces/IAuctionHouse.sol";

28: import { IAuctionHouse } from "./interfaces/IAuctionHouse.sol";

29: import { IVerbsToken } from "./interfaces/IVerbsToken.sol";

29: import { IVerbsToken } from "./interfaces/IVerbsToken.sol";

30: import { IWETH } from "./interfaces/IWETH.sol";

30: import { IWETH } from "./interfaces/IWETH.sol";

31: import { IERC20TokenEmitter } from "./interfaces/IERC20TokenEmitter.sol";

31: import { IERC20TokenEmitter } from "./interfaces/IERC20TokenEmitter.sol";

32: import { ICultureIndex } from "./interfaces/ICultureIndex.sol";

32: import { ICultureIndex } from "./interfaces/ICultureIndex.sol";

33: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

33: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

34: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

34: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

34: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

34: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

36: import { UUPS } from "./libs/proxy/UUPS.sol";

36: import { UUPS } from "./libs/proxy/UUPS.sol";

36: import { UUPS } from "./libs/proxy/UUPS.sol";

37: import { VersionedContract } from "./version/VersionedContract.sol";

37: import { VersionedContract } from "./version/VersionedContract.sol";

181:             msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100),

181:             msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100),

181:             msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100),

191:         bool extended = _auction.endTime - block.timestamp < timeBuffer;

192:         if (extended) auction.endTime = _auction.endTime = block.timestamp + timeBuffer;

315:             uint256 endTime = startTime + duration;

365:                 uint256 auctioneerPayment = (_auction.amount * (10_000 - creatorRateBps)) / 10_000;

365:                 uint256 auctioneerPayment = (_auction.amount * (10_000 - creatorRateBps)) / 10_000;

365:                 uint256 auctioneerPayment = (_auction.amount * (10_000 - creatorRateBps)) / 10_000;

368:                 uint256 creatorsShare = _auction.amount - auctioneerPayment;

384:                     for (uint256 i = 0; i < numCreators; i++) {

384:                     for (uint256 i = 0; i < numCreators; i++) {

390:                         uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);

390:                         uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);

390:                         uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);

390:                         uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);

391:                         ethPaidToCreators += paymentAmount;

400:                     creatorTokensEmitted = erc20TokenEmitter.buyToken{ value: creatorsShare - ethPaidToCreators }(

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol)

```solidity
File: packages/revolution/src/CultureIndex.sol

4: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

4: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

4: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

4: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

5: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

5: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

5: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

5: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

7: import { UUPS } from "./libs/proxy/UUPS.sol";

7: import { UUPS } from "./libs/proxy/UUPS.sol";

7: import { UUPS } from "./libs/proxy/UUPS.sol";

8: import { VersionedContract } from "./version/VersionedContract.sol";

8: import { VersionedContract } from "./version/VersionedContract.sol";

10: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

10: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

12: import { ERC20VotesUpgradeable } from "./base/erc20/ERC20VotesUpgradeable.sol";

12: import { ERC20VotesUpgradeable } from "./base/erc20/ERC20VotesUpgradeable.sol";

12: import { ERC20VotesUpgradeable } from "./base/erc20/ERC20VotesUpgradeable.sol";

13: import { MaxHeap } from "./MaxHeap.sol";

14: import { ICultureIndex } from "./interfaces/ICultureIndex.sol";

14: import { ICultureIndex } from "./interfaces/ICultureIndex.sol";

16: import { ERC721CheckpointableUpgradeable } from "./base/ERC721CheckpointableUpgradeable.sol";

16: import { ERC721CheckpointableUpgradeable } from "./base/ERC721CheckpointableUpgradeable.sol";

17: import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

17: import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

17: import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

17: import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

17: import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

18: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

18: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

18: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

48:     uint256 public constant MAX_QUORUM_VOTES_BPS = 6_000; // 6,000 basis points or 60%

48:     uint256 public constant MAX_QUORUM_VOTES_BPS = 6_000; // 6,000 basis points or 60%

185:         for (uint i; i < creatorArrayLength; i++) {

185:         for (uint i; i < creatorArrayLength; i++) {

187:             totalBps += creatorArray[i].bps;

218:         uint256 pieceId = _currentPieceId++;

218:         uint256 pieceId = _currentPieceId++;

234:         newPiece.quorumVotes = (quorumVotesBPS * newPiece.totalVotesSupply) / 10_000;

234:         newPiece.quorumVotes = (quorumVotesBPS * newPiece.totalVotesSupply) / 10_000;

236:         for (uint i; i < creatorArrayLength; i++) {

236:         for (uint i; i < creatorArrayLength; i++) {

243:         for (uint i; i < creatorArrayLength; i++) {

243:         for (uint i; i < creatorArrayLength; i++) {

285:         return erc20Balance + (erc721Balance * erc721VotingTokenWeight * 1e18);

285:         return erc20Balance + (erc721Balance * erc721VotingTokenWeight * 1e18);

285:         return erc20Balance + (erc721Balance * erc721VotingTokenWeight * 1e18);

317:         totalVoteWeights[pieceId] += weight;

355:         for (uint256 i; i < len; i++) {

355:         for (uint256 i; i < len; i++) {

403:         for (uint256 i; i < len; i++) {

403:         for (uint256 i; i < len; i++) {

407:         for (uint256 i; i < len; i++) {

407:         for (uint256 i; i < len; i++) {

431:         voteHash = keccak256(abi.encode(VOTE_TYPEHASH, from, pieceIds, nonces[from]++, deadline));

431:         voteHash = keccak256(abi.encode(VOTE_TYPEHASH, from, pieceIds, nonces[from]++, deadline));

511:             (quorumVotesBPS * _calculateVoteWeight(erc20VotingToken.totalSupply(), erc721VotingToken.totalSupply())) /

511:             (quorumVotesBPS * _calculateVoteWeight(erc20VotingToken.totalSupply(), erc721VotingToken.totalSupply())) /

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/CultureIndex.sol)

```solidity
File: packages/revolution/src/ERC20TokenEmitter.sol

4: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

4: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

4: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

4: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

5: import { TokenEmitterRewards } from "@collectivexyz/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol";

5: import { TokenEmitterRewards } from "@collectivexyz/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol";

5: import { TokenEmitterRewards } from "@collectivexyz/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol";

5: import { TokenEmitterRewards } from "@collectivexyz/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol";

5: import { TokenEmitterRewards } from "@collectivexyz/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol";

5: import { TokenEmitterRewards } from "@collectivexyz/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol";

6: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

6: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

6: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

6: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

7: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

7: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

7: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

7: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

9: import { VRGDAC } from "./libs/VRGDAC.sol";

9: import { VRGDAC } from "./libs/VRGDAC.sol";

10: import { toDaysWadUnsafe } from "./libs/SignedWadMath.sol";

10: import { toDaysWadUnsafe } from "./libs/SignedWadMath.sol";

11: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

11: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

11: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";

12: import { NontransferableERC20Votes } from "./NontransferableERC20Votes.sol";

13: import { IERC20TokenEmitter } from "./interfaces/IERC20TokenEmitter.sol";

13: import { IERC20TokenEmitter } from "./interfaces/IERC20TokenEmitter.sol";

15: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

15: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

173:         uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;

173:         uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;

173:         uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;

177:         uint256 creatorDirectPayment = ((msgValueRemaining - toPayTreasury) * entropyRateBps) / 10_000;

177:         uint256 creatorDirectPayment = ((msgValueRemaining - toPayTreasury) * entropyRateBps) / 10_000;

177:         uint256 creatorDirectPayment = ((msgValueRemaining - toPayTreasury) * entropyRateBps) / 10_000;

179:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0

179:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0

180:             ? getTokenQuoteForEther((msgValueRemaining - toPayTreasury) - creatorDirectPayment)

180:             ? getTokenQuoteForEther((msgValueRemaining - toPayTreasury) - creatorDirectPayment)

187:         emittedTokenWad += totalTokensForBuyers;

188:         if (totalTokensForCreators > 0) emittedTokenWad += totalTokensForCreators;

209:         for (uint256 i = 0; i < addresses.length; i++) {

209:         for (uint256 i = 0; i < addresses.length; i++) {

212:                 _mint(addresses[i], uint256((totalTokensForBuyers * int(basisPointSplits[i])) / 10_000));

212:                 _mint(addresses[i], uint256((totalTokensForBuyers * int(basisPointSplits[i])) / 10_000));

214:             bpsSum += basisPointSplits[i];

223:             msg.value - msgValueRemaining,

243:                 timeSinceStart: toDaysWadUnsafe(block.timestamp - startTime),

260:                 timeSinceStart: toDaysWadUnsafe(block.timestamp - startTime),

277:                 timeSinceStart: toDaysWadUnsafe(block.timestamp - startTime),

279:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)

279:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)

279:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)

279:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol)

```solidity
File: packages/revolution/src/MaxHeap.sol

4: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

4: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

4: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

4: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

5: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

5: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

5: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

5: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

6: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

6: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

8: import { UUPS } from "./libs/proxy/UUPS.sol";

8: import { UUPS } from "./libs/proxy/UUPS.sol";

8: import { UUPS } from "./libs/proxy/UUPS.sol";

9: import { VersionedContract } from "./version/VersionedContract.sol";

9: import { VersionedContract } from "./version/VersionedContract.sol";

80:         return (pos - 1) / 2;

80:         return (pos - 1) / 2;

95:         uint256 left = 2 * pos + 1;

95:         uint256 left = 2 * pos + 1;

96:         uint256 right = 2 * pos + 2;

96:         uint256 right = 2 * pos + 2;

102:         if (pos >= (size / 2) && pos <= size) return;

121:         valueMapping[itemId] = value; // Update the value mapping

121:         valueMapping[itemId] = value; // Update the value mapping

122:         positionMapping[itemId] = size; // Update the position mapping

122:         positionMapping[itemId] = size; // Update the position mapping

129:         size++;

129:         size++;

150:         } else if (newValue < oldValue) maxHeapify(position); // Downwards heapify

150:         } else if (newValue < oldValue) maxHeapify(position); // Downwards heapify

160:         heap[0] = heap[--size];

160:         heap[0] = heap[--size];

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/MaxHeap.sol)

```solidity
File: packages/revolution/src/NontransferableERC20Votes.sol

20: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

20: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

20: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

20: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

21: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

21: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

21: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

21: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

22: import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

22: import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

22: import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

22: import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

22: import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

24: import { ERC20VotesUpgradeable } from "./base/erc20/ERC20VotesUpgradeable.sol";

24: import { ERC20VotesUpgradeable } from "./base/erc20/ERC20VotesUpgradeable.sol";

24: import { ERC20VotesUpgradeable } from "./base/erc20/ERC20VotesUpgradeable.sol";

25: import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

25: import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

25: import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

25: import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

25: import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

27: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

27: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/NontransferableERC20Votes.sol)

```solidity
File: packages/revolution/src/VerbsToken.sol

20: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

20: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

20: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

20: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

21: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

21: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

21: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

21: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

22: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

22: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

22: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

22: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

24: import { UUPS } from "./libs/proxy/UUPS.sol";

24: import { UUPS } from "./libs/proxy/UUPS.sol";

24: import { UUPS } from "./libs/proxy/UUPS.sol";

25: import { VersionedContract } from "./version/VersionedContract.sol";

25: import { VersionedContract } from "./version/VersionedContract.sol";

27: import { ERC721CheckpointableUpgradeable } from "./base/ERC721CheckpointableUpgradeable.sol";

27: import { ERC721CheckpointableUpgradeable } from "./base/ERC721CheckpointableUpgradeable.sol";

28: import { IDescriptorMinimal } from "./interfaces/IDescriptorMinimal.sol";

28: import { IDescriptorMinimal } from "./interfaces/IDescriptorMinimal.sol";

29: import { ICultureIndex } from "./interfaces/ICultureIndex.sol";

29: import { ICultureIndex } from "./interfaces/ICultureIndex.sol";

30: import { IVerbsToken } from "./interfaces/IVerbsToken.sol";

30: import { IVerbsToken } from "./interfaces/IVerbsToken.sol";

31: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

31: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

162:         return string(abi.encodePacked("ipfs://", _contractURIHash));

162:         return string(abi.encodePacked("ipfs://", _contractURIHash));

294:             uint256 verbId = _currentVerbId++;

294:             uint256 verbId = _currentVerbId++;

306:             for (uint i = 0; i < artPiece.creators.length; i++) {

306:             for (uint i = 0; i < artPiece.creators.length; i++) {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/VerbsToken.sol)

```solidity
File: packages/revolution/src/libs/VRGDAC.sol

4: import { wadExp, wadLn, wadMul, wadDiv, unsafeWadDiv, wadPow } from "./SignedWadMath.sol";

35:         decayConstant = wadLn(1e18 - _priceDecayPercent);

49:             return pIntegral(timeSinceStart, sold + amount) - pIntegral(timeSinceStart, sold);

49:             return pIntegral(timeSinceStart, sold + amount) - pIntegral(timeSinceStart, sold);

55:         int256 soldDifference = wadMul(perTimeUnit, timeSinceStart) - sold;

74:                                         wadPow(1e18 - priceDecayPercent, wadDiv(soldDifference, perTimeUnit))

76:                                 ) - wadMul(amount, decayConstant)

89:                 -wadMul(

91:                     wadPow(1e18 - priceDecayPercent, timeSinceStart - unsafeWadDiv(sold, perTimeUnit)) -

91:                     wadPow(1e18 - priceDecayPercent, timeSinceStart - unsafeWadDiv(sold, perTimeUnit)) -

91:                     wadPow(1e18 - priceDecayPercent, timeSinceStart - unsafeWadDiv(sold, perTimeUnit)) -

92:                         wadPow(1e18 - priceDecayPercent, timeSinceStart)

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/libs/VRGDAC.sol)

### <a name="GAS-4"></a>[GAS-4] Use Custom Errors

[Source](https://blog.soliditylang.org/2021/04/21/custom-errors/)
Instead of using error strings, to reduce deployment and runtime cost, you should use Custom Errors. This would save both deployment and runtime cost.

*Instances (73)*:

```solidity
File: packages/protocol-rewards/src/abstract/RewardSplits.sol

30:         if (_protocolRewards == address(0) || _revolutionRewardRecipient == address(0)) revert("Invalid Address Zero");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/protocol-rewards/src/abstract/RewardSplits.sol)

```solidity
File: packages/revolution/src/AuctionHouse.sol

120:         require(msg.sender == address(manager), "Only manager can initialize");

121:         require(_weth != address(0), "WETH cannot be zero address");

175:         require(bidder != address(0), "Bidder cannot be zero address");

176:         require(_auction.verbId == verbId, "Verb not up for auction");

178:         require(block.timestamp < _auction.endTime, "Auction expired");

179:         require(msg.value >= reservePrice, "Must send at least reservePrice");

222:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");

234:         require(_minCreatorRateBps <= creatorRateBps, "Min creator rate must be less than or equal to creator rate");

235:         require(_minCreatorRateBps <= 10_000, "Min creator rate must be less than or equal to 10_000");

254:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");

311:         require(gasleft() >= MIN_TOKEN_MINT_GAS_THRESHOLD, "Insufficient gas for creating auction");

339:         require(_auction.startTime != 0, "Auction hasn't begun");

340:         require(!_auction.settled, "Auction has already been settled");

342:         require(block.timestamp >= _auction.endTime, "Auction hasn't completed");

421:         if (address(this).balance < _amount) revert("Insufficient balance");

441:             if (!wethSuccess) revert("WETH transfer failed");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol)

```solidity
File: packages/revolution/src/CultureIndex.sol

117:         require(msg.sender == address(manager), "Only manager can initialize");

119:         require(_cultureIndexParams.quorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "invalid quorum bps");

120:         require(_cultureIndexParams.erc721VotingTokenWeight > 0, "invalid erc721 voting token weight");

121:         require(_erc721VotingToken != address(0), "invalid erc721 voting token");

122:         require(_erc20VotingToken != address(0), "invalid erc20 voting token");

160:         require(uint8(metadata.mediaType) > 0 && uint8(metadata.mediaType) <= 5, "Invalid media type");

163:             require(bytes(metadata.image).length > 0, "Image URL must be provided");

165:             require(bytes(metadata.animationUrl).length > 0, "Animation URL must be provided");

167:             require(bytes(metadata.text).length > 0, "Text must be provided");

182:         require(creatorArrayLength <= MAX_NUM_CREATORS, "Creator array must not be > MAX_NUM_CREATORS");

186:             require(creatorArray[i].creator != address(0), "Invalid creator address");

190:         require(totalBps == 10_000, "Total BPS must sum up to 10,000");

308:         require(pieceId < _currentPieceId, "Invalid piece ID");

309:         require(voter != address(0), "Invalid voter address");

310:         require(!pieces[pieceId].isDropped, "Piece has already been dropped");

311:         require(!(votes[pieceId][voter].voterAddress != address(0)), "Already voted");

314:         require(weight > minVoteWeight, "Weight must be greater than minVoteWeight");

427:         require(deadline >= block.timestamp, "Signature expired");

452:         require(pieceId < _currentPieceId, "Invalid piece ID");

462:         require(pieceId < _currentPieceId, "Invalid piece ID");

487:         require(maxHeap.size() > 0, "Culture index is empty");

499:         require(newQuorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "CultureIndex::_setQuorumVotesBPS: invalid quorum bps");

520:         require(msg.sender == dropperAdmin, "Only dropper can drop pieces");

523:         require(totalVoteWeights[piece.pieceId] >= piece.quorumVotes, "Does not meet quorum votes to be dropped.");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/CultureIndex.sol)

```solidity
File: packages/revolution/src/ERC20TokenEmitter.sol

91:         require(msg.sender == address(manager), "Only manager can initialize");

96:         require(_treasury != address(0), "Invalid treasury address");

158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");

160:         require(msg.value > 0, "Must send ether");

162:         require(addresses.length == basisPointSplits.length, "Parallel arrays required");

192:         require(success, "Transfer failed.");

197:             require(success, "Transfer failed.");

217:         require(bpsSum == 10_000, "bps must add up to 10_000");

238:         require(amount > 0, "Amount must be greater than 0");

255:         require(etherAmount > 0, "Ether amount must be greater than 0");

272:         require(paymentAmount > 0, "Payment amount must be greater than 0");

289:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");

300:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");

310:         require(_creatorsAddress != address(0), "Invalid address");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol)

```solidity
File: packages/revolution/src/MaxHeap.sol

42:         require(msg.sender == admin, "Sender is not the admin");

56:         require(msg.sender == address(manager), "Only manager can initialize");

79:         require(pos != 0, "Position should not be zero");

157:         require(size > 0, "Heap is empty");

170:         require(size > 0, "Heap is empty");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/MaxHeap.sol)

```solidity
File: packages/revolution/src/NontransferableERC20Votes.sol

69:         require(msg.sender == address(manager), "Only manager can initialize");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/NontransferableERC20Votes.sol)

```solidity
File: packages/revolution/src/VerbsToken.sol

76:         require(!isMinterLocked, "Minter is locked");

84:         require(!isCultureIndexLocked, "CultureIndex is locked");

92:         require(!isDescriptorLocked, "Descriptor is locked");

100:         require(msg.sender == minter, "Sender is not the minter");

137:         require(msg.sender == address(manager), "Only manager can initialize");

139:         require(_minter != address(0), "Minter cannot be zero address");

140:         require(_initialOwner != address(0), "Initial owner cannot be zero address");

210:         require(_minter != address(0), "Minter cannot be zero address");

274:         require(verbId <= _currentVerbId, "Invalid piece ID");

317:             revert("dropTopVotedPiece failed");

330:         require(manager.isRegisteredUpgrade(_getImplementation(), _newImpl), "Invalid upgrade");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/VerbsToken.sol)

```solidity
File: packages/revolution/src/libs/VRGDAC.sol

38:         require(decayConstant < 0, "NON_NEGATIVE_DECAY_CONSTANT");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/libs/VRGDAC.sol)

### <a name="GAS-5"></a>[GAS-5] Don't initialize variables with default value

*Instances (7)*:

```solidity
File: packages/revolution/src/AuctionHouse.sol

346:         uint256 creatorTokensEmitted = 0;

380:                 uint256 ethPaidToCreators = 0;

384:                     for (uint256 i = 0; i < numCreators; i++) {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol)

```solidity
File: packages/revolution/src/ERC20TokenEmitter.sol

205:         uint256 bpsSum = 0;

209:         for (uint256 i = 0; i < addresses.length; i++) {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol)

```solidity
File: packages/revolution/src/MaxHeap.sol

67:     uint256 public size = 0;

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/MaxHeap.sol)

```solidity
File: packages/revolution/src/VerbsToken.sol

306:             for (uint i = 0; i < artPiece.creators.length; i++) {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/VerbsToken.sol)

### <a name="GAS-6"></a>[GAS-6] Long revert strings

*Instances (16)*:

```solidity
File: packages/revolution/src/AuctionHouse.sol

222:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");

234:         require(_minCreatorRateBps <= creatorRateBps, "Min creator rate must be less than or equal to creator rate");

235:         require(_minCreatorRateBps <= 10_000, "Min creator rate must be less than or equal to 10_000");

254:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");

311:         require(gasleft() >= MIN_TOKEN_MINT_GAS_THRESHOLD, "Insufficient gas for creating auction");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol)

```solidity
File: packages/revolution/src/CultureIndex.sol

120:         require(_cultureIndexParams.erc721VotingTokenWeight > 0, "invalid erc721 voting token weight");

182:         require(creatorArrayLength <= MAX_NUM_CREATORS, "Creator array must not be > MAX_NUM_CREATORS");

314:         require(weight > minVoteWeight, "Weight must be greater than minVoteWeight");

499:         require(newQuorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "CultureIndex::_setQuorumVotesBPS: invalid quorum bps");

523:         require(totalVoteWeights[piece.pieceId] >= piece.quorumVotes, "Does not meet quorum votes to be dropped.");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/CultureIndex.sol)

```solidity
File: packages/revolution/src/ERC20TokenEmitter.sol

158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");

255:         require(etherAmount > 0, "Ether amount must be greater than 0");

272:         require(paymentAmount > 0, "Payment amount must be greater than 0");

289:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");

300:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol)

```solidity
File: packages/revolution/src/VerbsToken.sol

140:         require(_initialOwner != address(0), "Initial owner cannot be zero address");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/VerbsToken.sol)

### <a name="GAS-7"></a>[GAS-7] Functions guaranteed to revert when called by normal users can be marked `payable`

If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as `payable` will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided.

*Instances (30)*:

```solidity
File: packages/revolution/src/AuctionHouse.sol

208:     function pause() external override onlyOwner {

217:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {

233:     function setMinCreatorRateBps(uint256 _minCreatorRateBps) external onlyOwner {

253:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {

265:     function unpause() external override onlyOwner {

277:     function setTimeBuffer(uint256 _timeBuffer) external override onlyOwner {

287:     function setReservePrice(uint256 _reservePrice) external override onlyOwner {

297:     function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {

452:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner whenPaused {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol)

```solidity
File: packages/revolution/src/CultureIndex.sol

498:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {

543:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/CultureIndex.sol)

```solidity
File: packages/revolution/src/ERC20TokenEmitter.sol

132:     function pause() external override onlyOwner {

141:     function unpause() external override onlyOwner {

288:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {

299:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {

309:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol)

```solidity
File: packages/revolution/src/MaxHeap.sol

119:     function insert(uint256 itemId, uint256 value) public onlyAdmin {

136:     function updateValue(uint256 itemId, uint256 newValue) public onlyAdmin {

156:     function extractMax() external onlyAdmin returns (uint256, uint256) {

181:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/MaxHeap.sol)

```solidity
File: packages/revolution/src/NontransferableERC20Votes.sol

134:     function mint(address account, uint256 amount) public onlyOwner {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/NontransferableERC20Votes.sol)

```solidity
File: packages/revolution/src/VerbsToken.sol

169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {

177:     function mint() public override onlyMinter nonReentrant returns (uint256) {

184:     function burn(uint256 verbId) public override onlyMinter nonReentrant {

209:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {

220:     function lockMinter() external override onlyOwner whenMinterNotLocked {

242:     function lockDescriptor() external override onlyOwner whenDescriptorNotLocked {

252:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {

262:     function lockCultureIndex() external override onlyOwner whenCultureIndexNotLocked {

328:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/VerbsToken.sol)

### <a name="GAS-8"></a>[GAS-8] `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too)

*Saves 5 gas per loop*

*Instances (13)*:

```solidity
File: packages/revolution/src/AuctionHouse.sol

384:                     for (uint256 i = 0; i < numCreators; i++) {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol)

```solidity
File: packages/revolution/src/CultureIndex.sol

185:         for (uint i; i < creatorArrayLength; i++) {

218:         uint256 pieceId = _currentPieceId++;

236:         for (uint i; i < creatorArrayLength; i++) {

243:         for (uint i; i < creatorArrayLength; i++) {

355:         for (uint256 i; i < len; i++) {

403:         for (uint256 i; i < len; i++) {

407:         for (uint256 i; i < len; i++) {

431:         voteHash = keccak256(abi.encode(VOTE_TYPEHASH, from, pieceIds, nonces[from]++, deadline));

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/CultureIndex.sol)

```solidity
File: packages/revolution/src/ERC20TokenEmitter.sol

209:         for (uint256 i = 0; i < addresses.length; i++) {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol)

```solidity
File: packages/revolution/src/MaxHeap.sol

129:         size++;

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/MaxHeap.sol)

```solidity
File: packages/revolution/src/VerbsToken.sol

294:             uint256 verbId = _currentVerbId++;

306:             for (uint i = 0; i < artPiece.creators.length; i++) {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/VerbsToken.sol)

### <a name="GAS-9"></a>[GAS-9] Using `private` rather than `public` for constants, saves gas

If needed, the values can be read from the verified contract source code, or if there are multiple values there can be a single getter function that [returns a tuple](https://github.com/code-423n4/2022-08-frax/blob/90f55a9ce4e25bceed3a74290b854341d8de6afa/src/contracts/FraxlendPair.sol#L156-L178) of the values of all currently-public constants. Saves **3406-3606 gas** in deployment gas due to the compiler not having to create non-payable getter functions for deployment calldata, not having to store the bytes of the value outside of where it's used, and not adding another entry to the method ID table

*Instances (6)*:

```solidity
File: packages/protocol-rewards/src/abstract/RewardSplits.sol

23:     uint256 public constant minPurchaseAmount = 0.0000001 ether;

24:     uint256 public constant maxPurchaseAmount = 50_000 ether;

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/protocol-rewards/src/abstract/RewardSplits.sol)

```solidity
File: packages/revolution/src/AuctionHouse.sol

88:     uint32 public constant MIN_TOKEN_MINT_GAS_THRESHOLD = 750_000;

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol)

```solidity
File: packages/revolution/src/CultureIndex.sol

29:     bytes32 public constant VOTE_TYPEHASH =

48:     uint256 public constant MAX_QUORUM_VOTES_BPS = 6_000; // 6,000 basis points or 60%

75:     uint256 public constant MAX_NUM_CREATORS = 100;

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/CultureIndex.sol)

### <a name="GAS-10"></a>[GAS-10] Use shift Right/Left instead of division/multiplication if possible

*Instances (2)*:

```solidity
File: packages/revolution/src/MaxHeap.sol

80:         return (pos - 1) / 2;

102:         if (pos >= (size / 2) && pos <= size) return;

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/MaxHeap.sol)

### <a name="GAS-11"></a>[GAS-11] Splitting require() statements that use && saves gas

*Instances (2)*:

```solidity
File: packages/revolution/src/CultureIndex.sol

160:         require(uint8(metadata.mediaType) > 0 && uint8(metadata.mediaType) <= 5, "Invalid media type");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/CultureIndex.sol)

```solidity
File: packages/revolution/src/ERC20TokenEmitter.sol

158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol)

### <a name="GAS-12"></a>[GAS-12] Use != 0 instead of > 0 for unsigned integer comparison

*Instances (21)*:

```solidity
File: packages/revolution/src/AuctionHouse.sol

363:             if (_auction.amount > 0) {

383:                 if (creatorsShare > 0 && entropyRateBps > 0) {

383:                 if (creatorsShare > 0 && entropyRateBps > 0) {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol)

```solidity
File: packages/revolution/src/CultureIndex.sol

120:         require(_cultureIndexParams.erc721VotingTokenWeight > 0, "invalid erc721 voting token weight");

160:         require(uint8(metadata.mediaType) > 0 && uint8(metadata.mediaType) <= 5, "Invalid media type");

163:             require(bytes(metadata.image).length > 0, "Image URL must be provided");

165:             require(bytes(metadata.animationUrl).length > 0, "Animation URL must be provided");

167:             require(bytes(metadata.text).length > 0, "Text must be provided");

487:         require(maxHeap.size() > 0, "Culture index is empty");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/CultureIndex.sol)

```solidity
File: packages/revolution/src/ERC20TokenEmitter.sol

160:         require(msg.value > 0, "Must send ether");

179:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0

184:         int totalTokensForBuyers = toPayTreasury > 0 ? getTokenQuoteForEther(toPayTreasury) : int(0);

188:         if (totalTokensForCreators > 0) emittedTokenWad += totalTokensForCreators;

195:         if (creatorDirectPayment > 0) {

201:         if (totalTokensForCreators > 0 && creatorsAddress != address(0)) {

210:             if (totalTokensForBuyers > 0) {

238:         require(amount > 0, "Amount must be greater than 0");

255:         require(etherAmount > 0, "Ether amount must be greater than 0");

272:         require(paymentAmount > 0, "Payment amount must be greater than 0");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol)

```solidity
File: packages/revolution/src/MaxHeap.sol

157:         require(size > 0, "Heap is empty");

170:         require(size > 0, "Heap is empty");

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/MaxHeap.sol)

## Non Critical Issues

| |Issue|Instances|
|-|:-|:-:|
| [NC-1](#NC-1) | Constants should be defined rather than using magic numbers | 1 |

### <a name="NC-1"></a>[NC-1] Constants should be defined rather than using magic numbers

*Instances (1)*:

```solidity
File: packages/revolution/src/AuctionHouse.sol

429:             success := call(50000, _to, _amount, 0, 0, 0, 0)

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol)

## Low Issues

| |Issue|Instances|
|-|:-|:-:|
| [L-1](#L-1) | Empty Function Body - Consider commenting why | 1 |
| [L-2](#L-2) | Initializers could be front-run | 37 |
| [L-3](#L-3) | Unsafe ERC20 operation(s) | 2 |
| [L-4](#L-4) | Use of ecrecover is susceptible to signature malleability | 1 |

### <a name="L-1"></a>[L-1] Empty Function Body - Consider commenting why

*Instances (1)*:

```solidity
File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

10:     ) payable RewardSplits(_protocolRewards, _revolutionRewardRecipient) {}

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol)

### <a name="L-2"></a>[L-2] Initializers could be front-run

Initializers could be front-run, allowing an attacker to either set their own values, take ownership of the contract, and in the best case forcing a re-deployment

*Instances (37)*:

```solidity
File: packages/revolution/src/AuctionHouse.sol

95:     constructor(address _manager) payable initializer {

113:     function initialize(

119:     ) external initializer {

123:         __Pausable_init();

124:         __ReentrancyGuard_init();

125:         __Ownable_init(_initialOwner);

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol)

```solidity
File: packages/revolution/src/CultureIndex.sol

92:     constructor(address _manager) payable initializer {

109:     function initialize(

116:     ) external initializer {

125:         __Ownable_init(_initialOwner);

128:         __EIP712_init(string.concat(_cultureIndexParams.name, " CultureIndex"), "1");

130:         __ReentrancyGuard_init();

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/CultureIndex.sol)

```solidity
File: packages/revolution/src/ERC20TokenEmitter.sol

68:     ) payable TokenEmitterRewards(_protocolRewards, _protocolFeeRecipient) initializer {

84:     function initialize(

90:     ) external initializer {

93:         __Pausable_init();

94:         __ReentrancyGuard_init();

99:         __Ownable_init(_initialOwner);

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol)

```solidity
File: packages/revolution/src/MaxHeap.sol

30:     constructor(address _manager) payable initializer {

55:     function initialize(address _initialOwner, address _admin) public initializer {

55:     function initialize(address _initialOwner, address _admin) public initializer {

60:         __Ownable_init(_initialOwner);

61:         __ReentrancyGuard_init();

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/MaxHeap.sol)

```solidity
File: packages/revolution/src/NontransferableERC20Votes.sol

44:     constructor(address _manager) payable initializer {

52:     function __NontransferableERC20Votes_init(

57:         __Ownable_init(_initialOwner);

58:         __ERC20_init(_name, _symbol);

59:         __EIP712_init(_name, "1");

65:     function initialize(

68:     ) external initializer {

71:         __NontransferableERC20Votes_init(_initialOwner, _erc20TokenParams.name, _erc20TokenParams.symbol);

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/NontransferableERC20Votes.sol)

```solidity
File: packages/revolution/src/VerbsToken.sol

116:     constructor(address _manager) payable initializer {

130:     function initialize(

136:     ) external initializer {

143:         __ReentrancyGuard_init();

146:         __Ownable_init(_initialOwner);

149:         __ERC721_init(_erc721TokenParams.name, _erc721TokenParams.symbol);

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/VerbsToken.sol)

### <a name="L-3"></a>[L-3] Unsafe ERC20 operation(s)

*Instances (2)*:

```solidity
File: packages/revolution/src/AuctionHouse.sol

361:             else verbs.transferFrom(address(this), _auction.bidder, _auction.verbId);

438:             bool wethSuccess = IWETH(WETH).transfer(_to, _amount);

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol)

### <a name="L-4"></a>[L-4] Use of ecrecover is susceptible to signature malleability

The built-in EVM precompile ecrecover is susceptible to signature malleability, which could lead to replay attacks.Consider using OpenZeppelin’s ECDSA library instead of the built-in function.

*Instances (1)*:

```solidity
File: packages/revolution/src/CultureIndex.sol

435:         address recoveredAddress = ecrecover(digest, v, r, s);

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/CultureIndex.sol)

## Medium Issues

| |Issue|Instances|
|-|:-|:-:|
| [M-1](#M-1) | Centralization Risk for trusted owners | 26 |

### <a name="M-1"></a>[M-1] Centralization Risk for trusted owners

#### Impact

Contracts have owners with privileged rights to perform admin tasks and need to be trusted to not perform malicious updates or drain funds.

*Instances (26)*:

```solidity
File: packages/revolution/src/AuctionHouse.sol

208:     function pause() external override onlyOwner {

217:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {

233:     function setMinCreatorRateBps(uint256 _minCreatorRateBps) external onlyOwner {

253:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {

265:     function unpause() external override onlyOwner {

277:     function setTimeBuffer(uint256 _timeBuffer) external override onlyOwner {

287:     function setReservePrice(uint256 _reservePrice) external override onlyOwner {

297:     function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {

452:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner whenPaused {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/AuctionHouse.sol)

```solidity
File: packages/revolution/src/CultureIndex.sol

498:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {

543:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/CultureIndex.sol)

```solidity
File: packages/revolution/src/ERC20TokenEmitter.sol

132:     function pause() external override onlyOwner {

141:     function unpause() external override onlyOwner {

288:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {

299:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {

309:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/ERC20TokenEmitter.sol)

```solidity
File: packages/revolution/src/MaxHeap.sol

181:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/MaxHeap.sol)

```solidity
File: packages/revolution/src/NontransferableERC20Votes.sol

134:     function mint(address account, uint256 amount) public onlyOwner {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/NontransferableERC20Votes.sol)

```solidity
File: packages/revolution/src/VerbsToken.sol

169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {

209:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {

220:     function lockMinter() external override onlyOwner whenMinterNotLocked {

232:     ) external override onlyOwner nonReentrant whenDescriptorNotLocked {

242:     function lockDescriptor() external override onlyOwner whenDescriptorNotLocked {

252:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {

262:     function lockCultureIndex() external override onlyOwner whenCultureIndexNotLocked {

328:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {

```

[Link to code](https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main/packages/revolution/src/VerbsToken.sol)
