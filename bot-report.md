# Winning bot race submission
 This is the top-ranked automated findings report, from vuln-detector bot. All findings in this report will be considered known issues for the purposes of your C4 audit.
 

 ## Summary

 | |Issue|Instances| Gas Savings
 |-|:-|:-:|:-:|
| [[M-01](#m-01)] | Privileged functions can create points of failure | 3| 0|
| [[M-02](#m-02)] | Transferred `ERC721` can be stuck permanently | 1| 0|
| [[L-01](#l-01)] | Missing checks for `address(0)` when assigning values to address state variables | 5| 0|
| [[L-02](#l-02)] | For loops in public or external functions should be avoided due to high gas costs and possible DOS | 5| 0|
| [[L-03](#l-03)] | Missing checks in constructor | 1| 0|
| [[L-04](#l-04)] | Constant decimal values | 1| 0|
| [[L-05](#l-05)] | Initialization can be front-run | 6| 0|
| [[L-06](#l-06)] | Lack of disableinitializers call to prevent uninitialized contracts | 6| 0|
| [[L-07](#l-07)] | `internal` Function calls within for loops | 11| 0|
| [[L-08](#l-08)] | NFT doesn't handle hard forks | 1| 0|
| [[L-09](#l-09)] | `onlyOwner` functions not accessible if `owner` renounces ownership | 26| 0|
| [[L-10](#l-10)] | Governance operations should be behind a timelock | 3| 0|
| [[L-11](#l-11)] | Consider using OpenZeppelin’s SafeCast library to prevent unexpected overflows when casting from various type int/uint values | 6| 0|
| [[L-12](#l-12)] | Setters should have initial value check | 6| 0|
| [[L-13](#l-13)] | Consider implementing two-step procedure for updating protocol addresses | 4| 0|
| [[L-14](#l-14)] | Upgradeable contract uses non-upgradeable version of the OpenZeppelin libraries/contracts | 3| 0|
| [[L-15](#l-15)] | Upgradeable contract is missing a `__gap[50]` storage variable to allow for new storage variables in later versions | 6| 0|
| [[L-16](#l-16)] | Consider using descriptive `constant`s when passing zero as a function argument | 1| 0|
| [[L-17](#l-17)] | Functions calling contracts/addresses with transfer hooks are missing reentrancy guards | 2| 0|
| [[L-18](#l-18)] | Some function should not be marked as payable | 6| 0|
| [[L-19](#l-19)] | prevent re-setting a state variable with the same value | 17| 0|
| [[G-01](#g-01)] | State variable read in a loop | 2| 0|
| [[G-02](#g-02)] | Multiple accesses of a mapping/array should use a local variable cache | 14| 588|
| [[G-03](#g-03)] | Use assembly to calculate hashes to save gas | 2| 160|
| [[G-04](#g-04)] | Use assembly to check for `address(0)` | 25| 150|
| [[G-05](#g-05)] | Optimize Address Storage Value Management with `assembly` | 8| 0|
| [[G-06](#g-06)] | Use assembly to emit events | 28| 1064|
| [[G-07](#g-07)] | Using bools for storage incurs overhead | 3| 300|
| [[G-08](#g-08)] | Use byte32 in place of string | 1| 0|
| [[G-09](#g-09)] | Cache array length outside of loop | 2| 194|
| [[G-10](#g-10)] | State variables should be cached in stack variables rather than re-reading them from storage | 2| 194|
| [[G-11](#g-11)] | Use calldata instead of memory for function arguments that do not get mutated | 8| 0|
| [[G-12](#g-12)] | With assembly, `.call (bool success)` transfer can be done gas-optimized | 2| 0|
| [[G-13](#g-13)] | Add `unchecked {}` for subtractions where the operands cannot underflow because of a previous `require()` or `if`-statement | 1| 85|
| [[G-14](#g-14)] | `x += y` costs more gas than `x = x + y` for state variables | 2| 226|
| [[G-15](#g-15)] | Use custom errors rather than `revert()`/`require()` strings to save gas | 79| 0|
| [[G-16](#g-16)] | Divisions which do not divide by -X cannot overflow or overflow so such operations can be unchecked to save gas | 18| 0|
| [[G-17](#g-17)] | Stack variable cost less while used in emiting event | 6| 600|
| [[G-18](#g-18)] | Events should be emitted outside of loops | 1| 375|
| [[G-19](#g-19)] | The result of function calls should be cached rather than re-calling the function | 1| 0|
| [[G-20](#g-20)] | `require()` or `revert()` statements that check input arguments should be at the top of the function | 5| 0|
| [[G-21](#g-21)] | `internal` functions only called once can be inlined to save gas | 6| 120|
| [[G-22](#g-22)] | `require()`/`revert()` strings longer than 32 bytes cost extra gas | 21| 378|
| [[G-23](#g-23)] | Consider merging sequential for loops | 2| 0|
| [[G-24](#g-24)] | Multiple `address`/ID mappings can be combined into a single `mapping` of an `address`/ID to a `struct`, where appropriate | 2| 0|
| [[G-25](#g-25)] | Optimize names to save gas | 7| 154|
| [[G-26](#g-26)] | Not using the named return variables anywhere in the function is confusing | 5| 0|
| [[G-27](#g-27)] | Constructors can be marked `payable` | 1| 21|
| [[G-28](#g-28)] | Using `private` rather than `public` for constants, saves gas | 6| 0|
| [[G-29](#g-29)] | Functions guaranteed to revert when called by normal users can be marked `payable` | 32| 672|
| [[G-30](#g-30)] | Avoid updating storage when the value hasn't changed to save gas | 17| 13600|
| [[G-31](#g-31)] | Use shift Right instead of division if possible to save gas | 2| 40|
| [[G-32](#g-32)] | Use shift Left instead of multiplication if possible to save gas | 2| 0|
| [[G-33](#g-33)] | Usage of `uints`/`ints` smaller than 32 bytes (256 bits) incurs overhead | 3| 0|
| [[G-34](#g-34)] | The use of a logical AND in place of double if is slightly less gas efficient in instances where there isn't a corresponding else statement for the given if statement | 3| 45|
| [[G-35](#g-35)] | Splitting `require()` statements that use `&&` saves gas | 3| 9|
| [[G-36](#g-36)] | Cache state variables outside of loop to avoid reading storage on every iteration | 1| 0|
| [[G-37](#g-37)] | `>=`/`<=` costs less gas than `>`/`<` | 40| 120|
| [[G-38](#g-38)] | Use assembly to validate `msg.sender` | 13| 156|
| [[G-39](#g-39)] | Can make the variable outside the loop to save gas | 2| 0|
| [[G-40](#g-40)] | Consider activating via-ir for deploying | 1| 250|
| [[G-41](#g-41)] | `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too) | 13| 0|
| [[G-42](#g-42)] | Use `@inheritdoc` rather than using a non-standard annotation | 1| 0|
| [[G-43](#g-43)] | Stat variables can be packed into fewer storage slots by truncating timestamp bytes | 2| 0|
| [[G-44](#g-44)] | State variables can be packed into fewer storage slots | 2| 4000|
| [[G-45](#g-45)] | Use `do while` loops instead of `for` loops | 9| 1089|
| [[G-46](#g-46)] | Avoid transferring amounts of zero in order to save gas | 1| 0|
| [[G-47](#g-47)] | Simple checks for zero `uint` can be done using assembly to save gas | 1| 6|
| [[G-48](#g-48)] | `++i`/`i++` should be `unchecked{++i}`/`unchecked{i++}` when it is not possible for them to overflow, as is the case when used in `for`- and `while`-loops | 9| 0|
| [[G-49](#g-49)] | Using `private` for constants saves gas | 11| 0|
| [[G-50](#g-50)] | Initializer can be marked `payable` | 6| 126|
| [[G-51](#g-51)] | Avoid caching global special variables | 1| 12|
| [[G-52](#g-52)] | Redundant state variable getters | 1| 0|
| [[G-53](#g-53)] | Gas savings can be achieved by changing the model for assigning value to the structure ***123 gas*** | 2| 246|
| [[G-54](#g-54)] | address(this) should be cached | 1| 0|
| [[N-01](#n-01)] | State variables declarations should have NatSpec descriptions | 51| 0|
| [[N-02](#n-02)] | Consider using modifiers for address control | 9| 0|
| [[N-03](#n-03)] | Large or complicated code bases should implement invariant tests | 1| 0|
| [[N-04](#n-04)] | Assembly blocks should have extensive comments | 1| 0|
| [[N-05](#n-05)] | Contract declarations should have NatSpec `@author` annotations | 7| 0|
| [[N-06](#n-06)] | Variable names that consist of all capital letters should be reserved for `constant`/`immutable` variables | 1| 0|
| [[N-07](#n-07)] | Common functions should be refactored to a common base contract | 2| 0|
| [[N-08](#n-08)] | Overly complicated arithmetic | 5| 0|
| [[N-09](#n-09)] | Constant redefined elsewhere | 5| 0|
| [[N-10](#n-10)] | Constants in comparisons should appear on the left side | 41| 0|
| [[N-11](#n-11)] | `const` Variable names don\'t follow the Solidity style guide | 2| 0|
| [[N-12](#n-12)] | NatSpec documentation for `contract` is missing | 6| 0|
| [[N-13](#n-13)] | Contract does not follow the Solidity style guide's suggested layout ordering | 2| 0|
| [[N-14](#n-14)] | Control structures do not follow the Solidity Style Guide | 14| 0|
| [[N-15](#n-15)] | Custom error has no error details | 2| 0|
| [[N-16](#n-16)] | Empty bytes check is missing | 2| 0|
| [[N-17](#n-17)] | Events are missing sender information | 23| 0|
| [[N-18](#n-18)] | Events may be emitted out of order due to reentrancy | 4| 0|
| [[N-19](#n-19)] | Defining All External/Public Functions in Contract Interfaces | 15| 0|
| [[N-20](#n-20)] | Fixed Compiler Version Required for Non-Library/Interface Files | 6| 0|
| [[N-21](#n-21)] | Floating pragma should be avoided | 6| 0|
| [[N-22](#n-22)] | NatSpec documentation for `function` is missing | 16| 0|
| [[N-23](#n-23)] | Function ordering does not follow the Solidity style guide | 6| 0|
| [[N-24](#n-24)] | Array indicies should be referenced via `enum`s rather than via numeric literals | 4| 0|
| [[N-25](#n-25)] | Hardcoded string that is repeatedly used can be replaced with a constant | 4| 0|
| [[N-26](#n-26)] | Duplicated `require()` checks should be refactored to a modifier or function | 7| 0|
| [[N-27](#n-27)] | Some if-statement can be converted to a ternary | 1| 0|
| [[N-28](#n-28)] | Imports could be organized more systematically | 6| 0|
| [[N-29](#n-29)] | Inconsistent spacing in comments | 27| 0|
| [[N-30](#n-30)] | Inconsistent usage of `require`/`error` | 17| 0|
| [[N-31](#n-31)] | Incorrect NatSpec Syntax | 3| 0|
| [[N-32](#n-32)] | Large numeric literals should use underscores for readability | 1| 0|
| [[N-33](#n-33)] | Long functions should be refactored into multiple, smaller, functions | 3| 0|
| [[N-34](#n-34)] | Long lines of code | 20| 0|
| [[N-35](#n-35)] | Missing event and or timelock for critical parameter change | 1| 0|
| [[N-36](#n-36)] | File is missing NatSpec | 1| 0|
| [[N-37](#n-37)] | Mixed usage of `int`/`uint` with `int256`/`uint256` | 12| 0|
| [[N-38](#n-38)] | Consider using named mappings | 9| 0|
| [[N-39](#n-39)] | Some error strings are not descriptive | 7| 0|
| [[N-40](#n-40)] | The `nonReentrant` `modifier` should occur before all other modifiers | 7| 0|
| [[N-41](#n-41)] | Public state variables shouldn't have a preceding _ in their name | 1| 0|
| [[N-42](#n-42)] | `override` function arguments that are unused should have the variable name removed or commented out to avoid compiler warnings | 4| 0|
| [[N-43](#n-43)] | Use of `override` is unnecessary | 30| 0|
| [[N-44](#n-44)] | NatSpec `@param` is missing | 24| 0|
| [[N-45](#n-45)] | Functions which are either private or internal should have a preceding _ in their name | 8| 0|
| [[N-46](#n-46)] | `public` functions not called by the contract should be declared `external` instead | 19| 0|
| [[N-47](#n-47)] | Redundant inheritance specifier | 1| 0|
| [[N-48](#n-48)] | `require()` / `revert()` statements should have descriptive reason strings | 4| 0|
| [[N-49](#n-49)] | Setters should prevent re-setting of the same value | 13| 0|
| [[N-50](#n-50)] | NatSpec `@return` argument is missing | 11| 0|
| [[N-51](#n-51)] | Consider using `SafeTransferLib.safeTransferETH()` or `Address.sendValue()` for clearer semantic meaning | 2| 0|
| [[N-52](#n-52)] | Large multiples of ten should use scientific notation (e.g. `1e6`) rather than decimal literals (e.g. `1000000`), for readability | 27| 0|
| [[N-53](#n-53)] | Consider moving `msg.sender` checks to a common authorization `modifier` | 7| 0|
| [[N-54](#n-54)] | State variables should have `Natspec` comments | 51| 0|
| [[N-55](#n-55)] | Contracts should have full test coverage | 1| 0|
| [[N-56](#n-56)] | Contract declarations should have NatSpec `@title` annotations | 7| 0|
| [[N-57](#n-57)] | Open TODOs | 2| 0|
| [[N-58](#n-58)] | Top level pragma declarations should be separated by two blank lines | 14| 0|
| [[N-59](#n-59)] | Critical functions should be a two step procedure | 15| 0|
| [[N-60](#n-60)] | uint variables should have the bit size defined explicitly | 2| 0|
| [[N-61](#n-61)] | Uncommented fields in a struct | 1| 0|
| [[N-62](#n-62)] | Unused Import | 5| 0|
| [[N-63](#n-63)] | Unused parameter | 6| 0|
| [[N-64](#n-64)] | Use `string.concat()` on strings instead of `abi.encodePacked()` for clearer semantic meaning | 1| 0|
| [[N-65](#n-65)] | Constants should be defined rather than using magic numbers | 30| 0|
| [[N-66](#n-66)] | Use a single file for system wide constants | 3| 0|
| [[N-67](#n-67)] | Consider using SMTChecker | 9| 0|
| [[N-68](#n-68)] | Whitespace in Expressions | 3| 0|
| [[N-69](#n-69)] | Complex function controle flow | 2| 0|
| [[N-70](#n-70)] | Consider bounding input array length | 2| 0|
| [[N-71](#n-71)] | A function which defines named returns in it's declaration doesn't need to use return | 5| 0|
| [[N-72](#n-72)] | `error` declarations should have NatSpec descriptions | 2| 0|
| [[N-73](#n-73)] | Contract declarations should have NatSpec `@dev` annotations | 8| 0|
| [[N-74](#n-74)] | Add inline comments for unnamed variables | 3| 0|
| [[N-75](#n-75)] | Contract should expose an `interface` | 15| 0|
| [[N-76](#n-76)] | Contract declarations should have NatSpec `@notice` annotations | 7| 0|
| [[N-77](#n-77)] | `function` names should use lowerCamelCase | 8| 0|
| [[N-78](#n-78)] | Expressions for constant values should use `immutable` rather than `constant` | 1| 0|
| [[N-79](#n-79)] | Contract uses both `require()`/`revert()` as well as custom errors | 8| 0|
| [[N-80](#n-80)] | `immutable` variable names don\'t follow the Solidity style guide | 12| 0|
| [[N-81](#n-81)] | `private`/`public` function name should start with underscore | 8| 0|
| [[N-82](#n-82)] | Add inline comments for unnamed parameters | 23| 0|
| [[N-83](#n-83)] | Consider adding formal verification proofs | 1| 0|
| [[N-84](#n-84)] | Missing zero address check in functions with address parameters | 28| 0|
| [[N-85](#n-85)] | Use a struct to encapsulate multiple function parameters | 4| 0|
| [[N-86](#n-86)] | Missing NatSpec `@notice` from function declaration | 34| 0|
| [[N-87](#n-87)] | Missing NatSpec `@dev` from function declaration | 60| 0|
| [[N-88](#n-88)] | Missing NatSpec `@dev` from `modifier` declaration | 5| 0|
| [[N-89](#n-89)] | Use custom errors rather than `revert()`/`require()` strings for better readability | 75| 0|
| [[N-90](#n-90)] | Use `@inheritdoc` for overridden functions | 35| 0|
| [[N-91](#n-91)] | Multiple mappings with same keys can be combined into a single struct mapping for readability | 2| 0|
| [[N-92](#n-92)] | constructor should emit an event | 9| 0|
| [[N-93](#n-93)] | `error` should be named using CapWords style | 2| 0|
| [[N-94](#n-94)] | Complex functions should include comments | 4| 0|
| [[N-95](#n-95)] | Make use of Solidiy's `using` keyword | 1| 0|
| [[N-96](#n-96)] | [Solidity]: All `verbatim` blocks are considered identical by deduplicator and can incorrectly be unified | 9| 0|


  ### Medium Risk Issues


### [M-01]<a name="m-01"></a> Privileged functions can create points of failure
Ensure such accounts are protected and consider implementing multi sig to prevent a single point of failure

*There are 3 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

119:     function insert(uint256 itemId, uint256 value) public onlyAdmin {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L119-L119

```solidity

File: packages/revolution/src/MaxHeap.sol

136:     function updateValue(uint256 itemId, uint256 newValue) public onlyAdmin {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L136-L136

```solidity

File: packages/revolution/src/MaxHeap.sol

156:     function extractMax() external onlyAdmin returns (uint256, uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L156-L156
### [M-02]<a name="m-02"></a> Transferred `ERC721` can be stuck permanently
If the recipient is not a EOA, `safeTransferFrom` ensures that the contract is able to safely receive the token. In the worst-case scenario, it may result in tokens frozen permanently, as the following code uses `transferFrom`, which doesn't check if the recipient can handle the NFT.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

361:             else verbs.transferFrom(address(this), _auction.bidder, _auction.verbId);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L361-L361### Low Risk Issues


### [L-01]<a name="l-01"></a> Missing checks for `address(0)` when assigning values to address state variables

*There are 5 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

139:         dropperAdmin = _dropperAdmin;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L139-L139

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

102:         creatorsAddress = _creatorsAddress;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L102-L102

```solidity

File: packages/revolution/src/MaxHeap.sol

58:         admin = _admin;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L58-L58

```solidity

File: packages/revolution/src/VerbsToken.sol

233:         descriptor = _descriptor;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L233-L233

```solidity

File: packages/revolution/src/VerbsToken.sol

253:         cultureIndex = _cultureIndex;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L253-L253
### [L-02]<a name="l-02"></a> For loops in public or external functions should be avoided due to high gas costs and possible DOS
In Solidity, for loops can potentially cause Denial of Service (DoS) attacks if not handled carefully. DoS attacks can occur when an attacker intentionally exploits the gas cost of a function, causing it to run out of gas or making it too expensive for other users to call. Below are some scenarios where for loops can lead to DoS attacks: Nested for loops can become exceptionally gas expensive and should be used sparingly

*There are 5 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

209:     function createPiece(
210:         ArtPieceMetadata calldata metadata,
211:         CreatorBps[] calldata creatorArray
212:     ) public returns (uint256) {
213:         uint256 creatorArrayLength = validateCreatorsArray(creatorArray);
214: 
215:         // Validate the media type and associated data
216:         validateMediaType(metadata);
217: 
218:         uint256 pieceId = _currentPieceId++;
219: 
220:         /// @dev Insert the new piece into the max heap
221:         maxHeap.insert(pieceId, 0);
222: 
223:         ArtPiece storage newPiece = pieces[pieceId];
224: 
225:         newPiece.pieceId = pieceId;
226:         newPiece.totalVotesSupply = _calculateVoteWeight(
227:             erc20VotingToken.totalSupply(),
228:             erc721VotingToken.totalSupply()
229:         );
230:         newPiece.totalERC20Supply = erc20VotingToken.totalSupply();
231:         newPiece.metadata = metadata;
232:         newPiece.sponsor = msg.sender;
233:         newPiece.creationBlock = block.number;
234:         newPiece.quorumVotes = (quorumVotesBPS * newPiece.totalVotesSupply) / 10_000;
235: 
236:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L209-L236

```solidity

File: packages/revolution/src/CultureIndex.sol

209:     function createPiece(
210:         ArtPieceMetadata calldata metadata,
211:         CreatorBps[] calldata creatorArray
212:     ) public returns (uint256) {
213:         uint256 creatorArrayLength = validateCreatorsArray(creatorArray);
214: 
215:         // Validate the media type and associated data
216:         validateMediaType(metadata);
217: 
218:         uint256 pieceId = _currentPieceId++;
219: 
220:         /// @dev Insert the new piece into the max heap
221:         maxHeap.insert(pieceId, 0);
222: 
223:         ArtPiece storage newPiece = pieces[pieceId];
224: 
225:         newPiece.pieceId = pieceId;
226:         newPiece.totalVotesSupply = _calculateVoteWeight(
227:             erc20VotingToken.totalSupply(),
228:             erc721VotingToken.totalSupply()
229:         );
230:         newPiece.totalERC20Supply = erc20VotingToken.totalSupply();
231:         newPiece.metadata = metadata;
232:         newPiece.sponsor = msg.sender;
233:         newPiece.creationBlock = block.number;
234:         newPiece.quorumVotes = (quorumVotesBPS * newPiece.totalVotesSupply) / 10_000;
235: 
236:         for (uint i; i < creatorArrayLength; i++) {
237:             newPiece.creators.push(creatorArray[i]);
238:         }
239: 
240:         emit PieceCreated(pieceId, msg.sender, metadata, newPiece.quorumVotes, newPiece.totalVotesSupply);
241: 
242:         // Emit an event for each creator
243:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L209-L243

```solidity

File: packages/revolution/src/CultureIndex.sol

389:     function batchVoteForManyWithSig(
390:         address[] memory from,
391:         uint256[][] calldata pieceIds,
392:         uint256[] memory deadline,
393:         uint8[] memory v,
394:         bytes32[] memory r,
395:         bytes32[] memory s
396:     ) external nonReentrant {
397:         uint256 len = from.length;
398:         require(
399:             len == pieceIds.length && len == deadline.length && len == v.length && len == r.length && len == s.length,
400:             "Array lengths must match"
401:         );
402: 
403:         for (uint256 i; i < len; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L389-L403

```solidity

File: packages/revolution/src/CultureIndex.sol

389:     function batchVoteForManyWithSig(
390:         address[] memory from,
391:         uint256[][] calldata pieceIds,
392:         uint256[] memory deadline,
393:         uint8[] memory v,
394:         bytes32[] memory r,
395:         bytes32[] memory s
396:     ) external nonReentrant {
397:         uint256 len = from.length;
398:         require(
399:             len == pieceIds.length && len == deadline.length && len == v.length && len == r.length && len == s.length,
400:             "Array lengths must match"
401:         );
402: 
403:         for (uint256 i; i < len; i++) {
404:             if (!_verifyVoteSignature(from[i], pieceIds[i], deadline[i], v[i], r[i], s[i])) revert INVALID_SIGNATURE();
405:         }
406: 
407:         for (uint256 i; i < len; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L389-L407

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

152:     function buyToken(
153:         address[] calldata addresses,
154:         uint[] calldata basisPointSplits,
155:         ProtocolRewardAddresses calldata protocolRewardsRecipients
156:     ) public payable nonReentrant whenNotPaused returns (uint256 tokensSoldWad) {
157:         //prevent treasury from paying itself
158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");
159: 
160:         require(msg.value > 0, "Must send ether");
161:         // ensure the same number of addresses and bps
162:         require(addresses.length == basisPointSplits.length, "Parallel arrays required");
163: 
164:         // Get value left after protocol rewards
165:         uint256 msgValueRemaining = _handleRewardsAndGetValueToSend(
166:             msg.value,
167:             protocolRewardsRecipients.builder,
168:             protocolRewardsRecipients.purchaseReferral,
169:             protocolRewardsRecipients.deployer
170:         );
171: 
172:         //Share of purchase amount to send to treasury
173:         uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;
174: 
175:         //Share of purchase amount to reserve for creators
176:         //Ether directly sent to creators
177:         uint256 creatorDirectPayment = ((msgValueRemaining - toPayTreasury) * entropyRateBps) / 10_000;
178:         //Tokens to emit to creators
179:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0
180:             ? getTokenQuoteForEther((msgValueRemaining - toPayTreasury) - creatorDirectPayment)
181:             : int(0);
182: 
183:         // Tokens to emit to buyers
184:         int totalTokensForBuyers = toPayTreasury > 0 ? getTokenQuoteForEther(toPayTreasury) : int(0);
185: 
186:         //Transfer ETH to treasury and update emitted
187:         emittedTokenWad += totalTokensForBuyers;
188:         if (totalTokensForCreators > 0) emittedTokenWad += totalTokensForCreators;
189: 
190:         //Deposit funds to treasury
191:         (bool success, ) = treasury.call{ value: toPayTreasury }(new bytes(0));
192:         require(success, "Transfer failed.");
193: 
194:         //Transfer ETH to creators
195:         if (creatorDirectPayment > 0) {
196:             (success, ) = creatorsAddress.call{ value: creatorDirectPayment }(new bytes(0));
197:             require(success, "Transfer failed.");
198:         }
199: 
200:         //Mint tokens for creators
201:         if (totalTokensForCreators > 0 && creatorsAddress != address(0)) {
202:             _mint(creatorsAddress, uint256(totalTokensForCreators));
203:         }
204: 
205:         uint256 bpsSum = 0;
206: 
207:         //Mint tokens to buyers
208: 
209:         for (uint256 i = 0; i < addresses.length; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L152-L209
### [L-03]<a name="l-03"></a> Missing checks in constructor
There are some missing checks in these functions, and this could lead to unexpected scenarios. Consider always adding a sanity check for state variables.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

//@audit _targetPrice, _perTimeUnit,  are not checked
28:     constructor(int256 _targetPrice, int256 _priceDecayPercent, int256 _perTimeUnit) {
29:         targetPrice = _targetPrice;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L28-L29
### [L-04]<a name="l-04"></a> Constant decimal values
The use of fixed decimal values such as 1e18 or 1e8 in Solidity contracts can lead to inaccuracies, bugs, and vulnerabilities, particularly when interacting with tokens having different decimal configurations.Not all ERC20 tokens follow the standard 18 decimal places, and assumptions about decimal places can lead to miscalculations.
Always retrieve and use the `decimals()` function from the token contract itself when performing calculations involving token amounts.This ensures that your contract correctly handles tokens with any number of decimal places, mitigating the risk of numerical errors or under / overflows that could jeopardize contract integrity and user funds.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

285:         return erc20Balance + (erc721Balance * erc721VotingTokenWeight * 1e18);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L285-L285
### [L-05]<a name="l-05"></a> Initialization can be front-run
The `initialize()` functions are not protected by a modifier, which allow attackers to call this function once the contract is deployed through the proxy. Consider adding modifiers to protect this function or create a contract that both deploy the project and initialize it on the same transaction.

*There are 6 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

113:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L113-L113

```solidity

File: packages/revolution/src/CultureIndex.sol

109:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L109-L109

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

84:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L84-L84

```solidity

File: packages/revolution/src/MaxHeap.sol

55:     function initialize(address _initialOwner, address _admin) public initializer {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L55-L55

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

65:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L65-L65

```solidity

File: packages/revolution/src/VerbsToken.sol

130:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L130-L130
### [L-06]<a name="l-06"></a> Lack of disableinitializers call to prevent uninitialized contracts
Multiple contracts are using the Initializable module from OpenZeppelin. For this reason and in order to prevent leaving that contract uninitialized OpenZeppelin's documentation recommends adding the _disableInitializers function in the constructor to automatically lock the contracts when they are deployed. this will protect the contract that holds the logic business from beeing initialized by an attack.

*There are 6 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

113:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L113-L113

```solidity

File: packages/revolution/src/CultureIndex.sol

109:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L109-L109

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

84:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L84-L84

```solidity

File: packages/revolution/src/MaxHeap.sol

55:     function initialize(address _initialOwner, address _admin) public initializer {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L55-L55

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

65:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L65-L65

```solidity

File: packages/revolution/src/VerbsToken.sol

130:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L130-L130
### [L-07]<a name="l-07"></a> `internal` Function calls within for loops
Making function calls or external calls within loops in Solidity can lead to inefficient gas usage, potential bottlenecks, and increased vulnerability to attacks. Each function call or external call consumes gas, and when executed within a loop, the gas cost multiplies, potentially causing the transaction to run out of gas or exceed block gas limits. This can result in transaction failure or unpredictable behavior.

*There are 11 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

394:                         _safeTransferETHWithFallback(creator.creator, paymentAmount);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L394-L394

```solidity

File: packages/revolution/src/CultureIndex.sol

356:             _vote(pieceIds[i], from);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L356-L356

```solidity

File: packages/revolution/src/CultureIndex.sol

404:             if (!_verifyVoteSignature(from[i], pieceIds[i], deadline[i], v[i], r[i], s[i])) revert INVALID_SIGNATURE();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L404-L404

```solidity

File: packages/revolution/src/CultureIndex.sol

408:             _voteForMany(pieceIds[i], from[i]);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L408-L408

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

212:                 _mint(addresses[i], uint256((totalTokensForBuyers * int(basisPointSplits[i])) / 10_000));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L212-L212

```solidity

File: packages/revolution/src/MaxHeap.sol

126:             swap(current, parent(current));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L126-L126

```solidity

File: packages/revolution/src/MaxHeap.sol

126:             swap(current, parent(current));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L126-L126

```solidity

File: packages/revolution/src/MaxHeap.sol

127:             current = parent(current);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L127-L127

```solidity

File: packages/revolution/src/MaxHeap.sol

147:                 swap(position, parent(position));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L147-L147

```solidity

File: packages/revolution/src/MaxHeap.sol

147:                 swap(position, parent(position));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L147-L147

```solidity

File: packages/revolution/src/MaxHeap.sol

148:                 position = parent(position);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L148-L148
### [L-08]<a name="l-08"></a> NFT doesn't handle hard forks
When there are hard forks, users often have to go through [many hoops](https://twitter.com/elerium115/status/1558471934924431363) to ensure that they control ownership on every fork. Consider adding `require(1 == chain.chainId)`, or the chain ID of whichever chain you prefer, to the functions below, or at least include the chain ID in the URI, so that there is no confusion about which chain is the owner of the NFT.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/VerbsToken.sol

193:     function tokenURI(uint256 tokenId) public view override returns (string memory) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L193-L193
### [L-09]<a name="l-09"></a> `onlyOwner` functions not accessible if `owner` renounces ownership
The `owner` is able to perform certain privileged activities, but it's possible to set the owner to `address(0)`. This can represent a certain risk if the ownership is renounced for any other reason than by design.
Renouncing ownership will leave the contract without an `owner`, therefore limiting any functionality that needs authority.

*There are 26 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

208:     function pause() external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L208-L208

```solidity

File: packages/revolution/src/AuctionHouse.sol

217:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L217-L217

```solidity

File: packages/revolution/src/AuctionHouse.sol

233:     function setMinCreatorRateBps(uint256 _minCreatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L233-L233

```solidity

File: packages/revolution/src/AuctionHouse.sol

253:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L253-L253

```solidity

File: packages/revolution/src/AuctionHouse.sol

265:     function unpause() external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L265-L265

```solidity

File: packages/revolution/src/AuctionHouse.sol

277:     function setTimeBuffer(uint256 _timeBuffer) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L277-L277

```solidity

File: packages/revolution/src/AuctionHouse.sol

287:     function setReservePrice(uint256 _reservePrice) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L287-L287

```solidity

File: packages/revolution/src/AuctionHouse.sol

297:     function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L297-L297

```solidity

File: packages/revolution/src/AuctionHouse.sol

452:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner whenPaused {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L452-L452

```solidity

File: packages/revolution/src/CultureIndex.sol

498:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L498-L498

```solidity

File: packages/revolution/src/CultureIndex.sol

543:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L543-L543

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

132:     function pause() external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L132-L132

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

141:     function unpause() external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L141-L141

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

288:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L288-L288

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

299:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L299-L299

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

309:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L309-L309

```solidity

File: packages/revolution/src/MaxHeap.sol

181:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L181-L181

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

134:     function mint(address account, uint256 amount) public onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L134-L134

```solidity

File: packages/revolution/src/VerbsToken.sol

169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L169-L169

```solidity

File: packages/revolution/src/VerbsToken.sol

209:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L209-L209

```solidity

File: packages/revolution/src/VerbsToken.sol

220:     function lockMinter() external override onlyOwner whenMinterNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L220-L220

```solidity

File: packages/revolution/src/VerbsToken.sol

230:     function setDescriptor(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L230-L230

```solidity

File: packages/revolution/src/VerbsToken.sol

242:     function lockDescriptor() external override onlyOwner whenDescriptorNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L242-L242

```solidity

File: packages/revolution/src/VerbsToken.sol

252:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L252-L252

```solidity

File: packages/revolution/src/VerbsToken.sol

262:     function lockCultureIndex() external override onlyOwner whenCultureIndexNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L262-L262

```solidity

File: packages/revolution/src/VerbsToken.sol

328:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L328-L328
### [L-10]<a name="l-10"></a> Governance operations should be behind a timelock
All critical and governance operations should be protected by a timelock. For example from the point of view of a user, the changing of the owner of a contract is a high risk operation that may have outcomes ranging from an attacker gaining control over the protocol, to the function no longer functioning due to a typo in the destination address. To give users plenty of warning so that they can validate any ownership changes, changes of ownership should be behind a timelock.

*There are 3 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

119:     function insert(uint256 itemId, uint256 value) public onlyAdmin {
120:         heap[size] = itemId;
121:         valueMapping[itemId] = value; // Update the value mapping
122:         positionMapping[itemId] = size; // Update the position mapping
123: 
124:         uint256 current = size;
125:         while (current != 0 && valueMapping[heap[current]] > valueMapping[heap[parent(current)]]) {
126:             swap(current, parent(current));
127:             current = parent(current);
128:         }
129:         size++;
130:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L119-L130

```solidity

File: packages/revolution/src/MaxHeap.sol

136:     function updateValue(uint256 itemId, uint256 newValue) public onlyAdmin {
137:         uint256 position = positionMapping[itemId];
138:         uint256 oldValue = valueMapping[itemId];
139: 
140:         // Update the value in the valueMapping
141:         valueMapping[itemId] = newValue;
142: 
143:         // Decide whether to perform upwards or downwards heapify
144:         if (newValue > oldValue) {
145:             // Upwards heapify
146:             while (position != 0 && valueMapping[heap[position]] > valueMapping[heap[parent(position)]]) {
147:                 swap(position, parent(position));
148:                 position = parent(position);
149:             }
150:         } else if (newValue < oldValue) maxHeapify(position); // Downwards heapify
151:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L136-L151

```solidity

File: packages/revolution/src/MaxHeap.sol

156:     function extractMax() external onlyAdmin returns (uint256, uint256) {
157:         require(size > 0, "Heap is empty");
158: 
159:         uint256 popped = heap[0];
160:         heap[0] = heap[--size];
161:         maxHeapify(0);
162: 
163:         return (popped, valueMapping[popped]);
164:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L156-L164
### [L-11]<a name="l-11"></a> Consider using OpenZeppelin’s SafeCast library to prevent unexpected overflows when casting from various type int/uint values

*There are 6 instance(s) of this issue:*

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `totalTokensForCreators` is getting converted from `int256` to `uint256`
202:             _mint(creatorsAddress, uint256(totalTokensForCreators));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L202-L202

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `totalTokensForBuyers` is getting converted from `int256` to `uint256`
224:             uint256(totalTokensForBuyers),


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L224-L224

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `totalTokensForCreators` is getting converted from `int256` to `uint256`
225:             uint256(totalTokensForCreators),


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L225-L225

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `totalTokensForBuyers` is getting converted from `int256` to `uint256`
229:         return uint256(totalTokensForBuyers);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L229-L229

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `amount` is getting converted from `uint256` to `int`
245:                 amount: int(amount)


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L245-L245

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `etherAmount` is getting converted from `uint256` to `int`
262:                 amount: int(etherAmount)


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L262-L262
### [L-12]<a name="l-12"></a> Setters should have initial value check
Setters should have initial value check to prevent assigning wrong value to the variable. Assginment of wrong value can lead to unexpected behavior of the contract.

*There are 6 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

277:     function setTimeBuffer(uint256 _timeBuffer) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L277-L277

```solidity

File: packages/revolution/src/AuctionHouse.sol

287:     function setReservePrice(uint256 _reservePrice) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L287-L287

```solidity

File: packages/revolution/src/AuctionHouse.sol

297:     function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L297-L297

```solidity

File: packages/revolution/src/VerbsToken.sol

169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L169-L169

```solidity

File: packages/revolution/src/VerbsToken.sol

230:     function setDescriptor(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L230-L230

```solidity

File: packages/revolution/src/VerbsToken.sol

252:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L252-L252
### [L-13]<a name="l-13"></a> Consider implementing two-step procedure for updating protocol addresses
A copy-paste error or a typo may end up bricking protocol functionality, or sending tokens to an address with no known private key. Consider implementing a two-step procedure for updating protocol addresses, where the recipient is set as pending, and must 'accept' the assignment by making an affirmative call. A straight forward way of doing this would be to have the target contracts implement [EIP-165](https://eips.ethereum.org/EIPS/eip-165), and to have the 'set' functions ensure that the recipient is of the right interface type.

*There are 4 instance(s) of this issue:*

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

309:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {
310:         require(_creatorsAddress != address(0), "Invalid address");
311: 
312:         emit CreatorsAddressUpdated(creatorsAddress = _creatorsAddress);
313:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L309-L313

```solidity

File: packages/revolution/src/VerbsToken.sol

209:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {
210:         require(_minter != address(0), "Minter cannot be zero address");
211:         minter = _minter;
212: 
213:         emit MinterUpdated(_minter);
214:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L209-L214

```solidity

File: packages/revolution/src/VerbsToken.sol

230:     function setDescriptor(
231:         IDescriptorMinimal _descriptor
232:     ) external override onlyOwner nonReentrant whenDescriptorNotLocked {
233:         descriptor = _descriptor;
234: 
235:         emit DescriptorUpdated(_descriptor);
236:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L230-L236

```solidity

File: packages/revolution/src/VerbsToken.sol

252:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {
253:         cultureIndex = _cultureIndex;
254: 
255:         emit CultureIndexUpdated(_cultureIndex);
256:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L252-L256
### [L-14]<a name="l-14"></a> Upgradeable contract uses non-upgradeable version of the OpenZeppelin libraries/contracts
OpenZeppelin has an [Upgradeable](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/tree/master/contracts/utils) variants of each of its libraries and contracts, and upgradeable contracts should use those variants.

*There are 3 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

18: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L18-L18

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

11: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L11-L11

```solidity

File: packages/revolution/src/VerbsToken.sol

22: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L22-L22
### [L-15]<a name="l-15"></a> Upgradeable contract is missing a `__gap[50]` storage variable to allow for new storage variables in later versions
See [this](https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps) link for a description of this storage variable. While some contracts may not currently be sub-classed, adding the variable now protects against forgetting to add it in the future.

*There are 6 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

39: contract AuctionHouse is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L39-L39

```solidity

File: packages/revolution/src/CultureIndex.sol

20: contract CultureIndex is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L20-L20

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

17: contract ERC20TokenEmitter is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L17-L17

```solidity

File: packages/revolution/src/MaxHeap.sol

14: contract MaxHeap is VersionedContract, UUPS, Ownable2StepUpgradeable, ReentrancyGuardUpgradeable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L14-L14

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

29: contract NontransferableERC20Votes is Initializable, ERC20VotesUpgradeable, Ownable2StepUpgradeable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L29-L29

```solidity

File: packages/revolution/src/VerbsToken.sol

33: contract VerbsToken is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L33-L33
### [L-16]<a name="l-16"></a> Consider using descriptive `constant`s when passing zero as a function argument
Passing zero as a function argument can sometimes result in a security issue (e.g. passing zero as the slippage parameter). Consider using a `constant` variable with a descriptive name, so it's clear that the argument is intentionally being used, and for the right reasons.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit parameter number 2 starting from left
221:         maxHeap.insert(pieceId, 0);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L221-L221
### [L-17]<a name="l-17"></a> Functions calling contracts/addresses with transfer hooks are missing reentrancy guards
Even if the function follows the best practice of check-effects-interaction, not using a reentrancy guard when there may be transfer hooks will open the users of this protocol up to [read-only reentrancies](https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/) with no way to protect against it, except by block-listing the whole protocol.

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit function `_settleAuction()` is not protected against reentrancy
361:             else verbs.transferFrom(address(this), _auction.bidder, _auction.verbId);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L361-L361

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit function `_safeTransferETHWithFallback()` is not protected against reentrancy
438:             bool wethSuccess = IWETH(WETH).transfer(_to, _amount);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L438-L438
### [L-18]<a name="l-18"></a> Some function should not be marked as payable
Some function should not be marked as payable, otherwise the ETH that mistakenly sent along with the function call is locked in the contract

*There are 6 instance(s) of this issue:*

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

29:     constructor(address _protocolRewards, address _revolutionRewardRecipient) payable {
30:         if (_protocolRewards == address(0) || _revolutionRewardRecipient == address(0)) revert("Invalid Address Zero");
31: 
32:         protocolRewards = IRevolutionProtocolRewards(_protocolRewards);
33:         revolutionRewardRecipient = _revolutionRewardRecipient;
34:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L29-L34

```solidity

File: packages/revolution/src/AuctionHouse.sol

95:     constructor(address _manager) payable initializer {
96:         manager = IRevolutionBuilder(_manager);
97:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L95-L97

```solidity

File: packages/revolution/src/CultureIndex.sol

92:     constructor(address _manager) payable initializer {
93:         manager = IRevolutionBuilder(_manager);
94:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L92-L94

```solidity

File: packages/revolution/src/MaxHeap.sol

30:     constructor(address _manager) payable initializer {
31:         manager = IRevolutionBuilder(_manager);
32:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L30-L32

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

44:     constructor(address _manager) payable initializer {
45:         manager = IRevolutionBuilder(_manager);
46:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L44-L46

```solidity

File: packages/revolution/src/VerbsToken.sol

116:     constructor(address _manager) payable initializer {
117:         manager = IRevolutionBuilder(_manager);
118:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L116-L118
### [L-19]<a name="l-19"></a> prevent re-setting a state variable with the same value
Not only is wasteful in terms of gas, but this is especially problematic when an event is emitted and the old and new values set are the same, as listeners might not expect this kind of scenario.

*There are 17 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

152:     function settleCurrentAndCreateNewAuction() external override nonReentrant whenNotPaused {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L152-L152

```solidity

File: packages/revolution/src/AuctionHouse.sol

161:     function settleAuction() external override whenPaused nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L161-L161

```solidity

File: packages/revolution/src/AuctionHouse.sol

217:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L217-L217

```solidity

File: packages/revolution/src/AuctionHouse.sol

233:     function setMinCreatorRateBps(uint256 _minCreatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L233-L233

```solidity

File: packages/revolution/src/AuctionHouse.sol

253:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L253-L253

```solidity

File: packages/revolution/src/AuctionHouse.sol

277:     function setTimeBuffer(uint256 _timeBuffer) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L277-L277

```solidity

File: packages/revolution/src/AuctionHouse.sol

287:     function setReservePrice(uint256 _reservePrice) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L287-L287

```solidity

File: packages/revolution/src/AuctionHouse.sol

297:     function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L297-L297

```solidity

File: packages/revolution/src/CultureIndex.sol

498:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L498-L498

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

288:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L288-L288

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

299:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L299-L299

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

309:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L309-L309

```solidity

File: packages/revolution/src/MaxHeap.sol

136:     function updateValue(uint256 itemId, uint256 newValue) public onlyAdmin {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L136-L136

```solidity

File: packages/revolution/src/VerbsToken.sol

169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L169-L169

```solidity

File: packages/revolution/src/VerbsToken.sol

209:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L209-L209

```solidity

File: packages/revolution/src/VerbsToken.sol

230:     function setDescriptor(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L230-L230

```solidity

File: packages/revolution/src/VerbsToken.sol

252:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L252-L252### Gas Risk Issues


   ### [G-01]<a name="g-01"></a> State variable read in a loop
The state variable should be cached in a local variable rather than reading it on every iteration of the for-loop, which will replace each Gwarmaccess (**100 gas**) with a much cheaper stack read.

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `verbs` is read in this loop
384:                     for (uint256 i = 0; i < numCreators; i++) {
385:                         ICultureIndex.CreatorBps memory creator = verbs.getArtPieceById(_auction.verbId).creators[i];


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L384-L385

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `entropyRateBps` is read in this loop
384:                     for (uint256 i = 0; i < numCreators; i++) {
385:                         ICultureIndex.CreatorBps memory creator = verbs.getArtPieceById(_auction.verbId).creators[i];
386:                         vrgdaReceivers[i] = creator.creator;
387:                         vrgdaSplits[i] = creator.bps;
388: 
389:                         //Calculate paymentAmount for specific creator based on BPS splits - same as multiplying by creatorDirectPayment
390:                         uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L384-L390
### [G-02]<a name="g-02"></a> Multiple accesses of a mapping/array should use a local variable cache
The instances below point to the second+ access of a value inside a mapping/array, within a function. Caching a mapping's value in a local `storage` or `calldata` variable when the value is accessed [multiple times](https://gist.github.com/IllIllI000/ec23a57daa30a8f8ca8b9681c8ccefb0), saves **~42 gas per access** due to not having to recalculate the key's keccak256 hash (Gkeccak256 - **30 gas**) and that calculation's associated stack operations. Caching an array's struct avoids recalculating the array offsets into memory/calldata

*There are 14 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

186:             require(creatorArray[i].creator != address(0), "Invalid creator address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L186-L186

```solidity

File: packages/revolution/src/CultureIndex.sol

244:             emit PieceCreatorAdded(pieceId, creatorArray[i].creator, msg.sender, creatorArray[i].bps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L244-L244

```solidity

File: packages/revolution/src/CultureIndex.sol

244:             emit PieceCreatorAdded(pieceId, creatorArray[i].creator, msg.sender, creatorArray[i].bps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L244-L244

```solidity

File: packages/revolution/src/CultureIndex.sol

310:         require(!pieces[pieceId].isDropped, "Piece has already been dropped");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L310-L310

```solidity

File: packages/revolution/src/CultureIndex.sol

311:         require(!(votes[pieceId][voter].voterAddress != address(0)), "Already voted");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L311-L311

```solidity

File: packages/revolution/src/CultureIndex.sol

317:         totalVoteWeights[pieceId] += weight;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L317-L317

```solidity

File: packages/revolution/src/CultureIndex.sol

404:             if (!_verifyVoteSignature(from[i], pieceIds[i], deadline[i], v[i], r[i], s[i])) revert INVALID_SIGNATURE();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L404-L404

```solidity

File: packages/revolution/src/CultureIndex.sol

404:             if (!_verifyVoteSignature(from[i], pieceIds[i], deadline[i], v[i], r[i], s[i])) revert INVALID_SIGNATURE();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L404-L404

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

212:                 _mint(addresses[i], uint256((totalTokensForBuyers * int(basisPointSplits[i])) / 10_000));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L212-L212

```solidity

File: packages/revolution/src/MaxHeap.sol

87:         (heap[fpos], heap[spos]) = (heap[spos], heap[fpos]);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L87-L87

```solidity

File: packages/revolution/src/MaxHeap.sol

87:         (heap[fpos], heap[spos]) = (heap[spos], heap[fpos]);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L87-L87

```solidity

File: packages/revolution/src/MaxHeap.sol

88:         (positionMapping[heap[fpos]], positionMapping[heap[spos]]) = (fpos, spos);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L88-L88

```solidity

File: packages/revolution/src/MaxHeap.sol

88:         (positionMapping[heap[fpos]], positionMapping[heap[spos]]) = (fpos, spos);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L88-L88

```solidity

File: packages/revolution/src/MaxHeap.sol

141:         valueMapping[itemId] = newValue;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L141-L141
### [G-03]<a name="g-03"></a> Use assembly to calculate hashes to save gas
Using assembly to calculate hashes can save *** 80 gas *** per instance

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

30:         keccak256("Vote(address from,uint256[] pieceIds,uint256 nonce,uint256 deadline)");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L30-L30

```solidity

File: packages/revolution/src/CultureIndex.sol

431:         voteHash = keccak256(abi.encode(VOTE_TYPEHASH, from, pieceIds, nonces[from]++, deadline));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L431-L431
### [G-04]<a name="g-04"></a> Use assembly to check for `address(0)`
*Saves 6 gas per instance*

*There are 25 instance(s) of this issue:*

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

30:         if (_protocolRewards == address(0) || _revolutionRewardRecipient == address(0)) revert("Invalid Address Zero");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L30-L30

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

30:         if (_protocolRewards == address(0) || _revolutionRewardRecipient == address(0)) revert("Invalid Address Zero");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L30-L30

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

74:         if (builderReferral == address(0)) builderReferral = revolutionRewardRecipient;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L74-L74

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

76:         if (deployer == address(0)) deployer = revolutionRewardRecipient;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L76-L76

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

78:         if (purchaseReferral == address(0)) purchaseReferral = revolutionRewardRecipient;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L78-L78

```solidity

File: packages/revolution/src/AuctionHouse.sol

121:         require(_weth != address(0), "WETH cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L121-L121

```solidity

File: packages/revolution/src/AuctionHouse.sol

175:         require(bidder != address(0), "Bidder cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L175-L175

```solidity

File: packages/revolution/src/AuctionHouse.sol

195:         if (lastBidder != address(0)) _safeTransferETHWithFallback(lastBidder, _auction.amount);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L195-L195

```solidity

File: packages/revolution/src/AuctionHouse.sol

350:             if (_auction.bidder != address(0)) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L350-L350

```solidity

File: packages/revolution/src/AuctionHouse.sol

358:             if (_auction.bidder == address(0))


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L358-L358

```solidity

File: packages/revolution/src/CultureIndex.sol

121:         require(_erc721VotingToken != address(0), "invalid erc721 voting token");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L121-L121

```solidity

File: packages/revolution/src/CultureIndex.sol

122:         require(_erc20VotingToken != address(0), "invalid erc20 voting token");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L122-L122

```solidity

File: packages/revolution/src/CultureIndex.sol

186:             require(creatorArray[i].creator != address(0), "Invalid creator address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L186-L186

```solidity

File: packages/revolution/src/CultureIndex.sol

257:         return votes[pieceId][voter].voterAddress != address(0);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L257-L257

```solidity

File: packages/revolution/src/CultureIndex.sol

309:         require(voter != address(0), "Invalid voter address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L309-L309

```solidity

File: packages/revolution/src/CultureIndex.sol

311:         require(!(votes[pieceId][voter].voterAddress != address(0)), "Already voted");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L311-L311

```solidity

File: packages/revolution/src/CultureIndex.sol

438:         if (from == address(0)) revert ADDRESS_ZERO();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L438-L438

```solidity

File: packages/revolution/src/CultureIndex.sol

441:         if (recoveredAddress == address(0) || recoveredAddress != from) revert INVALID_SIGNATURE();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L441-L441

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

96:         require(_treasury != address(0), "Invalid treasury address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L96-L96

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

201:         if (totalTokensForCreators > 0 && creatorsAddress != address(0)) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L201-L201

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

310:         require(_creatorsAddress != address(0), "Invalid address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L310-L310

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

128:         if (account == address(0)) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L128-L128

```solidity

File: packages/revolution/src/VerbsToken.sol

139:         require(_minter != address(0), "Minter cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L139-L139

```solidity

File: packages/revolution/src/VerbsToken.sol

140:         require(_initialOwner != address(0), "Initial owner cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L140-L140

```solidity

File: packages/revolution/src/VerbsToken.sol

210:         require(_minter != address(0), "Minter cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L210-L210
### [G-05]<a name="g-05"></a> Optimize Address Storage Value Management with `assembly`

*There are 8 instance(s) of this issue:*

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

33:         revolutionRewardRecipient = _revolutionRewardRecipient;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L33-L33

```solidity

File: packages/revolution/src/CultureIndex.sol

139:         dropperAdmin = _dropperAdmin;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L139-L139

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

101:         treasury = _treasury;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L101-L101

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

102:         creatorsAddress = _creatorsAddress;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L102-L102

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

312:         emit CreatorsAddressUpdated(creatorsAddress = _creatorsAddress);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L312-L312

```solidity

File: packages/revolution/src/MaxHeap.sol

58:         admin = _admin;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L58-L58

```solidity

File: packages/revolution/src/VerbsToken.sol

153:         minter = _minter;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L153-L153

```solidity

File: packages/revolution/src/VerbsToken.sol

211:         minter = _minter;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L211-L211
### [G-06]<a name="g-06"></a> Use assembly to emit events
We can use assembly to emit events efficiently by utilizing `scratch space` and the `free memory pointer`. This will allow us to potentially avoid memory expansion costs. Note: In order to do this optimization safely, we will need to cache and restore the free memory pointer.

*There are 28 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

197:         emit AuctionBid(_auction.verbId, bidder, msg.sender, msg.value, extended);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L197-L197

```solidity

File: packages/revolution/src/AuctionHouse.sol

199:         if (extended) emit AuctionExtended(_auction.verbId, _auction.endTime);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L199-L199

```solidity

File: packages/revolution/src/AuctionHouse.sol

225:         emit CreatorRateBpsUpdated(_creatorRateBps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L225-L225

```solidity

File: packages/revolution/src/AuctionHouse.sol

245:         emit MinCreatorRateBpsUpdated(_minCreatorRateBps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L245-L245

```solidity

File: packages/revolution/src/AuctionHouse.sol

257:         emit EntropyRateBpsUpdated(_entropyRateBps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L257-L257

```solidity

File: packages/revolution/src/AuctionHouse.sol

280:         emit AuctionTimeBufferUpdated(_timeBuffer);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L280-L280

```solidity

File: packages/revolution/src/AuctionHouse.sol

290:         emit AuctionReservePriceUpdated(_reservePrice);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L290-L290

```solidity

File: packages/revolution/src/AuctionHouse.sol

300:         emit AuctionMinBidIncrementPercentageUpdated(_minBidIncrementPercentage);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L300-L300

```solidity

File: packages/revolution/src/AuctionHouse.sol

326:             emit AuctionCreated(verbId, startTime, endTime);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L326-L326

```solidity

File: packages/revolution/src/AuctionHouse.sol

413:         emit AuctionSettled(_auction.verbId, _auction.bidder, _auction.amount, creatorTokensEmitted);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L413-L413

```solidity

File: packages/revolution/src/CultureIndex.sol

141:         emit QuorumVotesBPSSet(quorumVotesBPS, _cultureIndexParams.quorumVotesBPS);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L141-L141

```solidity

File: packages/revolution/src/CultureIndex.sol

240:         emit PieceCreated(pieceId, msg.sender, metadata, newPiece.quorumVotes, newPiece.totalVotesSupply);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L240-L240

```solidity

File: packages/revolution/src/CultureIndex.sol

244:             emit PieceCreatorAdded(pieceId, creatorArray[i].creator, msg.sender, creatorArray[i].bps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L244-L244

```solidity

File: packages/revolution/src/CultureIndex.sol

323:         emit VoteCast(pieceId, voter, weight, totalWeight);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L323-L323

```solidity

File: packages/revolution/src/CultureIndex.sol

500:         emit QuorumVotesBPSSet(quorumVotesBPS, newQuorumVotesBPS);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L500-L500

```solidity

File: packages/revolution/src/CultureIndex.sol

531:         emit PieceDropped(piece.pieceId, msg.sender);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L531-L531

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

219:         emit PurchaseFinalized(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L219-L219

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

291:         emit EntropyRateBpsUpdated(entropyRateBps = _entropyRateBps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L291-L291

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

302:         emit CreatorRateBpsUpdated(creatorRateBps = _creatorRateBps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L302-L302

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

312:         emit CreatorsAddressUpdated(creatorsAddress = _creatorsAddress);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L312-L312

```solidity

File: packages/revolution/src/VerbsToken.sol

186:         emit VerbBurned(verbId);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L186-L186

```solidity

File: packages/revolution/src/VerbsToken.sol

213:         emit MinterUpdated(_minter);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L213-L213

```solidity

File: packages/revolution/src/VerbsToken.sol

223:         emit MinterLocked();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L223-L223

```solidity

File: packages/revolution/src/VerbsToken.sol

235:         emit DescriptorUpdated(_descriptor);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L235-L235

```solidity

File: packages/revolution/src/VerbsToken.sol

245:         emit DescriptorLocked();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L245-L245

```solidity

File: packages/revolution/src/VerbsToken.sol

255:         emit CultureIndexUpdated(_cultureIndex);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L255-L255

```solidity

File: packages/revolution/src/VerbsToken.sol

265:         emit CultureIndexLocked();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L265-L265

```solidity

File: packages/revolution/src/VerbsToken.sol

312:             emit VerbCreated(verbId, artPiece);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L312-L312
### [G-07]<a name="g-07"></a> Using bools for storage incurs overhead
Use uint256(1) and uint256(2) for true/false to avoid a Gwarmaccess (100 gas), and to avoid Gsset (20000 gas) when changing from 'false' to 'true', after having been 'true' in the past. See [source](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/58f635312aa21f947cae5f8578638a85aa2519f5/contracts/security/ReentrancyGuard.sol#L23-L27).

*There are 3 instance(s) of this issue:*

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit avoid using `bool` type for isMinterLocked
51:     bool public isMinterLocked;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L51-L51

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit avoid using `bool` type for isCultureIndexLocked
54:     bool public isCultureIndexLocked;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L54-L54

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit avoid using `bool` type for isDescriptorLocked
57:     bool public isDescriptorLocked;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L57-L57
### [G-08]<a name="g-08"></a> Use byte32 in place of string
For strings of 32 char strings and below you can use bytes32 instead as it's more gas efficient

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/VerbsToken.sol

162:         return string(abi.encodePacked("ipfs://", _contractURIHash));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L162-L162
### [G-09]<a name="g-09"></a> Cache array length outside of loop
If not cached, the solidity compiler will always read the length of the array during each iteration. That is, if it is a storage array, this is an extra sload operation (100 additional extra gas for each iteration except for the first) and if it is a memory array, this is an extra mload operation (3 additional gas for each iteration except for the first).

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

209:         for (uint256 i = 0; i < addresses.length; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L209-L209

```solidity

File: packages/revolution/src/VerbsToken.sol

306:             for (uint i = 0; i < artPiece.creators.length; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L306-L306
### [G-10]<a name="g-10"></a> State variables should be cached in stack variables rather than re-reading them from storage
The instances below point to the second+ access of a state variable within a function. Caching of a state variable replaces each Gwarmaccess (100 gas) with a much cheaper stack read. Other less obvious fixes/optimizations include having local memory caches of state variable structs, or having local caches of state variable contracts/addresses.

*Saves 100 gas per instance*

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

438:             bool wethSuccess = IWETH(WETH).transfer(_to, _amount);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L438-L438

```solidity

File: packages/revolution/src/MaxHeap.sol

124:         uint256 current = size;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L124-L124
### [G-11]<a name="g-11"></a> Use calldata instead of memory for function arguments that do not get mutated
Mark data types as `calldata` instead of `memory` where possible. This makes it so that the data is not automatically loaded into memory. If the data passed into the function does not need to be changed (like updating values in an array), it can be passed in as `calldata`. The one exception to this is if the argument must later be passed into another function that takes an argument that specifies `memory` storage.

*There are 8 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit Make `_cultureIndexParams` as a calldata
115:         IRevolutionBuilder.CultureIndexParams memory _cultureIndexParams


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L115-L115

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit Make `from` as a calldata
390:         address[] memory from,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L390-L390

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit Make `deadline` as a calldata
392:         uint256[] memory deadline,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L392-L392

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit Make `v` as a calldata
393:         uint8[] memory v,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L393-L393

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit Make `r` as a calldata
394:         bytes32[] memory r,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L394-L394

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit Make `s` as a calldata
395:         bytes32[] memory s


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L395-L395

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit Make `_erc721TokenParams` as a calldata
135:         IRevolutionBuilder.ERC721TokenParams memory _erc721TokenParams


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L135-L135

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit Make `newContractURIHash` as a calldata
169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L169-L169
### [G-12]<a name="g-12"></a> With assembly, `.call (bool success)` transfer can be done gas-optimized
`return` data `(bool success,)` has to be stored due to EVM architecture, but in a usage like below, `out` and `outsize` values are given (0,0), this storage disappears and gas optimization is provided.

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

191:         (bool success, ) = treasury.call{ value: toPayTreasury }(new bytes(0));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L191-L191

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

196:             (success, ) = creatorsAddress.call{ value: creatorDirectPayment }(new bytes(0));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L196-L196
### [G-13]<a name="g-13"></a> Add `unchecked {}` for subtractions where the operands cannot underflow because of a previous `require()` or `if`-statement
`require(a <= b); x = b - a` => `require(a <= b); unchecked { x = b - a }`

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

400:                     creatorTokensEmitted = erc20TokenEmitter.buyToken{ value: creatorsShare - ethPaidToCreators }(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L400-L400
### [G-14]<a name="g-14"></a> `x += y` costs more gas than `x = x + y` for state variables
Not inlining costs 20 to 40 gas because of two extra JUMP instructions and additional stack operations needed for function calls.

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

187:         emittedTokenWad += totalTokensForBuyers;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L187-L187

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

188:         if (totalTokensForCreators > 0) emittedTokenWad += totalTokensForCreators;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L188-L188
### [G-15]<a name="g-15"></a> Use custom errors rather than `revert()`/`require()` strings to save gas
Custom errors are available from solidity version 0.8.4. Custom errors save [**~50 gas**](https://gist.github.com/IllIllI000/ad1bd0d29a0101b25e57c293b4b0c746) each time they're hit by [avoiding having to allocate and store the revert string](https://blog.soliditylang.org/2021/04/21/custom-errors/#errors-in-depth). Not defining the strings also save deployment gas

*There are 79 instance(s) of this issue:*

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

30:         if (_protocolRewards == address(0) || _revolutionRewardRecipient == address(0)) revert("Invalid Address Zero");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L30-L30

```solidity

File: packages/revolution/src/AuctionHouse.sol

120:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L120-L120

```solidity

File: packages/revolution/src/AuctionHouse.sol

121:         require(_weth != address(0), "WETH cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L121-L121

```solidity

File: packages/revolution/src/AuctionHouse.sol

129:         require(
130:             _auctionParams.creatorRateBps >= _auctionParams.minCreatorRateBps,
131:             "Creator rate must be greater than or equal to the creator rate"
132:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L129-L132

```solidity

File: packages/revolution/src/AuctionHouse.sol

175:         require(bidder != address(0), "Bidder cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L175-L175

```solidity

File: packages/revolution/src/AuctionHouse.sol

176:         require(_auction.verbId == verbId, "Verb not up for auction");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L176-L176

```solidity

File: packages/revolution/src/AuctionHouse.sol

178:         require(block.timestamp < _auction.endTime, "Auction expired");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L178-L178

```solidity

File: packages/revolution/src/AuctionHouse.sol

179:         require(msg.value >= reservePrice, "Must send at least reservePrice");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L179-L179

```solidity

File: packages/revolution/src/AuctionHouse.sol

180:         require(
181:             msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100),
182:             "Must send more than last bid by minBidIncrementPercentage amount"
183:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L180-L183

```solidity

File: packages/revolution/src/AuctionHouse.sol

218:         require(
219:             _creatorRateBps >= minCreatorRateBps,
220:             "Creator rate must be greater than or equal to minCreatorRateBps"
221:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L218-L221

```solidity

File: packages/revolution/src/AuctionHouse.sol

222:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L222-L222

```solidity

File: packages/revolution/src/AuctionHouse.sol

234:         require(_minCreatorRateBps <= creatorRateBps, "Min creator rate must be less than or equal to creator rate");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L234-L234

```solidity

File: packages/revolution/src/AuctionHouse.sol

235:         require(_minCreatorRateBps <= 10_000, "Min creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L235-L235

```solidity

File: packages/revolution/src/AuctionHouse.sol

238:         require(
239:             _minCreatorRateBps > minCreatorRateBps,
240:             "Min creator rate must be greater than previous minCreatorRateBps"
241:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L238-L241

```solidity

File: packages/revolution/src/AuctionHouse.sol

254:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L254-L254

```solidity

File: packages/revolution/src/AuctionHouse.sol

311:         require(gasleft() >= MIN_TOKEN_MINT_GAS_THRESHOLD, "Insufficient gas for creating auction");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L311-L311

```solidity

File: packages/revolution/src/AuctionHouse.sol

339:         require(_auction.startTime != 0, "Auction hasn't begun");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L339-L339

```solidity

File: packages/revolution/src/AuctionHouse.sol

340:         require(!_auction.settled, "Auction has already been settled");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L340-L340

```solidity

File: packages/revolution/src/AuctionHouse.sol

342:         require(block.timestamp >= _auction.endTime, "Auction hasn't completed");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L342-L342

```solidity

File: packages/revolution/src/AuctionHouse.sol

421:         if (address(this).balance < _amount) revert("Insufficient balance");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L421-L421

```solidity

File: packages/revolution/src/AuctionHouse.sol

441:             if (!wethSuccess) revert("WETH transfer failed");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L441-L441

```solidity

File: packages/revolution/src/CultureIndex.sol

117:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L117-L117

```solidity

File: packages/revolution/src/CultureIndex.sol

119:         require(_cultureIndexParams.quorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "invalid quorum bps");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L119-L119

```solidity

File: packages/revolution/src/CultureIndex.sol

120:         require(_cultureIndexParams.erc721VotingTokenWeight > 0, "invalid erc721 voting token weight");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L120-L120

```solidity

File: packages/revolution/src/CultureIndex.sol

121:         require(_erc721VotingToken != address(0), "invalid erc721 voting token");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L121-L121

```solidity

File: packages/revolution/src/CultureIndex.sol

122:         require(_erc20VotingToken != address(0), "invalid erc20 voting token");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L122-L122

```solidity

File: packages/revolution/src/CultureIndex.sol

160:         require(uint8(metadata.mediaType) > 0 && uint8(metadata.mediaType) <= 5, "Invalid media type");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L160-L160

```solidity

File: packages/revolution/src/CultureIndex.sol

163:             require(bytes(metadata.image).length > 0, "Image URL must be provided");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L163-L163

```solidity

File: packages/revolution/src/CultureIndex.sol

165:             require(bytes(metadata.animationUrl).length > 0, "Animation URL must be provided");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L165-L165

```solidity

File: packages/revolution/src/CultureIndex.sol

167:             require(bytes(metadata.text).length > 0, "Text must be provided");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L167-L167

```solidity

File: packages/revolution/src/CultureIndex.sol

182:         require(creatorArrayLength <= MAX_NUM_CREATORS, "Creator array must not be > MAX_NUM_CREATORS");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L182-L182

```solidity

File: packages/revolution/src/CultureIndex.sol

186:             require(creatorArray[i].creator != address(0), "Invalid creator address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L186-L186

```solidity

File: packages/revolution/src/CultureIndex.sol

190:         require(totalBps == 10_000, "Total BPS must sum up to 10,000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L190-L190

```solidity

File: packages/revolution/src/CultureIndex.sol

308:         require(pieceId < _currentPieceId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L308-L308

```solidity

File: packages/revolution/src/CultureIndex.sol

309:         require(voter != address(0), "Invalid voter address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L309-L309

```solidity

File: packages/revolution/src/CultureIndex.sol

310:         require(!pieces[pieceId].isDropped, "Piece has already been dropped");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L310-L310

```solidity

File: packages/revolution/src/CultureIndex.sol

311:         require(!(votes[pieceId][voter].voterAddress != address(0)), "Already voted");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L311-L311

```solidity

File: packages/revolution/src/CultureIndex.sol

314:         require(weight > minVoteWeight, "Weight must be greater than minVoteWeight");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L314-L314

```solidity

File: packages/revolution/src/CultureIndex.sol

398:         require(
399:             len == pieceIds.length && len == deadline.length && len == v.length && len == r.length && len == s.length,
400:             "Array lengths must match"
401:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L398-L401

```solidity

File: packages/revolution/src/CultureIndex.sol

427:         require(deadline >= block.timestamp, "Signature expired");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L427-L427

```solidity

File: packages/revolution/src/CultureIndex.sol

452:         require(pieceId < _currentPieceId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L452-L452

```solidity

File: packages/revolution/src/CultureIndex.sol

462:         require(pieceId < _currentPieceId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L462-L462

```solidity

File: packages/revolution/src/CultureIndex.sol

487:         require(maxHeap.size() > 0, "Culture index is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L487-L487

```solidity

File: packages/revolution/src/CultureIndex.sol

499:         require(newQuorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "CultureIndex::_setQuorumVotesBPS: invalid quorum bps");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L499-L499

```solidity

File: packages/revolution/src/CultureIndex.sol

520:         require(msg.sender == dropperAdmin, "Only dropper can drop pieces");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L520-L520

```solidity

File: packages/revolution/src/CultureIndex.sol

523:         require(totalVoteWeights[piece.pieceId] >= piece.quorumVotes, "Does not meet quorum votes to be dropped.");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L523-L523

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

91:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L91-L91

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

96:         require(_treasury != address(0), "Invalid treasury address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L96-L96

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L158-L158

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

160:         require(msg.value > 0, "Must send ether");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L160-L160

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

162:         require(addresses.length == basisPointSplits.length, "Parallel arrays required");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L162-L162

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

192:         require(success, "Transfer failed.");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L192-L192

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

197:             require(success, "Transfer failed.");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L197-L197

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

217:         require(bpsSum == 10_000, "bps must add up to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L217-L217

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

238:         require(amount > 0, "Amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L238-L238

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

255:         require(etherAmount > 0, "Ether amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L255-L255

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

272:         require(paymentAmount > 0, "Payment amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L272-L272

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

289:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L289-L289

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

300:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L300-L300

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

310:         require(_creatorsAddress != address(0), "Invalid address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L310-L310

```solidity

File: packages/revolution/src/MaxHeap.sol

42:         require(msg.sender == admin, "Sender is not the admin");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L42-L42

```solidity

File: packages/revolution/src/MaxHeap.sol

56:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L56-L56

```solidity

File: packages/revolution/src/MaxHeap.sol

79:         require(pos != 0, "Position should not be zero");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L79-L79

```solidity

File: packages/revolution/src/MaxHeap.sol

157:         require(size > 0, "Heap is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L157-L157

```solidity

File: packages/revolution/src/MaxHeap.sol

170:         require(size > 0, "Heap is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L170-L170

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

69:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L69-L69

```solidity

File: packages/revolution/src/VerbsToken.sol

76:         require(!isMinterLocked, "Minter is locked");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L76-L76

```solidity

File: packages/revolution/src/VerbsToken.sol

84:         require(!isCultureIndexLocked, "CultureIndex is locked");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L84-L84

```solidity

File: packages/revolution/src/VerbsToken.sol

92:         require(!isDescriptorLocked, "Descriptor is locked");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L92-L92

```solidity

File: packages/revolution/src/VerbsToken.sol

100:         require(msg.sender == minter, "Sender is not the minter");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L100-L100

```solidity

File: packages/revolution/src/VerbsToken.sol

137:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L137-L137

```solidity

File: packages/revolution/src/VerbsToken.sol

139:         require(_minter != address(0), "Minter cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L139-L139

```solidity

File: packages/revolution/src/VerbsToken.sol

140:         require(_initialOwner != address(0), "Initial owner cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L140-L140

```solidity

File: packages/revolution/src/VerbsToken.sol

210:         require(_minter != address(0), "Minter cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L210-L210

```solidity

File: packages/revolution/src/VerbsToken.sol

274:         require(verbId <= _currentVerbId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L274-L274

```solidity

File: packages/revolution/src/VerbsToken.sol

286:         require(
287:             artPiece.creators.length <= cultureIndex.MAX_NUM_CREATORS(),
288:             "Creator array must not be > MAX_NUM_CREATORS"
289:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L286-L289

```solidity

File: packages/revolution/src/VerbsToken.sol

317:             revert("dropTopVotedPiece failed");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L317-L317

```solidity

File: packages/revolution/src/VerbsToken.sol

330:         require(manager.isRegisteredUpgrade(_getImplementation(), _newImpl), "Invalid upgrade");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L330-L330

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

38:         require(decayConstant < 0, "NON_NEGATIVE_DECAY_CONSTANT");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L38-L38
### [G-16]<a name="g-16"></a> Divisions which do not divide by -X cannot overflow or overflow so such operations can be unchecked to save gas
Make such found divisions are unchecked when ensured it is safe to do so

*There are 18 instance(s) of this issue:*

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

44:             (paymentAmountWei * BUILDER_REWARD_BPS) /


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L44-L44

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

46:             (paymentAmountWei * PURCHASE_REFERRAL_BPS) /


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L46-L46

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

48:             (paymentAmountWei * DEPLOYER_REWARD_BPS) /


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L48-L48

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

50:             (paymentAmountWei * REVOLUTION_REWARD_BPS) /


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L50-L50

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

57:                 builderReferralReward: (paymentAmountWei * BUILDER_REWARD_BPS) / 10_000,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L57-L57

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

58:                 purchaseReferralReward: (paymentAmountWei * PURCHASE_REFERRAL_BPS) / 10_000,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L58-L58

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

59:                 deployerReward: (paymentAmountWei * DEPLOYER_REWARD_BPS) / 10_000,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L59-L59

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

60:                 revolutionReward: (paymentAmountWei * REVOLUTION_REWARD_BPS) / 10_000


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L60-L60

```solidity

File: packages/revolution/src/AuctionHouse.sol

181:             msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100),


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L181-L181

```solidity

File: packages/revolution/src/AuctionHouse.sol

365:                 uint256 auctioneerPayment = (_auction.amount * (10_000 - creatorRateBps)) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L365-L365

```solidity

File: packages/revolution/src/AuctionHouse.sol

390:                         uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L390-L390

```solidity

File: packages/revolution/src/CultureIndex.sol

234:         newPiece.quorumVotes = (quorumVotesBPS * newPiece.totalVotesSupply) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L234-L234

```solidity

File: packages/revolution/src/CultureIndex.sol

511:             (quorumVotesBPS * _calculateVoteWeight(erc20VotingToken.totalSupply(), erc721VotingToken.totalSupply())) /


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L511-L511

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

173:         uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L173-L173

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

177:         uint256 creatorDirectPayment = ((msgValueRemaining - toPayTreasury) * entropyRateBps) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L177-L177

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

279:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L279-L279

```solidity

File: packages/revolution/src/MaxHeap.sol

80:         return (pos - 1) / 2;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L80-L80

```solidity

File: packages/revolution/src/MaxHeap.sol

102:         if (pos >= (size / 2) && pos <= size) return;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L102-L102
### [G-17]<a name="g-17"></a> Stack variable cost less while used in emiting event
Even if the variable is going to be used only one time, caching a state variable and use its cache in an emit would help you reduce the cost by at least ***9 gas***

*There are 6 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

// @audit `startTime` is a state variable
326:             emit AuctionCreated(verbId, startTime, endTime);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L326-L326

```solidity

File: packages/revolution/src/CultureIndex.sol

// @audit `quorumVotesBPS` is a state variable
141:         emit QuorumVotesBPSSet(quorumVotesBPS, _cultureIndexParams.quorumVotesBPS);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L141-L141

```solidity

File: packages/revolution/src/CultureIndex.sol

// @audit `quorumVotesBPS` is a state variable
500:         emit QuorumVotesBPSSet(quorumVotesBPS, newQuorumVotesBPS);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L500-L500

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

// @audit `entropyRateBps` is a state variable
291:         emit EntropyRateBpsUpdated(entropyRateBps = _entropyRateBps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L291-L291

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

// @audit `creatorRateBps` is a state variable
302:         emit CreatorRateBpsUpdated(creatorRateBps = _creatorRateBps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L302-L302

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

// @audit `creatorsAddress` is a state variable
312:         emit CreatorsAddressUpdated(creatorsAddress = _creatorsAddress);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L312-L312
### [G-18]<a name="g-18"></a> Events should be emitted outside of loops
Emitting an event has an overhead of **375 gas**, which will be incurred on every iteration of the loop. It is cheaper to `emit` only [once](https://github.com/ethereum/EIPs/blob/adad5968fd6de29902174e0cb51c8fc3dceb9ab5/EIPS/eip-1155.md?plain=1#L68) after the loop has finished.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit PieceCreatorAdded is emited inside this loop
243:         for (uint i; i < creatorArrayLength; i++) {
244:             emit PieceCreatorAdded(pieceId, creatorArray[i].creator, msg.sender, creatorArray[i].bps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L243-L244
### [G-19]<a name="g-19"></a> The result of function calls should be cached rather than re-calling the function
The instances below point to the second+ call of the function within a single function

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

// @audit erc20VotingToken.totalSupply() is called 2 times in the function `createPiece`
209:     function createPiece(
210:         ArtPieceMetadata calldata metadata,
211:         CreatorBps[] calldata creatorArray
212:     ) public returns (uint256) {
213:         uint256 creatorArrayLength = validateCreatorsArray(creatorArray);
214: 
215:         // Validate the media type and associated data
216:         validateMediaType(metadata);
217: 
218:         uint256 pieceId = _currentPieceId++;
219: 
220:         /// @dev Insert the new piece into the max heap
221:         maxHeap.insert(pieceId, 0);
222: 
223:         ArtPiece storage newPiece = pieces[pieceId];
224: 
225:         newPiece.pieceId = pieceId;
226:         newPiece.totalVotesSupply = _calculateVoteWeight(
227:             erc20VotingToken.totalSupply(),
228:             erc721VotingToken.totalSupply()
229:         );
230:         newPiece.totalERC20Supply = erc20VotingToken.totalSupply();
231:         newPiece.metadata = metadata;
232:         newPiece.sponsor = msg.sender;
233:         newPiece.creationBlock = block.number;
234:         newPiece.quorumVotes = (quorumVotesBPS * newPiece.totalVotesSupply) / 10_000;
235: 
236:         for (uint i; i < creatorArrayLength; i++) {
237:             newPiece.creators.push(creatorArray[i]);
238:         }
239: 
240:         emit PieceCreated(pieceId, msg.sender, metadata, newPiece.quorumVotes, newPiece.totalVotesSupply);
241: 
242:         // Emit an event for each creator
243:         for (uint i; i < creatorArrayLength; i++) {
244:             emit PieceCreatorAdded(pieceId, creatorArray[i].creator, msg.sender, creatorArray[i].bps);
245:         }
246: 
247:         return newPiece.pieceId;
248:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L209-L248
### [G-20]<a name="g-20"></a> `require()` or `revert()` statements that check input arguments should be at the top of the function

*There are 5 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

171:     function createBid(uint256 verbId, address bidder) external payable override nonReentrant {
172:         IAuctionHouse.Auction memory _auction = auction;
173: 
174:         //require bidder is valid address
175:         require(bidder != address(0), "Bidder cannot be zero address");
176:         require(_auction.verbId == verbId, "Verb not up for auction");
177:         //slither-disable-next-line timestamp
178:         require(block.timestamp < _auction.endTime, "Auction expired");
179:         require(msg.value >= reservePrice, "Must send at least reservePrice");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L171-L179

```solidity

File: packages/revolution/src/AuctionHouse.sol

171:     function createBid(uint256 verbId, address bidder) external payable override nonReentrant {
172:         IAuctionHouse.Auction memory _auction = auction;
173: 
174:         //require bidder is valid address
175:         require(bidder != address(0), "Bidder cannot be zero address");
176:         require(_auction.verbId == verbId, "Verb not up for auction");
177:         //slither-disable-next-line timestamp
178:         require(block.timestamp < _auction.endTime, "Auction expired");
179:         require(msg.value >= reservePrice, "Must send at least reservePrice");
180:         require(
181:             msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100),


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L171-L181

```solidity

File: packages/revolution/src/CultureIndex.sol

109:     function initialize(
110:         address _erc20VotingToken,
111:         address _erc721VotingToken,
112:         address _initialOwner,
113:         address _maxHeap,
114:         address _dropperAdmin,
115:         IRevolutionBuilder.CultureIndexParams memory _cultureIndexParams
116:     ) external initializer {
117:         require(msg.sender == address(manager), "Only manager can initialize");
118: 
119:         require(_cultureIndexParams.quorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "invalid quorum bps");
120:         require(_cultureIndexParams.erc721VotingTokenWeight > 0, "invalid erc721 voting token weight");
121:         require(_erc721VotingToken != address(0), "invalid erc721 voting token");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L109-L121

```solidity

File: packages/revolution/src/CultureIndex.sol

109:     function initialize(
110:         address _erc20VotingToken,
111:         address _erc721VotingToken,
112:         address _initialOwner,
113:         address _maxHeap,
114:         address _dropperAdmin,
115:         IRevolutionBuilder.CultureIndexParams memory _cultureIndexParams
116:     ) external initializer {
117:         require(msg.sender == address(manager), "Only manager can initialize");
118: 
119:         require(_cultureIndexParams.quorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "invalid quorum bps");
120:         require(_cultureIndexParams.erc721VotingTokenWeight > 0, "invalid erc721 voting token weight");
121:         require(_erc721VotingToken != address(0), "invalid erc721 voting token");
122:         require(_erc20VotingToken != address(0), "invalid erc20 voting token");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L109-L122

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

84:     function initialize(
85:         address _initialOwner,
86:         address _erc20Token,
87:         address _treasury,
88:         address _vrgdac,
89:         address _creatorsAddress
90:     ) external initializer {
91:         require(msg.sender == address(manager), "Only manager can initialize");
92: 
93:         __Pausable_init();
94:         __ReentrancyGuard_init();
95: 
96:         require(_treasury != address(0), "Invalid treasury address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L84-L96
### [G-21]<a name="g-21"></a> `internal` functions only called once can be inlined to save gas
Not inlining costs 20 to 40 gas because of two extra JUMP instructions and additional stack operations needed for function calls.

*There are 6 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

159:     function validateMediaType(ArtPieceMetadata calldata metadata) internal pure {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L159-L159

```solidity

File: packages/revolution/src/CultureIndex.sol

179:     function validateCreatorsArray(CreatorBps[] calldata creatorArray) internal pure returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L179-L179

```solidity

File: packages/revolution/src/CultureIndex.sol

288:     function _getVotes(address account) internal view returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L288-L288

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

52:     function __NontransferableERC20Votes_init(
53:         address _initialOwner,
54:         string calldata _name,
55:         string calldata _symbol
56:     ) internal onlyInitializing {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L52-L56

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

127:     function _mint(address account, uint256 value) internal override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L127-L127

```solidity

File: packages/revolution/src/VerbsToken.sol

281:     function _mintTo(address to) internal returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L281-L281
### [G-22]<a name="g-22"></a> `require()`/`revert()` strings longer than 32 bytes cost extra gas
Each extra memory word of bytes past the original 32 [incurs an MSTORE](https://gist.github.com/hrkrshnn/ee8fabd532058307229d65dcd5836ddc#consider-having-short-revert-strings) which costs **3 gas**

*There are 21 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

129:         require(
130:             _auctionParams.creatorRateBps >= _auctionParams.minCreatorRateBps,
131:             "Creator rate must be greater than or equal to the creator rate"
132:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L129-L132

```solidity

File: packages/revolution/src/AuctionHouse.sol

180:         require(
181:             msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100),
182:             "Must send more than last bid by minBidIncrementPercentage amount"
183:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L180-L183

```solidity

File: packages/revolution/src/AuctionHouse.sol

218:         require(
219:             _creatorRateBps >= minCreatorRateBps,
220:             "Creator rate must be greater than or equal to minCreatorRateBps"
221:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L218-L221

```solidity

File: packages/revolution/src/AuctionHouse.sol

222:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");
223:         creatorRateBps = _creatorRateBps;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L222-L223

```solidity

File: packages/revolution/src/AuctionHouse.sol

234:         require(_minCreatorRateBps <= creatorRateBps, "Min creator rate must be less than or equal to creator rate");
235:         require(_minCreatorRateBps <= 10_000, "Min creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L234-L235

```solidity

File: packages/revolution/src/AuctionHouse.sol

235:         require(_minCreatorRateBps <= 10_000, "Min creator rate must be less than or equal to 10_000");
236: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L235-L236

```solidity

File: packages/revolution/src/AuctionHouse.sol

238:         require(
239:             _minCreatorRateBps > minCreatorRateBps,
240:             "Min creator rate must be greater than previous minCreatorRateBps"
241:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L238-L241

```solidity

File: packages/revolution/src/AuctionHouse.sol

254:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");
255: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L254-L255

```solidity

File: packages/revolution/src/AuctionHouse.sol

311:         require(gasleft() >= MIN_TOKEN_MINT_GAS_THRESHOLD, "Insufficient gas for creating auction");
312: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L311-L312

```solidity

File: packages/revolution/src/CultureIndex.sol

120:         require(_cultureIndexParams.erc721VotingTokenWeight > 0, "invalid erc721 voting token weight");
121:         require(_erc721VotingToken != address(0), "invalid erc721 voting token");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L120-L121

```solidity

File: packages/revolution/src/CultureIndex.sol

182:         require(creatorArrayLength <= MAX_NUM_CREATORS, "Creator array must not be > MAX_NUM_CREATORS");
183: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L182-L183

```solidity

File: packages/revolution/src/CultureIndex.sol

314:         require(weight > minVoteWeight, "Weight must be greater than minVoteWeight");
315: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L314-L315

```solidity

File: packages/revolution/src/CultureIndex.sol

499:         require(newQuorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "CultureIndex::_setQuorumVotesBPS: invalid quorum bps");
500:         emit QuorumVotesBPSSet(quorumVotesBPS, newQuorumVotesBPS);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L499-L500

```solidity

File: packages/revolution/src/CultureIndex.sol

523:         require(totalVoteWeights[piece.pieceId] >= piece.quorumVotes, "Does not meet quorum votes to be dropped.");
524: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L523-L524

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");
159: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L158-L159

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

255:         require(etherAmount > 0, "Ether amount must be greater than 0");
256:         // Note: By using toDaysWadUnsafe(block.timestamp - startTime) we are establishing that 1 "unit of time" is 1 day.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L255-L256

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

272:         require(paymentAmount > 0, "Payment amount must be greater than 0");
273:         // Note: By using toDaysWadUnsafe(block.timestamp - startTime) we are establishing that 1 "unit of time" is 1 day.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L272-L273

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

289:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");
290: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L289-L290

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

300:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");
301: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L300-L301

```solidity

File: packages/revolution/src/VerbsToken.sol

140:         require(_initialOwner != address(0), "Initial owner cannot be zero address");
141: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L140-L141

```solidity

File: packages/revolution/src/VerbsToken.sol

286:         require(
287:             artPiece.creators.length <= cultureIndex.MAX_NUM_CREATORS(),
288:             "Creator array must not be > MAX_NUM_CREATORS"
289:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L286-L289
### [G-23]<a name="g-23"></a> Consider merging sequential for loops
Merging multiple `for` loops within a function in Solidity can enhance efficiency and reduce gas costs, especially when they share a common iterating variable or perform related operations. By minimizing redundant iterations over the same data set, execution becomes more cost-effective. However, while merging can optimize gas usage and simplify logic, it may also increase code complexity. Therefore, careful balance between optimization and maintainability is essential, along with thorough testing to ensure the refactored code behaves as expected.

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

236:         for (uint i; i < creatorArrayLength; i++) {
237:             newPiece.creators.push(creatorArray[i]);
238:         }
239: 
240:         emit PieceCreated(pieceId, msg.sender, metadata, newPiece.quorumVotes, newPiece.totalVotesSupply);
241: 
242:         // Emit an event for each creator
243:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L236-L243

```solidity

File: packages/revolution/src/CultureIndex.sol

403:         for (uint256 i; i < len; i++) {
404:             if (!_verifyVoteSignature(from[i], pieceIds[i], deadline[i], v[i], r[i], s[i])) revert INVALID_SIGNATURE();
405:         }
406: 
407:         for (uint256 i; i < len; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L403-L407
### [G-24]<a name="g-24"></a> Multiple `address`/ID mappings can be combined into a single `mapping` of an `address`/ID to a `struct`, where appropriate
Saves a storage slot for the mapping. Depending on the circumstances and sizes of types, can avoid a Gsset (**20000 gas**) per mapping combined. Reads and subsequent writes can also be cheaper when a function requires both values and they both fit in the same storage slot. Finally, if both fields are accessed in the same function, can save **~42 gas per access** due to [not having to recalculate the key's keccak256 hash](https://gist.github.com/IllIllI000/ec23a57daa30a8f8ca8b9681c8ccefb0) (Gkeccak256 - 30 gas) and that calculation's associated stack operations.

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

33:     mapping(address => uint256) public nonces;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L33-L33

```solidity

File: packages/revolution/src/CultureIndex.sol

69:     mapping(uint256 => mapping(address => Vote)) public votes;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L69-L69
### [G-25]<a name="g-25"></a> Optimize names to save gas
`public`/`external` function names and `public` member variable names can be optimized to save gas. See [this](https://gist.github.com/IllIllI000/a5d8b486a8259f9f77891a919febd1a9) link for an example of how it works. Below are the interfaces/abstract contracts that can be optimized so that the most frequently-called functions use the least amount of gas possible during method lookup. Method IDs that have two leading zero bytes can save **128 gas** each during deployment, and renaming functions to have lower method IDs will save **22 gas** per call, [per sorted position shifted](https://medium.com/joyso/solidity-how-does-function-name-affect-gas-consumption-in-smart-contract-47d270d8ac92)

*There are 7 instance(s) of this issue:*

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

// @audit computeTotalReward(uint256) ==> computeTotalReward_Rsq(uint256),0000f5de
// @audit computePurchaseRewards(uint256) ==> computePurchaseRewards_WFd(uint256),0000d327
14: abstract contract RewardSplits {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L14-L14

```solidity

File: packages/revolution/src/CultureIndex.sol

// @audit _setQuorumVotesBPS(uint256) ==> _setQuorumVotesBPS_Qd9(uint256),0000963b
// @audit quorumVotes() ==> quorumVotes_zeE(),00007578
20: contract CultureIndex is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L20-L20

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

// @audit decimals() ==> decimals_ckx(),000000ea
// @audit buyTokenQuote(uint256) ==> buyTokenQuote_iCJ(uint256),0000793d
// @audit getTokenQuoteForEther(uint256) ==> getTokenQuoteForEther_3jT(uint256),0000c720
17: contract ERC20TokenEmitter is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L17-L17

```solidity

File: packages/revolution/src/MaxHeap.sol

// @audit initialize(address,address) ==> initialize_P1S(address,address),00000777
// @audit insert(uint256,uint256) ==> insert_8dF(uint256,uint256),00008bc9
// @audit updateValue(uint256,uint256) ==> updateValue_gqu(uint256,uint256),000015d5
// @audit extractMax() ==> extractMax_D3R(),00004b35
// @audit getMax() ==> getMax_Wk7(),0000871f
14: contract MaxHeap is VersionedContract, UUPS, Ownable2StepUpgradeable, ReentrancyGuardUpgradeable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L14-L14

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

// @audit mint(address,uint256) ==> mint_Qgo(address,uint256),00001784
29: contract NontransferableERC20Votes is Initializable, ERC20VotesUpgradeable, Ownable2StepUpgradeable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L29-L29

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit contractURI() ==> contractURI_0hx(),000078ff
// @audit setContractURIHash(string) ==> setContractURIHash_td8(string),0000a394
33: contract VerbsToken is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L33-L33

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

// @audit xToY(int256,int256,int256) ==> xToY_X1V(int256,int256,int256),00006000
// @audit yToX(int256,int256,int256) ==> yToX_0et(int256,int256,int256),00007bdc
11: contract VRGDAC {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L11-L11
### [G-26]<a name="g-26"></a> Not using the named return variables anywhere in the function is confusing
Consider changing the variable to be an unnamed one, since the variable is never assigned, nor is it returned by name. If the optimizer is not turned on, leaving the code as it is will also waste gas for the stack variable.

*There are 5 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

// @audit success
419:     function _verifyVoteSignature(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L419-L419

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

// @audit tokensSoldWad
152:     function buyToken(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L152-L152

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

// @audit spentY
237:     function buyTokenQuote(uint256 amount) public view returns (int spentY) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L237-L237

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

// @audit gainedX
254:     function getTokenQuoteForEther(uint256 etherAmount) public view returns (int gainedX) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L254-L254

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

// @audit gainedX
271:     function getTokenQuoteForPayment(uint256 paymentAmount) external view returns (int gainedX) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L271-L271
### [G-27]<a name="g-27"></a> Constructors can be marked `payable`
Payable functions cost less gas to execute, since the compiler does not have to add extra checks to ensure that a payment wasn't provided.A constructor can safely be marked as payable, since only the deployer would be able to pass funds, and the project itself would not pass any funds.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

28:     constructor(int256 _targetPrice, int256 _priceDecayPercent, int256 _perTimeUnit) {
29:         targetPrice = _targetPrice;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L28-L29
### [G-28]<a name="g-28"></a> Using `private` rather than `public` for constants, saves gas
If needed, the values can be read from the verified contract source code, or if there are multiple values there can be a single getter function that [returns a tuple](https://github.com/code-423n4/2022-08-frax/blob/90f55a9ce4e25bceed3a74290b854341d8de6afa/src/contracts/FraxlendPair.sol#L156-L178) of the values of all currently-public constants. Saves **3406-3606 gas** in deployment gas due to the compiler not having to create non-payable getter functions for deployment calldata, not having to store the bytes of the value outside of where it's used, and not adding another entry to the method ID table

*There are 6 instance(s) of this issue:*

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

23:     uint256 public constant minPurchaseAmount = 0.0000001 ether;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L23-L23

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

24:     uint256 public constant maxPurchaseAmount = 50_000 ether;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L24-L24

```solidity

File: packages/revolution/src/AuctionHouse.sol

88:     uint32 public constant MIN_TOKEN_MINT_GAS_THRESHOLD = 750_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L88-L88

```solidity

File: packages/revolution/src/CultureIndex.sol

29:     bytes32 public constant VOTE_TYPEHASH =


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L29-L29

```solidity

File: packages/revolution/src/CultureIndex.sol

48:     uint256 public constant MAX_QUORUM_VOTES_BPS = 6_000; // 6,000 basis points or 60%


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L48-L48

```solidity

File: packages/revolution/src/CultureIndex.sol

75:     uint256 public constant MAX_NUM_CREATORS = 100;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L75-L75
### [G-29]<a name="g-29"></a> Functions guaranteed to revert when called by normal users can be marked `payable`
If a function modifier such as `onlyOwner` is used, the function will revert if a normal user tries to pay the function. Marking the function as `payable` will lower the gas cost for legitimate callers because the compiler will not include checks for whether a payment was provided.The extra opcodes avoided are `CALLVALUE`(2), `DUP1`(3), `ISZERO`(3), `PUSH2`(3), `JUMPI`(10), `PUSH1`(3), `DUP1`(3), `REVERT`(0), `JUMPDEST`(1), `POP`(2), which costs an average of about ** 21 gas per call ** to the function, in addition to the extra deployment cost

*There are 32 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

208:     function pause() external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L208-L208

```solidity

File: packages/revolution/src/AuctionHouse.sol

217:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L217-L217

```solidity

File: packages/revolution/src/AuctionHouse.sol

233:     function setMinCreatorRateBps(uint256 _minCreatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L233-L233

```solidity

File: packages/revolution/src/AuctionHouse.sol

253:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L253-L253

```solidity

File: packages/revolution/src/AuctionHouse.sol

265:     function unpause() external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L265-L265

```solidity

File: packages/revolution/src/AuctionHouse.sol

277:     function setTimeBuffer(uint256 _timeBuffer) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L277-L277

```solidity

File: packages/revolution/src/AuctionHouse.sol

287:     function setReservePrice(uint256 _reservePrice) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L287-L287

```solidity

File: packages/revolution/src/AuctionHouse.sol

297:     function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L297-L297

```solidity

File: packages/revolution/src/AuctionHouse.sol

452:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner whenPaused {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L452-L452

```solidity

File: packages/revolution/src/CultureIndex.sol

498:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L498-L498

```solidity

File: packages/revolution/src/CultureIndex.sol

543:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L543-L543

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

132:     function pause() external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L132-L132

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

141:     function unpause() external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L141-L141

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

288:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L288-L288

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

299:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L299-L299

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

309:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L309-L309

```solidity

File: packages/revolution/src/MaxHeap.sol

119:     function insert(uint256 itemId, uint256 value) public onlyAdmin {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L119-L119

```solidity

File: packages/revolution/src/MaxHeap.sol

136:     function updateValue(uint256 itemId, uint256 newValue) public onlyAdmin {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L136-L136

```solidity

File: packages/revolution/src/MaxHeap.sol

156:     function extractMax() external onlyAdmin returns (uint256, uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L156-L156

```solidity

File: packages/revolution/src/MaxHeap.sol

181:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L181-L181

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

52:     function __NontransferableERC20Votes_init(
53:         address _initialOwner,
54:         string calldata _name,
55:         string calldata _symbol
56:     ) internal onlyInitializing {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L52-L56

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

134:     function mint(address account, uint256 amount) public onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L134-L134

```solidity

File: packages/revolution/src/VerbsToken.sol

169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L169-L169

```solidity

File: packages/revolution/src/VerbsToken.sol

177:     function mint() public override onlyMinter nonReentrant returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L177-L177

```solidity

File: packages/revolution/src/VerbsToken.sol

184:     function burn(uint256 verbId) public override onlyMinter nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L184-L184

```solidity

File: packages/revolution/src/VerbsToken.sol

209:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L209-L209

```solidity

File: packages/revolution/src/VerbsToken.sol

220:     function lockMinter() external override onlyOwner whenMinterNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L220-L220

```solidity

File: packages/revolution/src/VerbsToken.sol

230:     function setDescriptor(
231:         IDescriptorMinimal _descriptor
232:     ) external override onlyOwner nonReentrant whenDescriptorNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L230-L232

```solidity

File: packages/revolution/src/VerbsToken.sol

242:     function lockDescriptor() external override onlyOwner whenDescriptorNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L242-L242

```solidity

File: packages/revolution/src/VerbsToken.sol

252:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L252-L252

```solidity

File: packages/revolution/src/VerbsToken.sol

262:     function lockCultureIndex() external override onlyOwner whenCultureIndexNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L262-L262

```solidity

File: packages/revolution/src/VerbsToken.sol

328:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L328-L328
### [G-30]<a name="g-30"></a> Avoid updating storage when the value hasn't changed to save gas
If the old value is equal to the new value, not re-storing the value will avoid a Gsreset (**2900 gas**), potentially at the expense of a Gcoldsload (**2100 gas**) or a Gwarmaccess (**100 gas**)

*There are 17 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

152:     function settleCurrentAndCreateNewAuction() external override nonReentrant whenNotPaused {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L152-L152

```solidity

File: packages/revolution/src/AuctionHouse.sol

161:     function settleAuction() external override whenPaused nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L161-L161

```solidity

File: packages/revolution/src/AuctionHouse.sol

217:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L217-L217

```solidity

File: packages/revolution/src/AuctionHouse.sol

233:     function setMinCreatorRateBps(uint256 _minCreatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L233-L233

```solidity

File: packages/revolution/src/AuctionHouse.sol

253:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L253-L253

```solidity

File: packages/revolution/src/AuctionHouse.sol

277:     function setTimeBuffer(uint256 _timeBuffer) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L277-L277

```solidity

File: packages/revolution/src/AuctionHouse.sol

287:     function setReservePrice(uint256 _reservePrice) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L287-L287

```solidity

File: packages/revolution/src/AuctionHouse.sol

297:     function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L297-L297

```solidity

File: packages/revolution/src/CultureIndex.sol

498:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L498-L498

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

288:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L288-L288

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

299:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L299-L299

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

309:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L309-L309

```solidity

File: packages/revolution/src/MaxHeap.sol

136:     function updateValue(uint256 itemId, uint256 newValue) public onlyAdmin {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L136-L136

```solidity

File: packages/revolution/src/VerbsToken.sol

169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L169-L169

```solidity

File: packages/revolution/src/VerbsToken.sol

209:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L209-L209

```solidity

File: packages/revolution/src/VerbsToken.sol

230:     function setDescriptor(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L230-L230

```solidity

File: packages/revolution/src/VerbsToken.sol

252:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L252-L252
### [G-31]<a name="g-31"></a> Use shift Right instead of division if possible to save gas

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

80:         return (pos - 1) / 2;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L80-L80

```solidity

File: packages/revolution/src/MaxHeap.sol

102:         if (pos >= (size / 2) && pos <= size) return;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L102-L102
### [G-32]<a name="g-32"></a> Use shift Left instead of multiplication if possible to save gas

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

95:         uint256 left = 2 * pos + 1;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L95-L95

```solidity

File: packages/revolution/src/MaxHeap.sol

96:         uint256 right = 2 * pos + 2;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L96-L96
### [G-33]<a name="g-33"></a> Usage of `uints`/`ints` smaller than 32 bytes (256 bits) incurs overhead
> When using elements that are smaller than 32 bytes, your contract's gas usage may be higher. This is because the EVM operates on 32 bytes at a time. Therefore, if the element is smaller than that, the EVM must use more operations in order to reduce the size of the element from 32 bytes to the desired size.
https://docs.soliditylang.org/en/v0.8.11/internals/layout_in_storage.html
Each operation involving a `uint8` costs an extra [** 22 - 28 gas **](https://gist.github.com/IllIllI000/9388d20c70f9a4632eb3ca7836f54977) (depending on whether the other operand is also a variable of type `uint8`) as compared to ones involving `uint256`, due to the compiler having to clear the higher bits of the memory word before operating on the `uint8`, as well as the associated stack operations of doing so. Use a larger size then downcast where needed

*There are 3 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `_minBidIncrementPercentage` is `uint8`
297:     function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L297-L297

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `` is `uint8`
117:     function decimals() public view returns (uint8) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L117-L117

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit `` is `uint8`
87:     function decimals() public view virtual override returns (uint8) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L87-L87
### [G-34]<a name="g-34"></a> The use of a logical AND in place of double if is slightly less gas efficient in instances where there isn't a corresponding else statement for the given if statement
Using a double if statement instead of logical AND (&&) can provide similar short-circuiting behavior whereas double if is slightly more efficient.

*There are 3 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

383:                 if (creatorsShare > 0 && entropyRateBps > 0) {
384:                     for (uint256 i = 0; i < numCreators; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L383-L384

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

201:         if (totalTokensForCreators > 0 && creatorsAddress != address(0)) {
202:             _mint(creatorsAddress, uint256(totalTokensForCreators));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L201-L202

```solidity

File: packages/revolution/src/MaxHeap.sol

102:         if (pos >= (size / 2) && pos <= size) return;
103: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L102-L103
### [G-35]<a name="g-35"></a> Splitting `require()` statements that use `&&` saves gas
See [this issue](https://github.com/code-423n4/2022-01-xdefi-findings/issues/128) which describes the fact that there is a larger deployment gas cost, but with enough runtime calls, the change ends up being cheaper by **3 gas**

*There are 3 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

160:         require(uint8(metadata.mediaType) > 0 && uint8(metadata.mediaType) <= 5, "Invalid media type");
161: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L160-L161

```solidity

File: packages/revolution/src/CultureIndex.sol

398:         require(
399:             len == pieceIds.length && len == deadline.length && len == v.length && len == r.length && len == s.length,
400:             "Array lengths must match"
401:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L398-L401

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");
159: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L158-L159
### [G-36]<a name="g-36"></a> Cache state variables outside of loop to avoid reading storage on every iteration
Reading from storage should always try to be avoided within loops.In the following instances, we are able to cache state variables outside of the loop to save a Gwarmaccess(100 gas) per loop iteration.

Note: Due to stack too deep errors, we will not be able to cache all the state variables read within the loops.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `entropyRateBps` is a state variable, try to cache it outside the loop
390:                         uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L390-L390
### [G-37]<a name="g-37"></a> `>=`/`<=` costs less gas than `>`/`<`
The compiler uses opcodes `GT` and `ISZERO` for solidity code that uses `>`, but only requires `LT` for `>=`, [which saves **3 gas**](https://gist.github.com/IllIllI000/3dc79d25acccfa16dee4e83ffdc6ffde)

*There are 40 instance(s) of this issue:*

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

18:         if (msgValue < computeTotalReward(msgValue)) revert INVALID_ETH_AMOUNT();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L18-L18

```solidity

File: packages/revolution/src/AuctionHouse.sol

178:         require(block.timestamp < _auction.endTime, "Auction expired");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L178-L178

```solidity

File: packages/revolution/src/AuctionHouse.sol

191:         bool extended = _auction.endTime - block.timestamp < timeBuffer;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L191-L191

```solidity

File: packages/revolution/src/AuctionHouse.sol

239:             _minCreatorRateBps > minCreatorRateBps,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L239-L239

```solidity

File: packages/revolution/src/AuctionHouse.sol

348:         if (address(this).balance < reservePrice) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L348-L348

```solidity

File: packages/revolution/src/AuctionHouse.sol

363:             if (_auction.amount > 0) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L363-L363

```solidity

File: packages/revolution/src/AuctionHouse.sol

383:                 if (creatorsShare > 0 && entropyRateBps > 0) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L383-L383

```solidity

File: packages/revolution/src/AuctionHouse.sol

383:                 if (creatorsShare > 0 && entropyRateBps > 0) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L383-L383

```solidity

File: packages/revolution/src/AuctionHouse.sol

399:                 if (creatorsShare > ethPaidToCreators) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L399-L399

```solidity

File: packages/revolution/src/AuctionHouse.sol

421:         if (address(this).balance < _amount) revert("Insufficient balance");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L421-L421

```solidity

File: packages/revolution/src/CultureIndex.sol

120:         require(_cultureIndexParams.erc721VotingTokenWeight > 0, "invalid erc721 voting token weight");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L120-L120

```solidity

File: packages/revolution/src/CultureIndex.sol

160:         require(uint8(metadata.mediaType) > 0 && uint8(metadata.mediaType) <= 5, "Invalid media type");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L160-L160

```solidity

File: packages/revolution/src/CultureIndex.sol

163:             require(bytes(metadata.image).length > 0, "Image URL must be provided");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L163-L163

```solidity

File: packages/revolution/src/CultureIndex.sol

165:             require(bytes(metadata.animationUrl).length > 0, "Animation URL must be provided");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L165-L165

```solidity

File: packages/revolution/src/CultureIndex.sol

167:             require(bytes(metadata.text).length > 0, "Text must be provided");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L167-L167

```solidity

File: packages/revolution/src/CultureIndex.sol

308:         require(pieceId < _currentPieceId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L308-L308

```solidity

File: packages/revolution/src/CultureIndex.sol

314:         require(weight > minVoteWeight, "Weight must be greater than minVoteWeight");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L314-L314

```solidity

File: packages/revolution/src/CultureIndex.sol

452:         require(pieceId < _currentPieceId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L452-L452

```solidity

File: packages/revolution/src/CultureIndex.sol

462:         require(pieceId < _currentPieceId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L462-L462

```solidity

File: packages/revolution/src/CultureIndex.sol

487:         require(maxHeap.size() > 0, "Culture index is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L487-L487

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

160:         require(msg.value > 0, "Must send ether");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L160-L160

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

179:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L179-L179

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

184:         int totalTokensForBuyers = toPayTreasury > 0 ? getTokenQuoteForEther(toPayTreasury) : int(0);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L184-L184

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

188:         if (totalTokensForCreators > 0) emittedTokenWad += totalTokensForCreators;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L188-L188

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

195:         if (creatorDirectPayment > 0) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L195-L195

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

201:         if (totalTokensForCreators > 0 && creatorsAddress != address(0)) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L201-L201

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

210:             if (totalTokensForBuyers > 0) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L210-L210

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

238:         require(amount > 0, "Amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L238-L238

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

255:         require(etherAmount > 0, "Ether amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L255-L255

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

272:         require(paymentAmount > 0, "Payment amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L272-L272

```solidity

File: packages/revolution/src/MaxHeap.sol

104:         if (posValue < leftValue || posValue < rightValue) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L104-L104

```solidity

File: packages/revolution/src/MaxHeap.sol

104:         if (posValue < leftValue || posValue < rightValue) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L104-L104

```solidity

File: packages/revolution/src/MaxHeap.sol

105:             if (leftValue > rightValue) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L105-L105

```solidity

File: packages/revolution/src/MaxHeap.sol

125:         while (current != 0 && valueMapping[heap[current]] > valueMapping[heap[parent(current)]]) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L125-L125

```solidity

File: packages/revolution/src/MaxHeap.sol

144:         if (newValue > oldValue) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L144-L144

```solidity

File: packages/revolution/src/MaxHeap.sol

146:             while (position != 0 && valueMapping[heap[position]] > valueMapping[heap[parent(position)]]) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L146-L146

```solidity

File: packages/revolution/src/MaxHeap.sol

150:         } else if (newValue < oldValue) maxHeapify(position); // Downwards heapify


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L150-L150

```solidity

File: packages/revolution/src/MaxHeap.sol

157:         require(size > 0, "Heap is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L157-L157

```solidity

File: packages/revolution/src/MaxHeap.sol

170:         require(size > 0, "Heap is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L170-L170

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

38:         require(decayConstant < 0, "NON_NEGATIVE_DECAY_CONSTANT");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L38-L38
### [G-38]<a name="g-38"></a> Use assembly to validate `msg.sender`
We can use assembly to efficiently validate msg.sender with the least amount of opcodes necessary. For more details check the following report [Here](https://code4rena.com/reports/2023-05-juicebox#g-06-use-assembly-to-validate-msgsender)

*There are 13 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

120:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L120-L120

```solidity

File: packages/revolution/src/CultureIndex.sol

117:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L117-L117

```solidity

File: packages/revolution/src/CultureIndex.sol

520:         require(msg.sender == dropperAdmin, "Only dropper can drop pieces");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L520-L520

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

91:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L91-L91

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L158-L158

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L158-L158

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L158-L158

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L158-L158

```solidity

File: packages/revolution/src/MaxHeap.sol

42:         require(msg.sender == admin, "Sender is not the admin");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L42-L42

```solidity

File: packages/revolution/src/MaxHeap.sol

56:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L56-L56

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

69:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L69-L69

```solidity

File: packages/revolution/src/VerbsToken.sol

100:         require(msg.sender == minter, "Sender is not the minter");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L100-L100

```solidity

File: packages/revolution/src/VerbsToken.sol

137:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L137-L137
### [G-39]<a name="g-39"></a> Can make the variable outside the loop to save gas
Creating variables inside the loop consum more gas compared to declaring them outside and just reaffecting values to them inside the loop.

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit variable `creator` is created inside a loop.
385:                         ICultureIndex.CreatorBps memory creator = verbs.getArtPieceById(_auction.verbId).creators[i];


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L385-L385

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit variable `paymentAmount` is created inside a loop.
390:                         uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L390-L390
### [G-40]<a name="g-40"></a> Consider activating via-ir for deploying
The Solidity compiler's Intermediate Representation (IR) based code generator, which can be activated using --via-ir on the command line or {""viaIR"": true} in the options, serves a dual purpose. Firstly, it boosts the transparency and audibility of code generation, which enhances developers' comprehension and control over the contract's final bytecode. Secondly, it enables more sophisticated optimization passes that span multiple functions, thereby potentially leading to more efficient bytecode.
It's important to note that using the IR- based code generator may lengthen compile times due to the extra optimization steps.Therefore, it's advised to test your contract with and without this option enabled to measure the performance and gas cost implications.If the IR- based code generator significantly enhances your contract's performance or reduces gas costs, consider using the --via-ir flag during deployment.This way, you can leverage more advanced compiler optimizations without hindering your development workflow.

*There are 1 instance(s) of this issue:*

```solidity

File: foundry.toml

//@audit /2023-12-revolutionprotocol/node_modules/.pnpm/github.com+foundry-rs+forge-std@705263c95892a906d7af65f0f73ce8a4a0c80b80/node_modules/forge-std/foundry.toml
1: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//foundry.toml#L1-L1
### [G-41]<a name="g-41"></a> `++i` costs less gas than `i++`, especially when it's used in `for`-loops (`--i`/`i--` too)
*Saves 5 gas per loop*

*There are 13 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

384:                     for (uint256 i = 0; i < numCreators; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L384-L384

```solidity

File: packages/revolution/src/CultureIndex.sol

185:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L185-L185

```solidity

File: packages/revolution/src/CultureIndex.sol

218:         uint256 pieceId = _currentPieceId++;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L218-L218

```solidity

File: packages/revolution/src/CultureIndex.sol

236:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L236-L236

```solidity

File: packages/revolution/src/CultureIndex.sol

243:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L243-L243

```solidity

File: packages/revolution/src/CultureIndex.sol

355:         for (uint256 i; i < len; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L355-L355

```solidity

File: packages/revolution/src/CultureIndex.sol

403:         for (uint256 i; i < len; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L403-L403

```solidity

File: packages/revolution/src/CultureIndex.sol

407:         for (uint256 i; i < len; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L407-L407

```solidity

File: packages/revolution/src/CultureIndex.sol

431:         voteHash = keccak256(abi.encode(VOTE_TYPEHASH, from, pieceIds, nonces[from]++, deadline));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L431-L431

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

209:         for (uint256 i = 0; i < addresses.length; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L209-L209

```solidity

File: packages/revolution/src/MaxHeap.sol

129:         size++;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L129-L129

```solidity

File: packages/revolution/src/VerbsToken.sol

294:             uint256 verbId = _currentVerbId++;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L294-L294

```solidity

File: packages/revolution/src/VerbsToken.sol

306:             for (uint i = 0; i < artPiece.creators.length; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L306-L306
### [G-42]<a name="g-42"></a> Use `@inheritdoc` rather than using a non-standard annotation

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/VerbsToken.sol

191:      * @dev See {IERC721Metadata-tokenURI}.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L191-L191
### [G-43]<a name="g-43"></a> Stat variables can be packed into fewer storage slots by truncating timestamp bytes
By using a `uint32` rather than a larger type for variables that track timestamps, one can save gas by using fewer storage slots per struct, at the expense of the protocol breaking after the year 2106 (when `uint32` wraps). If this is an acceptable tradeoff, each slot saved can avoid an extra Gsset (**20000 gas**) for the first setting of the stat variable. Subsequent reads as well as writes have smaller gas savings

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit the following variables could be packed: 
uint256 public timeBuffer;
uint256 public duration;

39: contract AuctionHouse is


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L39-L39

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit the following variables could be packed: 
uint256 public startTime;

17: contract ERC20TokenEmitter is


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L17-L17
### [G-44]<a name="g-44"></a> State variables can be packed into fewer storage slots
If variables occupying the same slot are both written the same function or by the constructor, avoids a separate Gsset (**20000 gas**). Reads of the variables can also be cheaper

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

// @audit from 9 to 7 you need to change the structure elements order to: , uint256, uint256, uint256, uint256, uint256, uint256, address, uint8, IVerbsToken, IERC20TokenEmitter, IAuctionHouse.Auction, IRevolutionBuilder
039: contract AuctionHouse is
040:     IAuctionHouse,
041:     VersionedContract,
042:     UUPS,
043:     PausableUpgradeable,
044:     ReentrancyGuardUpgradeable,
045:     Ownable2StepUpgradeable
046: {
047:     // The Verbs ERC721 token contract
048:     IVerbsToken public verbs;
049: 
050:     // The ERC20 governance token
051:     IERC20TokenEmitter public erc20TokenEmitter;
052: 
053:     // The address of the WETH contract
054:     address public WETH;
055: 
056:     // The minimum amount of time left in an auction after a new bid is created
057:     uint256 public timeBuffer;
058: 
059:     // The minimum price accepted in an auction
060:     uint256 public reservePrice;
061: 
062:     // The minimum percentage difference between the last bid amount and the current bid
063:     uint8 public minBidIncrementPercentage;
064: 
065:     // The split of the winning bid that is reserved for the creator of the Verb in basis points
066:     uint256 public creatorRateBps;
067: 
068:     // The all time minimum split of the winning bid that is reserved for the creator of the Verb in basis points
069:     uint256 public minCreatorRateBps;
070: 
071:     // The split of (auction proceeds * creatorRate) that is sent to the creator as ether in basis points
072:     uint256 public entropyRateBps;
073: 
074:     // The duration of a single auction
075:     uint256 public duration;
076: 
077:     // The active auction
078:     IAuctionHouse.Auction public auction;
079: 
080:     ///                                                          ///
081:     ///                         IMMUTABLES                       ///
082:     ///                                                          ///
083: 
084:     /// @notice The contract upgrade manager
085:     IRevolutionBuilder public immutable manager;
086: 
087:     // TODO investigate this - The minimum gas threshold for creating an auction (minting VerbsToken)
088:     uint32 public constant MIN_TOKEN_MINT_GAS_THRESHOLD = 750_000;
089: 
090:     ///                                                          ///
091:     ///                         CONSTRUCTOR                      ///
092:     ///                                                          ///
093: 
094:     /// @param _manager The contract upgrade manager address
095:     constructor(address _manager) payable initializer {
096:         manager = IRevolutionBuilder(_manager);
097:     }
098: 
099:     ///                                                          ///
100:     ///                         INITIALIZER                      ///
101:     ///                                                          ///
102: 
103:     /**
104:      * @notice Initialize the auction house and base contracts,
105:      * populate configuration values, and pause the contract.
106:      * @dev This function can only be called once.
107:      * @param _erc721Token The address of the Verbs ERC721 token contract.
108:      * @param _erc20TokenEmitter The address of the ERC-20 token emitter contract.
109:      * @param _initialOwner The address of the owner.
110:      * @param _weth The address of the WETH contract
111:      * @param _auctionParams The auction params for auctions.
112:      */
113:     function initialize(
114:         address _erc721Token,
115:         address _erc20TokenEmitter,
116:         address _initialOwner,
117:         address _weth,
118:         IRevolutionBuilder.AuctionParams calldata _auctionParams
119:     ) external initializer {
120:         require(msg.sender == address(manager), "Only manager can initialize");
121:         require(_weth != address(0), "WETH cannot be zero address");
122: 
123:         __Pausable_init();
124:         __ReentrancyGuard_init();
125:         __Ownable_init(_initialOwner);
126: 
127:         _pause();
128: 
129:         require(
130:             _auctionParams.creatorRateBps >= _auctionParams.minCreatorRateBps,
131:             "Creator rate must be greater than or equal to the creator rate"
132:         );
133: 
134:         verbs = IVerbsToken(_erc721Token);
135:         erc20TokenEmitter = IERC20TokenEmitter(_erc20TokenEmitter);
136:         timeBuffer = _auctionParams.timeBuffer;
137:         reservePrice = _auctionParams.reservePrice;
138:         minBidIncrementPercentage = _auctionParams.minBidIncrementPercentage;
139:         duration = _auctionParams.duration;
140:         creatorRateBps = _auctionParams.creatorRateBps;
141:         entropyRateBps = _auctionParams.entropyRateBps;
142:         minCreatorRateBps = _auctionParams.minCreatorRateBps;
143:         WETH = _weth;
144:     }
145: 
146:     /**
147:      * @notice Settle the current auction, mint a new Verb, and put it up for auction.
148:      */
149:     // Can technically reenter via cross function reentrancies in _createAuction, auction, and pause, but those are only callable by the owner.
150:     // @wardens if you can find an exploit here go for it - we might be wrong.
151:     // slither-disable-next-line reentrancy-eth
152:     function settleCurrentAndCreateNewAuction() external override nonReentrant whenNotPaused {
153:         _settleAuction();
154:         _createAuction();
155:     }
156: 
157:     /**
158:      * @notice Settle the current auction.
159:      * @dev This function can only be called when the contract is paused.
160:      */
161:     function settleAuction() external override whenPaused nonReentrant {
162:         _settleAuction();
163:     }
164: 
165:     /**
166:      * @notice Create a bid for a Verb, with a given amount.
167:      * @dev This contract only accepts payment in ETH.
168:      * @param verbId The ID of the Verb to bid on.
169:      * @param bidder The address of the bidder.
170:      */
171:     function createBid(uint256 verbId, address bidder) external payable override nonReentrant {
172:         IAuctionHouse.Auction memory _auction = auction;
173: 
174:         //require bidder is valid address
175:         require(bidder != address(0), "Bidder cannot be zero address");
176:         require(_auction.verbId == verbId, "Verb not up for auction");
177:         //slither-disable-next-line timestamp
178:         require(block.timestamp < _auction.endTime, "Auction expired");
179:         require(msg.value >= reservePrice, "Must send at least reservePrice");
180:         require(
181:             msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100),
182:             "Must send more than last bid by minBidIncrementPercentage amount"
183:         );
184: 
185:         address payable lastBidder = _auction.bidder;
186: 
187:         auction.amount = msg.value;
188:         auction.bidder = payable(bidder);
189: 
190:         // Extend the auction if the bid was received within `timeBuffer` of the auction end time
191:         bool extended = _auction.endTime - block.timestamp < timeBuffer;
192:         if (extended) auction.endTime = _auction.endTime = block.timestamp + timeBuffer;
193: 
194:         // Refund the last bidder, if applicable
195:         if (lastBidder != address(0)) _safeTransferETHWithFallback(lastBidder, _auction.amount);
196: 
197:         emit AuctionBid(_auction.verbId, bidder, msg.sender, msg.value, extended);
198: 
199:         if (extended) emit AuctionExtended(_auction.verbId, _auction.endTime);
200:     }
201: 
202:     /**
203:      * @notice Pause the Verbs auction house.
204:      * @dev This function can only be called by the owner when the
205:      * contract is unpaused. While no new auctions can be started when paused,
206:      * anyone can settle an ongoing auction.
207:      */
208:     function pause() external override onlyOwner {
209:         _pause();
210:     }
211: 
212:     /**
213:      * @notice Set the split of the winning bid that is reserved for the creator of the Verb in basis points.
214:      * @dev Only callable by the owner.
215:      * @param _creatorRateBps New creator rate in basis points.
216:      */
217:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {
218:         require(
219:             _creatorRateBps >= minCreatorRateBps,
220:             "Creator rate must be greater than or equal to minCreatorRateBps"
221:         );
222:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");
223:         creatorRateBps = _creatorRateBps;
224: 
225:         emit CreatorRateBpsUpdated(_creatorRateBps);
226:     }
227: 
228:     /**
229:      * @notice Set the minimum split of the winning bid that is reserved for the creator of the Verb in basis points.
230:      * @dev Only callable by the owner.
231:      * @param _minCreatorRateBps New minimum creator rate in basis points.
232:      */
233:     function setMinCreatorRateBps(uint256 _minCreatorRateBps) external onlyOwner {
234:         require(_minCreatorRateBps <= creatorRateBps, "Min creator rate must be less than or equal to creator rate");
235:         require(_minCreatorRateBps <= 10_000, "Min creator rate must be less than or equal to 10_000");
236: 
237:         //ensure new min rate cannot be lower than previous min rate
238:         require(
239:             _minCreatorRateBps > minCreatorRateBps,
240:             "Min creator rate must be greater than previous minCreatorRateBps"
241:         );
242: 
243:         minCreatorRateBps = _minCreatorRateBps;
244: 
245:         emit MinCreatorRateBpsUpdated(_minCreatorRateBps);
246:     }
247: 
248:     /**
249:      * @notice Set the split of (auction proceeds * creatorRate) that is sent to the creator as ether in basis points.
250:      * @dev Only callable by the owner.
251:      * @param _entropyRateBps New entropy rate in basis points.
252:      */
253:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {
254:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");
255: 
256:         entropyRateBps = _entropyRateBps;
257:         emit EntropyRateBpsUpdated(_entropyRateBps);
258:     }
259: 
260:     /**
261:      * @notice Unpause the Verbs auction house.
262:      * @dev This function can only be called by the owner when the
263:      * contract is paused. If required, this function will start a new auction.
264:      */
265:     function unpause() external override onlyOwner {
266:         _unpause();
267: 
268:         if (auction.startTime == 0 || auction.settled) {
269:             _createAuction();
270:         }
271:     }
272: 
273:     /**
274:      * @notice Set the auction time buffer.
275:      * @dev Only callable by the owner.
276:      */
277:     function setTimeBuffer(uint256 _timeBuffer) external override onlyOwner {
278:         timeBuffer = _timeBuffer;
279: 
280:         emit AuctionTimeBufferUpdated(_timeBuffer);
281:     }
282: 
283:     /**
284:      * @notice Set the auction reserve price.
285:      * @dev Only callable by the owner.
286:      */
287:     function setReservePrice(uint256 _reservePrice) external override onlyOwner {
288:         reservePrice = _reservePrice;
289: 
290:         emit AuctionReservePriceUpdated(_reservePrice);
291:     }
292: 
293:     /**
294:      * @notice Set the auction minimum bid increment percentage.
295:      * @dev Only callable by the owner.
296:      */
297:     function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {
298:         minBidIncrementPercentage = _minBidIncrementPercentage;
299: 
300:         emit AuctionMinBidIncrementPercentageUpdated(_minBidIncrementPercentage);
301:     }
302: 
303:     /**
304:      * @notice Create an auction.
305:      * @dev Store the auction details in the `auction` state variable and emit an AuctionCreated event.
306:      * If the mint reverts, the minter was updated without pausing this contract first. To remedy this,
307:      * catch the revert and pause this contract.
308:      */
309:     function _createAuction() internal {
310:         // Check if there's enough gas to safely execute token.mint() and subsequent operations
311:         require(gasleft() >= MIN_TOKEN_MINT_GAS_THRESHOLD, "Insufficient gas for creating auction");
312: 
313:         try verbs.mint() returns (uint256 verbId) {
314:             uint256 startTime = block.timestamp;
315:             uint256 endTime = startTime + duration;
316: 
317:             auction = Auction({
318:                 verbId: verbId,
319:                 amount: 0,
320:                 startTime: startTime,
321:                 endTime: endTime,
322:                 bidder: payable(0),
323:                 settled: false
324:             });
325: 
326:             emit AuctionCreated(verbId, startTime, endTime);
327:         } catch {
328:             _pause();
329:         }
330:     }
331: 
332:     /**
333:      * @notice Settle an auction, finalizing the bid and paying out to the owner. Pays out to the creator and the owner based on the creatorRateBps and entropyRateBps.
334:      * @dev If there are no bids, the Verb is burned.
335:      */
336:     function _settleAuction() internal {
337:         IAuctionHouse.Auction memory _auction = auction;
338: 
339:         require(_auction.startTime != 0, "Auction hasn't begun");
340:         require(!_auction.settled, "Auction has already been settled");
341:         //slither-disable-next-line timestamp
342:         require(block.timestamp >= _auction.endTime, "Auction hasn't completed");
343: 
344:         auction.settled = true;
345: 
346:         uint256 creatorTokensEmitted = 0;
347:         // Check if contract balance is greater than reserve price
348:         if (address(this).balance < reservePrice) {
349:             // If contract balance is less than reserve price, refund to the last bidder
350:             if (_auction.bidder != address(0)) {
351:                 _safeTransferETHWithFallback(_auction.bidder, _auction.amount);
352:             }
353: 
354:             // And then burn the Noun
355:             verbs.burn(_auction.verbId);
356:         } else {
357:             //If no one has bid, burn the Verb
358:             if (_auction.bidder == address(0))
359:                 verbs.burn(_auction.verbId);
360:                 //If someone has bid, transfer the Verb to the winning bidder
361:             else verbs.transferFrom(address(this), _auction.bidder, _auction.verbId);
362: 
363:             if (_auction.amount > 0) {
364:                 // Ether going to owner of the auction
365:                 uint256 auctioneerPayment = (_auction.amount * (10_000 - creatorRateBps)) / 10_000;
366: 
367:                 //Total amount of ether going to creator
368:                 uint256 creatorsShare = _auction.amount - auctioneerPayment;
369: 
370:                 uint256 numCreators = verbs.getArtPieceById(_auction.verbId).creators.length;
371:                 address deployer = verbs.getArtPieceById(_auction.verbId).sponsor;
372: 
373:                 //Build arrays for erc20TokenEmitter.buyToken
374:                 uint256[] memory vrgdaSplits = new uint256[](numCreators);
375:                 address[] memory vrgdaReceivers = new address[](numCreators);
376: 
377:                 //Transfer auction amount to the DAO treasury
378:                 _safeTransferETHWithFallback(owner(), auctioneerPayment);
379: 
380:                 uint256 ethPaidToCreators = 0;
381: 
382:                 //Transfer creator's share to the creator, for each creator, and build arrays for erc20TokenEmitter.buyToken
383:                 if (creatorsShare > 0 && entropyRateBps > 0) {
384:                     for (uint256 i = 0; i < numCreators; i++) {
385:                         ICultureIndex.CreatorBps memory creator = verbs.getArtPieceById(_auction.verbId).creators[i];
386:                         vrgdaReceivers[i] = creator.creator;
387:                         vrgdaSplits[i] = creator.bps;
388: 
389:                         //Calculate paymentAmount for specific creator based on BPS splits - same as multiplying by creatorDirectPayment
390:                         uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);
391:                         ethPaidToCreators += paymentAmount;
392: 
393:                         //Transfer creator's share to the creator
394:                         _safeTransferETHWithFallback(creator.creator, paymentAmount);
395:                     }
396:                 }
397: 
398:                 //Buy token from ERC20TokenEmitter for all the creators
399:                 if (creatorsShare > ethPaidToCreators) {
400:                     creatorTokensEmitted = erc20TokenEmitter.buyToken{ value: creatorsShare - ethPaidToCreators }(
401:                         vrgdaReceivers,
402:                         vrgdaSplits,
403:                         IERC20TokenEmitter.ProtocolRewardAddresses({
404:                             builder: address(0),
405:                             purchaseReferral: address(0),
406:                             deployer: deployer
407:                         })
408:                     );
409:                 }
410:             }
411:         }
412: 
413:         emit AuctionSettled(_auction.verbId, _auction.bidder, _auction.amount, creatorTokensEmitted);
414:     }
415: 
416:     /// @notice Transfer ETH/WETH from the contract
417:     /// @param _to The recipient address
418:     /// @param _amount The amount transferring
419:     function _safeTransferETHWithFallback(address _to, uint256 _amount) private {
420:         // Ensure the contract has enough ETH to transfer
421:         if (address(this).balance < _amount) revert("Insufficient balance");
422: 
423:         // Used to store if the transfer succeeded
424:         bool success;
425: 
426:         assembly {
427:             // Transfer ETH to the recipient
428:             // Limit the call to 50,000 gas
429:             success := call(50000, _to, _amount, 0, 0, 0, 0)
430:         }
431: 
432:         // If the transfer failed:
433:         if (!success) {
434:             // Wrap as WETH
435:             IWETH(WETH).deposit{ value: _amount }();
436: 
437:             // Transfer WETH instead
438:             bool wethSuccess = IWETH(WETH).transfer(_to, _amount);
439: 
440:             // Ensure successful transfer
441:             if (!wethSuccess) revert("WETH transfer failed");
442:         }
443:     }
444: 
445:     ///                                                          ///
446:     ///                        AUCTION UPGRADE                   ///
447:     ///                                                          ///
448: 
449:     /// @notice Ensures the caller is authorized to upgrade the contract and the new implementation is valid
450:     /// @dev This function is called in `upgradeTo` & `upgradeToAndCall`
451:     /// @param _newImpl The new implementation address
452:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner whenPaused {
453:         // Ensure the new implementation is registered by the Builder DAO
454:         if (!manager.isRegisteredUpgrade(_getImplementation(), _newImpl)) revert INVALID_UPGRADE(_newImpl);
455:     }
456: }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L39-L456

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit from 5 to 4 you need to change the structure elements order to: , uint256, string, mapping, address, bool, bool, bool, IDescriptorMinimal, ICultureIndex, IRevolutionBuilder
033: contract VerbsToken is
034:     IVerbsToken,
035:     VersionedContract,
036:     UUPS,
037:     Ownable2StepUpgradeable,
038:     ReentrancyGuardUpgradeable,
039:     ERC721CheckpointableUpgradeable
040: {
041:     // An address who has permissions to mint Verbs
042:     address public minter;
043: 
044:     // The Verbs token URI descriptor
045:     IDescriptorMinimal public descriptor;
046: 
047:     // The CultureIndex contract
048:     ICultureIndex public cultureIndex;
049: 
050:     // Whether the minter can be updated
051:     bool public isMinterLocked;
052: 
053:     // Whether the CultureIndex can be updated
054:     bool public isCultureIndexLocked;
055: 
056:     // Whether the descriptor can be updated
057:     bool public isDescriptorLocked;
058: 
059:     // The internal verb ID tracker
060:     uint256 private _currentVerbId;
061: 
062:     // IPFS content hash of contract-level metadata
063:     string private _contractURIHash = "QmQzDwaZ7yQxHHs7sQQenJVB89riTSacSGcJRv9jtHPuz5";
064: 
065:     // The Verb art pieces
066:     mapping(uint256 => ICultureIndex.ArtPiece) public artPieces;
067: 
068:     ///                                                          ///
069:     ///                          MODIFIERS                       ///
070:     ///                                                          ///
071: 
072:     /**
073:      * @notice Require that the minter has not been locked.
074:      */
075:     modifier whenMinterNotLocked() {
076:         require(!isMinterLocked, "Minter is locked");
077:         _;
078:     }
079: 
080:     /**
081:      * @notice Require that the CultureIndex has not been locked.
082:      */
083:     modifier whenCultureIndexNotLocked() {
084:         require(!isCultureIndexLocked, "CultureIndex is locked");
085:         _;
086:     }
087: 
088:     /**
089:      * @notice Require that the descriptor has not been locked.
090:      */
091:     modifier whenDescriptorNotLocked() {
092:         require(!isDescriptorLocked, "Descriptor is locked");
093:         _;
094:     }
095: 
096:     /**
097:      * @notice Require that the sender is the minter.
098:      */
099:     modifier onlyMinter() {
100:         require(msg.sender == minter, "Sender is not the minter");
101:         _;
102:     }
103: 
104:     ///                                                          ///
105:     ///                         IMMUTABLES                       ///
106:     ///                                                          ///
107: 
108:     /// @notice The contract upgrade manager
109:     IRevolutionBuilder private immutable manager;
110: 
111:     ///                                                          ///
112:     ///                         CONSTRUCTOR                      ///
113:     ///                                                          ///
114: 
115:     /// @param _manager The contract upgrade manager address
116:     constructor(address _manager) payable initializer {
117:         manager = IRevolutionBuilder(_manager);
118:     }
119: 
120:     ///                                                          ///
121:     ///                         INITIALIZER                      ///
122:     ///                                                          ///
123: 
124:     /// @notice Initializes a DAO's ERC-721 token contract
125:     /// @param _minter The address of the minter
126:     /// @param _initialOwner The address of the initial owner
127:     /// @param _descriptor The address of the token URI descriptor
128:     /// @param _cultureIndex The address of the CultureIndex contract
129:     /// @param _erc721TokenParams The name, symbol, and contract metadata of the token
130:     function initialize(
131:         address _minter,
132:         address _initialOwner,
133:         address _descriptor,
134:         address _cultureIndex,
135:         IRevolutionBuilder.ERC721TokenParams memory _erc721TokenParams
136:     ) external initializer {
137:         require(msg.sender == address(manager), "Only manager can initialize");
138: 
139:         require(_minter != address(0), "Minter cannot be zero address");
140:         require(_initialOwner != address(0), "Initial owner cannot be zero address");
141: 
142:         // Initialize the reentrancy guard
143:         __ReentrancyGuard_init();
144: 
145:         // Setup ownable
146:         __Ownable_init(_initialOwner);
147: 
148:         // Initialize the ERC-721 token
149:         __ERC721_init(_erc721TokenParams.name, _erc721TokenParams.symbol);
150:         _contractURIHash = _erc721TokenParams.contractURIHash;
151: 
152:         // Set the contracts
153:         minter = _minter;
154:         descriptor = IDescriptorMinimal(_descriptor);
155:         cultureIndex = ICultureIndex(_cultureIndex);
156:     }
157: 
158:     /**
159:      * @notice The IPFS URI of contract-level metadata.
160:      */
161:     function contractURI() public view returns (string memory) {
162:         return string(abi.encodePacked("ipfs://", _contractURIHash));
163:     }
164: 
165:     /**
166:      * @notice Set the _contractURIHash.
167:      * @dev Only callable by the owner.
168:      */
169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {
170:         _contractURIHash = newContractURIHash;
171:     }
172: 
173:     /**
174:      * @notice Mint a Verb to the minter.
175:      * @dev Call _mintTo with the to address(es).
176:      */
177:     function mint() public override onlyMinter nonReentrant returns (uint256) {
178:         return _mintTo(minter);
179:     }
180: 
181:     /**
182:      * @notice Burn a verb.
183:      */
184:     function burn(uint256 verbId) public override onlyMinter nonReentrant {
185:         _burn(verbId);
186:         emit VerbBurned(verbId);
187:     }
188: 
189:     /**
190:      * @notice A distinct Uniform Resource Identifier (URI) for a given asset.
191:      * @dev See {IERC721Metadata-tokenURI}.
192:      */
193:     function tokenURI(uint256 tokenId) public view override returns (string memory) {
194:         return descriptor.tokenURI(tokenId, artPieces[tokenId].metadata);
195:     }
196: 
197:     /**
198:      * @notice Similar to `tokenURI`, but always serves a base64 encoded data URI
199:      * with the JSON contents directly inlined.
200:      */
201:     function dataURI(uint256 tokenId) public view override returns (string memory) {
202:         return descriptor.dataURI(tokenId, artPieces[tokenId].metadata);
203:     }
204: 
205:     /**
206:      * @notice Set the token minter.
207:      * @dev Only callable by the owner when not locked.
208:      */
209:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {
210:         require(_minter != address(0), "Minter cannot be zero address");
211:         minter = _minter;
212: 
213:         emit MinterUpdated(_minter);
214:     }
215: 
216:     /**
217:      * @notice Lock the minter.
218:      * @dev This cannot be reversed and is only callable by the owner when not locked.
219:      */
220:     function lockMinter() external override onlyOwner whenMinterNotLocked {
221:         isMinterLocked = true;
222: 
223:         emit MinterLocked();
224:     }
225: 
226:     /**
227:      * @notice Set the token URI descriptor.
228:      * @dev Only callable by the owner when not locked.
229:      */
230:     function setDescriptor(
231:         IDescriptorMinimal _descriptor
232:     ) external override onlyOwner nonReentrant whenDescriptorNotLocked {
233:         descriptor = _descriptor;
234: 
235:         emit DescriptorUpdated(_descriptor);
236:     }
237: 
238:     /**
239:      * @notice Lock the descriptor.
240:      * @dev This cannot be reversed and is only callable by the owner when not locked.
241:      */
242:     function lockDescriptor() external override onlyOwner whenDescriptorNotLocked {
243:         isDescriptorLocked = true;
244: 
245:         emit DescriptorLocked();
246:     }
247: 
248:     /**
249:      * @notice Set the token CultureIndex.
250:      * @dev Only callable by the owner when not locked.
251:      */
252:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {
253:         cultureIndex = _cultureIndex;
254: 
255:         emit CultureIndexUpdated(_cultureIndex);
256:     }
257: 
258:     /**
259:      * @notice Lock the CultureIndex
260:      * @dev This cannot be reversed and is only callable by the owner when not locked.
261:      */
262:     function lockCultureIndex() external override onlyOwner whenCultureIndexNotLocked {
263:         isCultureIndexLocked = true;
264: 
265:         emit CultureIndexLocked();
266:     }
267: 
268:     /**
269:      * @notice Fetch an art piece by its ID.
270:      * @param verbId The ID of the art piece.
271:      * @return The ArtPiece struct associated with the given ID.
272:      */
273:     function getArtPieceById(uint256 verbId) public view returns (ICultureIndex.ArtPiece memory) {
274:         require(verbId <= _currentVerbId, "Invalid piece ID");
275:         return artPieces[verbId];
276:     }
277: 
278:     /**
279:      * @notice Mint a Verb with `verbId` to the provided `to` address. Pulls the top voted art piece from the CultureIndex.
280:      */
281:     function _mintTo(address to) internal returns (uint256) {
282:         ICultureIndex.ArtPiece memory artPiece = cultureIndex.getTopVotedPiece();
283: 
284:         // Check-Effects-Interactions Pattern
285:         // Perform all checks
286:         require(
287:             artPiece.creators.length <= cultureIndex.MAX_NUM_CREATORS(),
288:             "Creator array must not be > MAX_NUM_CREATORS"
289:         );
290: 
291:         // Use try/catch to handle potential failure
292:         try cultureIndex.dropTopVotedPiece() returns (ICultureIndex.ArtPiece memory _artPiece) {
293:             artPiece = _artPiece;
294:             uint256 verbId = _currentVerbId++;
295: 
296:             ICultureIndex.ArtPiece storage newPiece = artPieces[verbId];
297: 
298:             newPiece.pieceId = artPiece.pieceId;
299:             newPiece.metadata = artPiece.metadata;
300:             newPiece.isDropped = artPiece.isDropped;
301:             newPiece.sponsor = artPiece.sponsor;
302:             newPiece.totalERC20Supply = artPiece.totalERC20Supply;
303:             newPiece.quorumVotes = artPiece.quorumVotes;
304:             newPiece.totalVotesSupply = artPiece.totalVotesSupply;
305: 
306:             for (uint i = 0; i < artPiece.creators.length; i++) {
307:                 newPiece.creators.push(artPiece.creators[i]);
308:             }
309: 
310:             _mint(to, verbId);
311: 
312:             emit VerbCreated(verbId, artPiece);
313: 
314:             return verbId;
315:         } catch {
316:             // Handle failure (e.g., revert, emit an event, set a flag, etc.)
317:             revert("dropTopVotedPiece failed");
318:         }
319:     }
320: 
321:     ///                                                          ///
322:     ///                         TOKEN UPGRADE                    ///
323:     ///                                                          ///
324: 
325:     // /// @notice Ensures the caller is authorized to upgrade the contract and that the new implementation is valid
326:     // /// @dev This function is called in `upgradeTo` & `upgradeToAndCall`
327:     // /// @param _newImpl The new implementation address
328:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {
329:         // Ensure the implementation is valid
330:         require(manager.isRegisteredUpgrade(_getImplementation(), _newImpl), "Invalid upgrade");
331:     }
332: }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L33-L332
### [G-45]<a name="g-45"></a> Use `do while` loops instead of `for` loops
A `do while` loop will cost less gas since the condition is not being checked for the first iteration, Check my example on [github](https://github.com/he110-1/gasOptimization/blob/main/forToDoWhileOptimizationProof.sol). Actually, `do while` alwayse cast less gas compared to `For` check my second example [github](https://github.com/he110-1/gasOptimization/blob/main/forToDoWhileOptimizationProof2.sol)

*There are 9 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

384:                     for (uint256 i = 0; i < numCreators; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L384-L384

```solidity

File: packages/revolution/src/CultureIndex.sol

185:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L185-L185

```solidity

File: packages/revolution/src/CultureIndex.sol

236:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L236-L236

```solidity

File: packages/revolution/src/CultureIndex.sol

243:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L243-L243

```solidity

File: packages/revolution/src/CultureIndex.sol

355:         for (uint256 i; i < len; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L355-L355

```solidity

File: packages/revolution/src/CultureIndex.sol

403:         for (uint256 i; i < len; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L403-L403

```solidity

File: packages/revolution/src/CultureIndex.sol

407:         for (uint256 i; i < len; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L407-L407

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

209:         for (uint256 i = 0; i < addresses.length; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L209-L209

```solidity

File: packages/revolution/src/VerbsToken.sol

306:             for (uint i = 0; i < artPiece.creators.length; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L306-L306
### [G-46]<a name="g-46"></a> Avoid transferring amounts of zero in order to save gas
Skipping the external call when nothing will be transferred, will save at least **100 gas**

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

361:             else verbs.transferFrom(address(this), _auction.bidder, _auction.verbId);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L361-L361
### [G-47]<a name="g-47"></a> Simple checks for zero `uint` can be done using assembly to save gas

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

268:         if (auction.startTime == 0 || auction.settled) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L268-L268
### [G-48]<a name="g-48"></a> `++i`/`i++` should be `unchecked{++i}`/`unchecked{i++}` when it is not possible for them to overflow, as is the case when used in `for`- and `while`-loops
The `unchecked` keyword is new in solidity version 0.8.0, so this only applies to that version or higher, which these instances are. This saves **30-40 gas [per loop](https://gist.github.com/hrkrshnn/ee8fabd532058307229d65dcd5836ddc#the-increment-in-for-loop-post-condition-can-be-made-unchecked)**

*There are 9 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

384:                     for (uint256 i = 0; i < numCreators; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L384-L384

```solidity

File: packages/revolution/src/CultureIndex.sol

185:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L185-L185

```solidity

File: packages/revolution/src/CultureIndex.sol

236:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L236-L236

```solidity

File: packages/revolution/src/CultureIndex.sol

243:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L243-L243

```solidity

File: packages/revolution/src/CultureIndex.sol

355:         for (uint256 i; i < len; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L355-L355

```solidity

File: packages/revolution/src/CultureIndex.sol

403:         for (uint256 i; i < len; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L403-L403

```solidity

File: packages/revolution/src/CultureIndex.sol

407:         for (uint256 i; i < len; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L407-L407

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

209:         for (uint256 i = 0; i < addresses.length; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L209-L209

```solidity

File: packages/revolution/src/VerbsToken.sol

306:             for (uint i = 0; i < artPiece.creators.length; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L306-L306
### [G-49]<a name="g-49"></a> Using `private` for constants saves gas
If needed, the values can be read from the verified contract source code, or if there are multiple values there can be a single getter function that [returns a tuple](https://github.com/code-423n4/2022-08-frax/blob/90f55a9ce4e25bceed3a74290b854341d8de6afa/src/contracts/FraxlendPair.sol#L156-L178) of the values of all currently-public constants. Saves **3406-3606 gas** in deployment gas due to the compiler not having to create non-payable getter functions for deployment calldata, not having to store the bytes of the value outside of where it's used, and not adding another entry to the method ID table

*There are 11 instance(s) of this issue:*

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

23:     uint256 public constant minPurchaseAmount = 0.0000001 ether;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L23-L23

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

24:     uint256 public constant maxPurchaseAmount = 50_000 ether;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L24-L24

```solidity

File: packages/revolution/src/AuctionHouse.sol

85:     IRevolutionBuilder public immutable manager;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L85-L85

```solidity

File: packages/revolution/src/AuctionHouse.sol

88:     uint32 public constant MIN_TOKEN_MINT_GAS_THRESHOLD = 750_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L88-L88

```solidity

File: packages/revolution/src/CultureIndex.sol

29:     bytes32 public constant VOTE_TYPEHASH =
30:         keccak256("Vote(address from,uint256[] pieceIds,uint256 nonce,uint256 deadline)");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L29-L30

```solidity

File: packages/revolution/src/CultureIndex.sol

48:     uint256 public constant MAX_QUORUM_VOTES_BPS = 6_000; // 6,000 basis points or 60%


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L48-L48

```solidity

File: packages/revolution/src/CultureIndex.sol

75:     uint256 public constant MAX_NUM_CREATORS = 100;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L75-L75

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

16:     int256 public immutable targetPrice;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L16-L16

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

18:     int256 public immutable perTimeUnit;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L18-L18

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

20:     int256 public immutable decayConstant;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L20-L20

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

22:     int256 public immutable priceDecayPercent;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L22-L22
### [G-50]<a name="g-50"></a> Initializer can be marked `payable`
Payable functions cost less gas to execute, since the compiler does not have to add extra checks to ensure that a payment wasn't provided.An Initializer can safely be marked as payable, since only the allowed user would be able to pass funds, and the project itself would not pass any funds.

*There are 6 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

113:     function initialize(
114:         address _erc721Token,
115:         address _erc20TokenEmitter,
116:         address _initialOwner,
117:         address _weth,
118:         IRevolutionBuilder.AuctionParams calldata _auctionParams
119:     ) external initializer {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L113-L119

```solidity

File: packages/revolution/src/CultureIndex.sol

109:     function initialize(
110:         address _erc20VotingToken,
111:         address _erc721VotingToken,
112:         address _initialOwner,
113:         address _maxHeap,
114:         address _dropperAdmin,
115:         IRevolutionBuilder.CultureIndexParams memory _cultureIndexParams
116:     ) external initializer {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L109-L116

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

84:     function initialize(
85:         address _initialOwner,
86:         address _erc20Token,
87:         address _treasury,
88:         address _vrgdac,
89:         address _creatorsAddress
90:     ) external initializer {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L84-L90

```solidity

File: packages/revolution/src/MaxHeap.sol

55:     function initialize(address _initialOwner, address _admin) public initializer {
56:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L55-L56

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

65:     function initialize(
66:         address _initialOwner,
67:         IRevolutionBuilder.ERC20TokenParams calldata _erc20TokenParams
68:     ) external initializer {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L65-L68

```solidity

File: packages/revolution/src/VerbsToken.sol

130:     function initialize(
131:         address _minter,
132:         address _initialOwner,
133:         address _descriptor,
134:         address _cultureIndex,
135:         IRevolutionBuilder.ERC721TokenParams memory _erc721TokenParams
136:     ) external initializer {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L130-L136
### [G-51]<a name="g-51"></a> Avoid caching global special variables
It's better not to cache the global special variables, because it's cheaper to use them directly (e.g. `msg.sender`).

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

314:             uint256 startTime = block.timestamp;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L314-L314
### [G-52]<a name="g-52"></a> Redundant state variable getters
Getters for public state variables are automatically generated so there is no need to code them manually and waste gas.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

478:     function pieceCount() external view returns (uint256) {
479:         return _currentPieceId;
480:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L478-L480
### [G-53]<a name="g-53"></a> Gas savings can be achieved by changing the model for assigning value to the structure ***123 gas***
Change this `structName a = structName({item1: val1,item2: val2}); ==> structName a; a.item1 = val1; a.item2 = val2;`

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

317:             auction = Auction({
318:                 verbId: verbId,
319:                 amount: 0,
320:                 startTime: startTime,
321:                 endTime: endTime,
322:                 bidder: payable(0),
323:                 settled: false
324:             });


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L317-L324

```solidity

File: packages/revolution/src/CultureIndex.sol

316:         votes[pieceId][voter] = Vote(voter, weight);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L316-L316
### [G-54]<a name="g-54"></a> address(this) should be cached
Cacheing saves gas when compared to repeating the calculation at each point it is used in the contract.The instance below represents the second+ time of calling address(this) in a specific function

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

361:             else verbs.transferFrom(address(this), _auction.bidder, _auction.verbId);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L361-L361### NonCritical Risk Issues


### [N-01]<a name="n-01"></a> State variables declarations should have NatSpec descriptions

*There are 51 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

67:     uint256 public size = 0;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L67-L67

```solidity

File: packages/revolution/src/CultureIndex.sol

36:     MaxHeap public maxHeap;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L36-L36

```solidity

File: packages/revolution/src/CultureIndex.sol

39:     ERC20VotesUpgradeable public erc20VotingToken;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L39-L39

```solidity

File: packages/revolution/src/CultureIndex.sol

42:     ERC721CheckpointableUpgradeable public erc721VotingToken;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L42-L42

```solidity

File: packages/revolution/src/CultureIndex.sol

45:     uint256 public erc721VotingTokenWeight;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L45-L45

```solidity

File: packages/revolution/src/CultureIndex.sol

63:     mapping(uint256 => ArtPiece) public pieces;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L63-L63

```solidity

File: packages/revolution/src/CultureIndex.sol

66:     uint256 public _currentPieceId;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L66-L66

```solidity

File: packages/revolution/src/CultureIndex.sol

69:     mapping(uint256 => mapping(address => Vote)) public votes;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L69-L69

```solidity

File: packages/revolution/src/CultureIndex.sol

72:     mapping(uint256 => uint256) public totalVoteWeights;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L72-L72

```solidity

File: packages/revolution/src/CultureIndex.sol

75:     uint256 public constant MAX_NUM_CREATORS = 100;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L75-L75

```solidity

File: packages/revolution/src/CultureIndex.sol

78:     address public dropperAdmin;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L78-L78

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

25:     address public treasury;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L25-L25

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

28:     NontransferableERC20Votes public token;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L28-L28

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

31:     VRGDAC public vrgdac;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L31-L31

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

34:     uint256 public startTime;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L34-L34

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

42:     uint256 public creatorRateBps;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L42-L42

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

45:     uint256 public entropyRateBps;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L45-L45

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

48:     address public creatorsAddress;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L48-L48

```solidity

File: packages/revolution/src/AuctionHouse.sol

48:     IVerbsToken public verbs;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L48-L48

```solidity

File: packages/revolution/src/AuctionHouse.sol

51:     IERC20TokenEmitter public erc20TokenEmitter;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L51-L51

```solidity

File: packages/revolution/src/AuctionHouse.sol

54:     address public WETH;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L54-L54

```solidity

File: packages/revolution/src/AuctionHouse.sol

57:     uint256 public timeBuffer;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L57-L57

```solidity

File: packages/revolution/src/AuctionHouse.sol

60:     uint256 public reservePrice;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L60-L60

```solidity

File: packages/revolution/src/AuctionHouse.sol

63:     uint8 public minBidIncrementPercentage;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L63-L63

```solidity

File: packages/revolution/src/AuctionHouse.sol

66:     uint256 public creatorRateBps;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L66-L66

```solidity

File: packages/revolution/src/AuctionHouse.sol

69:     uint256 public minCreatorRateBps;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L69-L69

```solidity

File: packages/revolution/src/AuctionHouse.sol

72:     uint256 public entropyRateBps;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L72-L72

```solidity

File: packages/revolution/src/AuctionHouse.sol

75:     uint256 public duration;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L75-L75

```solidity

File: packages/revolution/src/AuctionHouse.sol

78:     IAuctionHouse.Auction public auction;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L78-L78

```solidity

File: packages/revolution/src/AuctionHouse.sol

88:     uint32 public constant MIN_TOKEN_MINT_GAS_THRESHOLD = 750_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L88-L88

```solidity

File: packages/revolution/src/VerbsToken.sol

42:     address public minter;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L42-L42

```solidity

File: packages/revolution/src/VerbsToken.sol

45:     IDescriptorMinimal public descriptor;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L45-L45

```solidity

File: packages/revolution/src/VerbsToken.sol

48:     ICultureIndex public cultureIndex;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L48-L48

```solidity

File: packages/revolution/src/VerbsToken.sol

51:     bool public isMinterLocked;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L51-L51

```solidity

File: packages/revolution/src/VerbsToken.sol

54:     bool public isCultureIndexLocked;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L54-L54

```solidity

File: packages/revolution/src/VerbsToken.sol

57:     bool public isDescriptorLocked;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L57-L57

```solidity

File: packages/revolution/src/VerbsToken.sol

60:     uint256 private _currentVerbId;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L60-L60

```solidity

File: packages/revolution/src/VerbsToken.sol

63:     string private _contractURIHash = "QmQzDwaZ7yQxHHs7sQQenJVB89riTSacSGcJRv9jtHPuz5";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L63-L63

```solidity

File: packages/revolution/src/VerbsToken.sol

66:     mapping(uint256 => ICultureIndex.ArtPiece) public artPieces;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L66-L66

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

16:     int256 public immutable targetPrice;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L16-L16

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

18:     int256 public immutable perTimeUnit;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L18-L18

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

20:     int256 public immutable decayConstant;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L20-L20

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

22:     int256 public immutable priceDecayPercent;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L22-L22

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

18:     uint256 internal constant DEPLOYER_REWARD_BPS = 25;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L18-L18

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

19:     uint256 internal constant REVOLUTION_REWARD_BPS = 75;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L19-L19

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

20:     uint256 internal constant BUILDER_REWARD_BPS = 100;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L20-L20

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

21:     uint256 internal constant PURCHASE_REFERRAL_BPS = 50;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L21-L21

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

23:     uint256 public constant minPurchaseAmount = 0.0000001 ether;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L23-L23

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

24:     uint256 public constant maxPurchaseAmount = 50_000 ether;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L24-L24

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

26:     address internal immutable revolutionRewardRecipient;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L26-L26

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

27:     IRevolutionProtocolRewards internal immutable protocolRewards;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L27-L27
### [N-02]<a name="n-02"></a> Consider using modifiers for address control
Modifiers in Solidity can improve code readability and modularity by encapsulating repetitive checks, such as address validity checks, into a reusable construct. For example, an `onlyOwner` modifier can be used to replace repetitive `require(msg.sender == owner)` checks across several functions, reducing code redundancy and enhancing maintainability. To implement, define a modifier with the check, then apply the modifier to relevant functions.

*There are 9 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

56:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L56-L56

```solidity

File: packages/revolution/src/CultureIndex.sol

117:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L117-L117

```solidity

File: packages/revolution/src/CultureIndex.sol

520:         require(msg.sender == dropperAdmin, "Only dropper can drop pieces");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L520-L520

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

69:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L69-L69

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

91:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L91-L91

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L158-L158

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L158-L158

```solidity

File: packages/revolution/src/AuctionHouse.sol

120:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L120-L120

```solidity

File: packages/revolution/src/VerbsToken.sol

137:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L137-L137
### [N-03]<a name="n-03"></a> Large or complicated code bases should implement invariant tests
Large code bases, or code with lots of inline-assembly, complicated math, or complicated interactions between multiple contracts, should implement [invariant fuzzing tests](https://medium.com/coinmonks/smart-contract-fuzzing-d9b88e0b0a05). Invariant fuzzers such as Echidna require the test writer to come up with invariants which should not be violated under any circumstances, and the fuzzer tests various inputs and function calls to ensure that the invariants always hold. Even code with 100% code coverage can still have bugs due to the order of the operations a user performs, and invariant fuzzers, with properly and extensively-written invariants, can close this testing gap significantly.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

@audit Should implement invariant tests
1: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L1-L1
### [N-04]<a name="n-04"></a> Assembly blocks should have extensive comments
Assembly blocks are taking a lot more time to audit than normal Solidity code, and often have gotchas and side-effects that the Solidity versions of the same code do not. Consider adding more comments explaining what is being done in every step of the assembly code

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

426:         assembly {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L426-L426
### [N-05]<a name="n-05"></a> Contract declarations should have NatSpec `@author` annotations

*There are 7 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

20: contract CultureIndex is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L20-L20

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

29: contract NontransferableERC20Votes is Initializable, ERC20VotesUpgradeable, Ownable2StepUpgradeable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L29-L29

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

17: contract ERC20TokenEmitter is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L17-L17

```solidity

File: packages/revolution/src/AuctionHouse.sol

39: contract AuctionHouse is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L39-L39

```solidity

File: packages/revolution/src/VerbsToken.sol

33: contract VerbsToken is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L33-L33

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

6: abstract contract TokenEmitterRewards is RewardSplits {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L6-L6

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

13: /// @notice Common logic for Revolution ERC20TokenEmitter contracts for protocol reward splits & deposits
14: abstract contract RewardSplits {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L13-L14
### [N-06]<a name="n-06"></a> Variable names that consist of all capital letters should be reserved for `constant`/`immutable` variables

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

54:     address public WETH;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L54-L54
### [N-07]<a name="n-07"></a> Common functions should be refactored to a common base contract
The functions below have the same implementation as is seen in other files. The functions should be refactored into functions of a common base contract

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit this function is already seen in `packages/revolution/src/CultureIndex.sol`
543:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {
544:         // Ensure the new implementation is a registered upgrade
545:         if (!manager.isRegisteredUpgrade(_getImplementation(), _newImpl)) revert INVALID_UPGRADE(_newImpl);
546:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L543-L546

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit this function is already seen in `packages/revolution/src/AuctionHouse.sol`
208:     function pause() external override onlyOwner {
209:         _pause();
210:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L208-L210
### [N-08]<a name="n-08"></a> Overly complicated arithmetic
To maintain readability in code, particularly in Solidity which can involve complex mathematical operations, it is often recommended to limit the number of arithmetic operations to a maximum of 2-3 per line. Too many operations in a single line can make the code difficult to read and understand, increase the likelihood of mistakes, and complicate the process of debugging and reviewing the code. Consider splitting such operations over more than one line, take special care when dealing with division however. Try to limit the number of arithmetic operations to a maximum of 3 per line.

*There are 5 instance(s) of this issue:*

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

179:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0
180:             ? getTokenQuoteForEther((msgValueRemaining - toPayTreasury) - creatorDirectPayment)
181:             : int(0);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L179-L181

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

275:         return
276:             vrgdac.yToX({
277:                 timeSinceStart: toDaysWadUnsafe(block.timestamp - startTime),
278:                 sold: emittedTokenWad,
279:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)
280:             });


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L275-L280

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

87:         return
88:             wadDiv(
89:                 -wadMul(
90:                     wadMul(targetPrice, perTimeUnit),
91:                     wadPow(1e18 - priceDecayPercent, timeSinceStart - unsafeWadDiv(sold, perTimeUnit)) -
92:                         wadPow(1e18 - priceDecayPercent, timeSinceStart)
93:                 ),
94:                 decayConstant
95:             );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L87-L95

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

43:         return
44:             (paymentAmountWei * BUILDER_REWARD_BPS) /
45:             10_000 +
46:             (paymentAmountWei * PURCHASE_REFERRAL_BPS) /
47:             10_000 +
48:             (paymentAmountWei * DEPLOYER_REWARD_BPS) /
49:             10_000 +
50:             (paymentAmountWei * REVOLUTION_REWARD_BPS) /
51:             10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L43-L51

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

55:         return (
56:             RewardsSettings({
57:                 builderReferralReward: (paymentAmountWei * BUILDER_REWARD_BPS) / 10_000,
58:                 purchaseReferralReward: (paymentAmountWei * PURCHASE_REFERRAL_BPS) / 10_000,
59:                 deployerReward: (paymentAmountWei * DEPLOYER_REWARD_BPS) / 10_000,
60:                 revolutionReward: (paymentAmountWei * REVOLUTION_REWARD_BPS) / 10_000
61:             }),
62:             computeTotalReward(paymentAmountWei)
63:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L55-L63
### [N-09]<a name="n-09"></a> Constant redefined elsewhere
Consider defining in only one contract so that values cannot become out of sync when only one location is updated. A [cheap way](https://medium.com/coinmonks/gas-cost-of-solidity-library-functions-dbe0cedd4678) to store constants in a single location is to create an `internal constant` in a `library`. If the variable is a local cache of another contract's value, consider making the cache variable internal or private, which will require external users to query the contract with the source of truth, so that callers don't get out of sync.

*There are 5 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit The same constant is already defined on file : packages/revolution/src/MaxHeap.sol
85:     IRevolutionBuilder private immutable manager;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L85-L85

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit The same constant is already defined on file : packages/revolution/src/MaxHeap.sol
37:     IRevolutionBuilder private immutable manager;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L37-L37

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit The same constant is already defined on file : packages/revolution/src/MaxHeap.sol
55:     IRevolutionBuilder private immutable manager;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L55-L55

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit The same constant is already defined on file : packages/revolution/src/MaxHeap.sol
85:     IRevolutionBuilder public immutable manager;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L85-L85

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit The same constant is already defined on file : packages/revolution/src/MaxHeap.sol
109:     IRevolutionBuilder private immutable manager;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L109-L109
### [N-10]<a name="n-10"></a> Constants in comparisons should appear on the left side

*There are 41 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `0`
79:         require(pos != 0, "Position should not be zero");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L79-L79

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `0`
125:         while (current != 0 && valueMapping[heap[current]] > valueMapping[heap[parent(current)]]) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L125-L125

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `0`
146:             while (position != 0 && valueMapping[heap[position]] > valueMapping[heap[parent(position)]]) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L146-L146

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `0`
157:         require(size > 0, "Heap is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L157-L157

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `0`
170:         require(size > 0, "Heap is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L170-L170

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `MAX_QUORUM_VOTES_BPS`
119:         require(_cultureIndexParams.quorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "invalid quorum bps");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L119-L119

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `0`
120:         require(_cultureIndexParams.erc721VotingTokenWeight > 0, "invalid erc721 voting token weight");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L120-L120

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `0`
160:         require(uint8(metadata.mediaType) > 0 && uint8(metadata.mediaType) <= 5, "Invalid media type");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L160-L160

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `5`
160:         require(uint8(metadata.mediaType) > 0 && uint8(metadata.mediaType) <= 5, "Invalid media type");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L160-L160

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `0`
163:             require(bytes(metadata.image).length > 0, "Image URL must be provided");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L163-L163

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `0`
165:             require(bytes(metadata.animationUrl).length > 0, "Animation URL must be provided");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L165-L165

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `0`
167:             require(bytes(metadata.text).length > 0, "Text must be provided");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L167-L167

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `MAX_NUM_CREATORS`
182:         require(creatorArrayLength <= MAX_NUM_CREATORS, "Creator array must not be > MAX_NUM_CREATORS");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L182-L182

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `10_000`
190:         require(totalBps == 10_000, "Total BPS must sum up to 10,000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L190-L190

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `0`
487:         require(maxHeap.size() > 0, "Culture index is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L487-L487

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `MAX_QUORUM_VOTES_BPS`
499:         require(newQuorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "CultureIndex::_setQuorumVotesBPS: invalid quorum bps");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L499-L499

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `0`
188:         if (totalTokensForCreators > 0) emittedTokenWad += totalTokensForCreators;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L188-L188

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `0`
195:         if (creatorDirectPayment > 0) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L195-L195

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `0`
160:         require(msg.value > 0, "Must send ether");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L160-L160

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `0`
179:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L179-L179

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `0`
184:         int totalTokensForBuyers = toPayTreasury > 0 ? getTokenQuoteForEther(toPayTreasury) : int(0);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L184-L184

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `0`
201:         if (totalTokensForCreators > 0 && creatorsAddress != address(0)) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L201-L201

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `10_000`
217:         require(bpsSum == 10_000, "bps must add up to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L217-L217

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `0`
210:             if (totalTokensForBuyers > 0) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L210-L210

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `0`
238:         require(amount > 0, "Amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L238-L238

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `0`
255:         require(etherAmount > 0, "Ether amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L255-L255

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `0`
272:         require(paymentAmount > 0, "Payment amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L272-L272

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `10_000`
289:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L289-L289

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `10_000`
300:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L300-L300

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `10_000`
222:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L222-L222

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `10_000`
235:         require(_minCreatorRateBps <= 10_000, "Min creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L235-L235

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `10_000`
254:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L254-L254

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `0`
268:         if (auction.startTime == 0 || auction.settled) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L268-L268

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `MIN_TOKEN_MINT_GAS_THRESHOLD`
311:         require(gasleft() >= MIN_TOKEN_MINT_GAS_THRESHOLD, "Insufficient gas for creating auction");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L311-L311

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `0`
339:         require(_auction.startTime != 0, "Auction hasn't begun");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L339-L339

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `0`
363:             if (_auction.amount > 0) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L363-L363

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `0`
383:                 if (creatorsShare > 0 && entropyRateBps > 0) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L383-L383

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `0`
383:                 if (creatorsShare > 0 && entropyRateBps > 0) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L383-L383

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

//@audit `0`
38:         require(decayConstant < 0, "NON_NEGATIVE_DECAY_CONSTANT");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L38-L38

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit `minPurchaseAmount`
41:         if (paymentAmountWei <= minPurchaseAmount || paymentAmountWei >= maxPurchaseAmount) revert INVALID_ETH_AMOUNT();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L41-L41

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit `maxPurchaseAmount`
41:         if (paymentAmountWei <= minPurchaseAmount || paymentAmountWei >= maxPurchaseAmount) revert INVALID_ETH_AMOUNT();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L41-L41
### [N-11]<a name="n-11"></a> `const` Variable names don\'t follow the Solidity style guide
For `constant` variable names, each word should use all capital letters, with underscores separating each word (CONSTANT_CASE)

*There are 2 instance(s) of this issue:*

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

23:     uint256 public constant minPurchaseAmount = 0.0000001 ether;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L23-L23

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

24:     uint256 public constant maxPurchaseAmount = 50_000 ether;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L24-L24
### [N-12]<a name="n-12"></a> NatSpec documentation for `contract` is missing
It is recommended that Solidity contracts are fully annotated using NatSpec for all public interfaces (everything in the ABI). It is clearly stated in the Solidity official documentation. In complex projects such as Defi, the interpretation of all functions and their arguments and returns is important for code readability and auditability.[source](https://docs.soliditylang.org/en/v0.8.15/natspec-format.html)

*There are 6 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

20: contract CultureIndex is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L20-L20

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

29: contract NontransferableERC20Votes is Initializable, ERC20VotesUpgradeable, Ownable2StepUpgradeable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L29-L29

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

17: contract ERC20TokenEmitter is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L17-L17

```solidity

File: packages/revolution/src/AuctionHouse.sol

39: contract AuctionHouse is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L39-L39

```solidity

File: packages/revolution/src/VerbsToken.sol

33: contract VerbsToken is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L33-L33

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

6: abstract contract TokenEmitterRewards is RewardSplits {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L6-L6
### [N-13]<a name="n-13"></a> Contract does not follow the Solidity style guide's suggested layout ordering
The [style guide](https://docs.soliditylang.org/en/v0.8.16/style-guide.html#order-of-layout) says that, within a contract, the ordering should be 1) Type declarations, 2) State variables, 3) Events, 4) Modifiers, and 5) Functions, but the contract(s) below do not follow this ordering

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit the variable definition is misplaced
65:     mapping(uint256 => uint256) public heap;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L65-L65

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit the variable definition is misplaced
109:     IRevolutionBuilder private immutable manager;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L109-L109
### [N-14]<a name="n-14"></a> Control structures do not follow the Solidity Style Guide
See the [control structures](https://docs.soliditylang.org/en/latest/style-guide.html#control-structures) section of the Solidity Style Guide

*There are 14 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

109:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L109-L109

```solidity

File: packages/revolution/src/CultureIndex.sol

209:     function createPiece(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L209-L209

```solidity

File: packages/revolution/src/CultureIndex.sol

367:     function voteForManyWithSig(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L367-L367

```solidity

File: packages/revolution/src/CultureIndex.sol

389:     function batchVoteForManyWithSig(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L389-L389

```solidity

File: packages/revolution/src/CultureIndex.sol

419:     function _verifyVoteSignature(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L419-L419

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

52:     function __NontransferableERC20Votes_init(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L52-L52

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

65:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L65-L65

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

84:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L84-L84

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

152:     function buyToken(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L152-L152

```solidity

File: packages/revolution/src/AuctionHouse.sol

113:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L113-L113

```solidity

File: packages/revolution/src/VerbsToken.sol

130:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L130-L130

```solidity

File: packages/revolution/src/VerbsToken.sol

230:     function setDescriptor(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L230-L230

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

12:     function _handleRewardsAndGetValueToSend(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L12-L12

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

66:     function _depositPurchaseRewards(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L66-L66
### [N-15]<a name="n-15"></a> Custom error has no error details
Consider adding parameters to the error to indicate which user or values caused the failure

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

30:     error TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L30-L30

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

15:     error INVALID_ETH_AMOUNT();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L15-L15
### [N-16]<a name="n-16"></a> Empty bytes check is missing
When developing smart contracts in Solidity, it's crucial to validate the inputs of your functions. This includes ensuring that the bytes parameters are not empty, especially when they represent crucial data such as addresses, identifiers, or raw data that the contract needs to process.
Missing empty bytes checks can lead to unexpected behaviour in your contract.For instance, certain operations might fail, produce incorrect results, or consume unnecessary gas when performed with empty bytes.Moreover, missing input validation can potentially expose your contract to malicious activity, including exploitation of unhandled edge cases.
To mitigate these issues, always validate that bytes parameters are not empty when the logic of your contract requires it.

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit  ,r ,s are not checked
367:     function voteForManyWithSig(
368:         address from,
369:         uint256[] calldata pieceIds,
370:         uint256 deadline,
371:         uint8 v,
372:         bytes32 r,
373:         bytes32 s
374:     ) external nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L367-L374

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit  ,r ,s are not checked
419:     function _verifyVoteSignature(
420:         address from,
421:         uint256[] calldata pieceIds,
422:         uint256 deadline,
423:         uint8 v,
424:         bytes32 r,
425:         bytes32 s
426:     ) internal returns (bool success) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L419-L426
### [N-17]<a name="n-17"></a> Events are missing sender information
When an action is triggered based on a user's action, not being able to filter based on who triggered the action makes event processing a lot more cumbersome. Including the `msg.sender` the events of these types of action will make events much more useful to end users, especially when `msg.sender` is not `tx.origin`.

*There are 23 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

141:         emit QuorumVotesBPSSet(quorumVotesBPS, _cultureIndexParams.quorumVotesBPS);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L141-L141

```solidity

File: packages/revolution/src/CultureIndex.sol

323:         emit VoteCast(pieceId, voter, weight, totalWeight);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L323-L323

```solidity

File: packages/revolution/src/CultureIndex.sol

500:         emit QuorumVotesBPSSet(quorumVotesBPS, newQuorumVotesBPS);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L500-L500

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

291:         emit EntropyRateBpsUpdated(entropyRateBps = _entropyRateBps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L291-L291

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

302:         emit CreatorRateBpsUpdated(creatorRateBps = _creatorRateBps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L302-L302

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

312:         emit CreatorsAddressUpdated(creatorsAddress = _creatorsAddress);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L312-L312

```solidity

File: packages/revolution/src/AuctionHouse.sol

199:         if (extended) emit AuctionExtended(_auction.verbId, _auction.endTime);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L199-L199

```solidity

File: packages/revolution/src/AuctionHouse.sol

225:         emit CreatorRateBpsUpdated(_creatorRateBps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L225-L225

```solidity

File: packages/revolution/src/AuctionHouse.sol

245:         emit MinCreatorRateBpsUpdated(_minCreatorRateBps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L245-L245

```solidity

File: packages/revolution/src/AuctionHouse.sol

257:         emit EntropyRateBpsUpdated(_entropyRateBps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L257-L257

```solidity

File: packages/revolution/src/AuctionHouse.sol

280:         emit AuctionTimeBufferUpdated(_timeBuffer);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L280-L280

```solidity

File: packages/revolution/src/AuctionHouse.sol

290:         emit AuctionReservePriceUpdated(_reservePrice);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L290-L290

```solidity

File: packages/revolution/src/AuctionHouse.sol

300:         emit AuctionMinBidIncrementPercentageUpdated(_minBidIncrementPercentage);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L300-L300

```solidity

File: packages/revolution/src/AuctionHouse.sol

326:             emit AuctionCreated(verbId, startTime, endTime);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L326-L326

```solidity

File: packages/revolution/src/AuctionHouse.sol

413:         emit AuctionSettled(_auction.verbId, _auction.bidder, _auction.amount, creatorTokensEmitted);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L413-L413

```solidity

File: packages/revolution/src/VerbsToken.sol

186:         emit VerbBurned(verbId);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L186-L186

```solidity

File: packages/revolution/src/VerbsToken.sol

213:         emit MinterUpdated(_minter);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L213-L213

```solidity

File: packages/revolution/src/VerbsToken.sol

223:         emit MinterLocked();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L223-L223

```solidity

File: packages/revolution/src/VerbsToken.sol

235:         emit DescriptorUpdated(_descriptor);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L235-L235

```solidity

File: packages/revolution/src/VerbsToken.sol

245:         emit DescriptorLocked();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L245-L245

```solidity

File: packages/revolution/src/VerbsToken.sol

255:         emit CultureIndexUpdated(_cultureIndex);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L255-L255

```solidity

File: packages/revolution/src/VerbsToken.sol

265:         emit CultureIndexLocked();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L265-L265

```solidity

File: packages/revolution/src/VerbsToken.sol

312:             emit VerbCreated(verbId, artPiece);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L312-L312
### [N-18]<a name="n-18"></a> Events may be emitted out of order due to reentrancy
Ensure that events follow the best practice of check-effects-interaction, and are emitted before external calls

*There are 4 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

141:         emit QuorumVotesBPSSet(quorumVotesBPS, _cultureIndexParams.quorumVotesBPS);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L141-L141

```solidity

File: packages/revolution/src/CultureIndex.sol

240:         emit PieceCreated(pieceId, msg.sender, metadata, newPiece.quorumVotes, newPiece.totalVotesSupply);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L240-L240

```solidity

File: packages/revolution/src/CultureIndex.sol

323:         emit VoteCast(pieceId, voter, weight, totalWeight);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L323-L323

```solidity

File: packages/revolution/src/VerbsToken.sol

312:             emit VerbCreated(verbId, artPiece);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L312-L312
### [N-19]<a name="n-19"></a> Defining All External/Public Functions in Contract Interfaces
It is preferable to have all the external and public function in an interface to make using them easier by developers. This helps ensure the whole API is extracted in a interface.

*There are 15 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

119:     function insert(uint256 itemId, uint256 value) public onlyAdmin {
120:         heap[size] = itemId;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L119-L120

```solidity

File: packages/revolution/src/MaxHeap.sol

136:     function updateValue(uint256 itemId, uint256 newValue) public onlyAdmin {
137:         uint256 position = positionMapping[itemId];


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L136-L137

```solidity

File: packages/revolution/src/MaxHeap.sol

156:     function extractMax() external onlyAdmin returns (uint256, uint256) {
157:         require(size > 0, "Heap is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L156-L157

```solidity

File: packages/revolution/src/MaxHeap.sol

169:     function getMax() public view returns (uint256, uint256) {
170:         require(size > 0, "Heap is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L169-L170

```solidity

File: packages/revolution/src/CultureIndex.sol

498:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {
499:         require(newQuorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "CultureIndex::_setQuorumVotesBPS: invalid quorum bps");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L498-L499

```solidity

File: packages/revolution/src/CultureIndex.sol

509:     function quorumVotes() public view returns (uint256) {
510:         return


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L509-L510

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

237:     function buyTokenQuote(uint256 amount) public view returns (int spentY) {
238:         require(amount > 0, "Amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L237-L238

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

254:     function getTokenQuoteForEther(uint256 etherAmount) public view returns (int gainedX) {
255:         require(etherAmount > 0, "Ether amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L254-L255

```solidity

File: packages/revolution/src/VerbsToken.sol

161:     function contractURI() public view returns (string memory) {
162:         return string(abi.encodePacked("ipfs://", _contractURIHash));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L161-L162

```solidity

File: packages/revolution/src/VerbsToken.sol

169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {
170:         _contractURIHash = newContractURIHash;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L169-L170

```solidity

File: packages/revolution/src/VerbsToken.sol

252:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {
253:         cultureIndex = _cultureIndex;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L252-L253

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

47:     function xToY(int256 timeSinceStart, int256 sold, int256 amount) public view virtual returns (int256) {
48:         unchecked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L47-L48

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

54:     function yToX(int256 timeSinceStart, int256 sold, int256 amount) public view virtual returns (int256) {
55:         int256 soldDifference = wadMul(perTimeUnit, timeSinceStart) - sold;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L54-L55

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

40:     function computeTotalReward(uint256 paymentAmountWei) public pure returns (uint256) {
41:         if (paymentAmountWei <= minPurchaseAmount || paymentAmountWei >= maxPurchaseAmount) revert INVALID_ETH_AMOUNT();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L40-L41

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

54:     function computePurchaseRewards(uint256 paymentAmountWei) public pure returns (RewardsSettings memory, uint256) {
55:         return (


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L54-L55
### [N-20]<a name="n-20"></a> Fixed Compiler Version Required for Non-Library/Interface Files

*There are 6 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `MaxHeap` 
2: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L2-L2

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `CultureIndex` 
2: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L2-L2

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit `NontransferableERC20Votes` 
4: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L4-L4

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `ERC20TokenEmitter` 
2: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L2-L2

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `AuctionHouse` 
24: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L24-L24

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit `VerbsToken` 
18: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L18-L18
### [N-21]<a name="n-21"></a> Floating pragma should be avoided
If you leave a floating pragma in your code (pragma solidity 0.4>=0.6. 0. ), you won't know which version was deployed to compile your code, leading to unexpected behavior

*There are 6 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

2: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L2-L2

```solidity

File: packages/revolution/src/CultureIndex.sol

2: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L2-L2

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

4: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L4-L4

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

2: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L2-L2

```solidity

File: packages/revolution/src/AuctionHouse.sol

24: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L24-L24

```solidity

File: packages/revolution/src/VerbsToken.sol

18: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L18-L18
### [N-22]<a name="n-22"></a> NatSpec documentation for `function` is missing
It is recommended that Solidity contracts are fully annotated using NatSpec for all public interfaces (everything in the ABI). It is clearly stated in the Solidity official documentation. In complex projects such as Defi, the interpretation of all functions and their arguments and returns is important for code readability and auditability.[source](https://docs.soliditylang.org/en/v0.8.15/natspec-format.html)

*There are 16 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

288:     function _getVotes(address account) internal view returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L288-L288

```solidity

File: packages/revolution/src/CultureIndex.sol

292:     function _getPastVotes(address account, uint256 blockNumber) internal view returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L292-L292

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

134:     function mint(address account, uint256 amount) public onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L134-L134

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

108:     function _mint(address _to, uint256 _amount) private {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L108-L108

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

112:     function totalSupply() public view returns (uint) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L112-L112

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

117:     function decimals() public view returns (uint8) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L117-L117

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

122:     function balanceOf(address _owner) public view returns (uint) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L122-L122

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

47:     function xToY(int256 timeSinceStart, int256 sold, int256 amount) public view virtual returns (int256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L47-L47

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

54:     function yToX(int256 timeSinceStart, int256 sold, int256 amount) public view virtual returns (int256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L54-L54

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

86:     function pIntegral(int256 timeSinceStart, int256 sold) internal view returns (int256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L86-L86

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

7:     constructor(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L7-L7

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

12:     function _handleRewardsAndGetValueToSend(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L12-L12

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

29:     constructor(address _protocolRewards, address _revolutionRewardRecipient) payable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L29-L29

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

40:     function computeTotalReward(uint256 paymentAmountWei) public pure returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L40-L40

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

54:     function computePurchaseRewards(uint256 paymentAmountWei) public pure returns (RewardsSettings memory, uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L54-L54

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

66:     function _depositPurchaseRewards(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L66-L66
### [N-23]<a name="n-23"></a> Function ordering does not follow the Solidity style guide
According to the [Solidity style guide](https://docs.soliditylang.org/en/v0.8.17/style-guide.html#order-of-functions), functions should be laid out in the following order :`constructor()`, `receive()`, `fallback()`, `external`, `public`, `internal`, `private`, but the cases below do not follow this pattern

*There are 6 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

94:     function maxHeapify(uint256 pos) internal {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L94-L94

```solidity

File: packages/revolution/src/CultureIndex.sol

209:     function createPiece(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L209-L209

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

65:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L65-L65

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

112:     function totalSupply() public view returns (uint) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L112-L112

```solidity

File: packages/revolution/src/AuctionHouse.sol

452:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner whenPaused {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L452-L452

```solidity

File: packages/revolution/src/VerbsToken.sol

169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L169-L169
### [N-24]<a name="n-24"></a> Array indicies should be referenced via `enum`s rather than via numeric literals
Consider using an enum instead of hardcoding an index access to make the code easier to understand.

*There are 4 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `heap`
159:         uint256 popped = heap[0];


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L159-L159

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `heap`
160:         heap[0] = heap[--size];


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L160-L160

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `heap`
171:         return (heap[0], valueMapping[heap[0]]);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L171-L171

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `heap`
171:         return (heap[0], valueMapping[heap[0]]);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L171-L171
### [N-25]<a name="n-25"></a> Hardcoded string that is repeatedly used can be replaced with a constant
For better maintainability, please consider creating and using a constant for those strings instead of hardcoding

*There are 4 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `Heap is empty` is used multiple time consider using a constant for it.
157:         require(size > 0, "Heap is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L157-L157

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `Invalid piece ID` is used multiple time consider using a constant for it.
308:         require(pieceId < _currentPieceId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L308-L308

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `Transfer failed.` is used multiple time consider using a constant for it.
192:         require(success, "Transfer failed.");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L192-L192

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit `Minter cannot be zero address` is used multiple time consider using a constant for it.
139:         require(_minter != address(0), "Minter cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L139-L139
### [N-26]<a name="n-26"></a> Duplicated `require()` checks should be refactored to a modifier or function
The compiler will inline the function, which will avoid `JUMP` instructions usually associated with functions

*There are 7 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

56:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L56-L56

```solidity

File: packages/revolution/src/MaxHeap.sol

157:         require(size > 0, "Heap is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L157-L157

```solidity

File: packages/revolution/src/CultureIndex.sol

308:         require(pieceId < _currentPieceId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L308-L308

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

300:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L300-L300

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

289:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L289-L289

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

192:         require(success, "Transfer failed.");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L192-L192

```solidity

File: packages/revolution/src/VerbsToken.sol

139:         require(_minter != address(0), "Minter cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L139-L139
### [N-27]<a name="n-27"></a> Some if-statement can be converted to a ternary
Improving code readability and compactness is an integral part of optimal programming practices. The use of ternary operators in place of if-else conditions is one such measure. Ternary operators allow us to write conditional statements in a more concise manner, thereby enhancing readability and simplicity. They follow the syntax `condition ? exprIfTrue : exprIfFalse`, which interprets as "if the condition is true, evaluate to `exprIfTrue`, else evaluate to `exprIfFalse`". By adopting this approach, we make our code more streamlined and intuitive, which could potentially aid in better understanding and maintenance of the codebase.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

399:                 if (creatorsShare > ethPaidToCreators) {
400:                     creatorTokensEmitted = erc20TokenEmitter.buyToken{ value: creatorsShare - ethPaidToCreators }(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L399-L400
### [N-28]<a name="n-28"></a> Imports could be organized more systematically
The contract used interfaces should be imported first, followed by all other files. The examples below do not follow this layout.

*There are 6 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

6: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L6-L6

```solidity

File: packages/revolution/src/CultureIndex.sol

10: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L10-L10

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

27: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L27-L27

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

13: import { IERC20TokenEmitter } from "./interfaces/IERC20TokenEmitter.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L13-L13

```solidity

File: packages/revolution/src/AuctionHouse.sol

28: import { IAuctionHouse } from "./interfaces/IAuctionHouse.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L28-L28

```solidity

File: packages/revolution/src/VerbsToken.sol

22: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L22-L22
### [N-29]<a name="n-29"></a> Inconsistent spacing in comments
Some lines use `// x` and some use `//x`. The instances below point out the usages that don't follow the majority, within each file

*There are 27 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

181:         //Require that creatorArray is not more than MAX_NUM_CREATORS to prevent gas limit issues


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L181-L181

```solidity

File: packages/revolution/src/CultureIndex.sol

488:         //slither-disable-next-line unused-return


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L488-L488

```solidity

File: packages/revolution/src/CultureIndex.sol

525:         //set the piece as dropped


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L525-L525

```solidity

File: packages/revolution/src/CultureIndex.sol

528:         //slither-disable-next-line unused-return


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L528-L528

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

157:         //prevent treasury from paying itself


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L157-L157

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

172:         //Share of purchase amount to send to treasury


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L172-L172

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

175:         //Share of purchase amount to reserve for creators


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L175-L175

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

176:         //Ether directly sent to creators


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L176-L176

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

178:         //Tokens to emit to creators


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L178-L178

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

186:         //Transfer ETH to treasury and update emitted


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L186-L186

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

190:         //Deposit funds to treasury


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L190-L190

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

194:         //Transfer ETH to creators


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L194-L194

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

200:         //Mint tokens for creators


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L200-L200

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

207:         //Mint tokens to buyers


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L207-L207

```solidity

File: packages/revolution/src/AuctionHouse.sol

174:         //require bidder is valid address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L174-L174

```solidity

File: packages/revolution/src/AuctionHouse.sol

177:         //slither-disable-next-line timestamp


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L177-L177

```solidity

File: packages/revolution/src/AuctionHouse.sol

237:         //ensure new min rate cannot be lower than previous min rate


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L237-L237

```solidity

File: packages/revolution/src/AuctionHouse.sol

341:         //slither-disable-next-line timestamp


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L341-L341

```solidity

File: packages/revolution/src/AuctionHouse.sol

357:             //If no one has bid, burn the Verb


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L357-L357

```solidity

File: packages/revolution/src/AuctionHouse.sol

360:                 //If someone has bid, transfer the Verb to the winning bidder


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L360-L360

```solidity

File: packages/revolution/src/AuctionHouse.sol

367:                 //Total amount of ether going to creator


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L367-L367

```solidity

File: packages/revolution/src/AuctionHouse.sol

373:                 //Build arrays for erc20TokenEmitter.buyToken


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L373-L373

```solidity

File: packages/revolution/src/AuctionHouse.sol

377:                 //Transfer auction amount to the DAO treasury


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L377-L377

```solidity

File: packages/revolution/src/AuctionHouse.sol

382:                 //Transfer creator's share to the creator, for each creator, and build arrays for erc20TokenEmitter.buyToken


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L382-L382

```solidity

File: packages/revolution/src/AuctionHouse.sol

389:                         //Calculate paymentAmount for specific creator based on BPS splits - same as multiplying by creatorDirectPayment


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L389-L389

```solidity

File: packages/revolution/src/AuctionHouse.sol

393:                         //Transfer creator's share to the creator


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L393-L393

```solidity

File: packages/revolution/src/AuctionHouse.sol

398:                 //Buy token from ERC20TokenEmitter for all the creators


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L398-L398
### [N-30]<a name="n-30"></a> Inconsistent usage of `require`/`error`
Some parts of the codebase use `require` statements, while others use custom `error`s. Consider refactoring the code to use the same approach: the following findings represent the minority of `require` vs `error`, and they show the first occurance in each file, for brevity.

*There are 17 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

183:         if (!manager.isRegisteredUpgrade(_getImplementation(), _newImpl)) revert INVALID_UPGRADE(_newImpl);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L183-L183

```solidity

File: packages/revolution/src/CultureIndex.sol

377:         if (!success) revert INVALID_SIGNATURE();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L377-L377

```solidity

File: packages/revolution/src/CultureIndex.sol

438:         if (from == address(0)) revert ADDRESS_ZERO();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L438-L438

```solidity

File: packages/revolution/src/CultureIndex.sol

441:         if (recoveredAddress == address(0) || recoveredAddress != from) revert INVALID_SIGNATURE();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L441-L441

```solidity

File: packages/revolution/src/CultureIndex.sol

545:         if (!manager.isRegisteredUpgrade(_getImplementation(), _newImpl)) revert INVALID_UPGRADE(_newImpl);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L545-L545

```solidity

File: packages/revolution/src/CultureIndex.sol

404:             if (!_verifyVoteSignature(from[i], pieceIds[i], deadline[i], v[i], r[i], s[i])) revert INVALID_SIGNATURE();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L404-L404

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

95:         revert TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L95-L95

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

102:         revert TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L102-L102

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

109:         revert TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L109-L109

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

116:         revert TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L116-L116

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

142:         revert TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L142-L142

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

149:         revert TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L149-L149

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

156:         revert TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L156-L156

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

129:             revert ERC20InvalidReceiver(address(0));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L129-L129

```solidity

File: packages/revolution/src/AuctionHouse.sol

454:         if (!manager.isRegisteredUpgrade(_getImplementation(), _newImpl)) revert INVALID_UPGRADE(_newImpl);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L454-L454

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

18:         if (msgValue < computeTotalReward(msgValue)) revert INVALID_ETH_AMOUNT();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L18-L18

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

41:         if (paymentAmountWei <= minPurchaseAmount || paymentAmountWei >= maxPurchaseAmount) revert INVALID_ETH_AMOUNT();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L41-L41
### [N-31]<a name="n-31"></a> Incorrect NatSpec Syntax
In Solidity, just like in most other programming languages, regular comments serve to make code more understandable for developers. These are usually denoted by `//` for single line comments, or `/* ... */` for multi-line comments, and are ignored by the compiler.
On the other hand, NatSpec comments in Solidity, denoted by `///` for single - line comments, or`/** ... */` for multi - line comments, serve a different purpose.Besides aiding developer comprehension, they also form a part of the contract's interface, as they can be parsed and used by tools such as automated documentation generators or IDEs to provide users with details about the contract's functions, parameters and behavior.NatSpec comments can also be retrieved via JSON interfaces, and as such, they're included in the contract's ABI.
Thus, using`///` and `/** ... */` appropriately ensures not only proper documentation for developers, but also helps create a richer and more informative interface for users and external tools interacting with your contract.

*There are 3 instance(s) of this issue:*

```solidity

File: packages/revolution/src/VerbsToken.sol

325:     // /// @notice Ensures the caller is authorized to upgrade the contract and that the new implementation is valid


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L325-L325

```solidity

File: packages/revolution/src/VerbsToken.sol

326:     // /// @dev This function is called in `upgradeTo` & `upgradeToAndCall`


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L326-L326

```solidity

File: packages/revolution/src/VerbsToken.sol

327:     // /// @param _newImpl The new implementation address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L327-L327
### [N-32]<a name="n-32"></a> Large numeric literals should use underscores for readability

*There are 1 instance(s) of this issue:*

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

23:     uint256 public constant minPurchaseAmount = 0.0000001 ether;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L23-L23
### [N-33]<a name="n-33"></a> Long functions should be refactored into multiple, smaller, functions

*There are 3 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

109:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L109-L109

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

152:     function buyToken(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L152-L152

```solidity

File: packages/revolution/src/AuctionHouse.sol

336:     function _settleAuction() internal {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L336-L336
### [N-34]<a name="n-34"></a> Long lines of code
Usually lines in source code are limited to [80](https://softwareengineering.stackexchange.com/questions/148677/why-is-80-characters-the-standard-limit-for-code-width) characters. Today's screens are much larger so it's reasonable to stretch this in some cases. The solidity style guide recommends a maximumum line length of [120 characters](https://docs.soliditylang.org/en/v0.8.17/style-guide.html#maximum-line-length), so the lines below should be split when they reach that length.

*There are 20 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

53:     /// @notice The basis point number of votes in support of a art piece required in order for a quorum to be reached and for an art piece to be dropped.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L53-L53

```solidity

File: packages/revolution/src/CultureIndex.sol

197:      * @param metadata The metadata associated with the art piece, including name, description, image, and optional animation URL.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L197-L197

```solidity

File: packages/revolution/src/CultureIndex.sol

198:      * @param creatorArray An array of creators who contributed to the piece, along with their respective basis points that must sum up to 10,000.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L198-L198

```solidity

File: packages/revolution/src/CultureIndex.sol

304:      * @dev Requires that the pieceId is valid, the voter has not already voted on this piece, and the weight is greater than the minimum vote weight.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L304-L304

```solidity

File: packages/revolution/src/CultureIndex.sol

329:      * @dev Requires that the pieceId is valid, the voter has not already voted on this piece, and the weight is greater than the minimum vote weight.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L329-L329

```solidity

File: packages/revolution/src/CultureIndex.sol

339:      * @dev Requires that the pieceIds are valid, the voter has not already voted on this piece, and the weight is greater than the minimum vote weight.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L339-L339

```solidity

File: packages/revolution/src/CultureIndex.sol

350:      * @dev Requires that the pieceIds are valid, the voter has not already voted on this piece, and the weight is greater than the minimum vote weight.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L350-L350

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

7:  * @dev Extension of ERC-20 to support Compound-like voting and delegation. This version is more generic than Compound's,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L7-L7

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

146:      * @notice A payable function that allows a user to buy tokens for a list of addresses and a list of basis points to split the token purchase between.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L146-L146

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

233:      * @notice Returns the amount of wei that would be spent to buy an amount of tokens. Does not take into account the protocol rewards.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L233-L233

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

239:         // Note: By using toDaysWadUnsafe(block.timestamp - startTime) we are establishing that 1 "unit of time" is 1 day.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L239-L239

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

250:      * @notice Returns the amount of tokens that would be emitted for an amount of wei. Does not take into account the protocol rewards.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L250-L250

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

256:         // Note: By using toDaysWadUnsafe(block.timestamp - startTime) we are establishing that 1 "unit of time" is 1 day.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L256-L256

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

267:      * @notice Returns the amount of tokens that would be emitted for the payment amount, taking into account the protocol rewards.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L267-L267

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

273:         // Note: By using toDaysWadUnsafe(block.timestamp - startTime) we are establishing that 1 "unit of time" is 1 day.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L273-L273

```solidity

File: packages/revolution/src/AuctionHouse.sol

149:     // Can technically reenter via cross function reentrancies in _createAuction, auction, and pause, but those are only callable by the owner.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L149-L149

```solidity

File: packages/revolution/src/AuctionHouse.sol

333:      * @notice Settle an auction, finalizing the bid and paying out to the owner. Pays out to the creator and the owner based on the creatorRateBps and entropyRateBps.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L333-L333

```solidity

File: packages/revolution/src/AuctionHouse.sol

382:                 //Transfer creator's share to the creator, for each creator, and build arrays for erc20TokenEmitter.buyToken


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L382-L382

```solidity

File: packages/revolution/src/AuctionHouse.sol

389:                         //Calculate paymentAmount for specific creator based on BPS splits - same as multiplying by creatorDirectPayment


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L389-L389

```solidity

File: packages/revolution/src/VerbsToken.sol

279:      * @notice Mint a Verb with `verbId` to the provided `to` address. Pulls the top voted art piece from the CultureIndex.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L279-L279
### [N-35]<a name="n-35"></a> Missing event and or timelock for critical parameter change
Events help non-contract tools to track changes, and events prevent users from being surprised by changes

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/VerbsToken.sol

169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {
170:         _contractURIHash = newContractURIHash;
171:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L169-L171
### [N-36]<a name="n-36"></a> File is missing NatSpec

*There are 1 instance(s) of this issue:*

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

0: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L0-L0
### [N-37]<a name="n-37"></a> Mixed usage of `int`/`uint` with `int256`/`uint256`
`int256`/`uint256` are the preferred type names (they're what are used for function signatures), so they should be used consistently

*There are 12 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

185:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L185-L185

```solidity

File: packages/revolution/src/CultureIndex.sol

236:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L236-L236

```solidity

File: packages/revolution/src/CultureIndex.sol

243:         for (uint i; i < creatorArrayLength; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L243-L243

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

112:     function totalSupply() public view returns (uint) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L112-L112

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

122:     function balanceOf(address _owner) public view returns (uint) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L122-L122

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

154:         uint[] calldata basisPointSplits,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L154-L154

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

237:     function buyTokenQuote(uint256 amount) public view returns (int spentY) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L237-L237

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

254:     function getTokenQuoteForEther(uint256 etherAmount) public view returns (int gainedX) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L254-L254

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

271:     function getTokenQuoteForPayment(uint256 paymentAmount) external view returns (int gainedX) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L271-L271

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

179:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L179-L179

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

184:         int totalTokensForBuyers = toPayTreasury > 0 ? getTokenQuoteForEther(toPayTreasury) : int(0);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L184-L184

```solidity

File: packages/revolution/src/VerbsToken.sol

306:             for (uint i = 0; i < artPiece.creators.length; i++) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L306-L306
### [N-38]<a name="n-38"></a> Consider using named mappings
Consider using [named mappings](https://ethereum.stackexchange.com/a/145555) to make it easier to understand the purpose of each mapping

*There are 9 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

65:     mapping(uint256 => uint256) public heap;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L65-L65

```solidity

File: packages/revolution/src/MaxHeap.sol

70:     mapping(uint256 => uint256) public valueMapping;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L70-L70

```solidity

File: packages/revolution/src/MaxHeap.sol

73:     mapping(uint256 => uint256) public positionMapping;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L73-L73

```solidity

File: packages/revolution/src/CultureIndex.sol

33:     mapping(address => uint256) public nonces;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L33-L33

```solidity

File: packages/revolution/src/CultureIndex.sol

63:     mapping(uint256 => ArtPiece) public pieces;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L63-L63

```solidity

File: packages/revolution/src/CultureIndex.sol

69:     mapping(uint256 => mapping(address => Vote)) public votes;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L69-L69

```solidity

File: packages/revolution/src/CultureIndex.sol

69:     mapping(uint256 => mapping(address => Vote)) public votes;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L69-L69

```solidity

File: packages/revolution/src/CultureIndex.sol

72:     mapping(uint256 => uint256) public totalVoteWeights;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L72-L72

```solidity

File: packages/revolution/src/VerbsToken.sol

66:     mapping(uint256 => ICultureIndex.ArtPiece) public artPieces;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L66-L66
### [N-39]<a name="n-39"></a> Some error strings are not descriptive
Consider adding more detail to these error strings

*There are 7 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit This message need more details : Heap is empty
157:         require(size > 0, "Heap is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L157-L157

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit This message need more details : Heap is empty
170:         require(size > 0, "Heap is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L170-L170

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit This message need more details : Already voted
311:         require(!(votes[pieceId][voter].voterAddress != address(0)), "Already voted");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L311-L311

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit This message need more details : Must send ether
160:         require(msg.value > 0, "Must send ether");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L160-L160

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit This message need more details : Invalid address
310:         require(_creatorsAddress != address(0), "Invalid address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L310-L310

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit This message need more details : Auction expired
178:         require(block.timestamp < _auction.endTime, "Auction expired");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L178-L178

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit This message need more details : Invalid upgrade
330:         require(manager.isRegisteredUpgrade(_getImplementation(), _newImpl), "Invalid upgrade");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L330-L330
### [N-40]<a name="n-40"></a> The `nonReentrant` `modifier` should occur before all other modifiers
This is a best-practice to protect against reentrancy in other modifiers

*There are 7 instance(s) of this issue:*

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

309:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L309-L309

```solidity

File: packages/revolution/src/AuctionHouse.sol

161:     function settleAuction() external override whenPaused nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L161-L161

```solidity

File: packages/revolution/src/VerbsToken.sol

177:     function mint() public override onlyMinter nonReentrant returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L177-L177

```solidity

File: packages/revolution/src/VerbsToken.sol

184:     function burn(uint256 verbId) public override onlyMinter nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L184-L184

```solidity

File: packages/revolution/src/VerbsToken.sol

209:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L209-L209

```solidity

File: packages/revolution/src/VerbsToken.sol

230:     function setDescriptor(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L230-L230

```solidity

File: packages/revolution/src/VerbsToken.sol

252:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L252-L252
### [N-41]<a name="n-41"></a> Public state variables shouldn't have a preceding _ in their name
Remove the _ from the state variable name, ensure you also refactor where these state variables are internally called

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

66:     uint256 public _currentPieceId;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L66-L66
### [N-42]<a name="n-42"></a> `override` function arguments that are unused should have the variable name removed or commented out to avoid compiler warnings

*There are 4 instance(s) of this issue:*

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit from is not used
//@audit to is not used
//@audit value is not used
101:     function _transfer(address from, address to, uint256 value) internal override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L101-L101

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit owner is not used
//@audit spender is not used
//@audit value is not used
141:     function _approve(address owner, address spender, uint256 value) internal override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L141-L141

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit owner is not used
//@audit spender is not used
//@audit value is not used
//@audit emitEvent is not used
148:     function _approve(address owner, address spender, uint256 value, bool emitEvent) internal virtual override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L148-L148

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit owner is not used
//@audit spender is not used
//@audit value is not used
155:     function _spendAllowance(address owner, address spender, uint256 value) internal virtual override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L155-L155
### [N-43]<a name="n-43"></a> Use of `override` is unnecessary
Starting with Solidity version [0.8.8](https://docs.soliditylang.org/en/v0.8.20/contracts.html#function-overriding), using the `override` keyword when the function solely overrides an interface function, and the function doesn't exist in multiple base contracts, is unnecessary.

*There are 30 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

181:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L181-L181

```solidity

File: packages/revolution/src/CultureIndex.sol

265:     function getVotes(address account) external view override returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L265-L265

```solidity

File: packages/revolution/src/CultureIndex.sol

274:     function getPastVotes(address account, uint256 blockNumber) external view override returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L274-L274

```solidity

File: packages/revolution/src/CultureIndex.sol

543:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L543-L543

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

101:     function _transfer(address from, address to, uint256 value) internal override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L101-L101

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

127:     function _mint(address account, uint256 value) internal override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L127-L127

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

141:     function _approve(address owner, address spender, uint256 value) internal override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L141-L141

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

148:     function _approve(address owner, address spender, uint256 value, bool emitEvent) internal virtual override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L148-L148

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

155:     function _spendAllowance(address owner, address spender, uint256 value) internal virtual override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L155-L155

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

132:     function pause() external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L132-L132

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

141:     function unpause() external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L141-L141

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

309:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L309-L309

```solidity

File: packages/revolution/src/AuctionHouse.sol

152:     function settleCurrentAndCreateNewAuction() external override nonReentrant whenNotPaused {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L152-L152

```solidity

File: packages/revolution/src/AuctionHouse.sol

161:     function settleAuction() external override whenPaused nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L161-L161

```solidity

File: packages/revolution/src/AuctionHouse.sol

171:     function createBid(uint256 verbId, address bidder) external payable override nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L171-L171

```solidity

File: packages/revolution/src/AuctionHouse.sol

208:     function pause() external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L208-L208

```solidity

File: packages/revolution/src/AuctionHouse.sol

265:     function unpause() external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L265-L265

```solidity

File: packages/revolution/src/AuctionHouse.sol

277:     function setTimeBuffer(uint256 _timeBuffer) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L277-L277

```solidity

File: packages/revolution/src/AuctionHouse.sol

287:     function setReservePrice(uint256 _reservePrice) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L287-L287

```solidity

File: packages/revolution/src/AuctionHouse.sol

297:     function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L297-L297

```solidity

File: packages/revolution/src/AuctionHouse.sol

452:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner whenPaused {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L452-L452

```solidity

File: packages/revolution/src/VerbsToken.sol

177:     function mint() public override onlyMinter nonReentrant returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L177-L177

```solidity

File: packages/revolution/src/VerbsToken.sol

184:     function burn(uint256 verbId) public override onlyMinter nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L184-L184

```solidity

File: packages/revolution/src/VerbsToken.sol

201:     function dataURI(uint256 tokenId) public view override returns (string memory) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L201-L201

```solidity

File: packages/revolution/src/VerbsToken.sol

209:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L209-L209

```solidity

File: packages/revolution/src/VerbsToken.sol

220:     function lockMinter() external override onlyOwner whenMinterNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L220-L220

```solidity

File: packages/revolution/src/VerbsToken.sol

230:     function setDescriptor(
231:         IDescriptorMinimal _descriptor
232:     ) external override onlyOwner nonReentrant whenDescriptorNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L230-L232

```solidity

File: packages/revolution/src/VerbsToken.sol

242:     function lockDescriptor() external override onlyOwner whenDescriptorNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L242-L242

```solidity

File: packages/revolution/src/VerbsToken.sol

262:     function lockCultureIndex() external override onlyOwner whenCultureIndexNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L262-L262

```solidity

File: packages/revolution/src/VerbsToken.sol

328:     function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L328-L328
### [N-44]<a name="n-44"></a> NatSpec `@param` is missing

*There are 24 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

// @audit the @param blockNumber is missing

@notice Returns the voting power of a voter at the current block.
@param account The address of the voter.
@return The voting power of the voter.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L274-L1

```solidity

File: packages/revolution/src/CultureIndex.sol

// @audit the @param voter is missing

@notice Fetch the list of votes for a given art piece.
@param pieceId The ID of the art piece.
@return An array of Vote structs for the given art piece ID.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L461-L1

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

// @audit the @param _initialOwner is missing
// @audit the @param _name is missing
// @audit the @param _symbol is missing

///
             INITIALIZER                      ///
                                              ///


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L52-L1

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

// @audit the @param  is missing
// @audit the @param  is missing

@dev Not allowed


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L94-L1

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

// @audit the @param from is missing
// @audit the @param to is missing
// @audit the @param value is missing

@dev Not allowed


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L101-L1

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

// @audit the @param  is missing
// @audit the @param  is missing
// @audit the @param  is missing

@dev Not allowed


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L108-L1

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

// @audit the @param  is missing
// @audit the @param  is missing

@dev Not allowed


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L115-L1

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

// @audit the @param account is missing
// @audit the @param value is missing

@dev Creates a `value` amount of tokens and assigns them to `account`, by transferring it from address(0).
Relies on the `_update` mechanism
Emits a {Transfer} event with `from` set to the zero address.
NOTE: This function is not virtual, {_update} should be overridden instead.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L127-L1

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

// @audit the @param owner is missing
// @audit the @param spender is missing
// @audit the @param value is missing

@dev Not allowed


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L141-L1

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

// @audit the @param owner is missing
// @audit the @param spender is missing
// @audit the @param value is missing
// @audit the @param emitEvent is missing

@dev Not allowed


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L148-L1

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

// @audit the @param owner is missing
// @audit the @param spender is missing
// @audit the @param value is missing

@dev Not allowed


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L155-L1

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

// @audit the @param  is missing

@notice Set the creators address to pay the creatorRate to. Can be a contract.
@dev Only callable by the owner.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L309-L1

```solidity

File: packages/revolution/src/AuctionHouse.sol

// @audit the @param _timeBuffer is missing

@notice Set the auction time buffer.
@dev Only callable by the owner.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L277-L1

```solidity

File: packages/revolution/src/AuctionHouse.sol

// @audit the @param _reservePrice is missing

@notice Set the auction reserve price.
@dev Only callable by the owner.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L287-L1

```solidity

File: packages/revolution/src/AuctionHouse.sol

// @audit the @param _minBidIncrementPercentage is missing

@notice Set the auction minimum bid increment percentage.
@dev Only callable by the owner.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L297-L1

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit the @param newContractURIHash is missing

@notice Set the _contractURIHash.
@dev Only callable by the owner.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L169-L1

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit the @param verbId is missing

@notice Burn a verb.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L184-L1

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit the @param tokenId is missing

@notice A distinct Uniform Resource Identifier (URI) for a given asset.
@dev See {IERC721Metadata-tokenURI}.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L193-L1

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit the @param tokenId is missing

@notice Similar to `tokenURI`, but always serves a base64 encoded data URI
with the JSON contents directly inlined.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L201-L1

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit the @param  is missing

@notice Set the token minter.
@dev Only callable by the owner when not locked.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L209-L1

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit the @param _descriptor is missing

@notice Set the token URI descriptor.
@dev Only callable by the owner when not locked.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L230-L1

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit the @param _cultureIndex is missing

@notice Set the token CultureIndex.
@dev Only callable by the owner when not locked.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L252-L1

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit the @param to is missing

@notice Mint a Verb with `verbId` to the provided `to` address. Pulls the top voted art piece from the CultureIndex.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L281-L1

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit the @param _newImpl is missing

///
             TOKEN UPGRADE                    ///
                                              ///


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L328-L1
### [N-45]<a name="n-45"></a> Functions which are either private or internal should have a preceding _ in their name
Add a preceding underscore to the function name, take care to refactor where there functions are called

*There are 8 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

78:     function parent(uint256 pos) private pure returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L78-L78

```solidity

File: packages/revolution/src/MaxHeap.sol

86:     function swap(uint256 fpos, uint256 spos) private {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L86-L86

```solidity

File: packages/revolution/src/MaxHeap.sol

94:     function maxHeapify(uint256 pos) internal {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L94-L94

```solidity

File: packages/revolution/src/CultureIndex.sol

159:     function validateMediaType(ArtPieceMetadata calldata metadata) internal pure {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L159-L159

```solidity

File: packages/revolution/src/CultureIndex.sol

179:     function validateCreatorsArray(CreatorBps[] calldata creatorArray) internal pure returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L179-L179

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

86:     function pIntegral(int256 timeSinceStart, int256 sold) internal view returns (int256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L86-L86

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

07:     constructor(
08:         address _protocolRewards,
09:         address _revolutionRewardRecipient
10:     ) payable RewardSplits(_protocolRewards, _revolutionRewardRecipient) {}


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L7-L10

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

29:     constructor(address _protocolRewards, address _revolutionRewardRecipient) payable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L29-L29
### [N-46]<a name="n-46"></a> `public` functions not called by the contract should be declared `external` instead
Contracts [are allowed](https://docs.soliditylang.org/en/latest/contracts.html#function-overriding) to override their parents' functions and change the visibility from `external` to `public`.

*There are 19 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

55:     function initialize(address _initialOwner, address _admin) public initializer {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L55-L55

```solidity

File: packages/revolution/src/MaxHeap.sol

119:     function insert(uint256 itemId, uint256 value) public onlyAdmin {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L119-L119

```solidity

File: packages/revolution/src/MaxHeap.sol

136:     function updateValue(uint256 itemId, uint256 newValue) public onlyAdmin {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L136-L136

```solidity

File: packages/revolution/src/MaxHeap.sol

169:     function getMax() public view returns (uint256, uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L169-L169

```solidity

File: packages/revolution/src/CultureIndex.sol

209:     function createPiece(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L209-L209

```solidity

File: packages/revolution/src/CultureIndex.sol

332:     function vote(uint256 pieceId) public nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L332-L332

```solidity

File: packages/revolution/src/CultureIndex.sol

342:     function voteForMany(uint256[] calldata pieceIds) public nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L342-L342

```solidity

File: packages/revolution/src/CultureIndex.sol

451:     function getPieceById(uint256 pieceId) public view returns (ArtPiece memory) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L451-L451

```solidity

File: packages/revolution/src/CultureIndex.sol

461:     function getVote(uint256 pieceId, address voter) public view returns (Vote memory) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L461-L461

```solidity

File: packages/revolution/src/CultureIndex.sol

509:     function quorumVotes() public view returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L509-L509

```solidity

File: packages/revolution/src/CultureIndex.sol

519:     function dropTopVotedPiece() public nonReentrant returns (ArtPiece memory) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L519-L519

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

134:     function mint(address account, uint256 amount) public onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L134-L134

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

112:     function totalSupply() public view returns (uint) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L112-L112

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

117:     function decimals() public view returns (uint8) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L117-L117

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

122:     function balanceOf(address _owner) public view returns (uint) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L122-L122

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

152:     function buyToken(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L152-L152

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

237:     function buyTokenQuote(uint256 amount) public view returns (int spentY) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L237-L237

```solidity

File: packages/revolution/src/VerbsToken.sol

161:     function contractURI() public view returns (string memory) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L161-L161

```solidity

File: packages/revolution/src/VerbsToken.sol

273:     function getArtPieceById(uint256 verbId) public view returns (ICultureIndex.ArtPiece memory) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L273-L273
### [N-47]<a name="n-47"></a> Redundant inheritance specifier
The contracts below already extend the specified contract, so there is no need to list it in the inheritance list again

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit `Initializable` is already inherited by `ERC20VotesUpgradeable` 
29: contract NontransferableERC20Votes is Initializable, ERC20VotesUpgradeable, Ownable2StepUpgradeable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L29-L29
### [N-48]<a name="n-48"></a> `require()` / `revert()` statements should have descriptive reason strings

*There are 4 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

421:         if (address(this).balance < _amount) revert("Insufficient balance");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L421-L421

```solidity

File: packages/revolution/src/AuctionHouse.sol

441:             if (!wethSuccess) revert("WETH transfer failed");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L441-L441

```solidity

File: packages/revolution/src/VerbsToken.sol

317:             revert("dropTopVotedPiece failed");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L317-L317

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

30:         if (_protocolRewards == address(0) || _revolutionRewardRecipient == address(0)) revert("Invalid Address Zero");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L30-L30
### [N-49]<a name="n-49"></a> Setters should prevent re-setting of the same value
This especially problematic when the setter also emits the same value, which may be confusing to offline parsers

*There are 13 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `quorumVotesBPS` and `newQuorumVotesBPS` are never checked for the same value setting
498:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {
499:         require(newQuorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "CultureIndex::_setQuorumVotesBPS: invalid quorum bps");
500:         emit QuorumVotesBPSSet(quorumVotesBPS, newQuorumVotesBPS);
501: 
502:         quorumVotesBPS = newQuorumVotesBPS;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L498-L502

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `entropyRateBps` and `_entropyRateBps` are never checked for the same value setting
288:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {
289:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");
290: 
291:         emit EntropyRateBpsUpdated(entropyRateBps = _entropyRateBps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L288-L291

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `creatorRateBps` and `_creatorRateBps` are never checked for the same value setting
299:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {
300:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");
301: 
302:         emit CreatorRateBpsUpdated(creatorRateBps = _creatorRateBps);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L299-L302

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `creatorsAddress` and `_creatorsAddress` are never checked for the same value setting
309:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {
310:         require(_creatorsAddress != address(0), "Invalid address");
311: 
312:         emit CreatorsAddressUpdated(creatorsAddress = _creatorsAddress);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L309-L312

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `creatorRateBps` and `_creatorRateBps` are never checked for the same value setting
217:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {
218:         require(
219:             _creatorRateBps >= minCreatorRateBps,
220:             "Creator rate must be greater than or equal to minCreatorRateBps"
221:         );
222:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");
223:         creatorRateBps = _creatorRateBps;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L217-L223

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `entropyRateBps` and `_entropyRateBps` are never checked for the same value setting
253:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {
254:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");
255: 
256:         entropyRateBps = _entropyRateBps;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L253-L256

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `timeBuffer` and `_timeBuffer` are never checked for the same value setting
277:     function setTimeBuffer(uint256 _timeBuffer) external override onlyOwner {
278:         timeBuffer = _timeBuffer;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L277-L278

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `reservePrice` and `_reservePrice` are never checked for the same value setting
287:     function setReservePrice(uint256 _reservePrice) external override onlyOwner {
288:         reservePrice = _reservePrice;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L287-L288

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `minBidIncrementPercentage` and `_minBidIncrementPercentage` are never checked for the same value setting
297:     function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {
298:         minBidIncrementPercentage = _minBidIncrementPercentage;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L297-L298

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit `_contractURIHash` and `newContractURIHash` are never checked for the same value setting
169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {
170:         _contractURIHash = newContractURIHash;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L169-L170

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit `minter` and `_minter` are never checked for the same value setting
209:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {
210:         require(_minter != address(0), "Minter cannot be zero address");
211:         minter = _minter;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L209-L211

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit `descriptor` and `_descriptor` are never checked for the same value setting
230:     function setDescriptor(
231:         IDescriptorMinimal _descriptor
232:     ) external override onlyOwner nonReentrant whenDescriptorNotLocked {
233:         descriptor = _descriptor;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L230-L233

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit `cultureIndex` and `_cultureIndex` are never checked for the same value setting
252:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {
253:         cultureIndex = _cultureIndex;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L252-L253
### [N-50]<a name="n-50"></a> NatSpec `@return` argument is missing

*There are 11 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

// @audit the @return is missing
@notice Utility function to verify a signature for a specific vote
@param from Vote from this address
@param pieceIds Vote on this pieceId
@param deadline Deadline for the signature to be valid
@param v V component of signature
@param r R component of signature
@param s S component of signature


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L419-L1

```solidity

File: packages/revolution/src/CultureIndex.sol

// @audit the @return is missing
@notice Current quorum votes using ERC721 Total Supply, ERC721 Vote Weight, and ERC20 Total Supply
Differs from `GovernerBravo` which uses fixed amount


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L509-L1

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

// @audit the @return is missing
@dev Returns the number of decimals used to get its user representation.
For example, if `decimals` equals `2`, a balance of `505` tokens should
be displayed to a user as `5.05` (`505 / 10 ** 2`).
Tokens usually opt for a value of 18, imitating the relationship between
Ether and Wei. This is the default value returned by this function, unless
it's overridden.
NOTE: This information is only used for _display_ purposes: it in
no way affects any of the arithmetic of the contract, including
{IERC20-balanceOf} and {IERC20-transfer}.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L87-L1

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

// @audit the @return is missing
@dev Not allowed


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L94-L1

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

// @audit the @return is missing
@dev Not allowed


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L108-L1

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

// @audit the @return is missing
@dev Not allowed


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L115-L1

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit the @return is missing
@notice The IPFS URI of contract-level metadata.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L161-L1

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit the @return is missing
@notice Mint a Verb to the minter.
@dev Call _mintTo with the to address(es).


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L177-L1

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit the @return is missing
@notice A distinct Uniform Resource Identifier (URI) for a given asset.
@dev See {IERC721Metadata-tokenURI}.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L193-L1

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit the @return is missing
@notice Similar to `tokenURI`, but always serves a base64 encoded data URI
with the JSON contents directly inlined.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L201-L1

```solidity

File: packages/revolution/src/VerbsToken.sol

// @audit the @return is missing
@notice Mint a Verb with `verbId` to the provided `to` address. Pulls the top voted art piece from the CultureIndex.


```


   *GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L281-L1
### [N-51]<a name="n-51"></a> Consider using `SafeTransferLib.safeTransferETH()` or `Address.sendValue()` for clearer semantic meaning
These Functions indicate their purpose with their name more clearly than using low-level calls.

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

191:         (bool success, ) = treasury.call{ value: toPayTreasury }(new bytes(0));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L191-L191

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

196:             (success, ) = creatorsAddress.call{ value: creatorDirectPayment }(new bytes(0));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L196-L196
### [N-52]<a name="n-52"></a> Large multiples of ten should use scientific notation (e.g. `1e6`) rather than decimal literals (e.g. `1000000`), for readability
While the compiler knows to optimize away the exponentiation, it's still better coding practice to use idioms that do not require compiler optimization, if they exist

*There are 27 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `10_000`
512:             10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L512-L512

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `10_000`
190:         require(totalBps == 10_000, "Total BPS must sum up to 10,000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L190-L190

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `10_000`
234:         newPiece.quorumVotes = (quorumVotesBPS * newPiece.totalVotesSupply) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L234-L234

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `10_000`
173:         uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L173-L173

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `10_000`
177:         uint256 creatorDirectPayment = ((msgValueRemaining - toPayTreasury) * entropyRateBps) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L177-L177

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `10_000`
217:         require(bpsSum == 10_000, "bps must add up to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L217-L217

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `10_000`
289:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L289-L289

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `10_000`
300:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L300-L300

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `10_000`
279:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L279-L279

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `10_000`
173:         uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L173-L173

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `10_000`
212:                 _mint(addresses[i], uint256((totalTokensForBuyers * int(basisPointSplits[i])) / 10_000));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L212-L212

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `10_000`
279:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L279-L279

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `10_000`
222:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L222-L222

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `10_000`
235:         require(_minCreatorRateBps <= 10_000, "Min creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L235-L235

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `10_000`
254:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L254-L254

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `10_000`
365:                 uint256 auctioneerPayment = (_auction.amount * (10_000 - creatorRateBps)) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L365-L365

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `10_000`
365:                 uint256 auctioneerPayment = (_auction.amount * (10_000 - creatorRateBps)) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L365-L365

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `10_000`
390:                         uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L390-L390

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `10_000`
390:                         uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L390-L390

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit `10_000`
51:             10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L51-L51

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit `10_000`
49:             10_000 +


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L49-L49

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit `10_000`
57:                 builderReferralReward: (paymentAmountWei * BUILDER_REWARD_BPS) / 10_000,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L57-L57

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit `10_000`
58:                 purchaseReferralReward: (paymentAmountWei * PURCHASE_REFERRAL_BPS) / 10_000,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L58-L58

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit `10_000`
59:                 deployerReward: (paymentAmountWei * DEPLOYER_REWARD_BPS) / 10_000,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L59-L59

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit `10_000`
60:                 revolutionReward: (paymentAmountWei * REVOLUTION_REWARD_BPS) / 10_000


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L60-L60

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit `10_000`
45:             10_000 +


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L45-L45

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit `10_000`
47:             10_000 +


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L47-L47
### [N-53]<a name="n-53"></a> Consider moving `msg.sender` checks to a common authorization `modifier`

*There are 7 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

56:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L56-L56

```solidity

File: packages/revolution/src/CultureIndex.sol

117:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L117-L117

```solidity

File: packages/revolution/src/CultureIndex.sol

520:         require(msg.sender == dropperAdmin, "Only dropper can drop pieces");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L520-L520

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

69:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L69-L69

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

91:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L91-L91

```solidity

File: packages/revolution/src/AuctionHouse.sol

120:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L120-L120

```solidity

File: packages/revolution/src/VerbsToken.sol

137:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L137-L137
### [N-54]<a name="n-54"></a> State variables should have `Natspec` comments
Consider adding some `Natspec` comments on critical state variables to explain what they are supposed to do: this will help for future code reviews.

*There are 51 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit size need comments
67:     uint256 public size = 0;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L67-L67

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit maxHeap need comments
36:     MaxHeap public maxHeap;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L36-L36

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit erc20VotingToken need comments
39:     ERC20VotesUpgradeable public erc20VotingToken;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L39-L39

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit erc721VotingToken need comments
42:     ERC721CheckpointableUpgradeable public erc721VotingToken;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L42-L42

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit erc721VotingTokenWeight need comments
45:     uint256 public erc721VotingTokenWeight;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L45-L45

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit pieces need comments
63:     mapping(uint256 => ArtPiece) public pieces;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L63-L63

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit _currentPieceId need comments
66:     uint256 public _currentPieceId;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L66-L66

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit votes need comments
69:     mapping(uint256 => mapping(address => Vote)) public votes;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L69-L69

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit totalVoteWeights need comments
72:     mapping(uint256 => uint256) public totalVoteWeights;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L72-L72

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit MAX_NUM_CREATORS need comments
75:     uint256 public constant MAX_NUM_CREATORS = 100;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L75-L75

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit dropperAdmin need comments
78:     address public dropperAdmin;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L78-L78

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit treasury need comments
25:     address public treasury;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L25-L25

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit token need comments
28:     NontransferableERC20Votes public token;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L28-L28

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit vrgdac need comments
31:     VRGDAC public vrgdac;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L31-L31

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit startTime need comments
34:     uint256 public startTime;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L34-L34

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit creatorRateBps need comments
42:     uint256 public creatorRateBps;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L42-L42

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit entropyRateBps need comments
45:     uint256 public entropyRateBps;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L45-L45

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit creatorsAddress need comments
48:     address public creatorsAddress;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L48-L48

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit verbs need comments
48:     IVerbsToken public verbs;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L48-L48

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit erc20TokenEmitter need comments
51:     IERC20TokenEmitter public erc20TokenEmitter;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L51-L51

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit WETH need comments
54:     address public WETH;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L54-L54

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit timeBuffer need comments
57:     uint256 public timeBuffer;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L57-L57

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit reservePrice need comments
60:     uint256 public reservePrice;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L60-L60

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit minBidIncrementPercentage need comments
63:     uint8 public minBidIncrementPercentage;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L63-L63

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit creatorRateBps need comments
66:     uint256 public creatorRateBps;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L66-L66

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit minCreatorRateBps need comments
69:     uint256 public minCreatorRateBps;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L69-L69

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit entropyRateBps need comments
72:     uint256 public entropyRateBps;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L72-L72

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit duration need comments
75:     uint256 public duration;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L75-L75

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit auction need comments
78:     IAuctionHouse.Auction public auction;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L78-L78

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit MIN_TOKEN_MINT_GAS_THRESHOLD need comments
88:     uint32 public constant MIN_TOKEN_MINT_GAS_THRESHOLD = 750_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L88-L88

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit minter need comments
42:     address public minter;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L42-L42

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit descriptor need comments
45:     IDescriptorMinimal public descriptor;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L45-L45

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit cultureIndex need comments
48:     ICultureIndex public cultureIndex;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L48-L48

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit isMinterLocked need comments
51:     bool public isMinterLocked;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L51-L51

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit isCultureIndexLocked need comments
54:     bool public isCultureIndexLocked;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L54-L54

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit isDescriptorLocked need comments
57:     bool public isDescriptorLocked;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L57-L57

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit _currentVerbId need comments
60:     uint256 private _currentVerbId;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L60-L60

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit _contractURIHash need comments
63:     string private _contractURIHash = "QmQzDwaZ7yQxHHs7sQQenJVB89riTSacSGcJRv9jtHPuz5";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L63-L63

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit artPieces need comments
66:     mapping(uint256 => ICultureIndex.ArtPiece) public artPieces;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L66-L66

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

//@audit targetPrice need comments
16:     int256 public immutable targetPrice;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L16-L16

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

//@audit perTimeUnit need comments
18:     int256 public immutable perTimeUnit;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L18-L18

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

//@audit decayConstant need comments
20:     int256 public immutable decayConstant;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L20-L20

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

//@audit priceDecayPercent need comments
22:     int256 public immutable priceDecayPercent;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L22-L22

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit DEPLOYER_REWARD_BPS need comments
18:     uint256 internal constant DEPLOYER_REWARD_BPS = 25;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L18-L18

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit REVOLUTION_REWARD_BPS need comments
19:     uint256 internal constant REVOLUTION_REWARD_BPS = 75;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L19-L19

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit BUILDER_REWARD_BPS need comments
20:     uint256 internal constant BUILDER_REWARD_BPS = 100;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L20-L20

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit PURCHASE_REFERRAL_BPS need comments
21:     uint256 internal constant PURCHASE_REFERRAL_BPS = 50;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L21-L21

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit minPurchaseAmount need comments
23:     uint256 public constant minPurchaseAmount = 0.0000001 ether;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L23-L23

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit maxPurchaseAmount need comments
24:     uint256 public constant maxPurchaseAmount = 50_000 ether;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L24-L24

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit revolutionRewardRecipient need comments
26:     address internal immutable revolutionRewardRecipient;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L26-L26

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit protocolRewards need comments
27:     IRevolutionProtocolRewards internal immutable protocolRewards;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L27-L27
### [N-55]<a name="n-55"></a> Contracts should have full test coverage
While 100% code coverage does not guarantee that there are no bugs, it often will catch easy-to-find bugs, and will ensure that there are fewer regressions when the code invariably has to be modified. Furthermore, in order to get full coverage, code authors will often have to re-organize their code so that it is more modular, so that each component can be tested separately, which reduces interdependencies between modules and layers, and makes for code that is easier to reason about and audit.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

@audit Multiple files
1: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L1-L1
### [N-56]<a name="n-56"></a> Contract declarations should have NatSpec `@title` annotations

*There are 7 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

20: contract CultureIndex is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L20-L20

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

29: contract NontransferableERC20Votes is Initializable, ERC20VotesUpgradeable, Ownable2StepUpgradeable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L29-L29

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

17: contract ERC20TokenEmitter is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L17-L17

```solidity

File: packages/revolution/src/AuctionHouse.sol

39: contract AuctionHouse is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L39-L39

```solidity

File: packages/revolution/src/VerbsToken.sol

33: contract VerbsToken is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L33-L33

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

6: abstract contract TokenEmitterRewards is RewardSplits {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L6-L6

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

13: /// @notice Common logic for Revolution ERC20TokenEmitter contracts for protocol reward splits & deposits
14: abstract contract RewardSplits {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L13-L14
### [N-57]<a name="n-57"></a> Open TODOs
TODOs may signal that a feature is missing or not ready for audit, consider resolving the issue and removing the TODO comment

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

321:         // TODO add security consideration here based on block created to prevent flash attacks on drops?


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L321-L321

```solidity

File: packages/revolution/src/AuctionHouse.sol

87:     // TODO investigate this - The minimum gas threshold for creating an auction (minting VerbsToken)


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L87-L87
### [N-58]<a name="n-58"></a> Top level pragma declarations should be separated by two blank lines

*There are 14 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

2: pragma solidity ^0.8.22;
3: 
4: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L2-L4

```solidity

File: packages/revolution/src/CultureIndex.sol

2: pragma solidity ^0.8.22;
3: 
4: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L2-L4

```solidity

File: packages/revolution/src/CultureIndex.sol

18: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
19: 
20: contract CultureIndex is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L18-L20

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

27: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";
28: 
29: contract NontransferableERC20Votes is Initializable, ERC20VotesUpgradeable, Ownable2StepUpgradeable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L27-L29

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

2: pragma solidity ^0.8.22;
3: 
4: import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L2-L4

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

15: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";
16: 
17: contract ERC20TokenEmitter is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L15-L17

```solidity

File: packages/revolution/src/AuctionHouse.sol

24: pragma solidity ^0.8.22;
25: 
26: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L24-L26

```solidity

File: packages/revolution/src/AuctionHouse.sol

37: import { VersionedContract } from "./version/VersionedContract.sol";
38: 
39: contract AuctionHouse is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L37-L39

```solidity

File: packages/revolution/src/VerbsToken.sol

18: pragma solidity ^0.8.22;
19: 
20: import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L18-L20

```solidity

File: packages/revolution/src/VerbsToken.sol

31: import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";
32: 
33: contract VerbsToken is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L31-L33

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

2: pragma solidity 0.8.22;
3: 
4: import { wadExp, wadLn, wadMul, wadDiv, unsafeWadDiv, wadPow } from "./SignedWadMath.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L2-L4

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

2: pragma solidity 0.8.22;
3: 
4: import { RewardSplits } from "../RewardSplits.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L2-L4

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

4: import { RewardSplits } from "../RewardSplits.sol";
5: 
6: abstract contract TokenEmitterRewards is RewardSplits {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L4-L6

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

2: pragma solidity 0.8.22;
3: 
4: import { IRevolutionProtocolRewards } from "../interfaces/IRevolutionProtocolRewards.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L2-L4
### [N-59]<a name="n-59"></a> Critical functions should be a two step procedure
Critical functions in Solidity contracts should follow a two-step procedure to enhance security, minimize human error, and ensure proper access control. By dividing sensitive operations into distinct phases, such as initiation and confirmation, developers can introduce a safeguard against unintended actions or unauthorized access.

*There are 15 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

217:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L217-L217

```solidity

File: packages/revolution/src/AuctionHouse.sol

233:     function setMinCreatorRateBps(uint256 _minCreatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L233-L233

```solidity

File: packages/revolution/src/AuctionHouse.sol

253:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L253-L253

```solidity

File: packages/revolution/src/AuctionHouse.sol

277:     function setTimeBuffer(uint256 _timeBuffer) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L277-L277

```solidity

File: packages/revolution/src/AuctionHouse.sol

287:     function setReservePrice(uint256 _reservePrice) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L287-L287

```solidity

File: packages/revolution/src/AuctionHouse.sol

297:     function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L297-L297

```solidity

File: packages/revolution/src/CultureIndex.sol

498:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L498-L498

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

288:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L288-L288

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

299:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L299-L299

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

309:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L309-L309

```solidity

File: packages/revolution/src/MaxHeap.sol

136:     function updateValue(uint256 itemId, uint256 newValue) public onlyAdmin {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L136-L136

```solidity

File: packages/revolution/src/VerbsToken.sol

169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L169-L169

```solidity

File: packages/revolution/src/VerbsToken.sol

209:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L209-L209

```solidity

File: packages/revolution/src/VerbsToken.sol

230:     function setDescriptor(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L230-L230

```solidity

File: packages/revolution/src/VerbsToken.sol

252:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L252-L252
### [N-60]<a name="n-60"></a> uint variables should have the bit size defined explicitly
Instead of using uint to declare uint258, explicitly define uint258 to ensure there is no confusion

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit ``
112:     function totalSupply() public view returns (uint) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L112-L112

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit ``
122:     function balanceOf(address _owner) public view returns (uint) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L122-L122
### [N-61]<a name="n-61"></a> Uncommented fields in a struct
Consider adding comments for all the fields in a struct to improve the readability of the codebase.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit Add explanational comments to the following items `builderReferralReward`, `purchaseReferralReward`, `deployerReward`, `revolutionReward`, 
06: struct RewardsSettings {
07:     uint256 builderReferralReward;
08:     uint256 purchaseReferralReward;
09:     uint256 deployerReward;
10:     uint256 revolutionReward;
11: }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L6-L11
### [N-62]<a name="n-62"></a> Unused Import
Some files/Items are imported but never used

*There are 5 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `Strings` is not used
18: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L18-L18

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit `PausableUpgradeable` is not used
21: import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L21-L21

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit `EIP712Upgradeable` is not used
25: import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L25-L25

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `Strings` is not used
11: import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L11-L11

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit `IERC721` is not used
22: import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L22-L22
### [N-63]<a name="n-63"></a> Unused parameter

*There are 6 instance(s) of this issue:*

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit `from` is not used
101:     function _transfer(address from, address to, uint256 value) internal override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L101-L101

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit `to` is not used
101:     function _transfer(address from, address to, uint256 value) internal override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L101-L101

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit `value` is not used
101:     function _transfer(address from, address to, uint256 value) internal override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L101-L101

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit `owner` is not used
141:     function _approve(address owner, address spender, uint256 value) internal override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L141-L141

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit `spender` is not used
141:     function _approve(address owner, address spender, uint256 value) internal override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L141-L141

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit `value` is not used
141:     function _approve(address owner, address spender, uint256 value) internal override {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L141-L141
### [N-64]<a name="n-64"></a> Use `string.concat()` on strings instead of `abi.encodePacked()` for clearer semantic meaning
Starting with version 0.8.12, Solidity has the `string.concat()` function, which allows one to concatenate a list of strings, without extra padding. Using this function rather than `abi.encodePacked()` makes the intended operation more clear, leading to less reviewer confusion.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/VerbsToken.sol

162:         return string(abi.encodePacked("ipfs://", _contractURIHash));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L162-L162
### [N-65]<a name="n-65"></a> Constants should be defined rather than using magic numbers
Even [assembly](https://github.com/code-423n4/2022-05-opensea-seaport/blob/9d7ce4d08bf3c3010304a0476a785c70c0e90ae7/contracts/lib/TokenTransferrer.sol#L35-L39) can benefit from using readable constants instead of hex/numeric literals

*There are 30 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit Try to make a `constant` with `5` value
160:         require(uint8(metadata.mediaType) > 0 && uint8(metadata.mediaType) <= 5, "Invalid media type");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L160-L160

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit Try to make a `constant` with `10_000` value
190:         require(totalBps == 10_000, "Total BPS must sum up to 10,000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L190-L190

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit Try to make a `constant` with `10_000` value
234:         newPiece.quorumVotes = (quorumVotesBPS * newPiece.totalVotesSupply) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L234-L234

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit Try to make a `constant` with `10_000` value
512:             10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L512-L512

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit Try to make a `constant` with `18` value
88:         return 18;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L88-L88

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit Try to make a `constant` with `10_000` value
173:         uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L173-L173

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit Try to make a `constant` with `10_000` value
177:         uint256 creatorDirectPayment = ((msgValueRemaining - toPayTreasury) * entropyRateBps) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L177-L177

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit Try to make a `constant` with `10_000` value
217:         require(bpsSum == 10_000, "bps must add up to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L217-L217

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit Try to make a `constant` with `10_000` value
173:         uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L173-L173

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit Try to make a `constant` with `10_000` value
212:                 _mint(addresses[i], uint256((totalTokensForBuyers * int(basisPointSplits[i])) / 10_000));


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L212-L212

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit Try to make a `constant` with `10_000` value
279:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L279-L279

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit Try to make a `constant` with `10_000` value
279:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L279-L279

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit Try to make a `constant` with `10_000` value
289:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L289-L289

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit Try to make a `constant` with `10_000` value
300:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L300-L300

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit Try to make a `constant` with `100` value
181:             msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100),


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L181-L181

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit Try to make a `constant` with `10_000` value
222:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L222-L222

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit Try to make a `constant` with `10_000` value
235:         require(_minCreatorRateBps <= 10_000, "Min creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L235-L235

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit Try to make a `constant` with `10_000` value
254:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L254-L254

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit Try to make a `constant` with `10_000` value
365:                 uint256 auctioneerPayment = (_auction.amount * (10_000 - creatorRateBps)) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L365-L365

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit Try to make a `constant` with `10_000` value
365:                 uint256 auctioneerPayment = (_auction.amount * (10_000 - creatorRateBps)) / 10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L365-L365

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit Try to make a `constant` with `10_000` value
390:                         uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L390-L390

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit Try to make a `constant` with `10_000` value
390:                         uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L390-L390

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit Try to make a `constant` with `10_000` value
51:             10_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L51-L51

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit Try to make a `constant` with `10_000` value
49:             10_000 +


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L49-L49

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit Try to make a `constant` with `10_000` value
45:             10_000 +


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L45-L45

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit Try to make a `constant` with `10_000` value
47:             10_000 +


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L47-L47

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit Try to make a `constant` with `10_000` value
57:                 builderReferralReward: (paymentAmountWei * BUILDER_REWARD_BPS) / 10_000,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L57-L57

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit Try to make a `constant` with `10_000` value
58:                 purchaseReferralReward: (paymentAmountWei * PURCHASE_REFERRAL_BPS) / 10_000,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L58-L58

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit Try to make a `constant` with `10_000` value
59:                 deployerReward: (paymentAmountWei * DEPLOYER_REWARD_BPS) / 10_000,


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L59-L59

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit Try to make a `constant` with `10_000` value
60:                 revolutionReward: (paymentAmountWei * REVOLUTION_REWARD_BPS) / 10_000


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L60-L60
### [N-66]<a name="n-66"></a> Use a single file for system wide constants
Consider grouping all the system constants under a single file. This finding shows only the first constant for each file.

*There are 3 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

29:     bytes32 public constant VOTE_TYPEHASH =


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L29-L29

```solidity

File: packages/revolution/src/AuctionHouse.sol

88:     uint32 public constant MIN_TOKEN_MINT_GAS_THRESHOLD = 750_000;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L88-L88

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

18:     uint256 internal constant DEPLOYER_REWARD_BPS = 25;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L18-L18
### [N-67]<a name="n-67"></a> Consider using SMTChecker
The SMTChecker is a valuable tool for Solidity developers as it helps detect potential vulnerabilities and logical errors in the contract's code. By utilizing Satisfiability Modulo Theories (SMT) solvers, it can reason about the potential states a contract can be in, and therefore, identify conditions that could lead to undesirable behavior. This automatic formal verification can catch issues that might otherwise be missed in manual code reviews or standard testing, enhancing the overall contract's security and reliability.

*There are 9 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

2: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L2-L2

```solidity

File: packages/revolution/src/CultureIndex.sol

2: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L2-L2

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

4: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L4-L4

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

2: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L2-L2

```solidity

File: packages/revolution/src/AuctionHouse.sol

24: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L24-L24

```solidity

File: packages/revolution/src/VerbsToken.sol

18: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L18-L18

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

2: pragma solidity 0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L2-L2

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

2: pragma solidity 0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L2-L2

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

2: pragma solidity 0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L2-L2
### [N-68]<a name="n-68"></a> Whitespace in Expressions
See the [Whitespace in Expressions](https://docs.soliditylang.org/en/latest/style-guide.html#whitespace-in-expressions) section of the Solidity Style Guide

*There are 3 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit remove the whiteSpace before the ')' char
489:         (uint256 pieceId, ) = maxHeap.getMax();
490:         return pieceId;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L489-L490

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit remove the whiteSpace before the ')' char
191:         (bool success, ) = treasury.call{ value: toPayTreasury }(new bytes(0));
192:         require(success, "Transfer failed.");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L191-L192

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit remove the whiteSpace before the ')' char
196:             (success, ) = creatorsAddress.call{ value: creatorDirectPayment }(new bytes(0));
197:             require(success, "Transfer failed.");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L196-L197
### [N-69]<a name="n-69"></a> Complex function controle flow
Due to multiple if, loop and conditions the following functions has a very complex controle flow that could make auditing very difficult to cover all possible path
Therefore, consider breaking down these blocks into more manageable units, by splitting things into utility functions, by reducing nesting, and by using early returns

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

152:     function buyToken(
153:         address[] calldata addresses,
154:         uint[] calldata basisPointSplits,
155:         ProtocolRewardAddresses calldata protocolRewardsRecipients
156:     ) public payable nonReentrant whenNotPaused returns (uint256 tokensSoldWad) {
157:         //prevent treasury from paying itself
158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");
159: 
160:         require(msg.value > 0, "Must send ether");
161:         // ensure the same number of addresses and bps
162:         require(addresses.length == basisPointSplits.length, "Parallel arrays required");
163: 
164:         // Get value left after protocol rewards
165:         uint256 msgValueRemaining = _handleRewardsAndGetValueToSend(
166:             msg.value,
167:             protocolRewardsRecipients.builder,
168:             protocolRewardsRecipients.purchaseReferral,
169:             protocolRewardsRecipients.deployer
170:         );
171: 
172:         //Share of purchase amount to send to treasury
173:         uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;
174: 
175:         //Share of purchase amount to reserve for creators
176:         //Ether directly sent to creators
177:         uint256 creatorDirectPayment = ((msgValueRemaining - toPayTreasury) * entropyRateBps) / 10_000;
178:         //Tokens to emit to creators
179:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0
180:             ? getTokenQuoteForEther((msgValueRemaining - toPayTreasury) - creatorDirectPayment)
181:             : int(0);
182: 
183:         // Tokens to emit to buyers
184:         int totalTokensForBuyers = toPayTreasury > 0 ? getTokenQuoteForEther(toPayTreasury) : int(0);
185: 
186:         //Transfer ETH to treasury and update emitted
187:         emittedTokenWad += totalTokensForBuyers;
188:         if (totalTokensForCreators > 0) emittedTokenWad += totalTokensForCreators;
189: 
190:         //Deposit funds to treasury
191:         (bool success, ) = treasury.call{ value: toPayTreasury }(new bytes(0));
192:         require(success, "Transfer failed.");
193: 
194:         //Transfer ETH to creators
195:         if (creatorDirectPayment > 0) {
196:             (success, ) = creatorsAddress.call{ value: creatorDirectPayment }(new bytes(0));
197:             require(success, "Transfer failed.");
198:         }
199: 
200:         //Mint tokens for creators
201:         if (totalTokensForCreators > 0 && creatorsAddress != address(0)) {
202:             _mint(creatorsAddress, uint256(totalTokensForCreators));
203:         }
204: 
205:         uint256 bpsSum = 0;
206: 
207:         //Mint tokens to buyers
208: 
209:         for (uint256 i = 0; i < addresses.length; i++) {
210:             if (totalTokensForBuyers > 0) {
211:                 // transfer tokens to address
212:                 _mint(addresses[i], uint256((totalTokensForBuyers * int(basisPointSplits[i])) / 10_000));
213:             }
214:             bpsSum += basisPointSplits[i];
215:         }
216: 
217:         require(bpsSum == 10_000, "bps must add up to 10_000");
218: 
219:         emit PurchaseFinalized(
220:             msg.sender,
221:             msg.value,
222:             toPayTreasury,
223:             msg.value - msgValueRemaining,
224:             uint256(totalTokensForBuyers),
225:             uint256(totalTokensForCreators),
226:             creatorDirectPayment
227:         );
228: 
229:         return uint256(totalTokensForBuyers);
230:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L152-L230

```solidity

File: packages/revolution/src/AuctionHouse.sol

336:     function _settleAuction() internal {
337:         IAuctionHouse.Auction memory _auction = auction;
338: 
339:         require(_auction.startTime != 0, "Auction hasn't begun");
340:         require(!_auction.settled, "Auction has already been settled");
341:         //slither-disable-next-line timestamp
342:         require(block.timestamp >= _auction.endTime, "Auction hasn't completed");
343: 
344:         auction.settled = true;
345: 
346:         uint256 creatorTokensEmitted = 0;
347:         // Check if contract balance is greater than reserve price
348:         if (address(this).balance < reservePrice) {
349:             // If contract balance is less than reserve price, refund to the last bidder
350:             if (_auction.bidder != address(0)) {
351:                 _safeTransferETHWithFallback(_auction.bidder, _auction.amount);
352:             }
353: 
354:             // And then burn the Noun
355:             verbs.burn(_auction.verbId);
356:         } else {
357:             //If no one has bid, burn the Verb
358:             if (_auction.bidder == address(0))
359:                 verbs.burn(_auction.verbId);
360:                 //If someone has bid, transfer the Verb to the winning bidder
361:             else verbs.transferFrom(address(this), _auction.bidder, _auction.verbId);
362: 
363:             if (_auction.amount > 0) {
364:                 // Ether going to owner of the auction
365:                 uint256 auctioneerPayment = (_auction.amount * (10_000 - creatorRateBps)) / 10_000;
366: 
367:                 //Total amount of ether going to creator
368:                 uint256 creatorsShare = _auction.amount - auctioneerPayment;
369: 
370:                 uint256 numCreators = verbs.getArtPieceById(_auction.verbId).creators.length;
371:                 address deployer = verbs.getArtPieceById(_auction.verbId).sponsor;
372: 
373:                 //Build arrays for erc20TokenEmitter.buyToken
374:                 uint256[] memory vrgdaSplits = new uint256[](numCreators);
375:                 address[] memory vrgdaReceivers = new address[](numCreators);
376: 
377:                 //Transfer auction amount to the DAO treasury
378:                 _safeTransferETHWithFallback(owner(), auctioneerPayment);
379: 
380:                 uint256 ethPaidToCreators = 0;
381: 
382:                 //Transfer creator's share to the creator, for each creator, and build arrays for erc20TokenEmitter.buyToken
383:                 if (creatorsShare > 0 && entropyRateBps > 0) {
384:                     for (uint256 i = 0; i < numCreators; i++) {
385:                         ICultureIndex.CreatorBps memory creator = verbs.getArtPieceById(_auction.verbId).creators[i];
386:                         vrgdaReceivers[i] = creator.creator;
387:                         vrgdaSplits[i] = creator.bps;
388: 
389:                         //Calculate paymentAmount for specific creator based on BPS splits - same as multiplying by creatorDirectPayment
390:                         uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);
391:                         ethPaidToCreators += paymentAmount;
392: 
393:                         //Transfer creator's share to the creator
394:                         _safeTransferETHWithFallback(creator.creator, paymentAmount);
395:                     }
396:                 }
397: 
398:                 //Buy token from ERC20TokenEmitter for all the creators
399:                 if (creatorsShare > ethPaidToCreators) {
400:                     creatorTokensEmitted = erc20TokenEmitter.buyToken{ value: creatorsShare - ethPaidToCreators }(
401:                         vrgdaReceivers,
402:                         vrgdaSplits,
403:                         IERC20TokenEmitter.ProtocolRewardAddresses({
404:                             builder: address(0),
405:                             purchaseReferral: address(0),
406:                             deployer: deployer
407:                         })
408:                     );
409:                 }
410:             }
411:         }
412: 
413:         emit AuctionSettled(_auction.verbId, _auction.bidder, _auction.amount, creatorTokensEmitted);
414:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L336-L414
### [N-70]<a name="n-70"></a> Consider bounding input array length
The functions below take in an unbounded array, and make function calls for entries in the array. While the function will revert if it eventually runs out of gas, it may be a nicer user experience to `require()` that the length of the array is below some reasonable maximum, so that the user doesn't have to use up a full transaction's gas only to see that the transaction reverts.

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit array name creatorArray
209:     function createPiece(
210:         ArtPieceMetadata calldata metadata,
211:         CreatorBps[] calldata creatorArray
212:     ) public returns (uint256) {
213:         uint256 creatorArrayLength = validateCreatorsArray(creatorArray);
214: 
215:         // Validate the media type and associated data
216:         validateMediaType(metadata);
217: 
218:         uint256 pieceId = _currentPieceId++;
219: 
220:         /// @dev Insert the new piece into the max heap
221:         maxHeap.insert(pieceId, 0);
222: 
223:         ArtPiece storage newPiece = pieces[pieceId];
224: 
225:         newPiece.pieceId = pieceId;
226:         newPiece.totalVotesSupply = _calculateVoteWeight(
227:             erc20VotingToken.totalSupply(),
228:             erc721VotingToken.totalSupply()
229:         );
230:         newPiece.totalERC20Supply = erc20VotingToken.totalSupply();
231:         newPiece.metadata = metadata;
232:         newPiece.sponsor = msg.sender;
233:         newPiece.creationBlock = block.number;
234:         newPiece.quorumVotes = (quorumVotesBPS * newPiece.totalVotesSupply) / 10_000;
235: 
236:         for (uint i; i < creatorArrayLength; i++) {
237:             newPiece.creators.push(creatorArray[i]);
238:         }
239: 
240:         emit PieceCreated(pieceId, msg.sender, metadata, newPiece.quorumVotes, newPiece.totalVotesSupply);
241: 
242:         // Emit an event for each creator
243:         for (uint i; i < creatorArrayLength; i++) {
244:             emit PieceCreatorAdded(pieceId, creatorArray[i].creator, msg.sender, creatorArray[i].bps);
245:         }
246: 
247:         return newPiece.pieceId;
248:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L209-L248

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit array name from
389:     function batchVoteForManyWithSig(
390:         address[] memory from,
391:         uint256[][] calldata pieceIds,
392:         uint256[] memory deadline,
393:         uint8[] memory v,
394:         bytes32[] memory r,
395:         bytes32[] memory s
396:     ) external nonReentrant {
397:         uint256 len = from.length;
398:         require(
399:             len == pieceIds.length && len == deadline.length && len == v.length && len == r.length && len == s.length,
400:             "Array lengths must match"
401:         );
402: 
403:         for (uint256 i; i < len; i++) {
404:             if (!_verifyVoteSignature(from[i], pieceIds[i], deadline[i], v[i], r[i], s[i])) revert INVALID_SIGNATURE();
405:         }
406: 
407:         for (uint256 i; i < len; i++) {
408:             _voteForMany(pieceIds[i], from[i]);
409:         }
410:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L389-L410
### [N-71]<a name="n-71"></a> A function which defines named returns in it's declaration doesn't need to use return
Remove the return statement once ensuring it is safe to do so

*There are 5 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

419:     function _verifyVoteSignature(
420:         address from,
421:         uint256[] calldata pieceIds,
422:         uint256 deadline,
423:         uint8 v,
424:         bytes32 r,
425:         bytes32 s
426:     ) internal returns (bool success) {
427:         require(deadline >= block.timestamp, "Signature expired");
428: 
429:         bytes32 voteHash;
430: 
431:         voteHash = keccak256(abi.encode(VOTE_TYPEHASH, from, pieceIds, nonces[from]++, deadline));
432: 
433:         bytes32 digest = _hashTypedDataV4(voteHash);
434: 
435:         address recoveredAddress = ecrecover(digest, v, r, s);
436: 
437:         // Ensure to address is not 0
438:         if (from == address(0)) revert ADDRESS_ZERO();
439: 
440:         // Ensure signature is valid
441:         if (recoveredAddress == address(0) || recoveredAddress != from) revert INVALID_SIGNATURE();
442: 
443:         return true;
444:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L419-L444

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

152:     function buyToken(
153:         address[] calldata addresses,
154:         uint[] calldata basisPointSplits,
155:         ProtocolRewardAddresses calldata protocolRewardsRecipients
156:     ) public payable nonReentrant whenNotPaused returns (uint256 tokensSoldWad) {
157:         //prevent treasury from paying itself
158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");
159: 
160:         require(msg.value > 0, "Must send ether");
161:         // ensure the same number of addresses and bps
162:         require(addresses.length == basisPointSplits.length, "Parallel arrays required");
163: 
164:         // Get value left after protocol rewards
165:         uint256 msgValueRemaining = _handleRewardsAndGetValueToSend(
166:             msg.value,
167:             protocolRewardsRecipients.builder,
168:             protocolRewardsRecipients.purchaseReferral,
169:             protocolRewardsRecipients.deployer
170:         );
171: 
172:         //Share of purchase amount to send to treasury
173:         uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;
174: 
175:         //Share of purchase amount to reserve for creators
176:         //Ether directly sent to creators
177:         uint256 creatorDirectPayment = ((msgValueRemaining - toPayTreasury) * entropyRateBps) / 10_000;
178:         //Tokens to emit to creators
179:         int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0
180:             ? getTokenQuoteForEther((msgValueRemaining - toPayTreasury) - creatorDirectPayment)
181:             : int(0);
182: 
183:         // Tokens to emit to buyers
184:         int totalTokensForBuyers = toPayTreasury > 0 ? getTokenQuoteForEther(toPayTreasury) : int(0);
185: 
186:         //Transfer ETH to treasury and update emitted
187:         emittedTokenWad += totalTokensForBuyers;
188:         if (totalTokensForCreators > 0) emittedTokenWad += totalTokensForCreators;
189: 
190:         //Deposit funds to treasury
191:         (bool success, ) = treasury.call{ value: toPayTreasury }(new bytes(0));
192:         require(success, "Transfer failed.");
193: 
194:         //Transfer ETH to creators
195:         if (creatorDirectPayment > 0) {
196:             (success, ) = creatorsAddress.call{ value: creatorDirectPayment }(new bytes(0));
197:             require(success, "Transfer failed.");
198:         }
199: 
200:         //Mint tokens for creators
201:         if (totalTokensForCreators > 0 && creatorsAddress != address(0)) {
202:             _mint(creatorsAddress, uint256(totalTokensForCreators));
203:         }
204: 
205:         uint256 bpsSum = 0;
206: 
207:         //Mint tokens to buyers
208: 
209:         for (uint256 i = 0; i < addresses.length; i++) {
210:             if (totalTokensForBuyers > 0) {
211:                 // transfer tokens to address
212:                 _mint(addresses[i], uint256((totalTokensForBuyers * int(basisPointSplits[i])) / 10_000));
213:             }
214:             bpsSum += basisPointSplits[i];
215:         }
216: 
217:         require(bpsSum == 10_000, "bps must add up to 10_000");
218: 
219:         emit PurchaseFinalized(
220:             msg.sender,
221:             msg.value,
222:             toPayTreasury,
223:             msg.value - msgValueRemaining,
224:             uint256(totalTokensForBuyers),
225:             uint256(totalTokensForCreators),
226:             creatorDirectPayment
227:         );
228: 
229:         return uint256(totalTokensForBuyers);
230:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L152-L230

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

237:     function buyTokenQuote(uint256 amount) public view returns (int spentY) {
238:         require(amount > 0, "Amount must be greater than 0");
239:         // Note: By using toDaysWadUnsafe(block.timestamp - startTime) we are establishing that 1 "unit of time" is 1 day.
240:         // solhint-disable-next-line not-rely-on-time
241:         return
242:             vrgdac.xToY({
243:                 timeSinceStart: toDaysWadUnsafe(block.timestamp - startTime),
244:                 sold: emittedTokenWad,
245:                 amount: int(amount)
246:             });
247:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L237-L247

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

254:     function getTokenQuoteForEther(uint256 etherAmount) public view returns (int gainedX) {
255:         require(etherAmount > 0, "Ether amount must be greater than 0");
256:         // Note: By using toDaysWadUnsafe(block.timestamp - startTime) we are establishing that 1 "unit of time" is 1 day.
257:         // solhint-disable-next-line not-rely-on-time
258:         return
259:             vrgdac.yToX({
260:                 timeSinceStart: toDaysWadUnsafe(block.timestamp - startTime),
261:                 sold: emittedTokenWad,
262:                 amount: int(etherAmount)
263:             });
264:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L254-L264

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

271:     function getTokenQuoteForPayment(uint256 paymentAmount) external view returns (int gainedX) {
272:         require(paymentAmount > 0, "Payment amount must be greater than 0");
273:         // Note: By using toDaysWadUnsafe(block.timestamp - startTime) we are establishing that 1 "unit of time" is 1 day.
274:         // solhint-disable-next-line not-rely-on-time
275:         return
276:             vrgdac.yToX({
277:                 timeSinceStart: toDaysWadUnsafe(block.timestamp - startTime),
278:                 sold: emittedTokenWad,
279:                 amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)
280:             });
281:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L271-L281
### [N-72]<a name="n-72"></a> `error` declarations should have NatSpec descriptions

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

30:     error TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L30-L30

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

15:     error INVALID_ETH_AMOUNT();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L15-L15
### [N-73]<a name="n-73"></a> Contract declarations should have NatSpec `@dev` annotations

*There are 8 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

20: contract CultureIndex is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L20-L20

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

29: contract NontransferableERC20Votes is Initializable, ERC20VotesUpgradeable, Ownable2StepUpgradeable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L29-L29

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

17: contract ERC20TokenEmitter is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L17-L17

```solidity

File: packages/revolution/src/AuctionHouse.sol

39: contract AuctionHouse is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L39-L39

```solidity

File: packages/revolution/src/VerbsToken.sol

33: contract VerbsToken is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L33-L33

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

06: /// @title Continuous Variable Rate Gradual Dutch Auction
07: /// @author transmissions11 <t11s@paradigm.xyz>
08: /// @author FrankieIsLost <frankie@paradigm.xyz>
09: /// @author Dan Robinson <dan@paradigm.xyz>
10: /// @notice Sell tokens roughly according to an issuance schedule.
11: contract VRGDAC {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L6-L11

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

6: abstract contract TokenEmitterRewards is RewardSplits {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L6-L6

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

13: /// @notice Common logic for Revolution ERC20TokenEmitter contracts for protocol reward splits & deposits
14: abstract contract RewardSplits {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L13-L14
### [N-74]<a name="n-74"></a> Add inline comments for unnamed variables
`function foo(address x, address)` -> `function foo(address x, address /* y */)`

*There are 3 instance(s) of this issue:*

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit parameters 1, need comment
309:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L309-L309

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit parameters 1,2, need comment
171:     function createBid(uint256 verbId, address bidder) external payable override nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L171-L171

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit parameters 1, need comment
209:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L209-L209
### [N-75]<a name="n-75"></a> Contract should expose an `interface`
The `contract`s should expose an `interface` so that other projects can more easily integrate with it, without having to develop their own non-standard variants.

*There are 15 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

119:     function insert(uint256 itemId, uint256 value) public onlyAdmin {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L119-L119

```solidity

File: packages/revolution/src/MaxHeap.sol

136:     function updateValue(uint256 itemId, uint256 newValue) public onlyAdmin {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L136-L136

```solidity

File: packages/revolution/src/MaxHeap.sol

156:     function extractMax() external onlyAdmin returns (uint256, uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L156-L156

```solidity

File: packages/revolution/src/MaxHeap.sol

169:     function getMax() public view returns (uint256, uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L169-L169

```solidity

File: packages/revolution/src/CultureIndex.sol

498:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L498-L498

```solidity

File: packages/revolution/src/CultureIndex.sol

509:     function quorumVotes() public view returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L509-L509

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

237:     function buyTokenQuote(uint256 amount) public view returns (int spentY) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L237-L237

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

254:     function getTokenQuoteForEther(uint256 etherAmount) public view returns (int gainedX) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L254-L254

```solidity

File: packages/revolution/src/VerbsToken.sol

161:     function contractURI() public view returns (string memory) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L161-L161

```solidity

File: packages/revolution/src/VerbsToken.sol

169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L169-L169

```solidity

File: packages/revolution/src/VerbsToken.sol

252:     function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L252-L252

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

47:     function xToY(int256 timeSinceStart, int256 sold, int256 amount) public view virtual returns (int256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L47-L47

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

54:     function yToX(int256 timeSinceStart, int256 sold, int256 amount) public view virtual returns (int256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L54-L54

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

40:     function computeTotalReward(uint256 paymentAmountWei) public pure returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L40-L40

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

54:     function computePurchaseRewards(uint256 paymentAmountWei) public pure returns (RewardsSettings memory, uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L54-L54
### [N-76]<a name="n-76"></a> Contract declarations should have NatSpec `@notice` annotations

*There are 7 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

11: /// @title MaxHeap implementation in Solidity
12: /// @dev This contract implements a Max Heap data structure with basic operations
13: /// @author Written by rocketman and gpt4
14: contract MaxHeap is VersionedContract, UUPS, Ownable2StepUpgradeable, ReentrancyGuardUpgradeable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L11-L14

```solidity

File: packages/revolution/src/CultureIndex.sol

20: contract CultureIndex is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L20-L20

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

29: contract NontransferableERC20Votes is Initializable, ERC20VotesUpgradeable, Ownable2StepUpgradeable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L29-L29

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

17: contract ERC20TokenEmitter is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L17-L17

```solidity

File: packages/revolution/src/AuctionHouse.sol

39: contract AuctionHouse is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L39-L39

```solidity

File: packages/revolution/src/VerbsToken.sol

33: contract VerbsToken is


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L33-L33

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

6: abstract contract TokenEmitterRewards is RewardSplits {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L6-L6
### [N-77]<a name="n-77"></a> `function` names should use lowerCamelCase
Here is an example of camelCase/lowerCamelCase and other types:
'helloWorld' is a CamelCase
'HelloWorld' is Not CamelCase (PascalCase)
'hello_world' is Not CamelCase (snake_case)
[For more details](https://khalilstemmler.com/blogs/camel-case-snake-case-pascal-case/)

*There are 8 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `` is not in CamelCase
30:     constructor(address _manager) payable initializer {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L30-L30

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `` is not in CamelCase
92:     constructor(address _manager) payable initializer {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L92-L92

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `_setQuorumVotesBPS` is not in CamelCase
498:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L498-L498

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit `` is not in CamelCase
44:     constructor(address _manager) payable initializer {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L44-L44

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit `` is not in CamelCase
64:     constructor(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L64-L64

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit `` is not in CamelCase
95:     constructor(address _manager) payable initializer {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L95-L95

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit `` is not in CamelCase
116:     constructor(address _manager) payable initializer {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L116-L116

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

//@audit `` is not in CamelCase
28:     constructor(int256 _targetPrice, int256 _priceDecayPercent, int256 _perTimeUnit) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L28-L28
### [N-78]<a name="n-78"></a> Expressions for constant values should use `immutable` rather than `constant`
While it does not save gas for some simple binary expressions because the compiler knows that developers often make this mistake, it's still best to use the right tool for the task at hand. There is a difference between `constant` variables and `immutable` variables, and they should each be used in their appropriate contexts. `constants` should be used for literal values written into the code, and `immutable` variables should be used for expressions, or values calculated in, or passed into the constructor.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

29:     bytes32 public constant VOTE_TYPEHASH =
30:         keccak256("Vote(address from,uint256[] pieceIds,uint256 nonce,uint256 deadline)");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L29-L30
### [N-79]<a name="n-79"></a> Contract uses both `require()`/`revert()` as well as custom errors
Consider using just one method in a single file. The below instances represents the less used technique

*There are 8 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

183:         if (!manager.isRegisteredUpgrade(_getImplementation(), _newImpl)) revert INVALID_UPGRADE(_newImpl);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L183-L183

```solidity

File: packages/revolution/src/CultureIndex.sol

377:         if (!success) revert INVALID_SIGNATURE();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L377-L377

```solidity

File: packages/revolution/src/CultureIndex.sol

438:         if (from == address(0)) revert ADDRESS_ZERO();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L438-L438

```solidity

File: packages/revolution/src/CultureIndex.sol

441:         if (recoveredAddress == address(0) || recoveredAddress != from) revert INVALID_SIGNATURE();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L441-L441

```solidity

File: packages/revolution/src/CultureIndex.sol

545:         if (!manager.isRegisteredUpgrade(_getImplementation(), _newImpl)) revert INVALID_UPGRADE(_newImpl);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L545-L545

```solidity

File: packages/revolution/src/CultureIndex.sol

404:             if (!_verifyVoteSignature(from[i], pieceIds[i], deadline[i], v[i], r[i], s[i])) revert INVALID_SIGNATURE();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L404-L404

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

69:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L69-L69

```solidity

File: packages/revolution/src/AuctionHouse.sol

454:         if (!manager.isRegisteredUpgrade(_getImplementation(), _newImpl)) revert INVALID_UPGRADE(_newImpl);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L454-L454
### [N-80]<a name="n-80"></a> `immutable` variable names don\'t follow the Solidity style guide
For `immutable` variable names, each word should use all capital letters, with underscores separating each word (CONSTANT_CASE)

*There are 12 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

23:     IRevolutionBuilder private immutable manager;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L23-L23

```solidity

File: packages/revolution/src/CultureIndex.sol

85:     IRevolutionBuilder private immutable manager;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L85-L85

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

37:     IRevolutionBuilder private immutable manager;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L37-L37

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

55:     IRevolutionBuilder private immutable manager;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L55-L55

```solidity

File: packages/revolution/src/AuctionHouse.sol

85:     IRevolutionBuilder public immutable manager;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L85-L85

```solidity

File: packages/revolution/src/VerbsToken.sol

109:     IRevolutionBuilder private immutable manager;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L109-L109

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

16:     int256 public immutable targetPrice;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L16-L16

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

18:     int256 public immutable perTimeUnit;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L18-L18

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

20:     int256 public immutable decayConstant;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L20-L20

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

22:     int256 public immutable priceDecayPercent;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L22-L22

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

26:     address internal immutable revolutionRewardRecipient;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L26-L26

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

27:     IRevolutionProtocolRewards internal immutable protocolRewards;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L27-L27
### [N-81]<a name="n-81"></a> `private`/`public` function name should start with underscore
According to solidity style guide, Private or Public function name should start with underscore.

*There are 8 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `parent` is not in CamelCase
78:     function parent(uint256 pos) private pure returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L78-L78

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `swap` is not in CamelCase
86:     function swap(uint256 fpos, uint256 spos) private {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L86-L86

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit `maxHeapify` is not in CamelCase
94:     function maxHeapify(uint256 pos) internal {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L94-L94

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `validateMediaType` is not in CamelCase
159:     function validateMediaType(ArtPieceMetadata calldata metadata) internal pure {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L159-L159

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit `validateCreatorsArray` is not in CamelCase
179:     function validateCreatorsArray(CreatorBps[] calldata creatorArray) internal pure returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L179-L179

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

//@audit `pIntegral` is not in CamelCase
86:     function pIntegral(int256 timeSinceStart, int256 sold) internal view returns (int256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L86-L86

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

//@audit `` is not in CamelCase
7:     constructor(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L7-L7

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

//@audit `` is not in CamelCase
29:     constructor(address _protocolRewards, address _revolutionRewardRecipient) payable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L29-L29
### [N-82]<a name="n-82"></a> Add inline comments for unnamed parameters
`function func(address a, address)` -> `function func(address a, address /* b */)`

*There are 23 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit parameter number 0 starting from left need inline comment
78:     function parent(uint256 pos) private pure returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L78-L78

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit parameter number 0 starting from left need inline comment
//@audit parameter number 1 starting from left need inline comment
307:     function _vote(uint256 pieceId, address voter) internal {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L307-L307

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit parameter number 2 starting from left need inline comment
419:     function _verifyVoteSignature(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L419-L419

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit parameter number 0 starting from left need inline comment
451:     function getPieceById(uint256 pieceId) public view returns (ArtPiece memory) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L451-L451

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit parameter number 0 starting from left need inline comment
461:     function getVote(uint256 pieceId, address voter) public view returns (Vote memory) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L461-L461

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit parameter number 0 starting from left need inline comment
498:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L498-L498

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit parameter number 0 starting from left need inline comment
//@audit parameter number 1 starting from left need inline comment
94:     function transfer(address, uint256) public virtual override returns (bool) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L94-L94

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit parameter number 0 starting from left need inline comment
//@audit parameter number 1 starting from left need inline comment
//@audit parameter number 2 starting from left need inline comment
108:     function transferFrom(address, address, uint256) public virtual override returns (bool) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L108-L108

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit parameter number 0 starting from left need inline comment
//@audit parameter number 1 starting from left need inline comment
115:     function approve(address, uint256) public virtual override returns (bool) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L115-L115

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit parameter number 0 starting from left need inline comment
237:     function buyTokenQuote(uint256 amount) public view returns (int spentY) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L237-L237

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit parameter number 0 starting from left need inline comment
254:     function getTokenQuoteForEther(uint256 etherAmount) public view returns (int gainedX) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L254-L254

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit parameter number 0 starting from left need inline comment
271:     function getTokenQuoteForPayment(uint256 paymentAmount) external view returns (int gainedX) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L271-L271

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit parameter number 0 starting from left need inline comment
288:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L288-L288

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit parameter number 0 starting from left need inline comment
299:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L299-L299

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit parameter number 0 starting from left need inline comment
309:     function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L309-L309

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit parameter number 3 starting from left need inline comment
113:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L113-L113

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit parameter number 0 starting from left need inline comment
//@audit parameter number 1 starting from left need inline comment
171:     function createBid(uint256 verbId, address bidder) external payable override nonReentrant {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L171-L171

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit parameter number 0 starting from left need inline comment
217:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L217-L217

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit parameter number 0 starting from left need inline comment
233:     function setMinCreatorRateBps(uint256 _minCreatorRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L233-L233

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit parameter number 0 starting from left need inline comment
253:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L253-L253

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit parameter number 0 starting from left need inline comment
//@audit parameter number 1 starting from left need inline comment
130:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L130-L130

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit parameter number 0 starting from left need inline comment
209:     function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L209-L209

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit parameter number 0 starting from left need inline comment
273:     function getArtPieceById(uint256 verbId) public view returns (ICultureIndex.ArtPiece memory) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L273-L273
### [N-83]<a name="n-83"></a> Consider adding formal verification proofs
Consider using formal verification to mathematically prove that your code does what is intended, and does not have any edge cases with unexpected behavior. The solidity compiler itself has this functionality [built in](https://docs.soliditylang.org/en/latest/smtchecker.html#smtchecker-and-formal-verification)

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

@audit Should implement invariant tests
1: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L1-L1
### [N-84]<a name="n-84"></a> Missing zero address check in functions with address parameters
Adding a zero address check for each address type parameter can prevent errors.

*There are 28 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit ,  are not checked
78:     function parent(uint256 pos) private pure returns (uint256) {
79:         require(pos != 0, "Position should not be zero");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L78-L79

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit fpos, spos,  are not checked
86:     function swap(uint256 fpos, uint256 spos) private {
87:         (heap[fpos], heap[spos]) = (heap[spos], heap[fpos]);


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L86-L87

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit itemId, value,  are not checked
119:     function insert(uint256 itemId, uint256 value) public onlyAdmin {
120:         heap[size] = itemId;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L119-L120

```solidity

File: packages/revolution/src/MaxHeap.sol

//@audit itemId,  are not checked
136:     function updateValue(uint256 itemId, uint256 newValue) public onlyAdmin {
137:         uint256 position = positionMapping[itemId];


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L136-L137

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit ,  are not checked
307:     function _vote(uint256 pieceId, address voter) internal {
308:         require(pieceId < _currentPieceId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L307-L308

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit ,  are not checked
419:     function _verifyVoteSignature(
420:         address from,
421:         uint256[] calldata pieceIds,
422:         uint256 deadline,
423:         uint8 v,
424:         bytes32 r,
425:         bytes32 s
426:     ) internal returns (bool success) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L419-L426

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit ,  are not checked
451:     function getPieceById(uint256 pieceId) public view returns (ArtPiece memory) {
452:         require(pieceId < _currentPieceId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L451-L452

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit ,  are not checked
461:     function getVote(uint256 pieceId, address voter) public view returns (Vote memory) {
462:         require(pieceId < _currentPieceId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L461-L462

```solidity

File: packages/revolution/src/CultureIndex.sol

//@audit ,  are not checked
498:     function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {
499:         require(newQuorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "CultureIndex::_setQuorumVotesBPS: invalid quorum bps");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L498-L499

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit ,  are not checked
94:     function transfer(address, uint256) public virtual override returns (bool) {
95:         revert TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L94-L95

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit value,  are not checked
101:     function _transfer(address from, address to, uint256 value) internal override {
102:         revert TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L101-L102

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit ,  are not checked
108:     function transferFrom(address, address, uint256) public virtual override returns (bool) {
109:         revert TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L108-L109

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit ,  are not checked
115:     function approve(address, uint256) public virtual override returns (bool) {
116:         revert TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L115-L116

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit value,  are not checked
141:     function _approve(address owner, address spender, uint256 value) internal override {
142:         revert TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L141-L142

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit value, emitEvent,  are not checked
148:     function _approve(address owner, address spender, uint256 value, bool emitEvent) internal virtual override {
149:         revert TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L148-L149

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

//@audit value,  are not checked
155:     function _spendAllowance(address owner, address spender, uint256 value) internal virtual override {
156:         revert TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L155-L156

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit ,  are not checked
237:     function buyTokenQuote(uint256 amount) public view returns (int spentY) {
238:         require(amount > 0, "Amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L237-L238

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit ,  are not checked
254:     function getTokenQuoteForEther(uint256 etherAmount) public view returns (int gainedX) {
255:         require(etherAmount > 0, "Ether amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L254-L255

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit ,  are not checked
271:     function getTokenQuoteForPayment(uint256 paymentAmount) external view returns (int gainedX) {
272:         require(paymentAmount > 0, "Payment amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L271-L272

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit ,  are not checked
288:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {
289:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L288-L289

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

//@audit ,  are not checked
299:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {
300:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L299-L300

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit ,  are not checked
171:     function createBid(uint256 verbId, address bidder) external payable override nonReentrant {
172:         IAuctionHouse.Auction memory _auction = auction;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L171-L172

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit ,  are not checked
217:     function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {
218:         require(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L217-L218

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit ,  are not checked
233:     function setMinCreatorRateBps(uint256 _minCreatorRateBps) external onlyOwner {
234:         require(_minCreatorRateBps <= creatorRateBps, "Min creator rate must be less than or equal to creator rate");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L233-L234

```solidity

File: packages/revolution/src/AuctionHouse.sol

//@audit ,  are not checked
253:     function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {
254:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L253-L254

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit newContractURIHash,  are not checked
169:     function setContractURIHash(string memory newContractURIHash) external onlyOwner {
170:         _contractURIHash = newContractURIHash;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L169-L170

```solidity

File: packages/revolution/src/VerbsToken.sol

//@audit ,  are not checked
273:     function getArtPieceById(uint256 verbId) public view returns (ICultureIndex.ArtPiece memory) {
274:         require(verbId <= _currentVerbId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L273-L274

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

//@audit _targetPrice, _perTimeUnit,  are not checked
28:     constructor(int256 _targetPrice, int256 _priceDecayPercent, int256 _perTimeUnit) {
29:         targetPrice = _targetPrice;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L28-L29
### [N-85]<a name="n-85"></a> Use a struct to encapsulate multiple function parameters
If a function has too many parameters, replacing them with a struct can improve code readability and maintainability, increase reusability, and reduce the likelihood of errors when passing the parameters.

*There are 4 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

109:     function initialize(
110:         address _erc20VotingToken,
111:         address _erc721VotingToken,
112:         address _initialOwner,
113:         address _maxHeap,
114:         address _dropperAdmin,
115:         IRevolutionBuilder.CultureIndexParams memory _cultureIndexParams
116:     ) external initializer {
117:         require(msg.sender == address(manager), "Only manager can initialize");
118: 
119:         require(_cultureIndexParams.quorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "invalid quorum bps");
120:         require(_cultureIndexParams.erc721VotingTokenWeight > 0, "invalid erc721 voting token weight");
121:         require(_erc721VotingToken != address(0), "invalid erc721 voting token");
122:         require(_erc20VotingToken != address(0), "invalid erc20 voting token");
123: 
124:         // Setup ownable
125:         __Ownable_init(_initialOwner);
126: 
127:         // Initialize EIP-712 support
128:         __EIP712_init(string.concat(_cultureIndexParams.name, " CultureIndex"), "1");
129: 
130:         __ReentrancyGuard_init();
131: 
132:         erc20VotingToken = ERC20VotesUpgradeable(_erc20VotingToken);
133:         erc721VotingToken = ERC721CheckpointableUpgradeable(_erc721VotingToken);
134:         erc721VotingTokenWeight = _cultureIndexParams.erc721VotingTokenWeight;
135:         name = _cultureIndexParams.name;
136:         description = _cultureIndexParams.description;
137:         quorumVotesBPS = _cultureIndexParams.quorumVotesBPS;
138:         minVoteWeight = _cultureIndexParams.minVoteWeight;
139:         dropperAdmin = _dropperAdmin;
140: 
141:         emit QuorumVotesBPSSet(quorumVotesBPS, _cultureIndexParams.quorumVotesBPS);
142: 
143:         // Create maxHeap
144:         maxHeap = MaxHeap(_maxHeap);
145:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L109-L145

```solidity

File: packages/revolution/src/CultureIndex.sol

367:     function voteForManyWithSig(
368:         address from,
369:         uint256[] calldata pieceIds,
370:         uint256 deadline,
371:         uint8 v,
372:         bytes32 r,
373:         bytes32 s
374:     ) external nonReentrant {
375:         bool success = _verifyVoteSignature(from, pieceIds, deadline, v, r, s);
376: 
377:         if (!success) revert INVALID_SIGNATURE();
378: 
379:         _voteForMany(pieceIds, from);
380:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L367-L380

```solidity

File: packages/revolution/src/CultureIndex.sol

389:     function batchVoteForManyWithSig(
390:         address[] memory from,
391:         uint256[][] calldata pieceIds,
392:         uint256[] memory deadline,
393:         uint8[] memory v,
394:         bytes32[] memory r,
395:         bytes32[] memory s
396:     ) external nonReentrant {
397:         uint256 len = from.length;
398:         require(
399:             len == pieceIds.length && len == deadline.length && len == v.length && len == r.length && len == s.length,
400:             "Array lengths must match"
401:         );
402: 
403:         for (uint256 i; i < len; i++) {
404:             if (!_verifyVoteSignature(from[i], pieceIds[i], deadline[i], v[i], r[i], s[i])) revert INVALID_SIGNATURE();
405:         }
406: 
407:         for (uint256 i; i < len; i++) {
408:             _voteForMany(pieceIds[i], from[i]);
409:         }
410:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L389-L410

```solidity

File: packages/revolution/src/CultureIndex.sol

419:     function _verifyVoteSignature(
420:         address from,
421:         uint256[] calldata pieceIds,
422:         uint256 deadline,
423:         uint8 v,
424:         bytes32 r,
425:         bytes32 s
426:     ) internal returns (bool success) {
427:         require(deadline >= block.timestamp, "Signature expired");
428: 
429:         bytes32 voteHash;
430: 
431:         voteHash = keccak256(abi.encode(VOTE_TYPEHASH, from, pieceIds, nonces[from]++, deadline));
432: 
433:         bytes32 digest = _hashTypedDataV4(voteHash);
434: 
435:         address recoveredAddress = ecrecover(digest, v, r, s);
436: 
437:         // Ensure to address is not 0
438:         if (from == address(0)) revert ADDRESS_ZERO();
439: 
440:         // Ensure signature is valid
441:         if (recoveredAddress == address(0) || recoveredAddress != from) revert INVALID_SIGNATURE();
442: 
443:         return true;
444:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L419-L444
### [N-86]<a name="n-86"></a> Missing NatSpec `@notice` from function declaration

*There are 34 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

29:     /// @param _manager The contract upgrade manager address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L29-L29

```solidity

File: packages/revolution/src/CultureIndex.sol

91:     /// @param _manager The contract upgrade manager address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L91-L91

```solidity

File: packages/revolution/src/CultureIndex.sol

151:     /**
152:      *  Validates the media type and associated data.
153:      * @param metadata The metadata associated with the art piece.
154:      *
155:      * Requirements:
156:      * - The media type must be one of the defined types in the MediaType enum.
157:      * - The corresponding media data must not be empty.
158:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L151-L158

```solidity

File: packages/revolution/src/CultureIndex.sol

288:     function _getVotes(address account) internal view returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L288-L288

```solidity

File: packages/revolution/src/CultureIndex.sol

292:     function _getPastVotes(address account, uint256 blockNumber) internal view returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L292-L292

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

43:     /// @param _manager The contract upgrade manager address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L43-L43

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

48:     ///                                                          ///
49:     ///                         INITIALIZER                      ///
50:     ///                                                          ///
51: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L48-L51

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

74:     /**
75:      * @dev Returns the number of decimals used to get its user representation.
76:      * For example, if `decimals` equals `2`, a balance of `505` tokens should
77:      * be displayed to a user as `5.05` (`505 / 10 ** 2`).
78:      *
79:      * Tokens usually opt for a value of 18, imitating the relationship between
80:      * Ether and Wei. This is the default value returned by this function, unless
81:      * it's overridden.
82:      *
83:      * NOTE: This information is only used for _display_ purposes: it in
84:      * no way affects any of the arithmetic of the contract, including
85:      * {IERC20-balanceOf} and {IERC20-transfer}.
86:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L74-L86

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

91:     /**
92:      * @dev Not allowed
93:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L91-L93

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

098:     /**
099:      * @dev Not allowed
100:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L98-L100

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

105:     /**
106:      * @dev Not allowed
107:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L105-L107

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

112:     /**
113:      * @dev Not allowed
114:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L112-L114

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

119:     /**
120:      * @dev Creates a `value` amount of tokens and assigns them to `account`, by transferring it from address(0).
121:      * Relies on the `_update` mechanism
122:      *
123:      * Emits a {Transfer} event with `from` set to the zero address.
124:      *
125:      * NOTE: This function is not virtual, {_update} should be overridden instead.
126:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L119-L126

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

134:     function mint(address account, uint256 amount) public onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L134-L134

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

138:     /**
139:      * @dev Not allowed
140:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L138-L140

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

145:     /**
146:      * @dev Not allowed
147:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L145-L147

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

152:     /**
153:      * @dev Not allowed
154:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L152-L154

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

61:     /// @param _manager The contract upgrade manager address
62:     /// @param _protocolRewards The protocol rewards contract address
63:     /// @param _protocolFeeRecipient The protocol fee recipient address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L61-L63

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

108:     function _mint(address _to, uint256 _amount) private {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L108-L108

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

112:     function totalSupply() public view returns (uint) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L112-L112

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

117:     function decimals() public view returns (uint8) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L117-L117

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

122:     function balanceOf(address _owner) public view returns (uint) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L122-L122

```solidity

File: packages/revolution/src/AuctionHouse.sol

94:     /// @param _manager The contract upgrade manager address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L94-L94

```solidity

File: packages/revolution/src/VerbsToken.sol

115:     /// @param _manager The contract upgrade manager address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L115-L115

```solidity

File: packages/revolution/src/VerbsToken.sol

321:     ///                                                          ///
322:     ///                         TOKEN UPGRADE                    ///
323:     ///                                                          ///
324: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L321-L324

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

47:     function xToY(int256 timeSinceStart, int256 sold, int256 amount) public view virtual returns (int256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L47-L47

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

54:     function yToX(int256 timeSinceStart, int256 sold, int256 amount) public view virtual returns (int256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L54-L54

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

86:     function pIntegral(int256 timeSinceStart, int256 sold) internal view returns (int256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L86-L86

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

7:     constructor(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L7-L7

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

12:     function _handleRewardsAndGetValueToSend(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L12-L12

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

29:     constructor(address _protocolRewards, address _revolutionRewardRecipient) payable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L29-L29

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

40:     function computeTotalReward(uint256 paymentAmountWei) public pure returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L40-L40

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

54:     function computePurchaseRewards(uint256 paymentAmountWei) public pure returns (RewardsSettings memory, uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L54-L54

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

66:     function _depositPurchaseRewards(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L66-L66
### [N-87]<a name="n-87"></a> Missing NatSpec `@dev` from function declaration

*There are 60 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

29:     /// @param _manager The contract upgrade manager address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L29-L29

```solidity

File: packages/revolution/src/MaxHeap.sol

50:     /**
51:      * @notice Initializes the maxheap contract
52:      * @param _initialOwner The initial owner of the contract
53:      * @param _admin The contract that is allowed to update the data store
54:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L50-L54

```solidity

File: packages/revolution/src/MaxHeap.sol

75:     /// @notice Get the parent index of a given position
76:     /// @param pos The position for which to find the parent
77:     /// @return The index of the parent node


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L75-L77

```solidity

File: packages/revolution/src/MaxHeap.sol

83:     /// @notice Swap two nodes in the heap
84:     /// @param fpos The position of the first node
85:     /// @param spos The position of the second node


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L83-L85

```solidity

File: packages/revolution/src/CultureIndex.sol

91:     /// @param _manager The contract upgrade manager address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L91-L91

```solidity

File: packages/revolution/src/CultureIndex.sol

100:     /**
101:      * @notice Initializes a token's metadata descriptor
102:      * @param _erc20VotingToken The address of the ERC20 voting token, commonly referred to as "points"
103:      * @param _erc721VotingToken The address of the ERC721 voting token, commonly the dropped art pieces
104:      * @param _initialOwner The owner of the contract, allowed to drop pieces. Commonly updated to the AuctionHouse
105:      * @param _maxHeap The address of the max heap contract
106:      * @param _dropperAdmin The address that can drop new art pieces
107:      * @param _cultureIndexParams The CultureIndex settings
108:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L100-L108

```solidity

File: packages/revolution/src/CultureIndex.sol

151:     /**
152:      *  Validates the media type and associated data.
153:      * @param metadata The metadata associated with the art piece.
154:      *
155:      * Requirements:
156:      * - The media type must be one of the defined types in the MediaType enum.
157:      * - The corresponding media data must not be empty.
158:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L151-L158

```solidity

File: packages/revolution/src/CultureIndex.sol

170:     /**
171:      * @notice Checks the total basis points from an array of creators and returns the length
172:      * @param creatorArray An array of Creator structs containing address and basis points.
173:      * @return Returns the total basis points calculated from the array of creators.
174:      *
175:      * Requirements:
176:      * - The `creatorArray` must not contain any zero addresses.
177:      * - The function will return the length of the `creatorArray`.
178:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L170-L178

```solidity

File: packages/revolution/src/CultureIndex.sol

195:     /**
196:      * @notice Creates a new piece of art with associated metadata and creators.
197:      * @param metadata The metadata associated with the art piece, including name, description, image, and optional animation URL.
198:      * @param creatorArray An array of creators who contributed to the piece, along with their respective basis points that must sum up to 10,000.
199:      * @return Returns the unique ID of the newly created art piece.
200:      *
201:      * Emits a {PieceCreated} event for the newly created piece.
202:      * Emits a {PieceCreatorAdded} event for each creator added to the piece.
203:      *
204:      * Requirements:
205:      * - `metadata` must include name, description, and image. Animation URL is optional.
206:      * - `creatorArray` must not contain any zero addresses.
207:      * - The sum of basis points in `creatorArray` must be exactly 10,000.
208:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L195-L208

```solidity

File: packages/revolution/src/CultureIndex.sol

250:     /**
251:      * @notice Checks if a specific voter has already voted for a given art piece.
252:      * @param pieceId The ID of the art piece.
253:      * @param voter The address of the voter.
254:      * @return A boolean indicating if the voter has voted for the art piece.
255:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L250-L255

```solidity

File: packages/revolution/src/CultureIndex.sol

260:     /**
261:      * @notice Returns the voting power of a voter at the current block.
262:      * @param account The address of the voter.
263:      * @return The voting power of the voter.
264:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L260-L264

```solidity

File: packages/revolution/src/CultureIndex.sol

269:     /**
270:      * @notice Returns the voting power of a voter at the current block.
271:      * @param account The address of the voter.
272:      * @return The voting power of the voter.
273:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L269-L273

```solidity

File: packages/revolution/src/CultureIndex.sol

278:     /**
279:      * @notice Calculates the vote weight of a voter.
280:      * @param erc20Balance The ERC20 balance of the voter.
281:      * @param erc721Balance The ERC721 balance of the voter.
282:      * @return The vote weight of the voter.
283:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L278-L283

```solidity

File: packages/revolution/src/CultureIndex.sol

288:     function _getVotes(address account) internal view returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L288-L288

```solidity

File: packages/revolution/src/CultureIndex.sol

292:     function _getPastVotes(address account, uint256 blockNumber) internal view returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L292-L292

```solidity

File: packages/revolution/src/CultureIndex.sol

360:     /// @notice Execute a vote via signature
361:     /// @param from Vote from this address
362:     /// @param pieceIds Vote on this list of pieceIds
363:     /// @param deadline Deadline for the signature to be valid
364:     /// @param v V component of signature
365:     /// @param r R component of signature
366:     /// @param s S component of signature


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L360-L366

```solidity

File: packages/revolution/src/CultureIndex.sol

382:     /// @notice Execute a batch of votes via signature, each with their own signature
383:     /// @param from Vote from these addresses
384:     /// @param pieceIds Vote on these lists of pieceIds
385:     /// @param deadline Deadlines for the signature to be valid
386:     /// @param v V component of signatures
387:     /// @param r R component of signatures
388:     /// @param s S component of signatures


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L382-L388

```solidity

File: packages/revolution/src/CultureIndex.sol

412:     /// @notice Utility function to verify a signature for a specific vote
413:     /// @param from Vote from this address
414:     /// @param pieceIds Vote on this pieceId
415:     /// @param deadline Deadline for the signature to be valid
416:     /// @param v V component of signature
417:     /// @param r R component of signature
418:     /// @param s S component of signature


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L412-L418

```solidity

File: packages/revolution/src/CultureIndex.sol

446:     /**
447:      * @notice Fetch an art piece by its ID.
448:      * @param pieceId The ID of the art piece.
449:      * @return The ArtPiece struct associated with the given ID.
450:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L446-L450

```solidity

File: packages/revolution/src/CultureIndex.sol

456:     /**
457:      * @notice Fetch the list of votes for a given art piece.
458:      * @param pieceId The ID of the art piece.
459:      * @return An array of Vote structs for the given art piece ID.
460:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L456-L460

```solidity

File: packages/revolution/src/CultureIndex.sol

466:     /**
467:      * @notice Fetch the top-voted art piece.
468:      * @return The ArtPiece struct of the top-voted art piece.
469:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L466-L469

```solidity

File: packages/revolution/src/CultureIndex.sol

474:     /**
475:      * @notice Fetch the number of pieces
476:      * @return The number of pieces
477:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L474-L477

```solidity

File: packages/revolution/src/CultureIndex.sol

482:     /**
483:      * @notice Fetch the top-voted pieceId
484:      * @return The top-voted pieceId
485:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L482-L485

```solidity

File: packages/revolution/src/CultureIndex.sol

505:     /**
506:      * @notice Current quorum votes using ERC721 Total Supply, ERC721 Vote Weight, and ERC20 Total Supply
507:      * Differs from `GovernerBravo` which uses fixed amount
508:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L505-L508

```solidity

File: packages/revolution/src/CultureIndex.sol

515:     /**
516:      * @notice Pulls and drops the top-voted piece.
517:      * @return The top voted piece
518:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L515-L518

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

43:     /// @param _manager The contract upgrade manager address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L43-L43

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

48:     ///                                                          ///
49:     ///                         INITIALIZER                      ///
50:     ///                                                          ///
51: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L48-L51

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

62:     /// @notice Initializes a DAO's ERC-20 governance token contract
63:     /// @param _initialOwner The address of the initial owner
64:     /// @param _erc20TokenParams The params of the token


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L62-L64

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

134:     function mint(address account, uint256 amount) public onlyOwner {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L134-L134

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

61:     /// @param _manager The contract upgrade manager address
62:     /// @param _protocolRewards The protocol rewards contract address
63:     /// @param _protocolFeeRecipient The protocol fee recipient address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L61-L63

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

76:     /**
77:      * @notice Initialize the token emitter
78:      * @param _initialOwner The initial owner of the token emitter
79:      * @param _erc20Token The ERC-20 token contract address
80:      * @param _vrgdac The VRGDA contract address
81:      * @param _treasury The treasury address to pay funds to
82:      * @param _creatorsAddress The address to pay the creator reward to
83:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L76-L83

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

108:     function _mint(address _to, uint256 _amount) private {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L108-L108

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

112:     function totalSupply() public view returns (uint) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L112-L112

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

117:     function decimals() public view returns (uint8) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L117-L117

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

122:     function balanceOf(address _owner) public view returns (uint) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L122-L122

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

145:     /**
146:      * @notice A payable function that allows a user to buy tokens for a list of addresses and a list of basis points to split the token purchase between.
147:      * @param addresses The addresses to send purchased tokens to.
148:      * @param basisPointSplits The basis points of the purchase to send to each address.
149:      * @param protocolRewardsRecipients The addresses to pay the builder, purchaseRefferal, and deployer rewards to
150:      * @return tokensSoldWad The amount of tokens sold in wad units.
151:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L145-L151

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

232:     /**
233:      * @notice Returns the amount of wei that would be spent to buy an amount of tokens. Does not take into account the protocol rewards.
234:      * @param amount the amount of tokens to buy.
235:      * @return spentY The cost in wei of the token purchase.
236:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L232-L236

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

249:     /**
250:      * @notice Returns the amount of tokens that would be emitted for an amount of wei. Does not take into account the protocol rewards.
251:      * @param etherAmount the payment amount in wei.
252:      * @return gainedX The amount of tokens that would be emitted for the payment amount.
253:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L249-L253

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

266:     /**
267:      * @notice Returns the amount of tokens that would be emitted for the payment amount, taking into account the protocol rewards.
268:      * @param paymentAmount the payment amount in wei.
269:      * @return gainedX The amount of tokens that would be emitted for the payment amount.
270:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L266-L270

```solidity

File: packages/revolution/src/AuctionHouse.sol

94:     /// @param _manager The contract upgrade manager address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L94-L94

```solidity

File: packages/revolution/src/AuctionHouse.sol

146:     /**
147:      * @notice Settle the current auction, mint a new Verb, and put it up for auction.
148:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L146-L148

```solidity

File: packages/revolution/src/AuctionHouse.sol

416:     /// @notice Transfer ETH/WETH from the contract
417:     /// @param _to The recipient address
418:     /// @param _amount The amount transferring


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L416-L418

```solidity

File: packages/revolution/src/VerbsToken.sol

115:     /// @param _manager The contract upgrade manager address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L115-L115

```solidity

File: packages/revolution/src/VerbsToken.sol

124:     /// @notice Initializes a DAO's ERC-721 token contract
125:     /// @param _minter The address of the minter
126:     /// @param _initialOwner The address of the initial owner
127:     /// @param _descriptor The address of the token URI descriptor
128:     /// @param _cultureIndex The address of the CultureIndex contract
129:     /// @param _erc721TokenParams The name, symbol, and contract metadata of the token


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L124-L129

```solidity

File: packages/revolution/src/VerbsToken.sol

158:     /**
159:      * @notice The IPFS URI of contract-level metadata.
160:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L158-L160

```solidity

File: packages/revolution/src/VerbsToken.sol

181:     /**
182:      * @notice Burn a verb.
183:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L181-L183

```solidity

File: packages/revolution/src/VerbsToken.sol

197:     /**
198:      * @notice Similar to `tokenURI`, but always serves a base64 encoded data URI
199:      * with the JSON contents directly inlined.
200:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L197-L200

```solidity

File: packages/revolution/src/VerbsToken.sol

268:     /**
269:      * @notice Fetch an art piece by its ID.
270:      * @param verbId The ID of the art piece.
271:      * @return The ArtPiece struct associated with the given ID.
272:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L268-L272

```solidity

File: packages/revolution/src/VerbsToken.sol

278:     /**
279:      * @notice Mint a Verb with `verbId` to the provided `to` address. Pulls the top voted art piece from the CultureIndex.
280:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L278-L280

```solidity

File: packages/revolution/src/VerbsToken.sol

321:     ///                                                          ///
322:     ///                         TOKEN UPGRADE                    ///
323:     ///                                                          ///
324: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L321-L324

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

24:     /// @notice Sets target price and per time unit price decay for the VRGDA.
25:     /// @param _targetPrice The target price for a token if sold on pace, scaled by 1e18.
26:     /// @param _priceDecayPercent The percent price decays per unit of time with no sales, scaled by 1e18.
27:     /// @param _perTimeUnit The number of tokens to target selling in 1 full unit of time, scaled by 1e18.


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L24-L27

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

47:     function xToY(int256 timeSinceStart, int256 sold, int256 amount) public view virtual returns (int256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L47-L47

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

54:     function yToX(int256 timeSinceStart, int256 sold, int256 amount) public view virtual returns (int256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L54-L54

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

86:     function pIntegral(int256 timeSinceStart, int256 sold) internal view returns (int256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L86-L86

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

7:     constructor(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L7-L7

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

12:     function _handleRewardsAndGetValueToSend(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L12-L12

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

29:     constructor(address _protocolRewards, address _revolutionRewardRecipient) payable {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L29-L29

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

40:     function computeTotalReward(uint256 paymentAmountWei) public pure returns (uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L40-L40

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

54:     function computePurchaseRewards(uint256 paymentAmountWei) public pure returns (RewardsSettings memory, uint256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L54-L54

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

66:     function _depositPurchaseRewards(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L66-L66
### [N-88]<a name="n-88"></a> Missing NatSpec `@dev` from `modifier` declaration

*There are 5 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

38:     /**
39:      * @notice Require that the minter has not been locked.
40:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L38-L40

```solidity

File: packages/revolution/src/VerbsToken.sol

72:     /**
73:      * @notice Require that the minter has not been locked.
74:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L72-L74

```solidity

File: packages/revolution/src/VerbsToken.sol

80:     /**
81:      * @notice Require that the CultureIndex has not been locked.
82:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L80-L82

```solidity

File: packages/revolution/src/VerbsToken.sol

88:     /**
89:      * @notice Require that the descriptor has not been locked.
90:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L88-L90

```solidity

File: packages/revolution/src/VerbsToken.sol

96:     /**
97:      * @notice Require that the sender is the minter.
98:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L96-L98
### [N-89]<a name="n-89"></a> Use custom errors rather than `revert()`/`require()` strings for better readability
Custom errors are available from solidity version 0.8.4. Custom errors are more easily processed in try-catch blocks, and are easier to re-use and maintain.

*There are 75 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

42:         require(msg.sender == admin, "Sender is not the admin");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L42-L42

```solidity

File: packages/revolution/src/MaxHeap.sol

56:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L56-L56

```solidity

File: packages/revolution/src/MaxHeap.sol

79:         require(pos != 0, "Position should not be zero");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L79-L79

```solidity

File: packages/revolution/src/MaxHeap.sol

157:         require(size > 0, "Heap is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L157-L157

```solidity

File: packages/revolution/src/MaxHeap.sol

170:         require(size > 0, "Heap is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L170-L170

```solidity

File: packages/revolution/src/CultureIndex.sol

117:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L117-L117

```solidity

File: packages/revolution/src/CultureIndex.sol

119:         require(_cultureIndexParams.quorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "invalid quorum bps");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L119-L119

```solidity

File: packages/revolution/src/CultureIndex.sol

120:         require(_cultureIndexParams.erc721VotingTokenWeight > 0, "invalid erc721 voting token weight");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L120-L120

```solidity

File: packages/revolution/src/CultureIndex.sol

121:         require(_erc721VotingToken != address(0), "invalid erc721 voting token");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L121-L121

```solidity

File: packages/revolution/src/CultureIndex.sol

122:         require(_erc20VotingToken != address(0), "invalid erc20 voting token");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L122-L122

```solidity

File: packages/revolution/src/CultureIndex.sol

160:         require(uint8(metadata.mediaType) > 0 && uint8(metadata.mediaType) <= 5, "Invalid media type");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L160-L160

```solidity

File: packages/revolution/src/CultureIndex.sol

182:         require(creatorArrayLength <= MAX_NUM_CREATORS, "Creator array must not be > MAX_NUM_CREATORS");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L182-L182

```solidity

File: packages/revolution/src/CultureIndex.sol

190:         require(totalBps == 10_000, "Total BPS must sum up to 10,000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L190-L190

```solidity

File: packages/revolution/src/CultureIndex.sol

308:         require(pieceId < _currentPieceId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L308-L308

```solidity

File: packages/revolution/src/CultureIndex.sol

309:         require(voter != address(0), "Invalid voter address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L309-L309

```solidity

File: packages/revolution/src/CultureIndex.sol

310:         require(!pieces[pieceId].isDropped, "Piece has already been dropped");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L310-L310

```solidity

File: packages/revolution/src/CultureIndex.sol

311:         require(!(votes[pieceId][voter].voterAddress != address(0)), "Already voted");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L311-L311

```solidity

File: packages/revolution/src/CultureIndex.sol

314:         require(weight > minVoteWeight, "Weight must be greater than minVoteWeight");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L314-L314

```solidity

File: packages/revolution/src/CultureIndex.sol

398:         require(
399:             len == pieceIds.length && len == deadline.length && len == v.length && len == r.length && len == s.length,
400:             "Array lengths must match"
401:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L398-L401

```solidity

File: packages/revolution/src/CultureIndex.sol

427:         require(deadline >= block.timestamp, "Signature expired");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L427-L427

```solidity

File: packages/revolution/src/CultureIndex.sol

452:         require(pieceId < _currentPieceId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L452-L452

```solidity

File: packages/revolution/src/CultureIndex.sol

462:         require(pieceId < _currentPieceId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L462-L462

```solidity

File: packages/revolution/src/CultureIndex.sol

487:         require(maxHeap.size() > 0, "Culture index is empty");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L487-L487

```solidity

File: packages/revolution/src/CultureIndex.sol

499:         require(newQuorumVotesBPS <= MAX_QUORUM_VOTES_BPS, "CultureIndex::_setQuorumVotesBPS: invalid quorum bps");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L499-L499

```solidity

File: packages/revolution/src/CultureIndex.sol

520:         require(msg.sender == dropperAdmin, "Only dropper can drop pieces");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L520-L520

```solidity

File: packages/revolution/src/CultureIndex.sol

523:         require(totalVoteWeights[piece.pieceId] >= piece.quorumVotes, "Does not meet quorum votes to be dropped.");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L523-L523

```solidity

File: packages/revolution/src/CultureIndex.sol

163:             require(bytes(metadata.image).length > 0, "Image URL must be provided");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L163-L163

```solidity

File: packages/revolution/src/CultureIndex.sol

165:             require(bytes(metadata.animationUrl).length > 0, "Animation URL must be provided");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L165-L165

```solidity

File: packages/revolution/src/CultureIndex.sol

186:             require(creatorArray[i].creator != address(0), "Invalid creator address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L186-L186

```solidity

File: packages/revolution/src/CultureIndex.sol

167:             require(bytes(metadata.text).length > 0, "Text must be provided");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L167-L167

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

69:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L69-L69

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

91:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L91-L91

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

96:         require(_treasury != address(0), "Invalid treasury address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L96-L96

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

158:         require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L158-L158

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

160:         require(msg.value > 0, "Must send ether");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L160-L160

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

162:         require(addresses.length == basisPointSplits.length, "Parallel arrays required");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L162-L162

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

192:         require(success, "Transfer failed.");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L192-L192

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

217:         require(bpsSum == 10_000, "bps must add up to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L217-L217

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

238:         require(amount > 0, "Amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L238-L238

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

255:         require(etherAmount > 0, "Ether amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L255-L255

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

272:         require(paymentAmount > 0, "Payment amount must be greater than 0");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L272-L272

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

289:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L289-L289

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

300:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L300-L300

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

310:         require(_creatorsAddress != address(0), "Invalid address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L310-L310

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

197:             require(success, "Transfer failed.");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L197-L197

```solidity

File: packages/revolution/src/AuctionHouse.sol

120:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L120-L120

```solidity

File: packages/revolution/src/AuctionHouse.sol

121:         require(_weth != address(0), "WETH cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L121-L121

```solidity

File: packages/revolution/src/AuctionHouse.sol

129:         require(
130:             _auctionParams.creatorRateBps >= _auctionParams.minCreatorRateBps,
131:             "Creator rate must be greater than or equal to the creator rate"
132:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L129-L132

```solidity

File: packages/revolution/src/AuctionHouse.sol

175:         require(bidder != address(0), "Bidder cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L175-L175

```solidity

File: packages/revolution/src/AuctionHouse.sol

176:         require(_auction.verbId == verbId, "Verb not up for auction");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L176-L176

```solidity

File: packages/revolution/src/AuctionHouse.sol

178:         require(block.timestamp < _auction.endTime, "Auction expired");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L178-L178

```solidity

File: packages/revolution/src/AuctionHouse.sol

179:         require(msg.value >= reservePrice, "Must send at least reservePrice");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L179-L179

```solidity

File: packages/revolution/src/AuctionHouse.sol

180:         require(
181:             msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100),
182:             "Must send more than last bid by minBidIncrementPercentage amount"
183:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L180-L183

```solidity

File: packages/revolution/src/AuctionHouse.sol

218:         require(
219:             _creatorRateBps >= minCreatorRateBps,
220:             "Creator rate must be greater than or equal to minCreatorRateBps"
221:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L218-L221

```solidity

File: packages/revolution/src/AuctionHouse.sol

222:         require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L222-L222

```solidity

File: packages/revolution/src/AuctionHouse.sol

234:         require(_minCreatorRateBps <= creatorRateBps, "Min creator rate must be less than or equal to creator rate");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L234-L234

```solidity

File: packages/revolution/src/AuctionHouse.sol

235:         require(_minCreatorRateBps <= 10_000, "Min creator rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L235-L235

```solidity

File: packages/revolution/src/AuctionHouse.sol

238:         require(
239:             _minCreatorRateBps > minCreatorRateBps,
240:             "Min creator rate must be greater than previous minCreatorRateBps"
241:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L238-L241

```solidity

File: packages/revolution/src/AuctionHouse.sol

254:         require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L254-L254

```solidity

File: packages/revolution/src/AuctionHouse.sol

311:         require(gasleft() >= MIN_TOKEN_MINT_GAS_THRESHOLD, "Insufficient gas for creating auction");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L311-L311

```solidity

File: packages/revolution/src/AuctionHouse.sol

339:         require(_auction.startTime != 0, "Auction hasn't begun");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L339-L339

```solidity

File: packages/revolution/src/AuctionHouse.sol

340:         require(!_auction.settled, "Auction has already been settled");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L340-L340

```solidity

File: packages/revolution/src/AuctionHouse.sol

342:         require(block.timestamp >= _auction.endTime, "Auction hasn't completed");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L342-L342

```solidity

File: packages/revolution/src/VerbsToken.sol

76:         require(!isMinterLocked, "Minter is locked");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L76-L76

```solidity

File: packages/revolution/src/VerbsToken.sol

84:         require(!isCultureIndexLocked, "CultureIndex is locked");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L84-L84

```solidity

File: packages/revolution/src/VerbsToken.sol

92:         require(!isDescriptorLocked, "Descriptor is locked");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L92-L92

```solidity

File: packages/revolution/src/VerbsToken.sol

100:         require(msg.sender == minter, "Sender is not the minter");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L100-L100

```solidity

File: packages/revolution/src/VerbsToken.sol

137:         require(msg.sender == address(manager), "Only manager can initialize");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L137-L137

```solidity

File: packages/revolution/src/VerbsToken.sol

139:         require(_minter != address(0), "Minter cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L139-L139

```solidity

File: packages/revolution/src/VerbsToken.sol

140:         require(_initialOwner != address(0), "Initial owner cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L140-L140

```solidity

File: packages/revolution/src/VerbsToken.sol

210:         require(_minter != address(0), "Minter cannot be zero address");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L210-L210

```solidity

File: packages/revolution/src/VerbsToken.sol

274:         require(verbId <= _currentVerbId, "Invalid piece ID");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L274-L274

```solidity

File: packages/revolution/src/VerbsToken.sol

286:         require(
287:             artPiece.creators.length <= cultureIndex.MAX_NUM_CREATORS(),
288:             "Creator array must not be > MAX_NUM_CREATORS"
289:         );


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L286-L289

```solidity

File: packages/revolution/src/VerbsToken.sol

330:         require(manager.isRegisteredUpgrade(_getImplementation(), _newImpl), "Invalid upgrade");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L330-L330

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

38:         require(decayConstant < 0, "NON_NEGATIVE_DECAY_CONSTANT");


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L38-L38
### [N-90]<a name="n-90"></a> Use `@inheritdoc` for overridden functions

*There are 35 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

178:     /// @notice Ensures the caller is authorized to upgrade the contract and that the new implementation is valid
179:     /// @dev This function is called in `upgradeTo` & `upgradeToAndCall`
180:     /// @param _newImpl The new implementation address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L178-L180

```solidity

File: packages/revolution/src/CultureIndex.sol

260:     /**
261:      * @notice Returns the voting power of a voter at the current block.
262:      * @param account The address of the voter.
263:      * @return The voting power of the voter.
264:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L260-L264

```solidity

File: packages/revolution/src/CultureIndex.sol

269:     /**
270:      * @notice Returns the voting power of a voter at the current block.
271:      * @param account The address of the voter.
272:      * @return The voting power of the voter.
273:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L269-L273

```solidity

File: packages/revolution/src/CultureIndex.sol

540:     /// @notice Ensures the caller is authorized to upgrade the contract and that the new implementation is valid
541:     /// @dev This function is called in `upgradeTo` & `upgradeToAndCall`
542:     /// @param _newImpl The new implementation address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L540-L542

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

74:     /**
75:      * @dev Returns the number of decimals used to get its user representation.
76:      * For example, if `decimals` equals `2`, a balance of `505` tokens should
77:      * be displayed to a user as `5.05` (`505 / 10 ** 2`).
78:      *
79:      * Tokens usually opt for a value of 18, imitating the relationship between
80:      * Ether and Wei. This is the default value returned by this function, unless
81:      * it's overridden.
82:      *
83:      * NOTE: This information is only used for _display_ purposes: it in
84:      * no way affects any of the arithmetic of the contract, including
85:      * {IERC20-balanceOf} and {IERC20-transfer}.
86:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L74-L86

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

91:     /**
92:      * @dev Not allowed
93:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L91-L93

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

098:     /**
099:      * @dev Not allowed
100:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L98-L100

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

105:     /**
106:      * @dev Not allowed
107:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L105-L107

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

112:     /**
113:      * @dev Not allowed
114:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L112-L114

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

119:     /**
120:      * @dev Creates a `value` amount of tokens and assigns them to `account`, by transferring it from address(0).
121:      * Relies on the `_update` mechanism
122:      *
123:      * Emits a {Transfer} event with `from` set to the zero address.
124:      *
125:      * NOTE: This function is not virtual, {_update} should be overridden instead.
126:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L119-L126

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

138:     /**
139:      * @dev Not allowed
140:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L138-L140

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

145:     /**
146:      * @dev Not allowed
147:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L145-L147

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

152:     /**
153:      * @dev Not allowed
154:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L152-L154

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

127:     /**
128:      * @notice Pause the contract.
129:      * @dev This function can only be called by the owner when the
130:      * contract is unpaused.
131:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L127-L131

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

136:     /**
137:      * @notice Unpause the token emitter.
138:      * @dev This function can only be called by the owner when the
139:      * contract is paused.
140:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L136-L140

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

305:     /**
306:      * @notice Set the creators address to pay the creatorRate to. Can be a contract.
307:      * @dev Only callable by the owner.
308:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L305-L308

```solidity

File: packages/revolution/src/AuctionHouse.sol

146:     /**
147:      * @notice Settle the current auction, mint a new Verb, and put it up for auction.
148:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L146-L148

```solidity

File: packages/revolution/src/AuctionHouse.sol

157:     /**
158:      * @notice Settle the current auction.
159:      * @dev This function can only be called when the contract is paused.
160:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L157-L160

```solidity

File: packages/revolution/src/AuctionHouse.sol

165:     /**
166:      * @notice Create a bid for a Verb, with a given amount.
167:      * @dev This contract only accepts payment in ETH.
168:      * @param verbId The ID of the Verb to bid on.
169:      * @param bidder The address of the bidder.
170:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L165-L170

```solidity

File: packages/revolution/src/AuctionHouse.sol

202:     /**
203:      * @notice Pause the Verbs auction house.
204:      * @dev This function can only be called by the owner when the
205:      * contract is unpaused. While no new auctions can be started when paused,
206:      * anyone can settle an ongoing auction.
207:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L202-L207

```solidity

File: packages/revolution/src/AuctionHouse.sol

260:     /**
261:      * @notice Unpause the Verbs auction house.
262:      * @dev This function can only be called by the owner when the
263:      * contract is paused. If required, this function will start a new auction.
264:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L260-L264

```solidity

File: packages/revolution/src/AuctionHouse.sol

273:     /**
274:      * @notice Set the auction time buffer.
275:      * @dev Only callable by the owner.
276:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L273-L276

```solidity

File: packages/revolution/src/AuctionHouse.sol

283:     /**
284:      * @notice Set the auction reserve price.
285:      * @dev Only callable by the owner.
286:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L283-L286

```solidity

File: packages/revolution/src/AuctionHouse.sol

293:     /**
294:      * @notice Set the auction minimum bid increment percentage.
295:      * @dev Only callable by the owner.
296:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L293-L296

```solidity

File: packages/revolution/src/AuctionHouse.sol

449:     /// @notice Ensures the caller is authorized to upgrade the contract and the new implementation is valid
450:     /// @dev This function is called in `upgradeTo` & `upgradeToAndCall`
451:     /// @param _newImpl The new implementation address


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L449-L451

```solidity

File: packages/revolution/src/VerbsToken.sol

173:     /**
174:      * @notice Mint a Verb to the minter.
175:      * @dev Call _mintTo with the to address(es).
176:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L173-L176

```solidity

File: packages/revolution/src/VerbsToken.sol

181:     /**
182:      * @notice Burn a verb.
183:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L181-L183

```solidity

File: packages/revolution/src/VerbsToken.sol

189:     /**
190:      * @notice A distinct Uniform Resource Identifier (URI) for a given asset.
191:      * @dev See {IERC721Metadata-tokenURI}.
192:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L189-L192

```solidity

File: packages/revolution/src/VerbsToken.sol

197:     /**
198:      * @notice Similar to `tokenURI`, but always serves a base64 encoded data URI
199:      * with the JSON contents directly inlined.
200:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L197-L200

```solidity

File: packages/revolution/src/VerbsToken.sol

205:     /**
206:      * @notice Set the token minter.
207:      * @dev Only callable by the owner when not locked.
208:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L205-L208

```solidity

File: packages/revolution/src/VerbsToken.sol

216:     /**
217:      * @notice Lock the minter.
218:      * @dev This cannot be reversed and is only callable by the owner when not locked.
219:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L216-L219

```solidity

File: packages/revolution/src/VerbsToken.sol

226:     /**
227:      * @notice Set the token URI descriptor.
228:      * @dev Only callable by the owner when not locked.
229:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L226-L229

```solidity

File: packages/revolution/src/VerbsToken.sol

238:     /**
239:      * @notice Lock the descriptor.
240:      * @dev This cannot be reversed and is only callable by the owner when not locked.
241:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L238-L241

```solidity

File: packages/revolution/src/VerbsToken.sol

258:     /**
259:      * @notice Lock the CultureIndex
260:      * @dev This cannot be reversed and is only callable by the owner when not locked.
261:      */


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L258-L261

```solidity

File: packages/revolution/src/VerbsToken.sol

321:     ///                                                          ///
322:     ///                         TOKEN UPGRADE                    ///
323:     ///                                                          ///
324: 


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L321-L324
### [N-91]<a name="n-91"></a> Multiple mappings with same keys can be combined into a single struct mapping for readability
Well-organized data structures make code reviews easier, which may lead to fewer bugs. Consider combining related mappings into mappings to structs, so it's clear what data is related.

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

33:     mapping(address => uint256) public nonces;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L33-L33

```solidity

File: packages/revolution/src/CultureIndex.sol

69:     mapping(uint256 => mapping(address => Vote)) public votes;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L69-L69
### [N-92]<a name="n-92"></a> constructor should emit an event
Use events to signal significant changes to off-chain monitoring tools.

*There are 9 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

30:     constructor(address _manager) payable initializer {
31:         manager = IRevolutionBuilder(_manager);
32:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L30-L32

```solidity

File: packages/revolution/src/CultureIndex.sol

92:     constructor(address _manager) payable initializer {
93:         manager = IRevolutionBuilder(_manager);
94:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L92-L94

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

44:     constructor(address _manager) payable initializer {
45:         manager = IRevolutionBuilder(_manager);
46:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L44-L46

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

64:     constructor(
65:         address _manager,
66:         address _protocolRewards,
67:         address _protocolFeeRecipient
68:     ) payable TokenEmitterRewards(_protocolRewards, _protocolFeeRecipient) initializer {
69:         manager = IRevolutionBuilder(_manager);
70:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L64-L70

```solidity

File: packages/revolution/src/AuctionHouse.sol

95:     constructor(address _manager) payable initializer {
96:         manager = IRevolutionBuilder(_manager);
97:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L95-L97

```solidity

File: packages/revolution/src/VerbsToken.sol

116:     constructor(address _manager) payable initializer {
117:         manager = IRevolutionBuilder(_manager);
118:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L116-L118

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

28:     constructor(int256 _targetPrice, int256 _priceDecayPercent, int256 _perTimeUnit) {
29:         targetPrice = _targetPrice;
30: 
31:         perTimeUnit = _perTimeUnit;
32: 
33:         priceDecayPercent = _priceDecayPercent;
34: 
35:         decayConstant = wadLn(1e18 - _priceDecayPercent);
36: 
37:         // The decay constant must be negative for VRGDAs to work.
38:         require(decayConstant < 0, "NON_NEGATIVE_DECAY_CONSTANT");
39:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L28-L39

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

07:     constructor(
08:         address _protocolRewards,
09:         address _revolutionRewardRecipient
10:     ) payable RewardSplits(_protocolRewards, _revolutionRewardRecipient) {}


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L7-L10

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

29:     constructor(address _protocolRewards, address _revolutionRewardRecipient) payable {
30:         if (_protocolRewards == address(0) || _revolutionRewardRecipient == address(0)) revert("Invalid Address Zero");
31: 
32:         protocolRewards = IRevolutionProtocolRewards(_protocolRewards);
33:         revolutionRewardRecipient = _revolutionRewardRecipient;
34:     }


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L29-L34
### [N-93]<a name="n-93"></a> `error` should be named using CapWords style
See the [Solidity Style](https://docs.soliditylang.org/en/latest/style-guide.html#struct-names) Guide for more info.

*There are 2 instance(s) of this issue:*

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

30:     error TRANSFER_NOT_ALLOWED();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L30-L30

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

15:     error INVALID_ETH_AMOUNT();


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L15-L15
### [N-94]<a name="n-94"></a> Complex functions should include comments
Large and/or complex functions should include comments to make them easier to understand and reduce margin for error.

*There are 4 instance(s) of this issue:*

```solidity

File: packages/revolution/src/CultureIndex.sol

389:     function batchVoteForManyWithSig(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L389-L389

```solidity

File: packages/revolution/src/AuctionHouse.sol

113:     function initialize(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L113-L113

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

54:     function yToX(int256 timeSinceStart, int256 sold, int256 amount) public view virtual returns (int256) {


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L54-L54

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

66:     function _depositPurchaseRewards(


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L66-L66
### [N-95]<a name="n-95"></a> Make use of Solidiy's `using` keyword
The directive `using A for B` can be used to attach functions (`A`) as operators to user-defined value types or as member functions to any type (`B`). The member functions receive the object they are called on as their first parameter (like the `self` variable in Python). The operator functions receive operands as parameters.  Doing so improves readability, makes debugging easier, and promotes modularity and reusability in the code.

*There are 1 instance(s) of this issue:*

```solidity

File: packages/revolution/src/AuctionHouse.sol

403:                         IERC20TokenEmitter.ProtocolRewardAddresses({


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L403-L403
### [N-96]<a name="n-96"></a> [Solidity]: All `verbatim` blocks are considered identical by deduplicator and can incorrectly be unified
The block deduplicator is a step of the opcode-based optimizer which identifies equivalent assembly blocks and merges them into a single one. However, when blocks contained `verbatim`, their comparison was performed incorrectly, leading to the collapse of assembly blocks which are identical except for the contents of the ``verbatim`` items. Since `verbatim` is only available in Yul, compilation of Solidity sources is not affected. For more details check the following [link](https://blog.soliditylang.org/2023/11/08/verbatim-invalid-deduplication-bug/)

*There are 9 instance(s) of this issue:*

```solidity

File: packages/revolution/src/MaxHeap.sol

2: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/MaxHeap.sol#L2-L2

```solidity

File: packages/revolution/src/CultureIndex.sol

2: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/CultureIndex.sol#L2-L2

```solidity

File: packages/revolution/src/NontransferableERC20Votes.sol

4: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/NontransferableERC20Votes.sol#L4-L4

```solidity

File: packages/revolution/src/ERC20TokenEmitter.sol

2: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/ERC20TokenEmitter.sol#L2-L2

```solidity

File: packages/revolution/src/AuctionHouse.sol

24: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/AuctionHouse.sol#L24-L24

```solidity

File: packages/revolution/src/VerbsToken.sol

18: pragma solidity ^0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/VerbsToken.sol#L18-L18

```solidity

File: packages/revolution/src/libs/VRGDAC.sol

2: pragma solidity 0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/revolution/src/libs/VRGDAC.sol#L2-L2

```solidity

File: packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol

2: pragma solidity 0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol#L2-L2

```solidity

File: packages/protocol-rewards/src/abstract/RewardSplits.sol

2: pragma solidity 0.8.22;


```


*GitHub* : https://github.com/code-423n4/2023-12-revolutionprotocol/blob/main//packages/protocol-rewards/src/abstract/RewardSplits.sol#L2-L2 