// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title BigoCoin NFT holder reward claim (BNB Smart Chain)
/// @notice Pays a fixed BIGO reward per eligible NFT from the Bigo Network Collection (Polygon).
/// Eligibility is checked off-chain by the backend, which signs a voucher stating the wallet's
/// TOTAL eligible NFT count. This contract remembers how many NFTs each wallet has already been
/// paid for, so every eligible NFT is paid at most once and an old voucher can never pay twice.
contract BigoNFTRewardClaim is EIP712, Ownable, Pausable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    uint256 public immutable rewardPerNft;   // in token base units (500,000 BIGO = 500000e18)
    uint256 public immutable maxTotalUnits;  // hard cap on NFTs that can ever be paid (9,998)

    address public signer;
    mapping(address => uint256) public claimedUnits;
    uint256 public totalClaimedUnits;

    bytes32 private constant CLAIM_TYPEHASH =
        keccak256("NftClaim(address account,uint256 eligibleUnits,uint256 deadline)");

    event Claimed(address indexed account, uint256 units, uint256 amount);
    event SignerChanged(address indexed previousSigner, address indexed newSigner);
    event Withdrawn(address indexed to, uint256 amount);

    constructor(
        IERC20 token_,
        address signer_,
        address owner_,
        uint256 rewardPerNft_,
        uint256 maxTotalUnits_
    ) EIP712("Bigo NFT Reward Claim", "1") Ownable(owner_) {
        require(address(token_) != address(0), "Token is zero");
        require(signer_ != address(0), "Signer is zero");
        require(rewardPerNft_ > 0, "Reward is zero");
        require(maxTotalUnits_ > 0, "Cap is zero");
        token = token_;
        signer = signer_;
        rewardPerNft = rewardPerNft_;
        maxTotalUnits = maxTotalUnits_;
        emit SignerChanged(address(0), signer_);
    }

    /// @notice Claim the reward for every eligible NFT not yet paid to the caller.
    /// @param eligibleUnits Total NFTs the caller is eligible for, as signed by the backend.
    function claim(uint256 eligibleUnits, uint256 deadline, bytes calldata signature)
        external
        nonReentrant
        whenNotPaused
    {
        require(block.timestamp <= deadline, "Voucher expired");
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(CLAIM_TYPEHASH, msg.sender, eligibleUnits, deadline))
        );
        require(ECDSA.recover(digest, signature) == signer, "Invalid signature");

        uint256 already = claimedUnits[msg.sender];
        require(eligibleUnits > already, "Nothing to claim");
        uint256 newUnits = eligibleUnits - already;
        require(totalClaimedUnits + newUnits <= maxTotalUnits, "Collection cap reached");

        claimedUnits[msg.sender] = eligibleUnits;
        totalClaimedUnits += newUnits;

        uint256 amount = newUnits * rewardPerNft;
        token.safeTransfer(msg.sender, amount);
        emit Claimed(msg.sender, newUnits, amount);
    }

    /// @notice BIGO currently held by this contract and available for claims.
    function rewardBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function setSigner(address newSigner) external onlyOwner {
        require(newSigner != address(0), "Signer is zero");
        emit SignerChanged(signer, newSigner);
        signer = newSigner;
    }

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    /// @notice Owner can take back unused reward tokens (this contract never holds user deposits).
    function withdraw(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "To is zero");
        token.safeTransfer(to, amount);
        emit Withdrawn(to, amount);
    }
}
