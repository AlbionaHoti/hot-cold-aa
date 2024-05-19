// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@matterlabs/zksync-contracts/l2/system-contracts/interfaces/IAccount.sol";
import "@matterlabs/zksync-contracts/l2/system-contracts/libraries/TransactionHelper.sol";

import "@openzeppelin/contracts/interfaces/IERC1271.sol";

// Used for signature validation
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// Access zkSync system contracts for nonce validation via NONCE_HOLDER_SYSTEM_CONTRACT
import "@matterlabs/zksync-contracts/l2/system-contracts/Constants.sol";

// to call non-view function of system contracts
import "@matterlabs/zksync-contracts/l2/system-contracts/libraries/SystemContractsCaller.sol";

contract HotColdAA is IAccount, IERC1271 {
    // to get transaction hash
    using TransactionHelper for Transaction;

    // state variables for account owners
    address public hotWallet;
    address public coldWallet;
    uint256 public maxValue;

    constructor(address _hotWallet, address _coldWallet, uint256 _maxValue) {
        hotWallet = _hotWallet;
        coldWallet = _coldWallet;
        maxValue = _maxValue;
    }

    // TODO: check with Vlad on the usage of this one
    modifier onlyAccount() {
        require(msg.sender == address(this), "Only the account that inherits this contract can call this method.");
        _;
    }

    // bytes4 -> dinamically sized byte array
    bytes4 constant EIP1271_SUCCESS_RETURN_VALUE = 0x1626ba7e;

    modifier onlyBootloader() {
        /*
            This modifier ensures that only the bootloader calls the 
                1. validateTransaction
                2. executeTransaction
                3. payForTransaction
                4. prepareForPaymaster
                functions
        */
        require(msg.sender == BOOTLOADER_FORMAL_ADDRESS, "Only bootloader can call this function");
        // Continue execution if called from the bootloader.

        _;
    }

    function validateTransaction(bytes32, bytes32 _suggestedSignedHash, Transaction calldata _transaction)
        external
        payable
        override
        onlyBootloader
        returns (bytes4 magic)
    {
        magic = _validateTransaction(_suggestedSignedHash, _transaction);
    }

    function _validateTransaction(bytes32 _suggestedSignedHash, Transaction calldata _transaction)
        internal
        returns (bytes4 magic)
    {
        // Incrementing the nonce of the account.
        // Note, that reserved[0] by convention is currently equal to the nonce passed in the transaction
        // TODO: What is reserved[0]
        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(INonceHolder.incrementMinNonceIfEquals, (_transaction.nonce))
        );

        /**
         * problem statement: which wallet is signing the transaction?
         *         1. We will receive different tx from different wallets. Based on the wallet, we give more functionality to the owner
         *         How:
         *         1. We'll provide more hints to calldata
         *             - Using the first 1 byte to the calldata, to check if its a hot or cold wallet
         *             - The first 1 byte will provide a hint for the wallet on what to do
         *         2. How to use the one byte from signature? 
         *             - We can check on the validation of the transaction
         *             - signature byte: first byte determines what is the signer, other bytes ...
         */
        bytes32 txHash;
        // While the suggested signed hash is usually provided, it is generally
        // not recommended to rely on it to be present, since in the future there
        // may be tx types with no suggested signed hash.

        if (_suggestedSignedHash == bytes32(0)) {
            txHash = _transaction.encodeHash();
        } else {
            txHash = _suggestedSignedHash;
        }

        // The fact there is enough balance for the account
        // should be checked explicitly to prevent user paying for free for a
        // transaction that wouldn't be included on Ethereum.

        uint256 totalRequiredBalance = _transaction.totalRequiredBalance();
        require(totalRequiredBalance <= address(this).balance, "Not enough balance for fee + value");

        if (isValidSignature(txHash, _transaction.signature) == EIP1271_SUCCESS_RETURN_VALUE) {
            magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;
        } else {
            magic = bytes4(0);
        }

        // I could use first byte of the signature to determine the type of the walelt
        // prev: 65 bytes, now 66, the first byte will present who is the signer, other bytes the signature itself

        bytes1 firstByte = _transaction.signature[0];
        // we reused the first byte to read info

        if (firstByte == 0) {
            _checkRestrictions(_transaction);
        }
    }

    function executeTransaction(bytes32, bytes32, Transaction calldata _transaction)
        external
        payable
        override
        onlyBootloader
    {
        _executeTransaction(_transaction);
    }

    function _executeTransaction(Transaction calldata _transaction) internal {
        address to = address(uint160(_transaction.to));
        uint128 value = Utils.safeCastToU128(_transaction.value);
        bytes memory data = _transaction.data;

        if (to == address(DEPLOYER_SYSTEM_CONTRACT)) {
            uint32 gas = Utils.safeCastToU32(gasleft());

            // Note, that the deployer contract can only be called
            // with a "systemCall" flag.
            SystemContractsCaller.systemCallWithPropagatedRevert(gas, to, value, data);
        } else {
            bool success;
            assembly {
                success := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
            }
            require(success);
        }
    }

    function executeTransactionFromOutside(Transaction calldata _transaction) external payable {
        /*
                This function allows external users to initiate transactions from this account.

                We implement it by calling:
                1. validateTransaction
                2. executeTransaction
             */
        bytes4 magic = _validateTransaction(bytes32(0), _transaction);
        require(magic == ACCOUNT_VALIDATION_SUCCESS_MAGIC, "NOT VALIDATED");

        _executeTransaction(_transaction);
    }

    function isValidSignature(bytes32 _hash, bytes memory _signature) public view override returns (bytes4 magic) {
        // TO BE IMPLEMENTED

        magic = EIP1271_SUCCESS_RETURN_VALUE;
        // COMMENT: Provide data on why we're using this format.

        // we def need to verify -> signature corresponds to one of the wallets -> if we get a random sig, the wallet should not accept it

        /*
            Signature Validation Steps
            1. Check if the length of the received signature is correct, equal to 66
            2. Check if the signatures are in the correct format using the helper function 
                `checkValidEDCSASignatureFormat`
            3. We use EDCSASignatureFormat helper function, to check if the signature is in the correct format and is non-malleable.
            4. 
        
         */
        if (_signature.length != 66) {
            // Signature is invalid, but we need to proceed with the signature verification as usual
            // in order for the fee estimation to work correctly
            _signature = new bytes(66);

            // Making sure that the signature looks like a valid ECDSA signature and we're not rejected
            // rightaway while skipping the main verification process
            // TODO: since we moved forward the signature by one, change this as well
            _signature[65] = bytes1(uint8(27));
        }

        if (!checkValidECDSASignatureFormat(_signature)) {
            magic = bytes4(0);
        }

        address recoveredAddr = ECDSA.recover(_hash, _signature); // by this one we will know who signed the tx

        if (_signature[0] == 0) {
            if (recoveredAddr != hotWallet) {
                magic = bytes4(0);
            }
        } else {
            magic = bytes4(0);
        }
    }

    // Function to check transaction restrictions
    function _checkRestrictions(Transaction calldata _transaction) internal view {
        require(_transaction.value <= maxValue, "Transaction value exceeds the maximum allowed limit.");
    }

    // Function to update the maximum allowed value for transactions
    function setMaxValue(uint256 _newMaxValue) external {
        // only cold wallet will be able to call this function
        require(msg.sender == coldWallet);
        maxValue = _newMaxValue;
    }

    function payForTransaction(bytes32, bytes32, Transaction calldata _transaction)
        external
        payable
        override
        onlyBootloader
    {
        // TO BE IMPLEMENTED

        bool success = _transaction.payToTheBootloader();
        require(success, "Failed to pay the fee to the operator");
    }

    function prepareForPaymaster(
        bytes32, // _txHash
        bytes32, // _suggestedSignedHash
        Transaction calldata _transaction
    ) external payable override onlyBootloader {
        // TO BE IMPLEMENTED
        _transaction.processPaymasterInput();
    }

    // This function verifies that the ECDSA signature is both correct format and non-malleable
    function checkValidECDSASignatureFormat(bytes memory _signature) internal pure returns (bool) {
        /*
            This function checks if the signature is in the correct format and is non-malleable.
            The signature is expected to be in the format of r, s, v where r and s are 33 (since we changed) bytes each and v is 1 byte.
            The signature is expected to be 66 bytes long.
            The v value is expected to be 27 or 28.
            The s value is expected to be less than 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
         */

        if (_signature.length != 66) {
            return false;
        }

        uint8 v;
        bytes32 r;
        bytes32 s;

        // Signature loading code
        // we jump 33 (0x21) as the first slot of bytes contain the length
        // we jump 66 (0x42)
        // for v we load 32 bytes ending with v (the first 31 come from s) then apply a mask
        assembly {
            r := mload(add(_signature, 0x21))
            s := mload(add(_signature, 0x41))
            v := and(mload(add(_signature, 0x42)), 0xff)
        }
        if (v != 27 && v != 28) {
            return false; // ---- what is this?
        }

        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return false;
        }

        return true;
    }

    fallback() external {
        // fallback of default account shouldn't be called by bootloader under no circumstances

        assert(msg.sender != BOOTLOADER_FORMAL_ADDRESS);

        // If the contract is called directly, behave like an EOA
    }

    receive() external payable {
        // If the contract is called directly, behave like an EOA
        // Note, that is okay if the bootloader sends funds with no calldata as it may be used for refunds/operator payments
    }
}
