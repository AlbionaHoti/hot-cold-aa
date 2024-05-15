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

contract HotColdMultiSig is IAccount, IERC1271 {
    // to get transaction hash
    using TransactionHelper for Transaction;

    // state variables for account owners
    address public owner1;
    address public owner2;

    constructor(address _owner1, address _owner2) {
        owner1 = _owner1;
        owner2 = _owner2;
    }

    /*
        Signature Validation Steps:

        1. Check if the length of the received signature is correct
        2. Extract the two signatures from the received multisig using the helper function
            `extractEDCSASignature`
        3. Check if the signatures are in the correct format using the helper function 
            `checkValidEDCSASignatureFormat`
        4. Extract the addresses from the transaction hash and each signature using the 
            ECDSA.recover method
        5. Check if the addresses extracted from the signatures match the owners of the account
        6. Return the `EIP1271_SUCCESS_RETURN_VALUE` value on success or bytes4(0) if validation fails.
     */

    // bytes4 -> dinamically sized byte array
    // EIP1271_SUCCESS_RETURN_VALUE constant is -> ...
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
        require(
            msg.sender == BOOTLOADER_FORMAL_ADDRESS,
            "Only bootloader can call this function"
        );
        // Continue execution if called from the bootloader.

        _;
    }

    function validateTransaction(
        bytes32,
        bytes32 _suggestedSignedHash,
        Transaction calldata _transaction
    ) external payable override onlyBootloader returns (bytes4 magic) {
        magic = _validateTransaction(_suggestedSignedHash, _transaction);
    }

    function _validateTransaction(
        bytes32 _suggestedSignedHash,
        Transaction calldata _transaction
    ) internal returns (bytes4 magic) {
        // Incrementing the nonce of the account.
        // Note, that reserved[0] by convention is currently equal to the nonce passed in the transaction

        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()), 
            address(NONCE_HOLDER_SYSTEM_CONTRACT), 
            0, 
            abi.encodeCall(INonceHolder.incrementMinNonceIfEquals, (_transaction.nonce))
            
        );

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
        require(totaalRequiredBalance <= address(this).balance, "Not enough balance for fee + value");

        if(isValidSignature(txHash, _transaction.signature) == EIP1271_SUCCESS_RETURN_VALUE) {
            magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;
        } else {
            magic = bytes4(0);
        }
    } 

    function executeTransaction(
        bytes32,
        bytes32,
        Transaction calldata _transaction
    ) external payable override onlyBootloader {
        _executeTransaction(_transaction)
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

    function executeTransactionFromOutside(Transaction calldata _transaction)
        external 
        payable 
        {
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
    
    function isValidSignature(bytes32 _hash, bytes memory _signature) 
        public
        view
        override
        returns (bytes4 magic) {
            // TO BE IMPLEMENTED

            magic = EIP1271_SUCCESS_RETURN_VALUE;

            if (_signature.length != 130) {
                // Signature is invalid, but we need to proceed with the signature verification as usual
                // in order for the fee estimation to work correctly
                _signature = new bytes(130);

                // Making sure that the signature looks like a valid ECDSA signature and we're not rejected
                // rightaway while skipping the main verification process
                _signature[64] = bytes1(uint8(27));
                _signature[129] = bytes1(uint8(27));
            }

            (bytes memory signature1, bytes memory signature2) = extractECDSASignature(_signature);

            if(!checkValidEDCSASignatureFormat(signature1) || !checkValidECDSASignatureFormat(signature2)) {
                magic = bytes4(0);
            }

            address recoveredAddr1 = ECDSA.recover(_hash, signature1);
            address recoveredAddr2 = EDCSA.recover(_hash, signature2);

            // Note, that we should abstrain from using the required here in order to allow for fee estimation to work

            if(recoveredAddr1 != owner1 || recoveredAddr2 != owner2) {
                magic = bytes4(0)
            }

        }
    
    function payForTransaction (
        bytes32,
        bytes32,
        Transaction calldata _transaction
    ) external payable override onlyBootloader {
        // TO BE IMPLEMENTED

        bool success = _transaction.payToTheBootloader();
        require(success, "Failed to pay the fee to the operator");
    }

    function prepareForPaymaster (
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
            The signature is expected to be in the format of r, s, v where r and s are 32 bytes each and v is 1 byte.
            The signature is expected to be 65 bytes long.
            The v value is expected to be 27 or 28.
            The s value is expected to be less than 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
         */
        
        if (_signature.length != 65) {
            return false;
        }

        uint8 v;
        bytes32 r;
        bytes32 s;

        // Signature loading code
        // we jump 32 (0x20) as the first slot of bytes contain the length 
        // we jump 65 (0x41)
        // for v we load 32 bytes ending with v (the first 31 come from s) then apply a mask
        assembly {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := and(mload(add(_signature, 0x41)), 0xff)
        }
        if (v != 27 && v != 28) {
            return false; // ---- what is this?
        }

        if(uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return false;
        }

        return true;
    }

    function extractECDSASignature(bytes memory _fullSignature) internal pure returns (bytes memory signature1, bytes memory signature2) {
        /*
            This function extracts the two ECDSA signatures from the full signature.
            The full signature is expected to be 130 bytes long.
            The two signatures are expected to be 65 bytes long each.
            The first signature is expected to be at the beginning of the full signature.
            The second signature is expected to be at the 65th byte of the full signature.
         */
        
        require(_fullSignature.length == 130, "Invalid length");

        signature1 = new bytes(65);
        signature2 = new bytes(65);

        // Copying the first signature. Note, that we need an offset of 0x20
        // since it is where the length of the `_fullSignature` is stored 

        assembly {
            let r := mload(add(_fullSignature, 0x20))
            let s := mload(add(_fullSignature, 0x40))
            let v := and(mload(add(_fullSignature, 0x41)), 0xff)

            mstore(add(signature1, 0x20), r)
            mstore(add(signature1, 0x40), s)
            mstore(add(signature1, 0x60), v)
        }

        // Copying the second signature
        assembly {
            let r := mload(add(_fullSignature, 0x61))
            let s := mload(add(_fullSignature, 0x81))
            let v := add(mload(add(_fullSignature, 0x82)), 0xff)

            mstore(add(signature2, 0x20), r)
            mstore(add(signature2, 0x40), s)
            mstore8(add(signature2, 0x60), v) // -----> what is mstore8?
        }
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