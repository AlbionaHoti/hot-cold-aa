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

import "@openzeppelin/contracts/access/Ownable.sol";


contract HotColdAA is IAccount, IERC1271, Ownable {
    // to get transaction hash
    using TransactionHelper for Transaction;

    // setting the limit to 24 hr
    uint public ONE_DAY = 1 minutes;

    // state variables for account owners
    address public hotWallet;
    address public coldWallet;
    uint256 public maxValue;

    constructor(address _hotWallet, address _coldWallet, uint256 _maxValue) {
        hotWallet = _hotWallet;
        coldWallet = _coldWallet;
        maxValue = _maxValue
    }

    // A new struct that serves as data storage of hot wallet daily spending limits users enable
    // limit: the amount of a daily spending limit
    // available: the available amount that can be spent
    // resetTime: block.timestamp at the available amount is restored
    // isEnabled: true when a daily spending limit is enabled

    struct LimitTimeSpending {
        // comments for the hot and cold wallet
        uint limit; // the actual restriction
        uint available; // checking the amount of money available?
        uint resetTime; // we need this to reset the daily limit timing
        bool isEnabled; // I don't need this, bc we're not enabling limit, the restriction will happen directly
    }

    mapping(address => LimitTimeSpending) public limits; // token => Limit, we're mapping the address 
    // Note that the limits mapping uses the token address as its key. This means that users can set limits for ETH and any other ERC20 token.


    // TODO: check with Vlad ->
    /*
            Slots of type keccak256(A || X) on any other address. 
            (to cover mapping(address => value), which is usually used for balance in ERC20 tokens).
            -> I want to check the balance of ETH only transactions, so this AA will only limit the ETH token spending.

            - Is this mapping okay -> since `limits` will be used uder the checkRestrictions which is called from isValidSignature
     */

    
    // TODO: check with Vlad on the usage of this one
    modifier onlyAccount() {
        require(
            msg.sender == address(this),
            "Only the account that inherits this contract can call this method."
        );
        _;
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
        /**

         - problem statement: which wallet is signing the transaction ->
            - receiving different tx from different wallets -> based on the wallet we give more functionalities
                - bruto force recovery of each wallet 
                    1. lets try if its cold wallet -> verification succeed? -> recover
                    2.   else: hot wallet
                    3. If its neither -> reject   

                - provide hint to calldata
                    1. use 1 byte to the calldata -> to see if its hot or cold wallet
                       -> one small byte somewhere to store that will provide a hint for the wallet on what to do

                - how to use one byte from signature -> 
                    1. on the validation of the transaction 

                - signature byte: first byte determines what is the signer, other bytes ...

                

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

        // TODO: Check with Vlad if we need to check on here, or just when we validate the transaction -> that's where we pass it to be executed?
        // Spending limit tutorial: Call SpendLimit contract to ensure that ETH `value` doesn't exceed the daily spending limit
        if (value > 0) {
            _checkSpendingLimit(address(ETH_TOKEN_SYSTEM_CONTRACT), value);
        }

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

            // we def need to verify -> signature corresponds to one of the wallets -> if we get a random sig, the wallet should not accept it

            if (_signature.length != 65) {
                // we will have one signature to receive

                // Signature is invalid, but we need to proceed with the signature verification as usual
                // in order for the fee estimation to work correctly
                _signature = new bytes(65);

                // Making sure that the signature looks like a valid ECDSA signature and we're not rejected
                // rightaway while skipping the main verification process
                _signature[64] = bytes1(uint8(27));
            }

            // (bytes memory signature) = extractECDSASignature(_signature);

            // we need to extract the type of the signer
            // we don't need this one, we just need to check if the sig is length 65, that's enough -> TODO: delete this later
            // (bytes memory signature, uint8 signerType) = extractECDSASignature(_signature);


            // signerType

            // if we don't check this one, 65 bytes of the signature -> if we allow big signature lengths, and we verify that
            // it's pretty bad, as a user you send tx as a user, and someone can modify the signature to do smth more on your wallet
            // limited attack -> provide bigger signatuers, and bootloader will accept these sigtures -> force you to spend more gas
            // you send a tx, you have a tx hash (metamask will have it) -> the final tx is not matching, for user...

            if(!checkValidECDSASignatureFormat(signature)) {
                magic = bytes4(0);
            }

            address recoveredAddr = ECDSA.recover(_hash, signature); // by this one we will know who signed the tx
            // address can mean that there's a private key <-> address -> cold wallet and hot wallet, just addresses
            // that sign messages

            // address recoveredAddr2 = EDCSA.recover(_hash, signature2);

            // Note, that we should abstrain from using the required here in order to allow for fee estimation to work

            // compare the recoveredAdd if its cold or hot wallet
            // compare the recoveredAdd to the hot wallet -> it will return me an address that signed the tx ->
            
            // what call we want to have in the code -> GOAL: what wallet signs the message?

            if (recoveredAddr == hotWallet) {
                // a func -> we don't need to know in advance ->
                checkRestrictions(_transaction);
            } 

            // a func -> base behavior -> they can do whatever
          

            if(recoveredAddr != hotWallet && recoveredAddr != coldWallet) {
                magic = bytes4(0)
            }

        }

     // Function to check transaction restrictions
    function checkRestrictions(Transaction calldata _transaction) external view {
        require(_transaction.value <= maxValue, "Transaction value exceeds the maximum allowed limit.");
    }

     // Function to update the maximum allowed value for transactions
    function setMaxValue(uint256 _newMaxValue) external onlyOwner {
        maxValue = _newMaxValue;
    }

    // function checkRestrictions(Transaction calldata _transaction) internal {

    //     // get the value that is passed with that transaction to add restrictions
    //     // I need a daily spending restriction for the hot wallet

    //     uint amount = _transaction.value;
    //     require(amount != 0, "Invalid amount");

    //     // see the daily spending limit and use it here

    //     // split it into logical parts

    //     // TODO: Restrict the value X

    //     Limit memory limit = limits[_token];

    //     // return if spending limit hasn't been enabled yet
    //     // if (!limit.isEnabled) return;

    //     uint timestamp = block.timestamp; // L2 block timestamp, to limit the daily spend on the hot wallet

        

    //     // TODO: from the docs, it's stated the below -> check with Vlad
    //     /*
    //         * The account logic can not use context variables (e.g. block.number).
    //           - does this mean that I need to call the checkRestrictions from the executeTransaction step, and not the isValidSignature step? 
         
    //         * I think I need this check:
    //             - Reverts unless it is first spending after enabling
    //               or called after 24 hours have passed since the last update.
        
    //     if (limits[_token].isEnabled) {
    //         require(
    //             limits[_token].limit == limits[_token].available ||
    //                 block.timestamp > limits[_token].resetTime,
    //             "Invalid Update"
    //         );

    //         return true;
    //     } else {
    //         return false;
    //     }
    //      */

    //     // Renew resetTime and available amount, which is only performed
    //     // if a day has already passed since the last update: timestamp > resetTime
    //     // if (limit.limit != limit.available && timestamp > limit.resetTime) {
    //     //     limit.resetTime = timestamp + ONE_DAY;
    //     //     limit.available = limit.limit;

    //     //     // Or only resetTime is updated if it's the first spending after enabling limit
    //     // } else if (limit.limit == limit.available) {
    //     //     limit.resetTime = timestamp + ONE_DAY;
    //     // }

    //     // // reverts if the amount exceeds the remaining available amount.
    //     // require(limit.available >= _amount, "Exceed daily limit");

    //     // // decrement `available`
    //     // limit.available -= _amount;
    //     // limits[_token] = limit;

    //     // _updateLimit(_amount, _amount, resetTime, true);

    //     // magic = bytes4(0)

    // }

    
    // storage-modifying private function called by either setSpendingLimit or removeSpendingLimit (in our case: checkRestrictions)
    // function _updateLimit(
    //     address _token,
    //     uint _limit,
    //     uint _available,
    //     uint _resetTime,
    //     bool _isEnabled
    // ) private {
    //     Limit storage limit = limits[_token];
    //     limit.limit = _limit;
    //     limit.available = _available;
    //     limit.resetTime = _resetTime;
    //     limit.isEnabled = _isEnabled;
    // }


    // this function is called by the account before execution.
    // 
    function _checkSpendingLimit(address _token, uint _amount) internal {
        Limit memory limit = limits[_token];

        // return if spending limit hasn't been enabled yet
        if (!limit.isEnabled) return;

        uint timestamp = block.timestamp; // L2 block timestamp

        // Renew resetTime and available amount, which is only performed
        // if a day has already passed since the last update: timestamp > resetTime
        if (limit.limit != limit.available && timestamp > limit.resetTime) {
            limit.resetTime = timestamp + ONE_DAY;
            limit.available = limit.limit;

            // Or only resetTime is updated if it's the first spending after enabling limit
        } else if (limit.limit == limit.available) {
            limit.resetTime = timestamp + ONE_DAY;
        }

        // reverts if the amount exceeds the remaining available amount.
        require(limit.available >= _amount, "Exceed daily limit");

        // decrement `available`
        limit.available -= _amount;
        limits[_token] = limit;
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