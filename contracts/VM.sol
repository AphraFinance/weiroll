// SPDX-License-Identifier: MIT
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

import {Auth, Authority} from "solmate/auth/Auth.sol";
import "./CommandBuilder.sol";
uint8 constant FLAG_CT_DELEGATECALL = 0x00;
uint8 constant FLAG_CT_CALL = 0x01;
uint8 constant FLAG_CT_STATICCALL = 0x02;
uint8 constant FLAG_CT_VALUECALL = 0x03;
uint8 constant FLAG_CT_MASK = 0x03;
uint8 constant FLAG_EXTENDED_COMMAND = 0x80;
uint8 constant FLAG_TUPLE_RETURN = 0x40;

uint256 constant SHORT_COMMAND_FILL = 0x000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;


//change registry to a simple contract that manages registering new contracts into the authority via some process
//
//contract Registry {
//    mapping(address => mapping(bytes4 => bool)) public isActiveCommand;
//
//    mapping(bytes32 => bool) public byteCodeAllowList;
//
//    address governance;
//
//    address futureGovernance;
//
//    modifier onlyGovernance() {
//        require(address(msg.sender) == governance);
//        _;
//    }
//
//    constructor(address multiSig) {
//        governance = multiSig;
//    }
//
//    function transferGovernance(address governance) external onlyGovernance {
//        futureGovernance = governance;
//    }
//
//    function acceptGovernance() external {
//        require(msg.sender == futureGovernance, "must be futureGovernance to accept");
//        governance = futureGovernance;
//        futureGovernance = address(0);
//    }
//
//    function isValidCommand(address contractAddress, bytes4 selector)
//    public
//    view
//    returns (bool valid) {
//        bytes32 codeHash;
//        assembly {codeHash := extcodehash(externalContract)}
//
//        valid = (byteCodeAllowList[codeHash] && isActiveCommand[contractAddress][selector]);
//    }
//
//    function registerNewCommands(address[] contractsToEnable, bytes4[] selectorsToEnable)
//    public
//    onlyGovernance {
//        require(contractsToEnable.length == selectorsToEnable.length, "invalid length mismatch");
//        for (uint i = 0; i < contractsToEnable.length; i++) {
//            _registerNewContract(contractsToEnable[i], selectorsToEnable[i]);
//        }
//    }
//
//    modifier onlyGovernance() {
//        require(address(msg.sender) == guardian);
//        _;
//    }
//    function _registerNewContract(address externalContract, bytes4 selector) external onlyGovernance {
//        bytes32 codeHash;
//        assembly {codeHash := extcodehash(externalContract)}
//
//        require(!isActiveCommand[externalContract][selector], "Command already added");
//
//        byteCodeAllowList[codeHash] = true; //set into its own function maybe for 2 step activation, code and then contract/selector
//        isActiveCommand[externalContract][selector] = true;
//    }
//}
//
//interface IRegistry {
//    function isValidCommand(address contractAddress, bytes4 selector)
//    public
//    view
//    returns (bool valid);
//}

contract VM is Auth {
    using CommandBuilder for bytes[];

    address immutable self;

    error CmdNoAuth(address target, bytes4 selector);

    modifier ensureDelegateCall() {
        require(address(this) != self);
        _;
    }

    constructor(
        address GOVERNANCE_,
        address AUTHORITY_
    ) Auth(GOVERNANCE_, Authority(AUTHORITY_)) {
        self = address(this);
    }

    function execute(bytes32[] calldata commands, bytes[] memory state)
    public
    ensureDelegateCall
    requiresAuth
    returns (bytes[] memory)
    {
        bytes32 command;
        uint256 flags;
        bytes32 indices;

        bool success;
        bytes memory outdata;

        for (uint256 i = 0; i < commands.length; i++) {
            command = commands[i];
            address target = address(uint160(uint256(command)));
            bytes4 selector = bytes4(command);
            //check the calling contract(via delegate) against the command address and the function selector
            if( authority.canCall(address(this), target, selector) == false ) revert CmdNoAuth(target, selector);

            flags = uint8(bytes1(command << 32));

            if (flags & FLAG_EXTENDED_COMMAND != 0) {
                indices = commands[i++];
            } else {
                indices = bytes32(uint256(command << 40) | SHORT_COMMAND_FILL);
            }

            if (flags & FLAG_CT_MASK == FLAG_CT_DELEGATECALL) {
                (success, outdata) = target // target
                .delegatecall(
                // inputs
                    state.buildInputs(
                    //selector
                        selector,
                        indices
                    )
                );
            } else if (flags & FLAG_CT_MASK == FLAG_CT_CALL) {
                (success, outdata) = target.call(// target
                // inputs
                    state.buildInputs(
                    //selector
                        selector,
                        indices
                    )
                );
            } else if (flags & FLAG_CT_MASK == FLAG_CT_STATICCALL) {
                (success, outdata) = target // target
                .staticcall(
                // inputs
                    state.buildInputs(
                    //selector
                        selector,
                        indices
                    )
                );
            } else if (flags & FLAG_CT_MASK == FLAG_CT_VALUECALL) {
                uint256 calleth;
                bytes memory v = state[uint8(bytes1(indices))];
                assembly {
                    mstore(calleth, add(v, 0x20))
                }
                (success, outdata) = target.call{// target
                value : calleth
                }(
                // inputs
                    state.buildInputs(
                    //selector
                        selector,
                        bytes32(uint256(indices << 8) | IDX_END_OF_ARGS)
                    )
                );
            } else {
                revert("Invalid calltype");
            }

            require(success, "Call failed");

            if (flags & FLAG_TUPLE_RETURN != 0) {
                state.writeTuple(bytes1(command << 88), outdata);
            } else {
                state = state.writeOutputs(bytes1(command << 88), outdata);
            }
        }
        return state;
    }
}
