// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract Events {
    event LogBytes(bytes message);
    event LogString(string message);
    event LogBytes32(bytes32 message);
    event LogUint(uint256 message);

    function logBytes(bytes calldata message) external {
        emit LogBytes(message);
    }

    function logString(string calldata message) external {
        emit LogString(message);
    }

    function logBytes32(bytes32 message) external {
        emit LogBytes32(message);
    }

    function logUint(uint256 message) external {
        emit LogUint(message);
    }
}
