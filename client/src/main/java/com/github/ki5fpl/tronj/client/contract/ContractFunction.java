package com.github.ki5fpl.tronj.client.contract;

import com.google.protobuf.ByteString;
import com.github.ki5fpl.tronj.proto.Common.SmartContract.ABI.Entry;

import java.util.List;

public class ContractFunction {
    private Entry abi;
    private Contract cntr;
    private ByteString ownerAddr;
    private List<String> inputParams;
    private List<String> inputTypes;
    private List<String> outputs;
    private List<String> outputTypes;
    private long callValue = 0;
    private long callTokenValue = 0;
    private int callTokenId = 0;

  public ContractFunction(Entry abi, Contract cntr, ByteString ownerAddr, List<String> inputParams, List<String> inputTypes, List<String> outputs, List<String> outputTypes) {
    this.abi = abi;
    this.cntr = cntr;
    this.ownerAddr = ownerAddr;
    this.inputParams = inputParams;
    this.inputTypes = inputTypes;
    this.outputs = outputs;
    this.outputTypes = outputTypes;
  }
}