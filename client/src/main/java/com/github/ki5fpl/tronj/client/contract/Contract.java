package com.github.ki5fpl.tronj.client.contract;

import com.google.protobuf.ByteString;
import com.github.ki5fpl.tronj.proto.Chain.Transaction;
import com.github.ki5fpl.tronj.proto.Common.SmartContract;
import com.github.ki5fpl.tronj.proto.Common.SmartContract.ABI;
import com.github.ki5fpl.tronj.proto.Contract.CreateSmartContract;

import java.util.List;

public class Contract {
    private ByteString originAddr = ByteString.EMPTY;
    private ByteString cntrAddr = ByteString.EMPTY;
    private ABI abi;
    private ByteString bytecode;
    private long callValue = 0;
    private long consumeUserResourcePercent = 100;
    private String name;
    private long originEnergyLimit = 1;
    private ByteString codeHash = ByteString.EMPTY;
    private ByteString trxHash = ByteString.EMPTY;
    private ByteString ownerAddr = ByteString.EMPTY;
    private List<ContractFunction> functions;

    public Contract(ByteString cntrAddr, ABI abi, ByteString bytecode, long consumeUserResourcePercent, String name, long originEnergyLimit) {
        this.cntrAddr = cntrAddr;
        this.abi = abi;
        this.bytecode = bytecode;
        this.consumeUserResourcePercent = consumeUserResourcePercent;
        this.name = name;
        this.originEnergyLimit = originEnergyLimit;
    }

    public Contract(Builder builder) {
        this.originAddr = builder.originAddr;
        this.cntrAddr = builder.cntrAddr;
        this.abi = builder.abi;
        this.bytecode = builder.bytecode;
        this.callValue = builder.callValue;
        this.consumeUserResourcePercent = builder.consumeUserResourcePercent;
        this.name = builder.name;
        this.originEnergyLimit = builder.originEnergyLimit;
        this.ownerAddr = builder.ownerAddr;
    }

    public ByteString getOriginAddr() {
        return originAddr;
    }

    public void setOriginAddr(ByteString originAddr) {
        this.originAddr = originAddr;
    }

    public ByteString getCntrAddr() {
        return cntrAddr;
    }

    public void setCntrAddr(ByteString cntrAddr) {
        this.cntrAddr = cntrAddr;
    }

    public ABI getAbi() {
        return abi;
    }

    public void setAbi(ABI abi) {
        this.abi = abi;
    }

    public ByteString getBytecode() {
        return bytecode;
    }

    public void setBytecode(ByteString bytecode) {
        this.bytecode = bytecode;
    }

    public long getCallValue() {
        return callValue;
    }

    public void setCallValue(long callValue) {
        this.callValue = callValue;
    }

    public long getConsumeUserResourcePercent() {
        return consumeUserResourcePercent;
    }

    public void setConsumeUserResourcePercent(long consumeUserResourcePercent) {
        this.consumeUserResourcePercent = consumeUserResourcePercent;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public long getOriginEnergyLimit() {
        return originEnergyLimit;
    }

    public void setOriginEnergyLimit(long originEnergyLimit) {
        this.originEnergyLimit = originEnergyLimit;
    }

    public ByteString getCodeHash() {
        return codeHash;
    }

    public void setCodeHash(ByteString codeHash) {
        this.codeHash = codeHash;
    }

    public ByteString getTrxHash() {
        return trxHash;
    }

    public void setTrxHash(ByteString trxHash) {
        this.trxHash = trxHash;
    }

    public ByteString getOwnerAddr() {
        return ownerAddr;
    }

    public void setOwnerAddr(ByteString ownerAddr) {
        this.ownerAddr = ownerAddr;
    }


    //contract builder
    public static class Builder {
        private ByteString originAddr = ByteString.EMPTY;
        private ByteString cntrAddr = ByteString.EMPTY;
        private ABI abi;
        private ByteString bytecode;
        private long callValue = 0;
        private long consumeUserResourcePercent = 100;
        private String name;
        private long originEnergyLimit = 1;
        private ByteString codeHash = ByteString.EMPTY;
        private ByteString trxHash = ByteString.EMPTY;
        private ByteString ownerAddr = ByteString.EMPTY;

        public Builder setOriginAddr(ByteString originAddr) {
            this.originAddr = originAddr;
            return this;
        }

        public Builder setCntrAddr(ByteString cntrAddr) {
            this.cntrAddr = cntrAddr;
            return this;
        }

        public Builder setAbi(ABI abi) {
            this.abi = abi;
            return this;
        }

        public Builder setBytecode(ByteString bytecode) {
            this.bytecode = bytecode;
            return this;
        }

        public Builder setCallValue(long callValue) {
            this.callValue = callValue;
            return this;
        }

        public Builder setConsumeUserResourcePercent(long consumeUserResourcePercent) {
            this.consumeUserResourcePercent = consumeUserResourcePercent;
            return this;
        }

        public Builder setName(String name) {
            this.name = name;
            return this;
        }

        public Builder setOriginEnergyLimit(long originEnergyLimit) {
            this.originEnergyLimit = originEnergyLimit;
            return this;
        }

        public Builder setOwnerAddr(ByteString ownerAddr) {
            this.ownerAddr = ownerAddr;
            return this;
        }

        public Contract build() {
            return new Contract(this);
        }
    }

    private void abiToFunctions() {

    }

    public SmartContract toProto() {
        return SmartContract.newBuilder()
                   .setOriginAddress(originAddr)
                   .setContractAddress(cntrAddr)
                   .setAbi(abi)
                   .setBytecode(bytecode)
                   .setCallValue(callValue)
                   .setConsumeUserResourcePercent(consumeUserResourcePercent)
                   .setName(name)
                   .setOriginEnergyLimit(originEnergyLimit)
                   .setTrxHash(trxHash)
                   .build();
    }

    public CreateSmartContract deploy() {
        //No deposit when creating contract
        return deploy(0, 0);
    }

    public CreateSmartContract deploy(long callTokenValue, long tokenId) {
        //throws if deployed
        if (this.cntrAddr.isEmpty()) {
            throw new RuntimeException("This contract has already been deployed.");
        }
        //throws if origin address does not match owner address
        if (!this.originAddr.equals(this.ownerAddr)) {
            throw new RuntimeException("Origin address and owner address mismatch.");
        }
        //create
        CreateSmartContract.Builder builder = CreateSmartContract.newBuilder();
        builder.setOwnerAddress(ownerAddr);
        builder.setNewContract(toProto());
        //if any deposit
        if (tokenId != 0) {
            builder.setTokenId(tokenId);
            builder.setCallTokenValue(callTokenValue);
        }

        return builder.build();
    }
}