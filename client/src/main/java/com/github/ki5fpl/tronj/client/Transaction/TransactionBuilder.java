package com.github.ki5fpl.tronj.client.transaction;

import com.google.protobuf.ByteString;
import com.github.ki5fpl.tronj.proto.Chain.Transaction;

public class TransactionBuilder {
    private Transaction transaction;

    public TransactionBuilder(Transaction transaction) {
        this.transaction = transaction;
    }

    public Transaction getTransaction() {
        return transaction;
    }

    public void setTransaction(Transaction transaction) {
        this.transaction = transaction;
    }

    public TransactionBuilder setFeeLimit(long feeLimit) {
        transaction.toBuilder()
            .setRawData(transaction.getRawData().toBuilder().setFeeLimit(feeLimit))
            .build();
        return this;
    } 

    public TransactionBuilder setPermissionId(int permissionId) {
        transaction.getRawData().toBuilder()
            .setContract(0, transaction.getRawData().getContract(0).toBuilder().setPermissionId(permissionId))
            .build();
        return this;
    }

    public TransactionBuilder setMemoFromByte(byte[] memo) {
        transaction.toBuilder()
            .setRawData(transaction.getRawData().toBuilder().setData(ByteString.copyFrom(memo)))
            .build();
        return this;
    }

    public TransactionBuilder setMemoFromString(String memo) {
        transaction.toBuilder()
            .setRawData(transaction.getRawData().toBuilder().setData(ByteString.copyFromUtf8(memo)))
            .build();
        return this;
    }

    public Transaction build() {
        return this.transaction;
    }
}