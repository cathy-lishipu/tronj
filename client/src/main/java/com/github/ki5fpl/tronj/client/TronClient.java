package com.github.ki5fpl.tronj.client;

import com.github.ki5fpl.tronj.abi.TypeReference;
import com.github.ki5fpl.tronj.abi.Utils;
import com.github.ki5fpl.tronj.abi.datatypes.Address;
import com.github.ki5fpl.tronj.abi.datatypes.Bool;
import com.github.ki5fpl.tronj.abi.datatypes.Function;
import com.github.ki5fpl.tronj.abi.datatypes.Int;
import com.github.ki5fpl.tronj.abi.datatypes.generated.Uint256;
import com.github.ki5fpl.tronj.api.WalletGrpc;
import com.github.ki5fpl.tronj.crypto.SECP256K1;
import com.github.ki5fpl.tronj.proto.Chain.Transaction;
import com.github.ki5fpl.tronj.proto.Chain.Block;
import com.github.ki5fpl.tronj.proto.Contract.TransferAssetContract;
import com.github.ki5fpl.tronj.proto.Contract.TriggerSmartContract;
import com.github.ki5fpl.tronj.proto.Contract.UnfreezeBalanceContract;
import com.github.ki5fpl.tronj.proto.Contract.FreezeBalanceContract;
import com.github.ki5fpl.tronj.proto.Contract.TransferContract;
import com.github.ki5fpl.tronj.proto.Contract.VoteWitnessContract;
import com.github.ki5fpl.tronj.proto.Response.TransactionExtention;
import com.github.ki5fpl.tronj.proto.Response.TransactionReturn;
import com.github.ki5fpl.tronj.proto.Response.NodeInfo;
import com.github.ki5fpl.tronj.proto.Response.WitnessList;
import com.github.ki5fpl.tronj.api.GrpcAPI.NumberMessage;
import com.github.ki5fpl.tronj.api.GrpcAPI.EmptyMessage;
import com.github.ki5fpl.tronj.api.GrpcAPI.BytesMessage;
import com.github.ki5fpl.tronj.api.GrpcAPI.AccountAddressMessage;
import com.github.ki5fpl.tronj.utils.Base58Check;
import com.google.protobuf.ByteString;
import io.grpc.Channel;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.StatusRuntimeException;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.util.encoders.Hex;
import com.github.ki5fpl.tronj.abi.FunctionEncoder;
import com.github.ki5fpl.tronj.abi.FunctionReturnDecoder;
import com.github.ki5fpl.tronj.proto.Response.NodeList;
import com.github.ki5fpl.tronj.proto.Response.TransactionInfoList;
import com.github.ki5fpl.tronj.proto.Response.TransactionInfo;
import com.github.ki5fpl.tronj.proto.Response.Account;

import static com.github.ki5fpl.tronj.proto.Response.TransactionReturn.response_code.SUCCESS;

public class TronClient {
    public final WalletGrpc.WalletBlockingStub blockingStub;
    public final SECP256K1.KeyPair keyPair;

    public TronClient(String grpcEndpoint, String hexPrivateKey) {
        ManagedChannel channel = ManagedChannelBuilder.forTarget(grpcEndpoint).usePlaintext().build();
        blockingStub = WalletGrpc.newBlockingStub(channel);
        keyPair = SECP256K1.KeyPair.create(SECP256K1.PrivateKey.create(Bytes32.fromHexString(hexPrivateKey)));
    }

    public TronClient(Channel channel, String hexPrivateKey) {
        blockingStub = WalletGrpc.newBlockingStub(channel);
        keyPair = SECP256K1.KeyPair.create(SECP256K1.PrivateKey.create(Bytes32.fromHexString(hexPrivateKey)));
    }

    public static TronClient ofMainnet(String hexPrivateKey) {
        return new TronClient("grpc.trongrid.io:50051", hexPrivateKey);
    }

    public static TronClient ofShasta(String hexPrivateKey) {
        return new TronClient("grpc.shasta.trongrid.io:50051", hexPrivateKey);
    }

    public static TronClient ofNile(String hexPrivateKey) {
        return new TronClient("47.252.19.181:50051", hexPrivateKey);
    }

    public static String generateAddress() {
        // generate random address
        SECP256K1.KeyPair kp = SECP256K1.KeyPair.generate();

        SECP256K1.PublicKey pubKey = kp.getPublicKey();
        Keccak.Digest256 digest = new Keccak.Digest256();
        digest.update(pubKey.getEncoded(), 0, 64);
        byte[] raw = digest.digest();
        byte[] rawAddr = new byte[21];
        rawAddr[0] = 0x41;
        System.arraycopy(raw, 12, rawAddr, 1, 20);

        System.out.println("Base58Check: " + Base58Check.bytesToBase58(rawAddr));
        System.out.println("Hex Address: " + Hex.toHexString(rawAddr));
        System.out.println("Public Key:  " + Hex.toHexString(pubKey.getEncoded()));
        System.out.println("Private Key: " + Hex.toHexString(kp.getPrivateKey().getEncoded()));

        return Hex.toHexString(kp.getPrivateKey().getEncoded());
    }

    public static ByteString parseAddress(String address) {
        if (address.startsWith("T")) {
            byte[] raw = Base58Check.base58ToBytes(address);
            return ByteString.copyFrom(raw);
        } else if (address.startsWith("41")) {
            byte[] raw = Hex.decode(address);
            return ByteString.copyFrom(raw);
        } else if (address.startsWith("0x")) {
            byte[] raw = Hex.decode(address.substring(2));
            return ByteString.copyFrom(raw);
        } else {
            throw new IllegalArgumentException("Invalid address: " + address);
        }
    }

    public static ByteString parseHex(String hexString) {
        byte[] raw = Hex.decode(hexString);
        return ByteString.copyFrom(raw);
    }

    public static String toHex(byte[] raw) {
        return Hex.toHexString(raw);
    }

    public static String toHex(ByteString raw) {
        return Hex.toHexString(raw.toByteArray());
    }

    public Transaction signTransaction(TransactionExtention txnExt, SECP256K1.KeyPair kp) {
        SECP256K1.Signature sig = SECP256K1.sign(Bytes32.wrap(txnExt.getTxid().toByteArray()), kp);
        Transaction signedTxn =
                txnExt.getTransaction().toBuilder().addSignature(ByteString.copyFrom(sig.encodedBytes().toArray())).build();
        return signedTxn;
    }

    public Transaction signTransaction(Transaction txn, SECP256K1.KeyPair kp) {
        SHA256.Digest digest = new SHA256.Digest();
        digest.update(txn.getRawData().toByteArray());
        byte[] txid = digest.digest();
        SECP256K1.Signature sig = SECP256K1.sign(Bytes32.wrap(txid), kp);
        Transaction signedTxn = txn.toBuilder().addSignature(ByteString.copyFrom(sig.encodedBytes().toArray())).build();
        return signedTxn;
    }

    public Transaction signTransaction(TransactionExtention txnExt) {
        return signTransaction(txnExt, keyPair);
    }

    public Transaction signTransaction(Transaction txn) {
        return signTransaction(txn, keyPair);
    }

    public void transfer(String from, String to, long amount) throws Exception {
        System.out.println("Transfer from: " + from);
        System.out.println("Transfer to: " + from);

        byte[] rawFrom = Base58Check.base58ToBytes(from);
        byte[] rawTo = Base58Check.base58ToBytes(to);

        TransferContract req = TransferContract.newBuilder()
                .setOwnerAddress(ByteString.copyFrom(rawFrom))
                .setToAddress(ByteString.copyFrom(rawTo))
                .setAmount(amount)
                .build();
        System.out.println("transfer => " + req.toString());

        TransactionExtention txnExt = blockingStub.createTransaction2(req);
        System.out.println("txn id => " + Hex.toHexString(txnExt.getTxid().toByteArray()));
        System.out.println("Code = " + txnExt.getResult().getCode());
        if(SUCCESS != txnExt.getResult().getCode()){
            System.out.println("Message = " + txnExt.getResult().getMessage().toStringUtf8());
        }

        Transaction signedTxn = signTransaction(txnExt);

        System.out.println(signedTxn.toString());
        TransactionReturn ret = blockingStub.broadcastTransaction(signedTxn);
        System.out.println("======== Result ========\n" + ret.toString());
    }

    public void transferTrc10(String from, String to, int tokenId, long amount) throws Exception {
        System.out.println("Transfer from: " + from);
        System.out.println("Transfer to: " + from);
        System.out.println("Token id: " + tokenId);

        byte[] rawFrom = Base58Check.base58ToBytes(from);
        byte[] rawTo = Base58Check.base58ToBytes(to);
        byte[] rawTokenId = Integer.toString(tokenId).getBytes();

        TransferAssetContract req = TransferAssetContract.newBuilder()
                .setOwnerAddress(ByteString.copyFrom(rawFrom))
                .setToAddress(ByteString.copyFrom(rawTo))
                .setAssetName(ByteString.copyFrom(rawTokenId))
                .setAmount(amount)
                .build();
        System.out.println("transfer TRC10 => " + req.toString());

        TransactionExtention txnExt = blockingStub.transferAsset2(req);
        System.out.println("txn id => " + Hex.toHexString(txnExt.getTxid().toByteArray()));
        System.out.println("Code = " + txnExt.getResult().getCode());
        if(SUCCESS != txnExt.getResult().getCode()){
            System.out.println("Message = " + txnExt.getResult().getMessage().toStringUtf8());
        }

        Transaction signedTxn = signTransaction(txnExt);

        System.out.println(signedTxn.toString());
        TransactionReturn ret = blockingStub.broadcastTransaction(signedTxn);
        System.out.println("======== Result ========\n" + ret.toString());
    }

    public void freezeBalance(String from, long balance, long duration, int resourceCode, String receive) throws Exception {

        byte[] rawFrom = Base58Check.base58ToBytes(from);
        byte[] rawReceive = Base58Check.base58ToBytes(receive);
        FreezeBalanceContract freezeBalanceContract=
                FreezeBalanceContract.newBuilder()
                        .setOwnerAddress(ByteString.copyFrom(rawFrom))
                        .setFrozenBalance(balance)
                        .setFrozenDuration(duration)
                        .setResourceValue(resourceCode)
                        .setReceiverAddress(ByteString.copyFrom(rawReceive))
                        .build();
        System.out.println("freezeBalance => " + freezeBalanceContract.toString());
        TransactionExtention txnExt = blockingStub.freezeBalance2(freezeBalanceContract);
        System.out.println("txn id => " + TronClient.toHex(txnExt.getTxid().toByteArray()));
        System.out.println("Code = " + txnExt.getResult().getCode());
        if(SUCCESS != txnExt.getResult().getCode()){
            System.out.println("Message = " + txnExt.getResult().getMessage().toStringUtf8());
        }

        Transaction signedTxn = signTransaction(txnExt);

        System.out.println(signedTxn.toString());
        TransactionReturn ret = blockingStub.broadcastTransaction(signedTxn);
        System.out.println("======== Result ========\n" + ret.toString());
    }

    public void unfreezeBalance(String from, int resource) {

        UnfreezeBalanceContract unfreeze =
                UnfreezeBalanceContract.newBuilder()
                        .setOwnerAddress(TronClient.parseAddress(from))
                        .setResourceValue(resource)
                        .build();

        TransactionExtention txnExt = blockingStub.unfreezeBalance2(unfreeze);
        System.out.println("txn id => " + TronClient.toHex(txnExt.getTxid().toByteArray()));
        System.out.println("Code = " + txnExt.getResult().getCode());
        if(SUCCESS != txnExt.getResult().getCode()){
            System.out.println("Message = " + txnExt.getResult().getMessage().toStringUtf8());
        }

        Transaction signedTxn = signTransaction(txnExt);

        System.out.println(signedTxn.toString());
        TransactionReturn ret = blockingStub.broadcastTransaction(signedTxn);
        System.out.println("======== Result ========\n" + ret.toString());
    }

    public Block getBlockByNum(long blockNum) {
        NumberMessage.Builder builder = NumberMessage.newBuilder();
        builder.setNum(blockNum);
        System.out.println(blockingStub.getBlockByNum(builder.build()));
        return blockingStub.getBlockByNum(builder.build());
    }

    public Block getNowBlock() {
        System.out.println(blockingStub.getNowBlock(EmptyMessage.newBuilder().build()));
        return blockingStub.getNowBlock(EmptyMessage.newBuilder().build());
    }

    public NodeInfo getNodeInfo() {
        System.out.println(blockingStub.getNodeInfo(EmptyMessage.newBuilder().build()));
        return blockingStub.getNodeInfo(EmptyMessage.newBuilder().build());
    }

    public NodeList listNodes() {
        NodeList nodeList = blockingStub.listNodes(EmptyMessage.newBuilder().build());
        System.out.println(blockingStub.listNodes(EmptyMessage.newBuilder().build()));
        return nodeList;
    }

    public TransactionInfoList getTransactionInfoByBlockNum(long blockNum) {
        NumberMessage.Builder builder = NumberMessage.newBuilder();
        builder.setNum(blockNum);
        TransactionInfoList transactionInfoList = blockingStub.getTransactionInfoByBlockNum(builder.build());
        System.out.println(blockingStub.getTransactionInfoByBlockNum(builder.build()));
        return transactionInfoList;
    }

    public TransactionInfo getTransactionInfoById(String txID) {
        ByteArray byteArray = new ByteArray();
        ByteString bsTxid = ByteString.copyFrom(byteArray.fromHexString(txID));
        BytesMessage request = BytesMessage.newBuilder()
                .setValue(bsTxid)
                .build();
        TransactionInfo transactionInfo = blockingStub.getTransactionInfoById(request);
        System.out.println(blockingStub.getTransactionInfoById(request));
        return transactionInfo;
    }

    public Account getAccount(String address) {
        ByteArray byteArray = new ByteArray();
        ByteString bsAddress;
        String regex="^[A-Fa-f0-9]+$";
        if(address.matches(regex)){
            //HEX
            bsAddress = ByteString.copyFrom(byteArray.fromHexString(address));
        }else{
            byte[] rawAddress = Base58Check.base58ToBytes(address);
            bsAddress = ByteString.copyFrom(rawAddress);
        }
        AccountAddressMessage account = AccountAddressMessage.newBuilder()
                .setAddress(bsAddress)
                .build();
        System.out.println(blockingStub.getAccount(account));
        return blockingStub.getAccount(account);
    }

    public WitnessList listWitnesses() {
        WitnessList witnessList = blockingStub
                .listWitnesses(EmptyMessage.newBuilder().build());
        System.out.println(blockingStub
                .listWitnesses(EmptyMessage.newBuilder().build()));
        return witnessList;
    }

    public boolean voteWitness(String owner, HashMap<String, String> witness){
        byte[] rawFrom = Base58Check.base58ToBytes(owner);
        VoteWitnessContract voteWitnessContract = createVoteWitnessContract(rawFrom, witness);
        TransactionExtention txnExt = blockingStub.voteWitnessAccount2(voteWitnessContract);
        System.out.println(blockingStub.voteWitnessAccount2(voteWitnessContract));

        System.out.println("txn id => " + TronClient.toHex(txnExt.getTxid().toByteArray()));
        System.out.println("Code = " + txnExt.getResult().getCode());
        if(SUCCESS != txnExt.getResult().getCode()){
            System.out.println("Message = " + txnExt.getResult().getMessage().toStringUtf8());
        }

        Transaction signedTxn = signTransaction(txnExt);

        System.out.println(signedTxn.toString());
        TransactionReturn ret = blockingStub.broadcastTransaction(signedTxn);
        System.out.println("======== Result ========\n" + ret.toString());
        return true;
    }

    public static VoteWitnessContract createVoteWitnessContract(byte[] owner,
                                                                HashMap<String, String> witness) {
        VoteWitnessContract.Builder builder = VoteWitnessContract.newBuilder();
        builder.setOwnerAddress(ByteString.copyFrom(owner));
        for (String addressBase58 : witness.keySet()) {
            String value = witness.get(addressBase58);
            long count = Long.parseLong(value);
            VoteWitnessContract.Vote.Builder voteBuilder = VoteWitnessContract.Vote.newBuilder();
            byte[] address = Base58Check.base58ToBytes(addressBase58);
            if (address == null) {
                continue;
            }
            voteBuilder.setVoteAddress(ByteString.copyFrom(address));
            voteBuilder.setVoteCount(count);
            builder.addVotes(voteBuilder.build());
        }

        return builder.build();
    }

}
