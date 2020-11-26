package org.tron.tronj.client;


/**
 * A {@code TronClient} object is the entry point for calling the functions.
 *
 *<p>A {@code TronClient} object is bind with a private key and a full node.
 * {@link #broadcastTransaction}, {@link #signTransaction} and other transaction related
 * operations can be done via a {@code TronClient} object.</p>
 *
 * @since jdk13.0.2+8
 * @see org.tron.tronj.client.contract.Contract
 * @see org.tron.tronj.proto.Chain.Transaction
 * @see org.tron.tronj.proto.Contract
 */

import org.tron.tronj.abi.TypeReference;
import org.tron.tronj.abi.datatypes.Address;
import org.tron.tronj.abi.datatypes.Bool;
import org.tron.tronj.abi.datatypes.generated.Uint256;


import org.tron.tronj.abi.FunctionEncoder;
import org.tron.tronj.abi.datatypes.Function;
import org.tron.tronj.api.GrpcAPI;
import org.tron.tronj.api.GrpcAPI.BytesMessage;

import org.tron.tronj.api.WalletGrpc;
import org.tron.tronj.client.contract.Contract;
import org.tron.tronj.client.contract.ContractFunction;
import org.tron.tronj.client.Transaction.TransactionBuilder;
import org.tron.tronj.crypto.SECP256K1;
import org.tron.tronj.proto.Chain.Transaction;

import org.tron.tronj.proto.Chain.Block;

import org.tron.tronj.proto.Common.SmartContract;

import org.tron.tronj.proto.Contract.TransferAssetContract;
import org.tron.tronj.proto.Contract.UnfreezeBalanceContract;
import org.tron.tronj.proto.Contract.FreezeBalanceContract;
import org.tron.tronj.proto.Contract.TransferContract;
import org.tron.tronj.proto.Contract.VoteWitnessContract;
import org.tron.tronj.proto.Contract.TriggerSmartContract;
import org.tron.tronj.proto.Response.TransactionExtention;
import org.tron.tronj.proto.Response.TransactionReturn;
import org.tron.tronj.proto.Response.NodeInfo;
import org.tron.tronj.proto.Response.WitnessList;
import org.tron.tronj.api.GrpcAPI.NumberMessage;
import org.tron.tronj.api.GrpcAPI.EmptyMessage;
import org.tron.tronj.api.GrpcAPI.AccountAddressMessage;
import org.tron.tronj.utils.Base58Check;
import com.google.protobuf.ByteString;
import io.grpc.Channel;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;

import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.util.encoders.Hex;
import org.tron.tronj.proto.Response.NodeList;
import org.tron.tronj.proto.Response.TransactionInfoList;
import org.tron.tronj.proto.Response.TransactionInfo;
import org.tron.tronj.proto.Response.Account;

import static org.tron.tronj.proto.Response.TransactionReturn.response_code.SUCCESS;

import java.util.List;

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
        byte[] raw = new byte[0];
        if (address.startsWith("T")) {
            raw = Base58Check.base58ToBytes(address);
        } else if (address.startsWith("41")) {
            raw = Hex.decode(address);
        } else if (address.startsWith("0x")) {
            raw = Hex.decode(address.substring(2));
        } else {
            try {
                raw = Hex.decode(address);
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid address: " + address);
            }
        }
        return ByteString.copyFrom(raw);
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

    public TransactionReturn broadcastTransaction(Transaction txn) {
        return blockingStub.broadcastTransaction(txn);
    }

    public Transaction signTransaction(TransactionExtention txnExt) {
        return signTransaction(txnExt, keyPair);
    }

    public Transaction signTransaction(Transaction txn) {
        return signTransaction(txn, keyPair);
    }

    public void transfer(String from, String to, long amount) {
        System.out.println("Transfer from: " + from);
        System.out.println("Transfer to: " + from);

        ByteString rawFrom = parseAddress(from);
        ByteString rawTo = parseAddress(to);

        TransferContract req = TransferContract.newBuilder()
                .setOwnerAddress(rawFrom)
                .setToAddress(rawTo)
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

    public void transferTrc10(String from, String to, int tokenId, long amount) {
        System.out.println("Transfer from: " + from);
        System.out.println("Transfer to: " + from);
        System.out.println("Token id: " + tokenId);

        ByteString rawFrom = parseAddress(from);
        ByteString rawTo = parseAddress(to);
        byte[] rawTokenId = Integer.toString(tokenId).getBytes();

        TransferAssetContract req = TransferAssetContract.newBuilder()
                .setOwnerAddress(rawFrom)
                .setToAddress(rawTo)
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

    public void freezeBalance(String from, long balance, long duration, int resourceCode, String receive) {

        ByteString rawFrom = parseAddress(from);
        ByteString rawReceive = parseAddress(receive);
        FreezeBalanceContract freezeBalanceContract=
                FreezeBalanceContract.newBuilder()
                        .setOwnerAddress(rawFrom)
                        .setFrozenBalance(balance)
                        .setFrozenDuration(duration)
                        .setResourceValue(resourceCode)
                        .setReceiverAddress(rawReceive)
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
                        .setOwnerAddress(parseAddress(from))
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
        ByteString bsTxid = parseAddress(txID);
        BytesMessage request = BytesMessage.newBuilder()
                .setValue(bsTxid)
                .build();
        TransactionInfo transactionInfo = blockingStub.getTransactionInfoById(request);
        System.out.println(blockingStub.getTransactionInfoById(request));
        return transactionInfo;
    }

    public Account getAccount(String address) {
        ByteString bsAddress = parseAddress(address);
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

    public boolean voteWitness(String owner, HashMap<String, String> witness) {
        ByteString rawFrom = parseAddress(owner);
        VoteWitnessContract voteWitnessContract = createVoteWitnessContract(rawFrom, witness);
        TransactionExtention txnExt = blockingStub.voteWitnessAccount2(voteWitnessContract);
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


    public static VoteWitnessContract createVoteWitnessContract(ByteString owner,
                                                                HashMap<String, String> witness) {
        VoteWitnessContract.Builder builder = VoteWitnessContract.newBuilder();
        builder.setOwnerAddress(owner);
        for (String addressBase58 : witness.keySet()) {
            String value = witness.get(addressBase58);
            long count = Long.parseLong(value);
            VoteWitnessContract.Vote.Builder voteBuilder = VoteWitnessContract.Vote.newBuilder();
            ByteString address = parseAddress(addressBase58);
            if (address == null) {
                continue;
            }
            voteBuilder.setVoteAddress(address);
            voteBuilder.setVoteCount(count);
            builder.addVotes(voteBuilder.build());
        }

        return builder.build();
    }

    public void transferTrc20(String from, String to, String cntr, long feeLimit, long amount, int precision) throws Exception {
        System.out.println("============ TRC20 transfer =============");

        // transfer(address _to,uint256 _amount) returns (bool)
        // _to = TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA
        // _amount = 10 * 10^18
        Function trc20Transfer = new Function("transfer",
            Arrays.asList(new Address(to),
                new Uint256(BigInteger.valueOf(amount).multiply(BigInteger.valueOf(10).pow(precision)))),
            Arrays.asList(new TypeReference<Bool>() {}));

        String encodedHex = FunctionEncoder.encode(trc20Transfer);
        TriggerSmartContract trigger =
            TriggerSmartContract.newBuilder()
                .setOwnerAddress(TronClient.parseAddress(from))
                .setContractAddress(TronClient.parseAddress(cntr)) // JST
                .setData(TronClient.parseHex(encodedHex))
                .build();

        System.out.println("trigger:\n" + trigger);

        TransactionExtention txnExt = blockingStub.triggerContract(trigger);
        System.out.println("txn id => " + TronClient.toHex(txnExt.getTxid().toByteArray()));
        System.out.println("contsant result :" + txnExt.getConstantResult(0));

        Transaction unsignedTxn = txnExt.getTransaction().toBuilder()
            .setRawData(txnExt.getTransaction().getRawData().toBuilder().setFeeLimit(feeLimit))
            .build();

        Transaction signedTxn = signTransaction(unsignedTxn);

        System.out.println(signedTxn.toString());
        TransactionReturn ret = blockingStub.broadcastTransaction(signedTxn);
        System.out.println("======== Result ========\n" + ret.toString());
    }

    /**
     * Obtain a {@code Contract} object via an address
     * @param contractAddress smart contract address
     * @return the smart contract obtained from the address
     * @throws Exception if contract address does not match
     */
    public Contract getContract(String contractAddress) throws Exception{
        ByteString rawAddr = parseAddress(contractAddress);
        BytesMessage param = 
            BytesMessage.newBuilder()
            .setValue(rawAddr)
            .build();
        
            SmartContract cntr = blockingStub.getContract(param);

            Contract contract = 
                new Contract.Builder()
                .setCntrAddr(cntr.getContractAddress())
                .setBytecode(cntr.getBytecode())
                .setName(cntr.getName())
                .setAbi(cntr.getAbi())
                .setOriginEnergyLimit(cntr.getOriginEnergyLimit())
                .setConsumeUserResourcePercent(cntr.getConsumeUserResourcePercent())
                .build();

        return contract;
    }

    /**
     * Check whether a given method is in the contract.
     * @param cntr the smart contract.
     * @param function the smart contract function.
     * @return ture if function exists in the contract.
     */
    private boolean isFuncInContract(Contract cntr, Function function) {
        List<ContractFunction> functions = cntr.getFunctions();
        for (int i = 0; i < functions.size(); i++) {
            if (functions.get(i).getName().equalsIgnoreCase(function.getName())) {
                return true;
            }
        }
        return false;
    }

    /**
     * call function without signature and broadcasting
     * @param ownerAddr the caller
     * @param cntr the contract
     * @param function the function called
     * @return TransactionExtention 
     */
    private TransactionExtention callWithoutBroadcast(String ownerAddr, Contract cntr, Function function) {
        cntr.setOwnerAddr(parseAddress(ownerAddr));
            String encodedHex = FunctionEncoder.encode(function);
            TriggerSmartContract trigger = 
                TriggerSmartContract.newBuilder()
                .setOwnerAddress(cntr.getOwnerAddr())
                .setContractAddress(cntr.getCntrAddr())
                .setData(parseHex(encodedHex))
                .build();

            System.out.println("trigger:\n" + trigger);

            TransactionExtention txnExt = blockingStub.triggerConstantContract(trigger);
            System.out.println("txn id => " + toHex(txnExt.getTxid().toByteArray()));

            return txnExt;
    }

    /**
     * make a constant call - no broadcasting
     * @param ownerAddr the current caller.
     * @param contractAddr smart contract address.
     * @param function contract function.
     * @return TransactionExtention.
     * @throws RuntimeException if function cannot be found in the contract.
     */
    public TransactionExtention constantCall(String ownerAddr, String contractAddr, Function function) throws Exception{
        Contract cntr = getContract(contractAddr);
        if (isFuncInContract(cntr, function)) {
            return callWithoutBroadcast(ownerAddr, cntr, function);
        } else {
            throw new RuntimeException("Function not found in the contract");
        }
    }

    /**
     * make a trigger call. Trigger call consumes energy and bandwidth.
     * @param ownerAddr the current caller
     * @param contractAddr smart contract address
     * @param function contract function
     * @return transaction builder. Users may set other fields, e.g. feeLimit
     * @throws RuntimeException if function cannot be found in the contract
     */
    public TransactionBuilder triggerCall(String ownerAddr, String contractAddr, Function function) throws Exception {
        Contract cntr = getContract(contractAddr);
        if (isFuncInContract(cntr, function)) {
            TransactionExtention txnExt = callWithoutBroadcast(ownerAddr, cntr, function);
            return new TransactionBuilder(txnExt.getTransaction());
        } else {
            throw new RuntimeException("Function not found in the contract");
        }
    }

}
