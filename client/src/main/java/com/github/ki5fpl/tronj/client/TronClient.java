package com.github.ki5fpl.tronj.client;


/**
 * A {@code TronClient} object is the entry point for calling the functions.
 *
 *<p>A {@code TronClient} object is bind with a private key and a full node.
 * {@link #broadcastTransaction}, {@link #signTransaction} and other transaction related
 * operations can be done via a {@code TronClient} object.</p>
 *
 * @since jdk13.0.2+8
 * @see com.github.ki5fpl.tronj.client.contract.Contract
 * @see com.github.ki5fpl.tronj.proto.Chain.Transaction
 * @see com.github.ki5fpl.tronj.proto.Contract
 */

import com.github.ki5fpl.tronj.abi.TypeReference;
import com.github.ki5fpl.tronj.abi.Utils;
import com.github.ki5fpl.tronj.abi.datatypes.Address;
import com.github.ki5fpl.tronj.abi.datatypes.Bool;
import com.github.ki5fpl.tronj.abi.datatypes.Int;
import com.github.ki5fpl.tronj.abi.datatypes.generated.Uint256;


import com.github.ki5fpl.tronj.abi.FunctionEncoder;
import com.github.ki5fpl.tronj.abi.TypeReference;
import com.github.ki5fpl.tronj.abi.datatypes.Address;
import com.github.ki5fpl.tronj.abi.datatypes.Bool;
import com.github.ki5fpl.tronj.abi.datatypes.Function;
import com.github.ki5fpl.tronj.abi.datatypes.generated.Uint256;
import com.github.ki5fpl.tronj.api.GrpcAPI;
import com.github.ki5fpl.tronj.api.GrpcAPI.BytesMessage;

import com.github.ki5fpl.tronj.api.WalletGrpc;
import com.github.ki5fpl.tronj.client.contract.Contract;
import com.github.ki5fpl.tronj.client.contract.ContractFunction;
import com.github.ki5fpl.tronj.client.transaction.TransactionBuilder;
import com.github.ki5fpl.tronj.crypto.SECP256K1;
import com.github.ki5fpl.tronj.proto.Chain.Transaction;

import com.github.ki5fpl.tronj.proto.Chain.Block;

import com.github.ki5fpl.tronj.proto.Common.SmartContract;

import com.github.ki5fpl.tronj.proto.Contract.TransferAssetContract;
import com.github.ki5fpl.tronj.proto.Contract.TriggerSmartContract;
import com.github.ki5fpl.tronj.proto.Contract.UnfreezeBalanceContract;
import com.github.ki5fpl.tronj.proto.Contract.FreezeBalanceContract;
import com.github.ki5fpl.tronj.proto.Contract.TransferContract;

import com.github.ki5fpl.tronj.proto.Contract.VoteWitnessContract;

import com.github.ki5fpl.tronj.proto.Contract.TriggerSmartContract;

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

import java.math.BigInteger;
import java.util.Arrays;
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

    /**
     * Transfer TRX. amount in SUN
     * @param from owner address
     * @param to receive balance
     * @param amount transfer amount
     * @return TransactionReturn
     */
    public TransactionReturn transfer(String from, String to, long amount) throws IllegalNumException{

        ByteString rawFrom = parseAddress(from);
        ByteString rawTo = parseAddress(to);

        TransferContract req = TransferContract.newBuilder()
                .setOwnerAddress(rawFrom)
                .setToAddress(rawTo)
                .setAmount(amount)
                .build();
        TransactionExtention txnExt = blockingStub.createTransaction2(req);

        if(SUCCESS != txnExt.getResult().getCode()){
            throw new IllegalNumException(txnExt.getResult().getMessage().toStringUtf8());
        }

        Transaction signedTxn = signTransaction(txnExt);

        TransactionReturn ret = blockingStub.broadcastTransaction(signedTxn);
        return ret;
    }

    /**
     * Transfers TRC10 Asset
     * @param from owner address
     * @param to receive balance
     * @param tokenId asset name
     * @param amount transfer amount
     * @return TransactionReturn
     */
    public TransactionReturn transferTrc10(String from, String to, int tokenId, long amount) throws IllegalNumException{

        ByteString rawFrom = parseAddress(from);
        ByteString rawTo = parseAddress(to);
        byte[] rawTokenId = Integer.toString(tokenId).getBytes();

        TransferAssetContract req = TransferAssetContract.newBuilder()
                .setOwnerAddress(rawFrom)
                .setToAddress(rawTo)
                .setAssetName(ByteString.copyFrom(rawTokenId))
                .setAmount(amount)
                .build();

        TransactionExtention txnExt = blockingStub.transferAsset2(req);

        if(SUCCESS != txnExt.getResult().getCode()){
            throw new IllegalNumException(txnExt.getResult().getMessage().toStringUtf8());
        }

        Transaction signedTxn = signTransaction(txnExt);

        TransactionReturn ret = blockingStub.broadcastTransaction(signedTxn);
        return ret;
    }

    /**
     * Freeze balance to get energy or bandwidth, for 3 days
     * @param from owner address
     * @param balance frozen balance
     * @param duration frozen duration
     * @param resourceCode Resource type, can be 0("BANDWIDTH") or 1("ENERGY")
     * @return TransactionReturn
     */
    public TransactionReturn freezeBalance(String from, long balance, long duration, int resourceCode) throws IllegalNumException{

        ByteString rawFrom = parseAddress(from);
        FreezeBalanceContract freezeBalanceContract=
                FreezeBalanceContract.newBuilder()
                        .setOwnerAddress(rawFrom)
                        .setFrozenBalance(balance)
                        .setFrozenDuration(duration)
                        .setResourceValue(resourceCode)
                        .build();
        TransactionExtention txnExt = blockingStub.freezeBalance2(freezeBalanceContract);

        if(SUCCESS != txnExt.getResult().getCode()){
            throw new IllegalNumException(txnExt.getResult().getMessage().toStringUtf8());
        }

        Transaction signedTxn = signTransaction(txnExt);

        TransactionReturn ret = blockingStub.broadcastTransaction(signedTxn);
        return ret;
    }

    public TransactionReturn unfreezeBalance(String from, int resource) throws IllegalNumException{

        UnfreezeBalanceContract unfreeze =
                UnfreezeBalanceContract.newBuilder()
                        .setOwnerAddress(parseAddress(from))
                        .setResourceValue(resource)
                        .build();

        TransactionExtention txnExt = blockingStub.unfreezeBalance2(unfreeze);

        if(SUCCESS != txnExt.getResult().getCode()){
            throw new IllegalNumException(txnExt.getResult().getMessage().toStringUtf8());
        }

        Transaction signedTxn = signTransaction(txnExt);

        TransactionReturn ret = blockingStub.broadcastTransaction(signedTxn);
        return ret;
    }

    public Block getBlockByNum(long blockNum) throws IllegalNumException {
        NumberMessage.Builder builder = NumberMessage.newBuilder();
        builder.setNum(blockNum);
        Block block = blockingStub.getBlockByNum(builder.build());

        if(!block.hasBlockHeader()){
            throw new IllegalNumException();
        }
        return block;
    }

    public Block getNowBlock() throws IllegalNumException {
        Block block = blockingStub.getNowBlock(EmptyMessage.newBuilder().build());
        if(!block.hasBlockHeader()){
            throw new IllegalNumException("Fail to get latest block.");
        }
        return block;
    }

    public NodeInfo getNodeInfo() throws IllegalNumException {
        NodeInfo nodeInfo = blockingStub.getNodeInfo(EmptyMessage.newBuilder().build());

        if(nodeInfo.getBlock().isEmpty()){
            throw new IllegalNumException("Fail to get node info.");
        }
        return nodeInfo;
    }

    public NodeList listNodes() {
        NodeList nodeList = blockingStub.listNodes(EmptyMessage.newBuilder().build());
        return nodeList;
    }

    public TransactionInfoList getTransactionInfoByBlockNum(long blockNum) throws IllegalNumException {
        NumberMessage.Builder builder = NumberMessage.newBuilder();
        builder.setNum(blockNum);
        TransactionInfoList transactionInfoList = blockingStub.getTransactionInfoByBlockNum(builder.build());
        if(transactionInfoList.getTransactionInfoCount() == 0){
            throw new IllegalNumException();
        }
        return transactionInfoList;
    }

    public TransactionInfo getTransactionInfoById(String txID) throws IllegalNumException {
        ByteString bsTxid = parseAddress(txID);
        BytesMessage request = BytesMessage.newBuilder()
                .setValue(bsTxid)
                .build();
        TransactionInfo transactionInfo = blockingStub.getTransactionInfoById(request);

        if(transactionInfo.getBlockTimeStamp() == 0){
            throw new IllegalNumException();
        }
        return transactionInfo;
    }

    public Account getAccount(String address) throws IllegalNumException {
        ByteString bsAddress = parseAddress(address);
        AccountAddressMessage accountAddressMessage = AccountAddressMessage.newBuilder()
                .setAddress(bsAddress)
                .build();
        Account account = blockingStub.getAccount(accountAddressMessage);

        if(account.getCreateTime() == 0){
            throw new IllegalNumException();
        }
        return account;
    }

    public WitnessList listWitnesses() {
        WitnessList witnessList = blockingStub
                .listWitnesses(EmptyMessage.newBuilder().build());
        return witnessList;
    }

    /**
     * Vote for witnesses
     * @param owner owner address
     * @param witness <witness address, vote count>
     * @return TransactionReturn
     */
    public TransactionReturn voteWitness(String owner, HashMap<String, String> witness) throws IllegalNumException{
        ByteString rawFrom = parseAddress(owner);
        VoteWitnessContract voteWitnessContract = createVoteWitnessContract(rawFrom, witness);
        TransactionExtention txnExt = blockingStub.voteWitnessAccount2(voteWitnessContract);

        if(SUCCESS != txnExt.getResult().getCode()){
            throw new IllegalNumException(txnExt.getResult().getMessage().toStringUtf8());
        }

        Transaction signedTxn = signTransaction(txnExt);

        TransactionReturn ret = blockingStub.broadcastTransaction(signedTxn);

        return ret;
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

    public void transferTrc20(String from, String to, String cntr, long feeLimit, long amount, int precision) {
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
    public Contract getContract(String contractAddress) {
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
