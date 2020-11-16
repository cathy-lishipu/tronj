package com.github.ki5fpl.tronj.client;

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
import com.github.ki5fpl.tronj.proto.Common.SmartContract;
import com.github.ki5fpl.tronj.proto.Contract.TransferAssetContract;
import com.github.ki5fpl.tronj.proto.Contract.TransferContract;
import com.github.ki5fpl.tronj.proto.Contract.TriggerSmartContract;
import com.github.ki5fpl.tronj.proto.Response.TransactionExtention;
import com.github.ki5fpl.tronj.proto.Response.TransactionReturn;
import com.github.ki5fpl.tronj.utils.Base58Check;
import com.google.protobuf.ByteString;
import io.grpc.Channel;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.util.encoders.Hex;

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

    public TransactionReturn broadcastTransaction(Transaction txn) {
        return blockingStub.broadcastTransaction(txn);
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

        Transaction signedTxn = signTransaction(txnExt);

        System.out.println(signedTxn.toString());
        TransactionReturn ret = blockingStub.broadcastTransaction(signedTxn);
        System.out.println("======== Result ========\n" + ret.toString());
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
     * get a smart contract from a contract address
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
     * Check whether the method is in the contract
     * @param cntr the smart contract
     * @param function the smart contract function
     * @return ture if function exists in the contract
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
     * @param ownerAddr the current caller
     * @param contractAddr smart contract address
     * @param function contract function
     * @return TransactionExtention
     * @throws RuntimeException if function cannot be found in the contract
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
