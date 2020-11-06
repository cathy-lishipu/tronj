/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package demo;

import com.github.ki5fpl.tronj.abi.FunctionEncoder;
import com.github.ki5fpl.tronj.abi.FunctionReturnDecoder;
import com.github.ki5fpl.tronj.abi.TypeReference;
import com.github.ki5fpl.tronj.abi.datatypes.*;
import com.github.ki5fpl.tronj.abi.datatypes.generated.Bytes10;
import com.github.ki5fpl.tronj.abi.datatypes.generated.Uint256;
import com.github.ki5fpl.tronj.abi.datatypes.generated.Uint32;
import com.github.ki5fpl.tronj.client.Contract;
import com.github.ki5fpl.tronj.client.TronClient;
import com.github.ki5fpl.tronj.proto.Chain.Transaction;
import com.github.ki5fpl.tronj.proto.Contract.TriggerSmartContract;
import com.github.ki5fpl.tronj.proto.Response.BlockExtention;
import com.github.ki5fpl.tronj.proto.Response.TransactionExtention;
import com.github.ki5fpl.tronj.proto.Response.TransactionReturn;
import java.math.BigInteger;
import java.util.*;

public class App {
    public String encodeFunctionCalling() {
        System.out.println("! function sam(bytes _, bool _, address _, uint[])");
        Function function = new Function("sam",
            Arrays.asList(new DynamicBytes("dave".getBytes()), new Bool(true),
                new Address("T9yKC9LCoVvmhaFxKcdK9iL18TUWtyFtjh"),
                new DynamicArray<>(
                    new Uint(BigInteger.ONE), new Uint(BigInteger.valueOf(2)), new Uint(BigInteger.valueOf(3)))),
            Collections.emptyList());
        String encodedHex = FunctionEncoder.encode(function);
        return encodedHex;
    }

    public void decodeFunctionReturn() {
        Function function = new Function("test", Collections.<Type>emptyList(),
            Arrays.asList(new TypeReference<Uint>() {}, new TypeReference<Address>() {}));

        List<Type> outputs =
            FunctionReturnDecoder.decode("0000000000000000000000000000000000000000000000000000000000000037"
                    + "00000000000000000000000028263f17875e4f277a72f6c6910bb7a692108b3e",
                function.getOutputParameters());
        for (Type obj : outputs) {
            System.out.println(obj.getTypeAsString() + "  " + obj.toString());
            if (Uint.class.isInstance(obj)) {
                System.out.println("  parsed value => " + ((Uint) obj).getValue());
            }
        }
        // assertEquals(outputs,
        //    (Arrays.asList(new Uint(BigInteger.valueOf(55)), new Uint(BigInteger.valueOf(7)))));
    }

    public void trc20Encode() {
        Function trc20Transfer = new Function("transfer",
            Arrays.asList(new Address("TV3KSjZHF4o6bC92SMrjhNJ3RE65xHNDuo"),
                new Uint256(BigInteger.valueOf(1000).multiply(BigInteger.valueOf(10).pow(18)))),
            Arrays.asList(new TypeReference<Bool>() {}));

        String encodedHex = FunctionEncoder.encode(trc20Transfer);
        System.out.println("! encoding a TRC20 transfer");
        System.out.println(encodedHex);
    }

    public void sendTrx() {
        System.out.println("============= TRC transfer =============");
        TronClient client = TronClient.ofNile("3333333333333333333333333333333333333333333333333333333333333333");
        try {
            client.transfer("TJRabPrwbZy45sbavfcjinPJC18kjpRTv8", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", 2_000_000);
        } catch (Exception e) {
            System.out.println("error: " + e);
        }
    }

    // public void sendTrc20Transaction() {
    //     System.out.println("============ TRC20 transfer =============");
    //     // Any of `ofShasta`, `ofMainnet`.
    //     TronClient client = TronClient.ofNile("3333333333333333333333333333333333333333333333333333333333333333");

    //     // transfer(address _to,uint256 _amount) returns (bool)
    //     // _to = TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA
    //     // _amount = 10 * 10^18
    //     Function trc20Transfer = new Function("transfer",
    //         Arrays.asList(new Address("TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA"),
    //             new Uint256(BigInteger.valueOf(10).multiply(BigInteger.valueOf(10).pow(18)))),
    //         Arrays.asList(new TypeReference<Bool>() {}));

    //     String encodedHex = FunctionEncoder.encode(trc20Transfer);
    //     TriggerSmartContract trigger =
    //         TriggerSmartContract.newBuilder()
    //             .setOwnerAddress(TronClient.parseAddress("TJRabPrwbZy45sbavfcjinPJC18kjpRTv8"))
    //             .setContractAddress(TronClient.parseAddress("TF17BgPaZYbz8oxbjhriubPDsA7ArKoLX3")) // JST
    //             .setData(TronClient.parseHex(encodedHex))
    //             .build();

    //     System.out.println("trigger:\n" + trigger);

    //     TransactionExtention txnExt = client.blockingStub.triggerContract(trigger);
    //     System.out.println("txn id => " + TronClient.toHex(txnExt.getTxid().toByteArray()));

    //     Transaction unsignedTxn = txnExt.getTransaction.toBuilder()
    //         .setRawData(txnExt.getTransaction().getRawData().toBuilder().setFeeLimit(10000000L))
    //         .build();

    //     Transaction signedTxn = client.signTransaction(unsignedTxn);

    //     System.out.println(signedTxn.toString());
    //     TransactionReturn ret = client.blockingStub.broadcastTransaction(signedTxn);
    //     System.out.println("======== Result ========\n" + ret.toString());
    // }

    public void transferTrc20() {
        // Any of `ofShasta`, `ofMainnet`.
        TronClient client = TronClient.ofNile("3333333333333333333333333333333333333333333333333333333333333333");
        try {
            //JST transfer
            client.transferTrc20("TJRabPrwbZy45sbavfcjinPJC18kjpRTv8", "TVjsyZ7fYF3qLF6BQgPmTEZy1xrNNyVAAA", "TF17BgPaZYbz8oxbjhriubPDsA7ArKoLX3", 1000000000L, 10L, 18);
        } catch (Exception e) {
            System.out.println("error: " + e);
        }
    }

    public void getSmartContract() {
        TronClient client = TronClient.ofNile("3333333333333333333333333333333333333333333333333333333333333333");
        try {
            //get JST contract
            Contract cntr = client.getContract("TF17BgPaZYbz8oxbjhriubPDsA7ArKoLX3");
            System.out.println("Contract name: " + cntr.getName());
        } catch (Exception e) {
            System.out.println("error: " + e);
        }
    }

    public static void main(String[] args) {
        App app = new App();
        System.out.println(app.encodeFunctionCalling());

        // app.decodeFunctionReturn();
        // app.trc20Encode();
        // app.sendTrx();
        // app.sendTrc20Transaction();
        // app.transferTrc20();
        app.getSmartContract();
    }
}
