package org.tron.tronj.client;

public class IllegalNumException extends  Exception {
    public IllegalNumException(){
        super("The query failed, please check if the parameters are correct.");
    }

    public IllegalNumException(String message){
        super(message);
    }
}
