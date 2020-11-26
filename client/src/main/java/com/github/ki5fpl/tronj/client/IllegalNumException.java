package com.github.ki5fpl.tronj.client;

public class IllegalNumException extends  Exception {
    public IllegalNumException(){
        super("The query failed, please check if the parameters are correct.");
    }

    public IllegalNumException(String message){
        super(message);
    }
}
