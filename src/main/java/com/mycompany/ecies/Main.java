/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.ecies;

import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author sjdonado
 */
public class Main {
    
    public static void main(String[] args) {
        ECIES ecies = new ECIES();
        EllipticCurve ellipticCurve = new EllipticCurve(ecies);
        
        byte[][] recipientKeyPairs = ellipticCurve.generateKeyPair();

        System.out.println("**** RECIPIENT ****");
        System.out.println("private key: " + Hex.toHexString(recipientKeyPairs[0]));
        System.out.println("public key: " + Hex.toHexString(recipientKeyPairs[1]));

        byte[][] senderKeyPairs = ellipticCurve.generateKeyPair();
        byte[] IV = ecies.getRandomNumber();
        byte[] sharedSecret = ellipticCurve.getSharedKey(recipientKeyPairs[0],
                senderKeyPairs[1]);
//        byte[] randomNumber = ellipticCurve.getRandomNumber();
//        byte[] R = ellipticCurve.generateR(randomNumber);

        System.out.println("**** SENDER ****");
        System.out.println("private key: " + Hex.toHexString(senderKeyPairs[0]));
        System.out.println("public key: " + Hex.toHexString(senderKeyPairs[1]));
        System.out.println("IV: " + Hex.toHexString(IV));
        System.out.println("sharedSecret: " + Hex.toHexString(sharedSecret));
//        System.out.println("r: " + Hex.toHexString(randomNumber));
//        System.out.println("R: " + Hex.toHexString(R));
        
    }
}
