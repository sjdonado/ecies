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
        EllipticCurve ellipticCurve = new EllipticCurve();
        byte[][] keyPair = ellipticCurve.generateKeyPair();
        byte[] randomNumber = ellipticCurve.getRandomNumber();
        byte[] R = ellipticCurve.generateR(randomNumber);
        byte[] sharedSecret = ellipticCurve.getSharedKey(keyPair[0], keyPair[1]);
        
        System.out.println("Private key: " + Hex.toHexString(keyPair[0]));
        System.out.println("Public key: " + Hex.toHexString(keyPair[1]));
        System.out.println("r: " + Hex.toHexString(randomNumber));
        System.out.println("R: " + Hex.toHexString(R));
        System.out.println("sharedSecret: " + Hex.toHexString(sharedSecret));
        
//        byte[] randomNumber = ellipticCurve.generateR();
//        byte[] simetricKey = ellip
//        byte[] R = 
    }
}
