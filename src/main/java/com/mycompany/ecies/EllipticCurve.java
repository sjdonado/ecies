/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.ecies;

import djb.Curve25519;

/**
 *
 * @author sjdonado
 */
public class EllipticCurve {
    ECIES ecies;
    
    public EllipticCurve(ECIES ecies) {
        this.ecies = ecies;
    }
    
    /**
    *
    * @return byte[][]{ byte[] privateKey, byte[] publicKey }
    */
    public byte[][] generateKeyPair() {
        byte[] privateKey = ecies.getRandomNumber(ecies.getKeySize());
        byte[] publicKey = new byte[ecies.getKeySize()];
        Curve25519.keygen(publicKey, null, privateKey);
        
        return new byte[][]{ privateKey, publicKey };
    }
    
    /**
    *
    * @param r byte[]
    * @return byte[]
    */
    public byte[] generateR(byte[] r) {
        byte[] R = new byte[r.length];
        Curve25519.curve(R, r, null);
        return R;
    }
    
    /**
    *
    * @param r byte[]
    * @param publicKey byte[]
    * @return byte[]
    */
    public byte[] encryptionPoint(byte[] r, byte[] publicKey) {
        byte[] Z = new byte[ecies.getKeySize()];
        Curve25519.curve(Z, r, publicKey);
        return Z;
    }
    
    /**
    *
    * @param R byte[]
    * @param privateKey byte[]
    * @return byte[]
    */
    public byte[] decryptionPoint(byte[] R, byte[] privateKey) {
        byte[] Z = new byte[ecies.getKeySize()];
        Curve25519.curve(Z, privateKey, R);
        return Z;
    }
}
