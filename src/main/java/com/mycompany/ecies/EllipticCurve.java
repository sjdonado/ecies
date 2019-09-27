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
        byte[] privateKey = new byte[ecies.getKeySize()];
//        ECIES...nextBytes(privateKey);
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
        byte[] R = new byte[ecies.getKeySize()];
        Curve25519.curve(R, r, null);
        return R;
    }
    
    /**
    *
    * @param publickey byte[]
    * @param privateKey byte[]
    * @return byte[]
    */
    public byte[] getSharedKey(byte[] publickey, byte[] privateKey) {
        byte[] Z = new byte[ecies.getKeySize()];
        Curve25519.curve(Z, privateKey, publickey);
        return Z;
    }
}
