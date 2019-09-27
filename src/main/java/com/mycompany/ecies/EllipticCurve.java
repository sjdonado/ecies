/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.ecies;

import djb.Curve25519;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.whispersystems.curve25519.Curve25519;
//import org.whispersystems.curve25519.Curve25519KeyPair;

/**
 *
 * @author sjdonado
 */
public class EllipticCurve {
//    Curve25519 curve;
    final int KEY_SIZE = 32;
    SecureRandom random;
    
    public EllipticCurve() {
        Security.addProvider(new BouncyCastleProvider());
//        this.curve = Curve25519.getInstance(Curve25519.BEST);
        this.random = new SecureRandom();
    }
    
    /**
    *
    * @return { byte[] privateKey, byte[] publicKey } byte[][]
    */
    public byte[][] generateKeyPair() {
        byte[] privateKey = new byte[KEY_SIZE];
        random.nextBytes(privateKey);
        byte[] publicKey = new byte[KEY_SIZE];
        Curve25519.keygen(publicKey, null, privateKey);
        
        return new byte[][]{ privateKey, publicKey };
    }
    
    /**
    *
    * @return randomNumber byte[]
    */
    public byte[] getRandomNumber() {
        byte[] r = new byte[KEY_SIZE];
        random.nextBytes(r);
        return r;
    }
    
    /**
    *
    * @param r byte[]
    * @return R byte[]
    */
    public byte[] generateR(byte[] r) {
        byte[] R = new byte[KEY_SIZE];
        Curve25519.curve(R, r, null);
        return R;
    }
    
    /**
    *
    * @param publickey byte[]
    * @param privateKey byte[]
    * @return Z byte[]
    */
    public byte[] getSharedKey(byte[] publickey, byte[] privateKey) {
        byte[] Z = new byte[KEY_SIZE];
        Curve25519.curve(Z, privateKey, publickey);
        return Z;
    }
}
