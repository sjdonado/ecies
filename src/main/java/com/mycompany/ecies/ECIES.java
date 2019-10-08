/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.ecies;

import java.security.SecureRandom;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;

/**
 *
 * @author sjdonado
 */
public class ECIES {
    private final int KEY_SIZE = 32;
    private final SecureRandom random;
//    private KDF2BytesGenerator kdf2;
    
    public ECIES() {
        this.random = new SecureRandom();
//        this.kdf2 = new KDF2BytesGenerator((org.bouncycastle.crypto.Digest) new Digest());
    }
    
    /**
    *
    * @return byte[]
    */
    public byte[] getRandomNumber() {
        byte[] r = new byte[KEY_SIZE];
        random.nextBytes(r);
        return r;
    }
    
    /**
    *
    * @return int
    */
    public int getKeySize() {
        return KEY_SIZE;
    }
    
//    public int keyDerivationFunction(byte[] shared, byte[] iv) {
//        kdf2.init(new KDFParameters(shared, iv));
//        return kdf2.generateBytes(iv, 0, KEY_SIZE);
////        kdf2.generateBytes(bytes, KEY_SIZE, KEY_SIZE)
//    }
    
 }
