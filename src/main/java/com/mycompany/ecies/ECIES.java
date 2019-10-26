/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.ecies;

import java.security.SecureRandom;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 *
 * @author sjdonado
 */
public class ECIES {
    private final int KEY_SIZE = 32;
    private final SecureRandom random;
    private KDF2BytesGenerator kdf2;
    private SHA256Digest sha256;
    private KDFParameters param;
    
    public ECIES() {
        this.random = new SecureRandom();
        sha256 = new SHA256Digest();
        this.kdf2 = new KDF2BytesGenerator(sha256);
        //param = new KDFParameters(null,null);//iv, SharedSecret
        kdf2.init(param);
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
    
    public int keyDerivationFunction(byte[] shared, byte[] iv, byte[] output) {
        param = new KDFParameters(shared, iv);
        kdf2.init(param);
        return kdf2.generateBytes(output, 0, KEY_SIZE);
//        kdf2.generateBytes(bytes, KEY_SIZE, KEY_SIZE)
    }
    
 }
