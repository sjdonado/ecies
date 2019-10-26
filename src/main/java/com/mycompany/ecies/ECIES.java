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
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author sjdonado
 */
public class ECIES {
    private final int KEY_SIZE = 32;
    private final SecureRandom random;
    private KDF2BytesGenerator kdf2;
    private SHA256Digest sha256;
    private KDFParameters kdfParam;
    private HMac hmac;
    
    public ECIES() {
        this.random = new SecureRandom();
        this.sha256 = new SHA256Digest();
        this.kdf2 = new KDF2BytesGenerator(sha256);
        this.hmac = new HMac(sha256);
        //param = new KDFParameters(null,null);//iv, SharedSecret
        //kdf2.init(kdfParam);
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
        kdfParam = new KDFParameters(shared, iv);
        kdf2.init(kdfParam);
        return kdf2.generateBytes(output, 0, KEY_SIZE);
//        kdf2.generateBytes(bytes, KEY_SIZE, KEY_SIZE)
    }
    
    public byte[] hMacKey(byte[] initValue){
        hmac.init(new KeyParameter(initValue));
        byte[] resBuf = new byte[hmac.getMacSize()];
        hmac.doFinal(resBuf, 0);
        return resBuf;
    }
    
 }
