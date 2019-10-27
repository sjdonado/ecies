/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.ecies;

import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
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
    private Cipher cipher;
    
    public ECIES() {
        this.random = new SecureRandom();
        this.sha256 = new SHA256Digest();
        this.kdf2 = new KDF2BytesGenerator(sha256);
        this.hmac = new HMac(sha256);
        this.cipher = new Cipher();
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

    /**
     * @return the cipher
     */
    public Cipher getCipher() {
        return cipher;
    }

    /**
     * @param cipher the cipher to set
     */
    public void setCipher(Cipher cipher) {
        this.cipher = cipher;
    }
    
    public byte[] encrypt(byte[] sharedSecret, byte[] iv, byte[] plainText){
        try {
            byte[] output = new byte[32];
            int size = keyDerivationFunction(sharedSecret,iv,output);
            byte[] kMac = new byte[size/2];
            byte[] kEnc = new byte[size/2];
            System.arraycopy(output, 0, kMac, 0, size/2);
            System.arraycopy(output, size/2 -1, kEnc, 0, size/2);
            byte[] tag = hMacKey(kMac);
            System.out.println("p: "+plainText.length + " iv:" + iv.length);
            byte[] cipherText = cipher.encrypt(plainText, kEnc, iv);
            byte[] res = new byte[tag.length + cipherText.length];
            System.arraycopy(tag, 0, res, 0, tag.length);
            System.arraycopy(cipherText, 0, res, tag.length, cipherText.length);
            return res;
        } catch (Exception ex) {
            Logger.getLogger(ECIES.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
 }
