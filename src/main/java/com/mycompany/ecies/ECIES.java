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
    private final Cipher cipher;
    
    public ECIES() {
        this.random = new SecureRandom();
        this.cipher = new Cipher();
    }
    
    /**
    *
    * @param keySize int
    * @return byte[]
    */
    public byte[] getRandomNumber(int keySize) {
        byte[] r = new byte[keySize];
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
    
    public int keyDerivationFunction(byte[] key, byte[] iv, byte[] output) {
        KDF2BytesGenerator kdf2 = new KDF2BytesGenerator(new SHA256Digest());
        kdf2.init(new KDFParameters(key, iv));
        int size = kdf2.generateBytes(output, 0, KEY_SIZE);
        System.out.println("output: " + Hex.toHexString(output));
        return size;
//        kdf2.generateBytes(bytes, KEY_SIZE, KEY_SIZE)
    }
    
    public byte[] hMacKey(byte[] initValue,byte[] plainText){
        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(initValue));
        byte[] res = new byte[plainText.length];
        System.arraycopy(plainText,0,res,0,res.length);
        hmac.update(res, 0, res.length);
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
    
    public byte[] encrypt(byte[] encryptionPoint, byte[] iv, byte[] plainText){
        try {
            byte[] output = new byte[KEY_SIZE];
            int size = keyDerivationFunction(encryptionPoint, iv, output);
            byte[] kMac = new byte[size / 2];
            byte[] kEnc = new byte[size / 2];
            System.arraycopy(output, 0, kMac, 0, size / 2);
            System.arraycopy(output, size/2 -1, kEnc, 0, size / 2);
            
            byte[] tag = hMacKey(kMac,plainText);
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
    
//    public byte[] decrypt(byte[] decryptionPoint, byte[] iv, byte[] chiperText){
//        try {
//            byte[] output = new byte[KEY_SIZE];
//            int size = keyDerivationFunction(decryptionPoint, iv, output);
//            byte[] kEnc = new byte[size / 2];
//            System.arraycopy(output, size / 2 - 1, kEnc, 0, size / 2);
//            return cipher.decrypt(chiperText, kEnc, iv);
//        } catch (Exception ex) {
//            Logger.getLogger(ECIES.class.getName()).log(Level.SEVERE, null, ex);
//        }
//        return null;
//    }
 }
