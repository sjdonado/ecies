/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.ecies;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 *
 * @author acjesusr
 */
public class Cipher {

    private byte[] cipherData(PaddedBufferedBlockCipher cipher, byte[] data)
        throws Exception
    {
        int minSize = cipher.getOutputSize(data.length);
        byte[] outBuf = new byte[minSize];
        int length1 = cipher.processBytes(data, 0, data.length, outBuf, 0);
        int length2 = cipher.doFinal(outBuf, length1);
        int actualLength = length1 + length2;
        byte[] result = new byte[actualLength];
        System.arraycopy(outBuf, 0, result, 0, result.length);
        return result;
    }

    public byte[] decrypt(byte[] cipher, byte[] key, byte[] iv) throws Exception
    {
        PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(
                new AESEngine()));
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
        aes.init(false, ivAndKey);
        return cipherData(aes, cipher);
    }

    public byte[] encrypt(byte[] plain, byte[] key, byte[] iv) throws Exception
    {
        PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(
                new AESEngine()));
        System.out.println(aes.getBlockSize());
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
        aes.init(true, ivAndKey);
        return cipherData(aes, plain);
    }
}