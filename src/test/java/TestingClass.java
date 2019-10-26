
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.digests.SHA256Digest;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author acjesusr
 */
public class TestingClass {
    
    public static void main(String[] args) {
        try {
            //1888d5d67258aa90aa11c5cd8edb143eb75b8123b9b8709f51b5f5f4ff764d76
            //cd95dbf2513b5dea9a0c7438dbfd1e0fe3a972bfc27d032445db3d7455d596a1
            byte[] b1={(byte)0x18, (byte)0x88, (byte)0xd5, (byte)0xd6, (byte)0x72, (byte)0x58, (byte)0xaa, (byte)0x90,
                    (byte)0xaa, (byte)0x11, (byte)0xc5, (byte)0xcd, (byte)0x8e, (byte)0xdb, (byte)0x14, (byte)0x3e};
            //System.out.println(Hex.toHexString(b1));
            byte[] b2 = {(byte)0xcd ,(byte)0x95 ,(byte)0xdb,(byte)0xf2,(byte)0x51,(byte)0x3b,(byte)0x5d,(byte)0xea,
                (byte)0x9a,(byte)0x0c,(byte)0x74,(byte)0x38,(byte)0xdb,(byte)0xfd,(byte)0x1e,(byte)0x0f};
            byte[] b3 = {(byte)0x18, (byte)0x88, (byte)0xd5, (byte)0xd6, (byte)0x72, (byte)0x58, (byte)0xaa, (byte)0x90,
                (byte)0x9a,(byte)0x0c,(byte)0x74,(byte)0x38,(byte)0xdb,(byte)0xfd,(byte)0x1e,(byte)0x0f};
            //--------KDF--------
            SHA256Digest sha256 = new SHA256Digest();
            KDF2BytesGenerator kdf2 = new KDF2BytesGenerator(sha256);
            byte[] iv = b2, sharedSecret = b3;
            KDFParameters param = new KDFParameters(iv,sharedSecret);
            kdf2.init(param);
            byte[] output = new byte[32];
            System.out.println("out: " + Hex.toHexString(output));
            int a = kdf2.generateBytes(output, 0, output.length);
            System.out.println("kdf: " + Hex.toHexString(output) + " -> " + a);
            //-------------------
            System.out.println(Hex.toHexString(encrypt("Lorem ipsum dolor sit amet amet.".getBytes(),b1,b2)));
        } catch (Exception ex) {
            Logger.getLogger(TestingClass.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    public static byte[] cipherData(PaddedBufferedBlockCipher cipher, byte[] data)
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

    public static byte[] decrypt(byte[] cipher, byte[] key, byte[] iv) throws Exception
    {
        PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(
                new AESEngine()));
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
        aes.init(false, ivAndKey);
        return cipherData(aes, cipher);
    }

    public static byte[] encrypt(byte[] plain, byte[] key, byte[] iv) throws Exception
    {
        PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(
                new AESEngine()));
        System.out.println(aes.getBlockSize());
        System.out.println(plain.length + " " + iv.length + "" + key.length);
        CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
        aes.init(true, ivAndKey);
        return cipherData(aes, plain);
    }
}
