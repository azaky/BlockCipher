/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package blockcipher;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Toshiba
 */
public class BlockCipher {
    
    private byte[][] roundKey;
    
    /**
     * Fungsi enkripsi utama, mengenkripsi data dengan kunci key.
     * @return cipherteks hasil enkripsi
     */
    public byte[] encrypt(byte[] data, byte[] key) {
        return null;
    }
    
    /**
     * Fungsi dekripsi utama, mendekripsi data dengan kunci key.
     * @return plainteks hasil dekripsi
     */
    public byte[] decrypt(byte[] data, byte[] key) {
        return null;
    }
    
    /**
     * Fungsi H pada skema Lai-Massey.
     * @param input 32 Byte data. 16 Byte data MSB adalah L, dan 16 Byte
     * data LSB adalah R.
     * @return 32 Byte data hasil aplikasi fungsi H. L dan R sama seperti di
     * atas.
     */
    private byte[] H(byte[] input) {
        return null;
    }
    
    /**
     * Fungsi H(-1) pada skema Lai-Massey.
     * @param input 32 Byte data. 16 Byte data MSB adalah L, dan 16 Byte
     * data LSB adalah R.
     * @return 32 Byte data hasil aplikasi fungsi H(-1). L dan R sama seperti di
     * atas.
     */
    private byte[] HInverse(byte[] input) {
        return null;
    }
    
    /**
     * Fungsi PBox, mempermutasikan input sesuai dengan key yang diberikan.
     * @param input 16 Byte data. Input ini sekaligus menjadi output dari
     * prosedur ini.
     * @param key Kunci yang terdiri dari 16 Byte data.
     */
    private void PBox(byte[] input, byte[] key) {
        assert(input != null && key != null && input.length == 16
                && key.length == 16);
        
        for (int i = 0; i < 16; ++i) {
            // cari indeks yang akan ditukar
            int idxA = (key[i] >> 4) & 0xF;
            int idxB = key[i] & 0xF;
            
            // lakukan swap dan XOR
            byte temp = input[idxB];
            input[idxB] = (byte)(input[idxA] ^ input[idxB]);
            input[idxA] = temp;
        }
    }
    
    /**
     * Membuat roundKey dari key yang diberikan. Terdapat 4 roundKey, tiap key
     * terdiri atas 16 Byte.
     * @param key 32 Byte kunci.
     */
    private void generateKey(byte[] key) {
        assert(key != null && key.length == 32);
        
        // alokasi roundKey
        roundKey = new byte[4][16];
        
        // key 0
        for (int i = 0; i < 16; ++i) {
            roundKey[0][i] = key[i];
        }
        
        // key 1
        for (int i = 0; i < 16; ++i) {
            roundKey[1][i] = key[i + 16];
        }
        
        // key 2
        for (int i = 0; i < 16; ++i) {
            roundKey[2][i] = key[((i + 4) % 16) + 16];
        }
        
        // key 3
        for (int i = 0; i < 16; ++i) {
            roundKey[3][i] = key[((i + 7) % 16) + 16];
        }
    }
    
    /**
     * Fungsi F pada skema Lai-Massey.
     * @param input 16 Byte data.
     * @param key 16 Byte data.
     * @return Hasil fungsi F, terdiri atas 16 Byte data.
     */
    private byte[] F(byte[] input, byte[] key) {
        assert(input != null && key != null && input.length == 16
                && key.length == 16);
        
        // aplikasikan xor antara input dengan key
        byte[] ret = new byte[16];
        for (int i = 0; i < 16; ++i) {
            ret[i] = (byte)(input[i] ^ key[i]);
        }
        
        // aplikasikan pbox
        PBox(ret, key);
        
        // aplikasikan MD5 pada key
        byte[] md5Key = new byte[16];
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md5Key = md.digest(key);
            assert(md5Key.length == 16);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(BlockCipher.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        // aplikasikan xor terakhir
        for (int i = 0; i < 16; ++i) {
            ret[i] = (byte)(ret[i] ^ md5Key[i]);
        }
        
        return ret;
    }
    
    /**
     * 1 ronde enkripsi pada skema Lai-Massey.
     * @param input 32 Byte data. 16 Byte data MSB adalah L, dan 16 Byte
     * data LSB adalah R.
     * @param key 16 Byte data.
     * @return hasil enkripsi 1 ronde.
     */
    private byte[] encryptionRound(byte[] input, byte[] key) {
        assert(input != null && key != null && input.length == 32
                && key.length == 16);
        
        // Aplikasikan fungsi H
        byte temp[] = H(input);
        
        // kurangkan kedua bagian pada temp
        byte redc[] = new byte[16];
        for (int i = 0; i < 16; ++i) {
            redc[i] = (byte)(temp[i] - temp[i + 16]);
        }
        
        // aplikasikan F pada redc
        redc = F(redc, key);
        
        // tambahkan redc ke temp
        for (int i = 0; i < 16; ++i) {
            temp[i] = (byte)(temp[i] + redc[i]);
            temp[i + 16] = (byte)(temp[i + 16] + redc[i]);
        }
        
        return temp;
    }

    /**
     * 1 ronde dekripsi pada skema Lai-Massey.
     * @param input 32 Byte data. 16 Byte data MSB adalah L, dan 16 Byte
     * data LSB adalah R.
     * @param key 16 Byte data.
     * @return hasil dekripsi 1 ronde.
     */
    private byte[] decryptionRound(byte[] input, byte[] key) {
        assert(input != null && key != null && input.length == 32
                && key.length == 16);
        
        // Aplikasikan fungsi H inverse
        byte temp[] = HInverse(input);
        
        // kurangkan kedua bagian pada temp
        byte redc[] = new byte[16];
        for (int i = 0; i < 16; ++i) {
            redc[i] = (byte)(temp[i] - temp[i + 16]);
        }
        
        // aplikasikan F pada redc
        redc = F(redc, key);
        
        // tambahkan redc ke temp
        for (int i = 0; i < 16; ++i) {
            temp[i] = (byte)(temp[i] + redc[i]);
            temp[i + 16] = (byte)(temp[i + 16] + redc[i]);
        }
        
        return temp;
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
}
