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
        generateKey(key);
        
        byte[][] splitted = new byte[data.length/32 + 1][];
        
        //Split
        int i, j, k;
        k = 0 ;
        for (i=0; i<splitted.length; i++)
        {
            splitted[i] = new byte[32];
            
            for (j=0; j<32; j++)
            {
                if (k < data.length)
                {
                    splitted[i][j] = data[k];
                } else {
                    splitted[i][j] = 0;
                }
                k++;
            }
        }
        
        for (i=0; i<splitted.length; i++)
        {
            splitted[i] = encryptionRound(splitted[i], key);
        }
        
        for (i=0; i<splitted.length; i++)
        {
            splitted[i] = H(splitted[i]);
        }
       
        //Gabungin
        byte[] out = new byte[splitted.length * 32];
        k = 0 ;
        for (i=0; i<splitted.length; i++)
        {
            for (j=0; j<32; j++)
            {
                out[k] = splitted[i][j];
                k++;
            }
        }
        
        return out;
    }
    
    /**
     * Fungsi dekripsi utama, mendekripsi data dengan kunci key.
     * @return plainteks hasil dekripsi
     */
    public byte[] decrypt(byte[] data, byte[] key) {
        generateKey(key);
        
        byte[][] splitted = new byte[data.length/32 + 1][];
        
        //Split
        int i, j, k;
        k = 0 ;
        for (i=0; i<splitted.length; i++)
        {
            splitted[i] = new byte[32];
            
            for (j=0; j<32; j++)
            {
                if (k < data.length)
                {
                    splitted[i][j] = data[k];
                } else {
                    splitted[i][j] = 0;
                }
                k++;
            }
        }
        
        for (i=0; i<splitted.length; i++)
        {
            splitted[i] = HInverse(splitted[i]);
        }
        
        for (i=0; i<splitted.length; i++)
        {
            splitted[i] = decryptionRound(splitted[i], key);
        }
       
        //Gabungin
        byte[] out = new byte[splitted.length * 32];
        k = 0 ;
        for (i=0; i<splitted.length; i++)
        {
            for (j=0; j<32; j++)
            {
                out[k] = splitted[i][j];
                k++;
            }
        }
        
        return out;
    }
    
    /**
     * Fungsi H pada skema Lai-Massey.
     * @param input 32 Byte data. 16 Byte data MSB adalah L, dan 16 Byte
     * data LSB adalah R.
     * @return 32 Byte data hasil aplikasi fungsi H. L dan R sama seperti di
     * atas.
     */
    private byte[] H(byte[] input) {
        assert(input != null && input.length == 32);
        // bagi dua
        byte[] r = new byte[16];
        byte[] l = new byte[16];
        
        int i;
        for (i=0; i<16; i++)
        {
            l[i] = input[i];
        }
        for (i=0; i<16; i++)
        {
            r[i] = input[i + 16];
        }
        
        //Jumlahin
        for (i=0; i<16; i++)
        {
            l[i] = (byte) (l[i] + r[i]);
        }
        
        //Shift Left
        byte[] temp = new byte[16];
        for (i=0; i<16; i++)
        {
            temp[i] = l[(i + 4) % 16];
        }
        l = temp;
        
        //Shift Left
        temp = new byte[16];
        for (i=0; i<16; i++)
        {
            temp[i] = r[(i + 4) % 16];
        }
        r = temp;
        
        // Jumlahin
        for (i=0; i<16; i++)
        {
            r[i] = (byte) (r[i] + l[i]);
        }
        
        //Gabungin
        byte[] out = new byte[32];
        for(i=0;i<16;i++)
        {
            out[i] = l[i];
        }
        for(i=0; i<16; i++)
        {
            out[i+16] = l[i];
        }
        
        return out;
    }
    
    /**
     * Fungsi H(-1) pada skema Lai-Massey.
     * @param input 32 Byte data. 16 Byte data MSB adalah L, dan 16 Byte
     * data LSB adalah R.
     * @return 32 Byte data hasil aplikasi fungsi H(-1). L dan R sama seperti di
     * atas.
     */
    private byte[] HInverse(byte[] input) {
        assert(input != null && input.length == 32);
        // bagi dua
        byte[] r = new byte[16];
        byte[] l = new byte[16];
        
        int i;
        for (i=0; i<16; i++)
        {
            l[i] = input[i];
        }
        for (i=0; i<16; i++)
        {
            r[i] = input[i + 16];
        }
        
        //Jumlahin
        for (i=0; i<16; i++)
        {
            l[i] = (byte) (l[i] - r[i]);
        }
        
        //Shift Left
        byte[] temp = new byte[16];
        for (i=0; i<16; i++)
        {
            temp[i] = l[Math.abs(i - 4) % 16];
        }
        l = temp;
        
        //Shift Left
        temp = new byte[16];
        for (i=0; i<16; i++)
        {
            temp[i] = r[Math.abs(i - 4) % 16];
        }
        r = temp;
        
        // Jumlahin
        for (i=0; i<16; i++)
        {
            r[i] = (byte) (r[i] - l[i]);
        }
        
        //Gabungin
        byte[] out = new byte[32];
        for(i=0;i<16;i++)
        {
            out[i] = l[i];
        }
        for(i=0; i<16; i++)
        {
            out[i+16] = l[i];
        }
        
        return out;
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
        
        // kurangkan kedua bagian pada temp
        byte redc[] = new byte[16];
        for (int i = 0; i < 16; ++i) {
            redc[i] = (byte)(input[i] - input[i + 16]);
        }
        
        // aplikasikan F pada redc
        redc = F(redc, key);
        
        // tambahkan redc ke temp
        byte temp[] = new byte[32];
        for (int i = 0; i < 16; ++i) {
            temp[i] = (byte)(input[i] + redc[i]);
            temp[i + 16] = (byte)(input[i + 16] + redc[i]);
        }
        
        // Aplikasikan fungsi H inverse
        temp = HInverse(temp);
        
        return temp;
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
}
