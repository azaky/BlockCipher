/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package blockcipher;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Fahziar Riesad Wutono dan Ahmad Zaky
 */
public class BlockCipher {
    
    private static boolean DEBUG_MODE = false;
    private byte[][] roundKey;
    private byte[] IV;
    
    // mode enkripsi/dekripsi
    public final static int MODE_ECB        = 0;
    public final static int MODE_CBC        = 1;
    public final static int MODE_CFB        = 2;
    public int mode = MODE_ECB;
    
    /**
     * Fungsi enkripsi utama, mengenkripsi data dengan kunci key.
     * @return cipherteks hasil enkripsi
     */
    public byte[] encrypt(byte[] data, byte[] key) {
        generateKey(key);
        
        byte[][] splitted = new byte[(data.length + 31) / 32][];
        
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
        
        generateInitializationVector(key);
        
        if (DEBUG_MODE) System.out.println("Encryption:");
        
        for (i = 0; i < splitted.length; ++i) {
            switch (mode) {
                case MODE_ECB:
                    splitted[i] = blockEncrypt(splitted[i], key);
                    break;
                    
                case MODE_CBC:
                    if (i == 0) {
                        splitted[i] = xorBytes(splitted[i], IV);
                    } else {
                        splitted[i] = xorBytes(splitted[i], splitted[i-1]);
                    }
                    splitted[i] = blockEncrypt(splitted[i], key);
                    break;
                    
                case MODE_CFB:
                    if (i == 0) {
                        splitted[i] = xorBytes(splitted[i], blockEncrypt(IV, key));
                    } else {
                        splitted[i] = xorBytes(splitted[i], blockEncrypt(splitted[i-1], key));
                    }
                    break;
            }
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
        
        byte[][] splitted = new byte[(data.length + 31)/32][];
        
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

        if (DEBUG_MODE) System.out.println("Decryption:");
        
        byte[][] plaintext = new byte[splitted.length][];
        
        for (i = 0; i < splitted.length; ++i) {
            switch (mode) {
                case MODE_CBC:
                    if (i == 0) {
                        plaintext[i] = xorBytes(blockDecrypt(splitted[i], key), IV);
                    } else {
                        plaintext[i] = xorBytes(blockDecrypt(splitted[i], key), splitted[i-1]);
                    }
                    break;
                    
                case MODE_CFB:
                    if (i == 0) {
                        plaintext[i] = xorBytes(splitted[i], blockEncrypt(IV, key));
                    } else {
                        plaintext[i] = xorBytes(splitted[i], blockEncrypt(splitted[i-1], key));
                    }
                    break;

                case MODE_ECB:
                default:
                    plaintext[i] = blockDecrypt(splitted[i], key);
                    break;
            }
        }

        //Gabungin
        byte[] out = new byte[plaintext.length * 32];
        k = 0 ;
        for (i=0; i<plaintext.length; i++)
        {
            for (j=0; j<32; j++)
            {
                out[k] = plaintext[i][j];
                k++;
            }
        }
        
        return out;
    }
    
    /**
     * Fungsi yang mengenkripsi satu buah blok
     * @return cipherteks hasil enkripsi
     */
    private byte[] blockEncrypt(byte[] data, byte[] key) {
        assert(data != null && key != null && data.length == 32 && key.length == 32);
        
        byte[] ciphertext = new byte[32];
        for (int i = 0; i < 32; ++i) {
            ciphertext[i] = data[i];
        }
        
        for (int round = 0; round < 4; ++round) {
            if (DEBUG_MODE) System.out.printf("Round %2d  : ", round);
            ciphertext = encryptionRound(ciphertext, roundKey[round]);
            
            if (DEBUG_MODE) {
                Test.printBytes(ciphertext);
                System.out.println();
            }
        }
        
        if (DEBUG_MODE) System.out.printf("Half Round: ");
        ciphertext = H(ciphertext);
        if (DEBUG_MODE) {
            Test.printBytes(ciphertext);
            System.out.println();
        }
        
        return ciphertext;
    }
    
    /**
     * Fungsi yang mendekripsi satu buah blok
     * @return plainteks hasil dekripsi
     */
    private byte[] blockDecrypt(byte[] data, byte[] key) {
        assert(data != null && key != null && data.length == 32 && key.length == 32);
        
        byte[] plaintext = new byte[32];
        for (int i = 0; i < 32; ++i) {
            plaintext[i] = data[i];
        }
        
        if (DEBUG_MODE) System.out.printf("Half Round: ");
        plaintext = HInverse(plaintext);
        if (DEBUG_MODE) {
            Test.printBytes(plaintext);
            System.out.println();
        }
        
        for (int round = 3; round >= 0; --round) {
            if (DEBUG_MODE) System.out.printf("Round %2d  : ", round);
            plaintext = decryptionRound(plaintext, roundKey[round]);
            
            if (DEBUG_MODE) {
                Test.printBytes(plaintext);
                System.out.println();
            }
        }
        
        
        return plaintext;
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
        
        // XOR
        for (i=0; i<16; i++)
        {
            l[i] = (byte) (l[i] ^ r[i]);
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
            temp[i] = r[(i + 7) % 16];
        }
        r = temp;
        
        // XOR
        for (i=0; i<16; i++)
        {
            r[i] = (byte) (r[i] ^ l[i]);
        }
        
        //Gabungin
        byte[] out = new byte[32];
        for(i=0;i<16;i++)
        {
            out[i] = l[i];
        }
        for(i=0; i<16; i++)
        {
            out[i+16] = r[i];
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
        
        // XOR
        for (i=0; i<16; i++)
        {
            r[i] = (byte) (l[i] ^ r[i]);
        }
        
        //Shift Left
        byte[] temp = new byte[16];
        for (i=0; i<16; i++)
        {
            temp[i] = l[(i + 12) % 16];
        }
        l = temp;
        
        //Shift Left
        temp = new byte[16];
        for (i=0; i<16; i++)
        {
            temp[i] = r[(i + 9) % 16];
        }
        r = temp;
        
        // XOR
        for (i=0; i<16; i++)
        {
            l[i] = (byte) (r[i] ^ l[i]);
        }
        
        //Gabungin
        byte[] out = new byte[32];
        for(i=0;i<16;i++)
        {
            out[i] = l[i];
        }
        for(i=0; i<16; i++)
        {
            out[i+16] = r[i];
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
        
        // kurangkan temp dari redc
        byte temp[] = new byte[32];
        for (int i = 0; i < 16; ++i) {
            temp[i] = (byte)(input[i] - redc[i]);
            temp[i + 16] = (byte)(input[i + 16] - redc[i]);
        }
        
        // Aplikasikan fungsi H inverse
        temp = HInverse(temp);
        
        return temp;
    }
    
    /**
     * Membuat IV berdasarkan kunci yang ada.
     * @param key 
     */
    private void generateInitializationVector(byte[] key) {
        IV = new byte[32];
        
        // use key as seed for IV
        long seed = 0;
        for (int i = 0; i < key.length; ++i) {
            seed *= 257;
            seed += key[i];
        }
        Random random = new Random(seed);
        random.nextBytes(IV);
    }
    
    /**
     * Menghitung xor dari dua buah array of byte
     * @return 
     */
    private byte[] xorBytes(byte[] a, byte[] b) {
        assert(a != null && b != null && a.length == b.length);
        
        byte[] result = new byte[a.length];
        for (int i = 0; i < result.length; ++i) {
            result[i] = (byte)(a[i] ^ b[i]);
        }
        return result;
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        Test.main(null);
    }
}
