/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package blockcipher;

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
        
    }
    
    /**
     * Membuat roundKey dari key yang diberikan. Terdapat 4 roundKey, tiap key
     * terdiri atas 16 Byte.
     * @param key 32 Byte kunci.
     */
    private void generateKey(byte[] key) {
        
    }
    
    /**
     * Fungsi F pada skema Lai-Massey.
     * @param input 16 Byte data.
     * @param key 16 Byte data.
     * @return Hasil fungsi F, terdiri atas 16 Byte data.
     */
    private byte[] F(byte[] input, byte[] key) {
        return null;
    }
    
    /**
     * 1 ronde enkripsi pada skema Lai-Massey.
     * @param input 32 Byte data. 16 Byte data MSB adalah L, dan 16 Byte
     * data LSB adalah R.
     * @param key 16 Byte data.
     * @return hasil enkripsi 1 ronde.
     */
    private byte[] encryptionRound(byte[] input, byte[] key) {
        return null;
    }

    /**
     * 1 ronde dekripsi pada skema Lai-Massey.
     * @param input 32 Byte data. 16 Byte data MSB adalah L, dan 16 Byte
     * data LSB adalah R.
     * @param key 16 Byte data.
     * @return hasil dekripsi 1 ronde.
     */
    private byte[] decryptionRound(byte[] input, byte[] key) {
        return null;
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
    }
}
