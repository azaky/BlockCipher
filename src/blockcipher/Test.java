/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package blockcipher;

import java.util.Random;

/**
 *
 * @author Toshiba
 */
public class Test {
    public static void printBytes(byte[] a) {
        for (int i = 0; i < a.length; ++i) {
            if (i > 0) {
                System.out.printf(" ");
            }
            System.out.printf("%02x", a[i]);
        }
    }
    
    public static boolean test(byte[] plaintext, byte[] key, int mode, boolean print) {
        BlockCipher bc = new BlockCipher();
        bc.mode = mode;
        
        if (print) {
            System.out.printf("Index      : ");
            for (int i = 0; i < 32; ++i) {
                if (i > 0) {
                    System.out.printf(" ");
                }
                System.out.printf("%2d", i);
            }
            System.out.println();

            System.out.printf("Key        : ");
            printBytes(key);
            System.out.println();

            System.out.printf("Plain Text : ");
            printBytes(plaintext);
            System.out.println();
        }
        
        byte[] ciphertext = bc.encrypt(plaintext, key);
        
        if (print) {
            System.out.printf("Cipher Text: ");
            printBytes(ciphertext);
            System.out.println();
        }
        
        byte[] decrypted = bc.decrypt(ciphertext, key);
        
        if (print) {
            System.out.printf("Decrypted  : ");
            printBytes(decrypted);
            System.out.println();
        
            System.out.println();
        }
        
        // check if it is the same
        if (decrypted.length < plaintext.length) {
            return false;
        }
        for (int i = 0; i < plaintext.length; ++i) {
            if (plaintext[i] != decrypted[i]) {
                return false;
            }
        }
        for (int i = plaintext.length; i < decrypted.length; ++i) {
            if (decrypted[i] != 0) {
                return false;
            }
        }
        return true;
    }
    
    public static void main(String args[]) {
        byte[] plaintext = new byte[1048576];
        byte[] key = new byte[32];
        
        Random random = new Random(System.currentTimeMillis());
        
        for (int mode = 0; mode < 3; ++mode) {
            for (int testcase = 0; testcase < 10; ++testcase) {
                random.nextBytes(key);
                random.nextBytes(plaintext);

                long startTime = System.currentTimeMillis();
                boolean result = test(plaintext, key, mode, false);
                long finishTime = System.currentTimeMillis();

                System.out.printf("Test %2d, Mode %d (%4d ms): %s\n", testcase, mode, finishTime - startTime, result ? "SUCCESS" : "FAILURE");
            }
        }
    }
}
