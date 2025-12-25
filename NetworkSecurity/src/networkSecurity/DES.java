package networkSecurity;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;


import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;


public class DES {


    //DES Encrypt and Decrypt Methods:
    public static byte[] E(byte[] data, byte[] keyBytes) {
        try {
            SecretKey key = new SecretKeySpec(keyBytes, "DES");
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("DES encryption failed", e);
        }
    }


    public static byte[] D(byte[] data, byte[] keyBytes) throws Exception {
        SecretKey key = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }


    //Additional methods:

    //Method that creates random DES key for a session
    public static SecretKey generateRandomKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("DES");
            keyGen.init(56);
            SecretKey key = keyGen.generateKey();
            return key;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    //gets the DES key from password
    public static SecretKey getKeyFromPassword(String password) {
        byte[] keyBytes = Arrays.copyOf(password.getBytes(StandardCharsets.UTF_8), 8);
        return new SecretKeySpec(keyBytes, "DES");
    }


    //process key padding/trimming
    public static byte[] processKey(String str) {
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            if (i < bytes.length) {
                keyBytes[i] = bytes[i];
            } else {
                keyBytes[i] = 0;
            }
        }
        return keyBytes;
    }





}
