package com.authorityverifier.dataSighner;

import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class Tester {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
        System.out.println("Max Key Size for AES : " + maxKeySize);
    }
}
