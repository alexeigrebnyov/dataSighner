package com.authorityverifier.dataSighner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class KeyGenerator {

    private CertificateFactory certFactory= CertificateFactory
            .getInstance("X.509", "BC");
    private X509Certificate certificate = (X509Certificate) certFactory
            .generateCertificate(new FileInputStream("cert.cer"));

    private char[] keystorePassword = "sslPASS03042022".toCharArray();
    private char[] keyPassword = "sslPASS03042022".toCharArray();

    private KeyStore keystore = KeyStore.getInstance("PKCS12");
     private KeyStore getKeystore() throws IOException, CertificateException, NoSuchAlgorithmException {
         keystore.load(new FileInputStream("vashcert.p12"), keystorePassword);
         return keystore;
     }
    PrivateKey key = (PrivateKey) keystore.getKey("second", keyPassword);
     

       public KeyGenerator() throws CertificateException, NoSuchProviderException, FileNotFoundException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
    }

    public void addProvider() {
           Security.addProvider(new BouncyCastleProvider());
    }



}
