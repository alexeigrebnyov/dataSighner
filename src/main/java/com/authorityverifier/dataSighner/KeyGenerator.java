package com.authorityverifier.dataSighner;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
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
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class KeyGenerator {

    public void addProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }


    private CertificateFactory certFactory= CertificateFactory
            .getInstance("X.509", "BC");
    private X509Certificate certificate = (X509Certificate) certFactory
            .generateCertificate(new FileInputStream("cert.cer"));

    private char[] keystorePassword = "sslPASS03042022".toCharArray();
    private char[] keyPassword = "sslPASS03042022".toCharArray();

     private KeyStore getKeystore() throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
         keystore.load(new FileInputStream("vashcert.p12"), keystorePassword);
         return keystore;
     }
     private PrivateKey key = (PrivateKey) getKeystore().getKey("second", keyPassword);
     

       public KeyGenerator() throws CertificateException, NoSuchProviderException, IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
    }

    public static byte[] signData(
            byte[] data,
            X509Certificate signingCertificate,
            PrivateKey signingKey) throws Exception {

        byte[] signedMessage = null;
        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        CMSTypedData cmsData= new CMSProcessableByteArray(data);
        certList.add(signingCertificate);
        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        ContentSigner contentSigner
                = new JcaContentSignerBuilder("SHA256withRSA").build(signingKey);
        cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC")
                        .build()).build(contentSigner, signingCertificate));
        cmsGenerator.addCertificates(certs);

        CMSSignedData cms = cmsGenerator.generate(cmsData, true);
        signedMessage = cms.getEncoded();
        return signedMessage;
    }

    public static boolean verifSignedData(byte[] signedData)
            throws Exception {

        X509Certificate signCert = null;
        ByteArrayInputStream inputStream
                = new ByteArrayInputStream(signedData);
        ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);
        CMSSignedData cmsSignedData = new CMSSignedData(
                ContentInfo.getInstance(asnInputStream.readObject()));

        SignerInformationStore signers
                = cmsSignedData/*getCertificates()*/.getSignerInfos();
        SignerInformation signer = signers.getSigners().iterator().next();
        Collection<X509CertificateHolder> certCollection
                = certs.getMatches(signer.getSID());
        X509CertificateHolder certHolder = certCollection.iterator().next();

        return signer
                .verify(new JcaSimpleSignerInfoVerifierBuilder()
                        .build(certHolder));
    }





}
