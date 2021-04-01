package main;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class Certificate {
	java.security.cert.Certificate cert;
	KeyStore keystore;
	public Certificate(String pathFile) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		File file = new File(pathFile);
        FileInputStream is = new FileInputStream(file);
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        /*Information for certificate to be generated */ 
        String password = "PASSWORD";
        String alias = "mydomain";
        keystore.load(is, password.toCharArray());
        
        java.security.cert.Certificate cert = keystore.getCertificate(alias); 
         this.cert = cert;
         this.keystore = keystore;
	}
	
	public java.security.cert.Certificate getCert() {
		return this.cert;
	}
    
    public PrivateKey getPrivateKey (String pathCertificate) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
    	File file = new File(pathCertificate);
        FileInputStream is = new FileInputStream(file);
        String password = "PASSWORD";
        String alias = "mydomain";
        keystore.load(is, password.toCharArray());
        PrivateKey key = (PrivateKey)keystore.getKey(alias, "PASSWORD".toCharArray());
        
		return key;
    }
}
