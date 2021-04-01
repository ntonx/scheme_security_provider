package main;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MyAES extends Cipher1{


	byte[] keyGen(int secLevel){
		if(secLevel == 256 || secLevel == 192 || secLevel == 128) {
			SecretKey myDesKey = null;
			try{   
				KeyGenerator generator = KeyGenerator.getInstance("AES");
				generator.init(secLevel); 
				myDesKey = generator.generateKey();
				if (myDesKey == null){
					System.out.println("No es posible generar la llave AES");
					return null;
				}
				return myDesKey.getEncoded();
			}catch(Exception e){}
		}else {
			System.out.println("AES solo usa llaves de 128, 192 o 256 bits");
			return null;
		}
		return null;
	}   


	/*
	 * THIS METHOD DOES NOT USE A INICIALIZED VECTOR. IT IS ECB BLOCK ENCRYPTION
	 */
	@Override
	public byte[] encrypt(byte[] plaintext, byte[] key) {
		javax.crypto.Cipher aesCipher = null;
		try {
			aesCipher = javax.crypto.Cipher.getInstance("AES");
			aesCipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new SecretKeySpec(key,"AES"));
			byte[] byteCipherText = aesCipher.doFinal(plaintext);
			return byteCipherText;
		}catch(Exception e) {}
		return null;
	}

	/*
	 * THIS METHOD DOES NOT USE A INICIALIZED VECTOR. IT IS ECB BLOCK ENCRYPTION
	 */
	@Override
	byte[] decrypt(byte[] cipherText, byte[] key) {
		javax.crypto.Cipher cipher = null;
		try{
			cipher = javax.crypto.Cipher.getInstance("AES");
			cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
			byte[] byteCipherText = cipher.doFinal(cipherText);
			return byteCipherText;

		}catch(Exception e) {}

		return null;
	}

	/*
	 * THIS METHOD DOES USE A INICIALIZED VECTOR. IT IS AES/CBC/PKCS5Padding
	 */
	@Override
	byte[] encrypt(byte[] plaintext, byte[] key,IvParameterSpec VI ){
		javax.crypto.Cipher cipher = null;
		try {		   
			SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
			cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, skeySpec, VI);
			byte[] cipherTextString = cipher.doFinal(plaintext);
			return cipherTextString;
		}catch(Exception e) {
			return null;
		}
	}

	/*
	 * THIS METHOD DOES USE A INICIALIZED VECTOR. IT IS AES/CBC/PKCS5Padding
	 */
	@Override
	byte[] decrypt(byte[] CipherText, byte[] key, IvParameterSpec vI) {

		javax.crypto.Cipher cipher = null;
		try {		   
			SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
			cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(javax.crypto.Cipher.DECRYPT_MODE, skeySpec, vI);
			byte[] plaintext = cipher.doFinal(CipherText);
			return plaintext;
		}catch(Exception e) {
			return null;
		}
	}



}