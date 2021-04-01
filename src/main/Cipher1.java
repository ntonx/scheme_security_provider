package main;

import javax.crypto.spec.IvParameterSpec;

public abstract class Cipher1{

   abstract byte[] keyGen(int secLevel);   
   public abstract byte[] encrypt(byte[] plaintext, byte[] key);
   abstract byte[] decrypt(byte[] cipherText, byte[] key);
   abstract byte[] encrypt(byte[] plaintext, byte[] key, IvParameterSpec vI);
   abstract byte[] decrypt(byte[] CipherText, byte[] key, IvParameterSpec vI);
}

