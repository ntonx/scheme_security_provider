package main;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Lab02 {


	static String pathResultFile = "D:\\eclipse-workspace\\Lab02_InfoSecu\\result.csv";
	static String pathCertificate = "D:\\eclipse-workspace\\Lab02_InfoSecu\\certificate\\KeyStore.jks";
	static String sink1 = "D:\\results\\AES\\enc\\";
	static String sink2 = "D:\\results\\AES\\dec\\";
	static String Source = "D:\\dataset1";
	static String signatures = "D:\\results\\signatures\\";
	static String pubkeys = "D:\\results\\pubkeys\\";

	public static void main (String[] args)throws Exception	{	

		if (args.length != 2) uso();
		//READ PARAMS
		int levelSecurity = Integer.parseInt(args[0]);
		String source = args[1];
		
		String algo = "AES";
		long sizeFiles = 0;
		long start = 0;
		long totalTime = 0;
		
		//................................................................................
		//UPLOAD CERTIFICATE ON CODE......................................................
		//................................................................................

		System.out.println("#####-----LOAD CERTIFICATE CREATED BY USER-----#####");
		Certificate mycer = new Certificate (pathCertificate);
		java.security.cert.Certificate cert = mycer.getCert();
		PrivateKey keyver = mycer.getPrivateKey(pathCertificate);
		PublicKey keysig = cert.getPublicKey();

		//................................................................................
		//DELETE DIRECTORIES TO SAVE FILES................................................
		//................................................................................

		Utilities.deleteFiles(sink1);
		Utilities.deleteFiles(sink2);
		Utilities.deleteFiles(signatures);
		Utilities.deleteFiles(pubkeys);
		File[]  target =  Utilities.readFiles(source);

		System.out.println("\nCleaning directories to save files\nReading files from: "+source+"\nGenerating simetric key");

		if(checkSpecification(levelSecurity, algo)) {

			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(levelSecurity);
			int RSAkeySize = checkSize(levelSecurity);
			SecretKey simetricKey = keyGen.generateKey();
			System.out.println("\n#####-----ENCRYPTING FILES USING "+algo+ " "+ levelSecurity+"-----#####\nSaving encrypted files in: "+sink1);
			System.out.println("Getting signatures to each file saved in: "+source+"\n");


			//................................................................................
			//ENCRYPT FILES USING SIMETRIC AES TECHNIQUE......................................
			//................................................................................
			
			sizeFiles = getTotalSizeSource(source);
			start = System.currentTimeMillis();

			for(File file : target) {
				byte[] fileData = Files.readAllBytes(Paths.get(file.getPath()));
				processCipher(algo,simetricKey,fileData,file.getName());
			}
			totalTime = (System.currentTimeMillis() - start);
			Utilities.writeTimeResults(algo+",encrypt,"+String.valueOf(levelSecurity)+","+String.valueOf(sizeFiles)+","+totalTime, pathResultFile);


			//................................................................................
			//GETTING SIGNATURES TO EACH FILE SAVED IN THE SOURCE PATH........................
			//................................................................................
			
			start = System.currentTimeMillis();
			for(File file : target) {
				signDocument(file,keyver,keysig);
			}
			totalTime = (System.currentTimeMillis() - start);
			Utilities.writeTimeResults("Sha256WithRSA,sign,"+String.valueOf(RSAkeySize)+","+String.valueOf(sizeFiles)+","+totalTime, pathResultFile);
			System.out.println("\n#####-----SAVING RESULTS FROM SIGNATURE PROCESS ON: "+signatures+ "  and  "+pubkeys +" -----#####");


			//................................................................................
			//ENCRYPT SIMETRIC KEY USING AN ASIMETRIC RSA TECHNIQUE...........................
			//................................................................................
			
			KeyPairGenerator generadorLlaves = KeyPairGenerator.getInstance("RSA");
			generadorLlaves.initialize(RSAkeySize);
			KeyPair parLlaves = generadorLlaves.genKeyPair();
			System.out.println("\n#####-----ENCRYPTING SYMETRIC KEY USING RSA -----#####");
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			//....starting computing time
			start = System.currentTimeMillis();
			cipher.init(Cipher.ENCRYPT_MODE, parLlaves.getPublic());
			byte[] simetricKeyCiphered = cipher.doFinal(simetricKey.getEncoded());
			totalTime = (System.currentTimeMillis() - start);
			Utilities.writeTimeResults("RSA,generateEnvelope,"+String.valueOf(RSAkeySize)+","+String.valueOf(simetricKeyCiphered.length)+","+totalTime, pathResultFile);


			//................................................................................
			//DECRYPT SIMETRIC KEY USING AN ASIMETRIC RSA TECHNIQUE...........................
			//................................................................................
			
			System.out.println("\n#####-----DECRYPTING SYMETRIC KEY USING RSA-----#####");
			//....starting computing time
			start = System.currentTimeMillis();
			cipher.init(Cipher.DECRYPT_MODE, parLlaves.getPrivate());
			byte[] keySimetricPlain =  cipher.doFinal(simetricKeyCiphered);//data.getBytes());
			SecretKey secretKeyDec = new SecretKeySpec(keySimetricPlain,"AES");
			totalTime = (System.currentTimeMillis() - start);
			Utilities.writeTimeResults("RSA,openEnvelope,"+String.valueOf(RSAkeySize)+","+String.valueOf(keySimetricPlain.length)+","+totalTime, pathResultFile);


			//................................................................................
			//DECRYPT FILES USING SIMETRIC AES TECHNIQUE......................................
			//................................................................................ 
			
			System.out.println("Reading files to decrypt from:"+sink1+"\n\n#####-----DECRYPTING FILES FROM " +sink1+ " USING "+algo +"-----#####\nSaving files decrypted in "+sink2);
			System.out.println("Reading files to check signature from: "+sink2+"\n\n#####-----VERIFICATION PROCESS FOR SIGNATURES SAVED ON "+signatures+" and files saved on "+sink2+" and "+pubkeys+" -----#####");
			File[]  targetDec = Utilities.readFiles(sink1);
			sizeFiles = getTotalSizeSource(sink1);
			start = System.currentTimeMillis();
			for(File file : targetDec) {
				byte[] fileData = Files.readAllBytes(Paths.get(file.getPath()));
				processDeCipher(algo,secretKeyDec,fileData,file.getName());
			}
			totalTime = (System.currentTimeMillis() - start);
			Utilities.writeTimeResults(algo+",decrypt,"+String.valueOf(levelSecurity)+","+String.valueOf(sizeFiles)+","+totalTime, pathResultFile);


			//................................................................................
			//VERIFYING SIGNATURES FROM THE DECRYPTED FILES...................................
			//................................................................................
			
			start = System.currentTimeMillis();
			for(File file : targetDec) {
				String filename = file.getName();
				String fil = filename.substring(0, filename.lastIndexOf('.'));
				verifyMySignature(fil);
			}
			totalTime = (System.currentTimeMillis() - start);
			Utilities.writeTimeResults("Sha256WithRSA,verify,"+String.valueOf(RSAkeySize)+","+String.valueOf(sizeFiles)+","+totalTime, pathResultFile);

			System.out.println("\n#####-----PROCESS FINISHED-----#####\n--------------------------------------------------------------------\n--------------------------------------------------------------------\n\n");

		}else {
			System.err.println(algo+" does not accept "+levelSecurity+" for level security");
		}
	}

	private static long getTotalSizeSource(String source) {
		long sizeFiles = 0;
		File[]  target =  Utilities.readFiles(source);
		for(File file : target) {
			sizeFiles = sizeFiles + file.length();}
		return sizeFiles;
	}

	private static int checkSize(int levelSecurity) {
		int size = 0;
		if(levelSecurity ==128) {
			size = 3072;
		}else if(levelSecurity == 192) {
			size = 7680;
		}else {
			size = 15360;
		}
		return size;
	}

	private static void verifyMySignature(String fil) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidKeySpecException {

		FileInputStream keyfis = new FileInputStream(pubkeys+"suepk"+fil);
		byte[] encKey = new byte[keyfis.available()];  
		keyfis.read(encKey);
		keyfis.close();
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
		FileInputStream sigfis = new FileInputStream(signatures+"sig"+fil);
		byte[] sigToVerify = new byte[sigfis.available()]; 
		sigfis.read(sigToVerify );
		sigfis.close();
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initVerify(pubKey);
		FileInputStream datafis = new FileInputStream(sink2+fil);
		BufferedInputStream bufin = new BufferedInputStream(datafis);
		byte[] buffer = new byte[1024];
		int len;
		while (bufin.available() != 0) {
			len = bufin.read(buffer);
			sig.update(buffer, 0, len);
		};
		bufin.close();
		boolean verifies = sig.verify(sigToVerify);
		System.out.println("Verifying signature to file"+fil+" ----->\tResult signature verification: \t" + verifies);
	}

	private static void signDocument(File file, PrivateKey keyver, PublicKey keysig) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException, IOException {
		Signature generadorFirma = Signature.getInstance("Sha256WithRSA");
		generadorFirma.initSign(keyver);

		FileInputStream fis = new FileInputStream(file.getAbsolutePath());
		BufferedInputStream bufin = new BufferedInputStream(fis);

		byte[] buffer = new byte[1024];
		int len;
		while ((len = bufin.read(buffer)) >= 0) {
			generadorFirma.update(buffer, 0, len);
		};
		bufin.close();
		byte[] realSig = generadorFirma.sign();

		/* Save the signature in a file */
		FileOutputStream sigfos = new FileOutputStream(signatures+"sig"+file.getName());
		sigfos.write(realSig);
		sigfos.close();
		/* Save the public key in a file */
		byte[] key = keysig.getEncoded();
		FileOutputStream keyfos = new FileOutputStream(pubkeys+"suepk"+file.getName());
		keyfos.write(key);
		keyfos.close();

		//Show an base64 encode signature to the user
		Encoder encoder = Base64.getEncoder();
		String firmaDigitaENC = encoder.encodeToString(realSig);           
		System.out.println("Sello digital (codificacion Base64) de archivo " + file.getName()+":");
		System.out.println(firmaDigitaENC);

	}


	private static void processCipher(String algo, SecretKey key, byte[] fileData,String fileName) {
		Cipher1 cipherE1 = null;
		if(algo.equals("AES")){
			cipherE1  = new MyAES();
			byte[] myKey = key.getEncoded();
			byte[] myCipherText = cipherE1.encrypt(fileData, myKey);			
			Utilities.writeOnDisk(sink1+fileName+"."+algo.toLowerCase(),myCipherText);
		}		
	}


	private static void processDeCipher(String algo, SecretKey key, byte[] fileData, String fileName) {
		Cipher1 cipherE1 = null;
		if(algo.equals("AES")) {
			cipherE1  = new MyAES();
			byte[] myKey = key.getEncoded();
			byte[] myPlainText = cipherE1.decrypt(fileData, myKey);			
			Utilities.writeOnDisk(sink2+fileName.substring(0, fileName.lastIndexOf('.')),myPlainText);
		}	
	}


	private static boolean checkSpecification(int levelS, String algo) {
		boolean result = false;
		if((levelS==128||levelS==192||levelS==256) && algo.equals("AES")){
			result = true;
		} 	    
		return result;
	}


	private static void uso(){
		System.err.println("Uso: java main/Lab02 levelSecurity[128|192|256]  sourcePath");
		System.exit(1);
	}



}
