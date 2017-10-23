package com.qiuxiang.ibeJCA;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Base64;

public class KEM_IBE{
	public static void main(String[] args) throws NoSuchAlgorithmException, 
												  InvalidKeySpecException, 
												  NoSuchPaddingException, 
												  InvalidKeyException, 
												  InvalidAlgorithmParameterException, 
												  IllegalBlockSizeException, 
												  BadPaddingException, IOException {

//*****************************Key Generation***************************************

		// IBE System parameters
		String parameFile = "params/curves/a.properties";
	    String mskFile = "MSKFILE";
	    PairingParameters params = PairingFactory.
		  		  getPairingParameters(parameFile);
		IBESetup ibeSetup = new IBESetup(params, mskFile);
		Pairing pairing = ibeSetup.getPairing();		
		MessageDigest mDigest = null;
		try {
			mDigest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("No such algorithm");
		}
		IBESystemParameters ibeSystemParameters = new IBESystemParameters(pairing, 
																mDigest, mskFile);		
		
		// Generate key pair for the identity "example@foo.com"
		String id = "example@foo.com";
		// IBE Key parameters for identity "example@foo.com"
        IBEKeyParameters ibeKeyParameters = new IBEKeyParameters(mDigest, id, 
        														mskFile, pairing);
        // IBE Key pair for idenitty "example@foo.com"
        IBEKeyPairGenerator ibeKeyPairGenerator = new IBEKeyPairGenerator();
        ibeKeyPairGenerator.initialize(ibeKeyParameters);     
        KeyPair keyPair = ibeKeyPairGenerator.generateKeyPair();
        // IBE Public Key for "exmaple@foo.com"
        IBEPublicKey ibePublicKey = (IBEPublicKey)keyPair.getPublic();
        // IBE Private Key for "example@foo.com"
        IBEPrivateKey ibePrivateKey = (IBEPrivateKey)keyPair.getPrivate();
        
	    // Symmetric encryption algorithm
	    String algorithm = "PBEWithMD5AndDES";
	    // salt
	    byte[] salt = new byte[8];
	    //count of iterations
	    int iterations = 20;	    
	    // spassphrase is the exmaple passphrase used in the PBE encryption
	    String spassphrase = "passphrase";
	    char[] passphrase = spassphrase.toCharArray();
	    // Generate a secret key based on the passphrase
	    KeySpec ks = new PBEKeySpec(passphrase);
	    SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);
	    SecretKey key = skf.generateSecret(ks);
	    	    
	    // plaintext is the file to be encrytped
	    File inputFile = new File("plaintext");
	    // ciphertext is the file to store the symmetric PBE ciphertexts
	    File outputFile = new File("ciphertext");
	    // outputFile is the file to store the asymmetric IBE ciphertexts
	    File ibeCiphertextFile = new File("outputFile");

// *********************************Begin of Encryption*******************************

	    // Encrypt the secret key with IBE
	    byte[] encodedSecretKey = Base64.getEncoder().encodeToString(key.getEncoded()).getBytes();
	    IBECipher ibeCipher = new IBECipher();
	    ibeCipher.engineInit(Cipher.ENCRYPT_MODE, ibePublicKey, ibeSystemParameters,
                new SecureRandom());
        byte[] ibeCiphertextSent = ibeCipher.engineDoFinal(encodedSecretKey, 0, 
        													encodedSecretKey.length);
        @SuppressWarnings("resource")
		FileOutputStream ibeOut = new FileOutputStream(ibeCiphertextFile);
        ibeOut.write(ibeCiphertextSent);
        
        // Read plaintext from the file
	    FileInputStream in = new FileInputStream(inputFile);
	    int length = (int)inputFile.length();
	    byte[] input = new byte[length];
	    in.read(input);
	    in.close();
	    
        // Create the salt from eight bytes of the digest of P || M.
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(spassphrase.getBytes());
        md.update(input);
        byte[] digest = md.digest();
        System.arraycopy(digest, 0, salt, 0, 8);
        
        // Encrypt the plaintext file and store it into ciphertext
	    AlgorithmParameterSpec aps = new PBEParameterSpec(salt, iterations);
	    Cipher cipher = Cipher.getInstance(algorithm);
	    cipher.init(Cipher.ENCRYPT_MODE, key, aps);
	    byte[] output = cipher.doFinal(input);
	    OutputStream out = new FileOutputStream(outputFile);
	    out.write(salt);
	    out.write(output);
	    out.close(); 
	    System.out.println("Encryption Done");

// *********************************Begin of Decryption*****************************
	    
	    inputFile = new File("ciphertext");
	    outputFile = new File("decrypted");
	    
	    // IBE decryption to get the secret key
	    byte[] ibeCipherTextReceived = new byte [(int)ibeCiphertextFile.length()];
        FileInputStream ibeIn = new FileInputStream(ibeCiphertextFile);
        ibeIn.read(ibeCipherTextReceived);
        
        ibeCipher.engineInit(Cipher.DECRYPT_MODE, ibePrivateKey, ibeSystemParameters,
                new SecureRandom());
        byte[] ibeplaintext = ibeCipher.engineDoFinal(ibeCipherTextReceived, 0, 
        		ibeCipherTextReceived.length);

	    byte[] decodedKey = Base64.getDecoder().decode(ibeplaintext);
	    // Secret key of PBE
	    SecretKey key2 = new SecretKeySpec(decodedKey, 0, decodedKey.length, "PBEWithMD5AndDES");
		    	    
	    in = new FileInputStream(inputFile);
	    length = (int)inputFile.length();
	    in.read(salt);
	    input = new byte[length - 8];
	    in.read(input);
	    in.close();
	    
	    // Create the algorithm parameters
	    aps = new PBEParameterSpec(salt, iterations);
	    // Decrypt the ciphertext
	    cipher = Cipher.getInstance(algorithm);
	    cipher.init(Cipher.DECRYPT_MODE, key2, aps);
	    byte[] outputPlaintext = cipher.doFinal(input);
	    // Write the output
	    out = new FileOutputStream(outputFile);
	    out.write(outputPlaintext);
	    out.close();  
	    System.out.println("Decryption Done");
	}
}
