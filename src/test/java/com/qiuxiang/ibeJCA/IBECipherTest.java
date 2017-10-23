package com.qiuxiang.ibeJCA;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.Arrays;
import junit.framework.TestCase;

public class IBECipherTest extends TestCase{
	public void testBigMessage() {
		//Pairing
		String parameFile = "params/curves/a.properties";
	    PairingParameters params = PairingFactory.
		  		  getPairingParameters(parameFile);
	    Pairing pairing = PairingFactory.getPairing(params);
	    //Master secret key
	    String masterKeyFile = "MasterSecretKey";
	    Path path = Paths.get(masterKeyFile);
	    byte[] data = new byte[]{};
		try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			throw new NullPointerException("masterKey cannot be null");
		}
	    Element msk = pairing.getZr().newElementFromBytes(data);
	    
	    //identity
		byte[] id = "qiuxiang.dong@asu.edu".getBytes();
		Element Qid = pairing.getG1().newElement().setFromHash(id, 0, id.length);
		MessageDigest mDigest = null;
		try {
			mDigest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.toString());
		}
		IBESystemParameters ibeSystemParameters = new IBESystemParameters(pairing, mDigest, masterKeyFile);
		
		IBECipher ibeCipher = new IBECipher();
        IBEPublicKey publickey = new IBEPublicKey(id);
        try {
        	ibeCipher.engineInit(Cipher.ENCRYPT_MODE, publickey, ibeSystemParameters,
                              new SecureRandom());
        } catch (InvalidKeyException iae) {
            assertTrue(false);
        } catch (InvalidAlgorithmParameterException iape) {
            assertTrue(false);
        }
        
        //Get the encrypted data
        BigInteger m = new BigInteger(999, new SecureRandom());
        byte input[] = m.toByteArray();
        byte ciphertext[] = new byte[0];
        try {
            ciphertext = ibeCipher.engineDoFinal(input, 0, input.length);
        } catch (IllegalBlockSizeException ibse) {
            assertTrue(ibse.toString(), false);
        } catch (BadPaddingException bpe) {
            assertTrue(bpe.toString(), false);
        }
        
		Element privatekeyE = Qid.mulZn(msk);
		IBEPrivateKey ibePrivateKey = new IBEPrivateKey(privatekeyE);
        try {
        	ibeCipher.engineInit(Cipher.DECRYPT_MODE, ibePrivateKey, ibeSystemParameters,
                              new SecureRandom());
        } catch (InvalidKeyException iae) {
            assertTrue(false);
        } catch (InvalidAlgorithmParameterException iape) {
            assertTrue(false);
        }
        
        // get the decrypted data
        byte plaintext[] = new byte[0];
        try {
            plaintext = ibeCipher.engineDoFinal(ciphertext, 0, ciphertext.length);
        } catch (IllegalBlockSizeException ibse) {
            assertTrue(ibse.toString(), false);
        } catch (BadPaddingException bpe) {
            assertTrue(bpe.toString(), false);
        }
        assertTrue(m.compareTo(new BigInteger(1, plaintext)) == 0);
	}	
	
	public void testEncryptDecryptBlock() {
		//Pairing
		String parameFile = "params/curves/a.properties";
	    PairingParameters params = PairingFactory.
		  		  getPairingParameters(parameFile);
	    Pairing pairing = PairingFactory.getPairing(params);
	    
	    //Master secret key
	    String masterKeyFile = "MasterSecretKey";
	    Path path = Paths.get(masterKeyFile);
	    byte[] data = new byte[]{};
		try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			throw new NullPointerException("masterKey cannot be null");
		}
	    Element msk = pairing.getZr().newElementFromBytes(data);
	    
	    //IBESystem parameter
	    MessageDigest mDigest = null;
		try {
			mDigest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e1) {
			assertTrue(true);
		}
				
		Element P = pairing.getG1().newRandomElement().getImmutable();
		Element Ppub = P.mulZn(msk);
	    IBESystemParameters ibeSystemParameters = new IBESystemParameters(pairing, P,
	    													Ppub, mDigest);	   
	    //identity
		byte[] id = "qiuxiang.dong@asu.edu".getBytes();
		Element Qid = pairing.getG1().newElement().setFromHash(id, 0, id.length);
		
		IBECipher ibeCipher = new IBECipher();
		IBEPublicKey ibePublicKey = new IBEPublicKey(id);
        try {
        	ibeCipher.engineInit(Cipher.ENCRYPT_MODE, ibePublicKey, 
        						ibeSystemParameters, new SecureRandom());
        } catch (InvalidKeyException iae) {
            assertTrue(true);
        } catch (InvalidAlgorithmParameterException iape) {
            assertTrue(true);
        }
        
        // get the encrypted data
        BigInteger m = new BigInteger("32");
        byte input[] = m.toByteArray();
        byte ciphertext[] = ibeCipher.encryptBlock(input);
        
        Element Did = Qid.mulZn(msk);
        IBEPrivateKey ibePrivateKey = new IBEPrivateKey(Did);
        
        try {
        	ibeCipher.engineInit(Cipher.DECRYPT_MODE, ibePrivateKey, 
        						ibeSystemParameters, new SecureRandom());
        } catch (InvalidKeyException iae) {
            assertTrue(true);
        } catch (InvalidAlgorithmParameterException iape) {
            assertTrue(true);
        }
        // get the decrypted data
        byte plaintext[] = ibeCipher.decryptBlock(ciphertext);
        assertTrue(m.compareTo(new BigInteger(1, plaintext)) == 0);
	}
	
	public void testEngineDoFinal() {
		//Pairing
		String parameFile = "params/curves/a.properties";
	    PairingParameters params = PairingFactory.
		  		  getPairingParameters(parameFile);
	    Pairing pairing = PairingFactory.getPairing(params);
	    
	    //Master secret key
	    String masterKeyFile = "MasterSecretKey";
	    Path path = Paths.get(masterKeyFile);
	    byte[] data = new byte[]{};
		try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			throw new NullPointerException("masterKey cannot be null");
		}
	    Element msk = pairing.getZr().newElementFromBytes(data);
	    
	    //IBESystem parameter
	    MessageDigest mDigest = null;
		try {
			mDigest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e1) {
			assertTrue(true);
		}
				
		Element P = pairing.getG1().newRandomElement().getImmutable();
		Element Ppub = P.mulZn(msk);
	    IBESystemParameters ibeSystemParameters = new IBESystemParameters(pairing, P,
	    													Ppub, mDigest);	   
	    IBECipher ibeCipher = new IBECipher();
	    //Identity
		byte[] id = "qiuxiang.dong@asu.edu".getBytes();
		Element Qid = pairing.getG1().newElement().setFromHash(id, 0, id.length);
	    IBEPublicKey ibePublicKey = new IBEPublicKey(id);
        try {
        	ibeCipher.engineInit(Cipher.ENCRYPT_MODE, ibePublicKey, 
        						ibeSystemParameters, new SecureRandom());
        } catch (InvalidKeyException iae) {
            assertTrue(true);
        } catch (InvalidAlgorithmParameterException iape) {
            assertTrue(true);
        }
        
        BigInteger m = new BigInteger("32");
        byte input[] = m.toByteArray();
        byte ciphertext[] = new byte[0];
        try {
            ciphertext = ibeCipher.engineDoFinal(input, 0, input.length);
        } catch (IllegalBlockSizeException ibse) {
            assertTrue(ibse.toString(), false);
        } catch (BadPaddingException bpe) {
            assertTrue(bpe.toString(), false);
        }
		Element privatekeyE = Qid.mulZn(msk);
		IBEPrivateKey ibePrivateKey = new IBEPrivateKey(privatekeyE);
        try {
        	ibeCipher.engineInit(Cipher.DECRYPT_MODE, ibePrivateKey, ibeSystemParameters,
                              new SecureRandom());
        } catch (InvalidKeyException iae) {
            assertTrue(false);
        } catch (InvalidAlgorithmParameterException iape) {
            assertTrue(false);
        }
        
        // get the decrypted data
        byte plaintext[] = new byte[0];
        try {
            plaintext = ibeCipher.engineDoFinal(ciphertext, 0, ciphertext.length);
        } catch (IllegalBlockSizeException ibse) {
            assertTrue(ibse.toString(), false);
        } catch (BadPaddingException bpe) {
            assertTrue(bpe.toString(), false);
        }
        assertTrue(m.compareTo(new BigInteger(1, plaintext)) == 0);
	}
	
	public void testGordon() {
		//Pairing
		String parameFile = "params/curves/a.properties";
	    PairingParameters params = PairingFactory.
		  		  getPairingParameters(parameFile);
	    Pairing pairing = PairingFactory.getPairing(params);
	    //Master secret key
	    String masterKeyFile = "MasterSecretKey";
	    Path path = Paths.get(masterKeyFile);
	    byte[] data = new byte[]{};
		try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			throw new NullPointerException("masterKey cannot be null");
		}
	    Element msk = pairing.getZr().newElementFromBytes(data);
	    
	    MessageDigest mDigest = null;
	    try {
			mDigest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			assertTrue(true);
		}
	    
	    mDigest.update(new String("qiuxiang.dong@asu.edu").getBytes());
	    byte[] id = mDigest.digest();
		Element Qid = pairing.getG1().newElement().setFromHash(id, 0, id.length);
		
		IBESystemParameters ibeSystemParameters = new IBESystemParameters(pairing, mDigest, masterKeyFile);
		
		IBECipher ibeCipher = new IBECipher();
		IBEPublicKey ibePublicKey = new IBEPublicKey(id);
        try {
        	ibeCipher.engineInit(Cipher.ENCRYPT_MODE, ibePublicKey, 
        						ibeSystemParameters, new SecureRandom());
        } catch (InvalidKeyException iae) {
            assertTrue(true);
        } catch (InvalidAlgorithmParameterException iape) {
            assertTrue(true);
        }
        
        //Get the encrypted data
        BigInteger m = new BigInteger(999, new SecureRandom());
        byte input[] = m.toByteArray();
        byte ciphertext[] = new byte[0];
        try {
            ciphertext = ibeCipher.engineDoFinal(input, 0, input.length);
        } catch (IllegalBlockSizeException ibse) {
            assertTrue(ibse.toString(), false);
        } catch (BadPaddingException bpe) {
            assertTrue(bpe.toString(), false);
        }
        
		Element privatekeyE = Qid.mulZn(msk);
		IBEPrivateKey ibePrivateKey = new IBEPrivateKey(privatekeyE);
        try {
        	ibeCipher.engineInit(Cipher.DECRYPT_MODE, ibePrivateKey, ibeSystemParameters,
                              new SecureRandom());
        } catch (InvalidKeyException iae) {
            assertTrue(false);
        } catch (InvalidAlgorithmParameterException iape) {
            assertTrue(false);
        }
        
        // get the decrypted data
        byte plaintext[] = new byte[0];
        try {
            plaintext = ibeCipher.engineDoFinal(ciphertext, 0, ciphertext.length);
        } catch (IllegalBlockSizeException ibse) {
            assertTrue(ibse.toString(), false);
        } catch (BadPaddingException bpe) {
            assertTrue(bpe.toString(), false);
        }
        assertTrue(m.compareTo(new BigInteger(1, plaintext)) == 0);    
	}
	
	public void testHashBlock() {
		IBECipher ibeCipher = new IBECipher();
        BigInteger m = new BigInteger("32");
        BigInteger h2 = new BigInteger("1015");
        byte V[] = ibeCipher.hashBlock(m.toByteArray(), h2.toByteArray());
        assertTrue(new BigInteger(1, V).compareTo(new BigInteger("35")) == 0);
        BigInteger W = new BigInteger("1015");
        byte P[] = ibeCipher.hashBlock(V, W.toByteArray());
        assertTrue(new BigInteger(1, P).compareTo(new BigInteger("32")) == 0);
	}
	
	public void testIBEAlgorithm() {
		IBECipher ibeCipher = new IBECipher();
		//Get the pairing
		String parameFile = "params/curves/a.properties";
	    PairingParameters params = PairingFactory.
		  		  getPairingParameters(parameFile);
	    Pairing pairing = PairingFactory.getPairing(params);
	    //Master secret key
	    String masterKeyFile = "MasterSecretKey";
	    Path path = Paths.get(masterKeyFile);
	    byte[] data = new byte[]{};
		try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			throw new NullPointerException("masterKey cannot be null");
		}
	    Element msk = pairing.getZr().newElementFromBytes(data);
		byte[] id = "qiuxiang.dong@asu.edu".getBytes();
		Element Qid = pairing.getG1().newElement().setFromHash(id, 0, id.length);
		Element P = pairing.getG1().newRandomElement().getImmutable();
		Element Ppub = P.mulZn(msk);
        Element Gid = pairing.pairing(Qid, Ppub);
        Element rElement = pairing.getZr().newRandomElement();
        Gid = Gid.powZn(rElement);
        byte[] h2 = Gid.toBytes();
        BigInteger mBigInteger = new BigInteger("137");
        byte[] m = mBigInteger.toByteArray();
        Element U = P.mulZn(rElement);
        byte V[] = ibeCipher.hashBlock(m, h2);
        Element Did = Qid.mulZn(msk);
        Element W = pairing.pairing(Did, U);
        byte[] p = ibeCipher.hashBlock(V, W.toBytes());
        assertTrue(mBigInteger.compareTo(new BigInteger(1, p)) == 0);      
        
        mBigInteger = new BigInteger(String.valueOf(Integer.MAX_VALUE));
        V = ibeCipher.hashBlock(mBigInteger.toByteArray(), h2);
        p = ibeCipher.hashBlock(V, W.toBytes());
        assertTrue(mBigInteger.compareTo(new BigInteger(1, p)) == 0);   
        
        mBigInteger = new BigInteger(String.valueOf(Integer.MAX_VALUE));
        mBigInteger.add(BigInteger.ONE);
        V = ibeCipher.hashBlock(mBigInteger.toByteArray(), h2);
        p = ibeCipher.hashBlock(V, W.toBytes());
        assertTrue(mBigInteger.compareTo(new BigInteger(1, p)) == 0);
        
        mBigInteger = new BigInteger("4757843987432974790435798345987983479083");
        V = ibeCipher.hashBlock(mBigInteger.toByteArray(), h2);
        p = ibeCipher.hashBlock(V, W.toBytes());
        assertTrue(mBigInteger.compareTo(new BigInteger(1, p)) == 0);   
	}
	
	public void testMessageDigest() {
		//Pairing
		String parameFile = "params/curves/a.properties";
	    PairingParameters params = PairingFactory.
		  		  getPairingParameters(parameFile);
	    Pairing pairing = PairingFactory.getPairing(params);
	    //Master secret key
	    String masterKeyFile = "MasterSecretKey";
	    Path path = Paths.get(masterKeyFile);
	    byte[] data = new byte[]{};
		try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			throw new NullPointerException("masterKey cannot be null");
		}
	    Element msk = pairing.getZr().newElementFromBytes(data);
	    
	    MessageDigest mDigest = null;
	    try {
			mDigest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			assertTrue(true);
		}
	    
	    mDigest.update(new String("qiuxiang.dong@asu.edu").getBytes());
	    byte[] id = mDigest.digest();
		Element Qid = pairing.getG1().newElement().setFromHash(id, 0, id.length);
		
		IBESystemParameters ibeSystemParameters = new IBESystemParameters(pairing, mDigest, masterKeyFile);
		
		IBECipher ibeCipher = new IBECipher();
		IBEPublicKey ibePublicKey = new IBEPublicKey(id);
        try {
        	ibeCipher.engineInit(Cipher.ENCRYPT_MODE, ibePublicKey, 
        						ibeSystemParameters, new SecureRandom());
        } catch (InvalidKeyException iae) {
            assertTrue(true);
        } catch (InvalidAlgorithmParameterException iape) {
            assertTrue(true);
        }
        //Get the encrypted data
        BigInteger m = new BigInteger(999, new SecureRandom());
        byte input[] = m.toByteArray();
        byte ciphertext[] = new byte[0];
        try {
            ciphertext = ibeCipher.engineDoFinal(input, 0, input.length);
        } catch (IllegalBlockSizeException ibse) {
            assertTrue(ibse.toString(), false);
        } catch (BadPaddingException bpe) {
            assertTrue(bpe.toString(), false);
        }
        
        Element Did = Qid.mulZn(msk);
        IBEPrivateKey ibePrivateKey = new IBEPrivateKey(Did);
        try {
        	ibeCipher.engineInit(Cipher.DECRYPT_MODE, ibePrivateKey, 
        						ibeSystemParameters, new SecureRandom());
        } catch (InvalidKeyException iae) {
            assertTrue(false);
        } catch (InvalidAlgorithmParameterException iape) {
            assertTrue(false);
        }
        // get the decrypted data
        byte plaintext[] = new byte[0];
        try {
            plaintext = ibeCipher.engineDoFinal(ciphertext, 0, ciphertext.length);
        } catch (IllegalBlockSizeException ibse) {
            assertTrue(ibse.toString(), false);
        } catch (BadPaddingException bpe) {
            assertTrue(bpe.toString(), false);
        }

        assertTrue(m.compareTo(new BigInteger(1, plaintext)) == 0);
	}
	
	public void testSystemParameters() {
		//Pairing
		String parameFile = "params/curves/a.properties";
	    PairingParameters params = PairingFactory.
		  		  getPairingParameters(parameFile);
	    Pairing pairing = PairingFactory.getPairing(params);
	    //Master secret key
	    String masterKeyFile = "MasterSecretKey";
	    Path path = Paths.get(masterKeyFile);
	    byte[] data = new byte[]{};
		try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			throw new NullPointerException("masterKey cannot be null");
		}
	    Element msk = pairing.getZr().newElementFromBytes(data);
	    
	    MessageDigest mDigest = null;
	    try {
			mDigest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			assertTrue(true);
		}
	    
	    mDigest.update(new String("qiuxiang.dong@asu.edu").getBytes());
	    byte[] id = mDigest.digest();
		Element Qid = pairing.getG1().newElement().setFromHash(id, 0, id.length);
		
		IBESystemParameters ibeSystemParameters = new IBESystemParameters(pairing, mDigest, masterKeyFile);
		
		IBECipher ibeCipher = new IBECipher();
		IBEPublicKey ibePublicKey = new IBEPublicKey(id);
        try {
        	ibeCipher.engineInit(Cipher.ENCRYPT_MODE, ibePublicKey, 
        						ibeSystemParameters, new SecureRandom());
        } catch (InvalidKeyException iae) {
            assertTrue(true);
        } catch (InvalidAlgorithmParameterException iape) {
            assertTrue(true);
        }
        BigInteger m = new BigInteger("32");
        byte input[] = m.toByteArray();
        byte ciphertext[] = new byte[0];
        try {
            ciphertext = ibeCipher.engineDoFinal(input, 0, input.length);
        } catch (IllegalBlockSizeException ibse) {
            assertTrue(ibse.toString(), false);
        } catch (BadPaddingException bpe) {
            assertTrue(bpe.toString(), false);
        }
		Element privatekeyE = Qid.mulZn(msk);
		IBEPrivateKey ibePrivateKey = new IBEPrivateKey(privatekeyE);
        try {
        	ibeCipher.engineInit(Cipher.DECRYPT_MODE, ibePrivateKey, ibeSystemParameters,
                              new SecureRandom());
        } catch (InvalidKeyException iae) {
            assertTrue(false);
        } catch (InvalidAlgorithmParameterException iape) {
            assertTrue(false);
        }
        
        // get the decrypted data
        byte plaintext[] = new byte[0];
        try {
            plaintext = ibeCipher.engineDoFinal(ciphertext, 0, ciphertext.length);
        } catch (IllegalBlockSizeException ibse) {
            assertTrue(ibse.toString(), false);
        } catch (BadPaddingException bpe) {
            assertTrue(bpe.toString(), false);
        }
        assertTrue(m.compareTo(new BigInteger(1, plaintext)) == 0);
	}
}
