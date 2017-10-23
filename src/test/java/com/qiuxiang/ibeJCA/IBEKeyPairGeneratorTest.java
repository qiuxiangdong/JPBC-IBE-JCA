package com.qiuxiang.ibeJCA;

import java.io.IOException;
import java.lang.reflect.Array;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;


public class IBEKeyPairGeneratorTest extends TestCase{
	public void testGenerateKeyPair() {
		String id = "qiuxiang.dong@asu.edu";
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
		    String parameters = "params/curves/a.properties";
		    Pairing map = PairingFactory.getPairing(PairingFactory.
		  		  getPairingParameters(parameters));
		    String mskFile = "MasterSecretKey";
		    Path path = Paths.get(mskFile);
		    byte[] data = new byte[]{};
			try {
				data = Files.readAllBytes(path);
			} catch (IOException e) {
				throw new NullPointerException("masterKey cannot be null");
			}
		    Element msk = map.getZr().newElementFromBytes(data);
	    			    
	        IBEKeyParameters params = new IBEKeyParameters(md, id, mskFile, map);
	        
	        IBEKeyPairGenerator generator = new IBEKeyPairGenerator();
	        generator.initialize(params);
	        
	        KeyPair kPair = generator.generateKeyPair();
	       
	        IBEPublicKey publicKey = (IBEPublicKey) kPair.getPublic();
	        
	        assertTrue(id.equals(new String(publicKey.getIdentity())));
	        
	        Element Qid = map.getG1().newElementFromHash(id.getBytes(), 0, id.getBytes().length);
	        Element Did = Qid.mulZn(msk);	
	        
	        IBEPrivateKey privateKey = (IBEPrivateKey) kPair.getPrivate();
	       	      
	        assertTrue(Arrays.equals(Did.toBytes(), privateKey.getPrivateKey()));
	        			        
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.toString());
		}
		
		
	}
}
