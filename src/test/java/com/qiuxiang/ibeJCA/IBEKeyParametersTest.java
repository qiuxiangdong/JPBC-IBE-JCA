package com.qiuxiang.ibeJCA;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import com.qiuxiang.ibeJCA.IBEKeyParameters;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

public class IBEKeyParametersTest extends TestCase{
	public void testConstructor() {
		String id = new String("qiuxiang.dong@asu.edu");
		MessageDigest mDigest = null;
		try {
			mDigest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			assertTrue(true);
		}
		
		try {
			new IBEKeyParameters(null, id);
		} catch (NullPointerException e) {
			assertTrue(true);
		}
		
		try {
			new IBEKeyParameters(mDigest, null);
		} catch (NullPointerException e) {
			assertTrue(true);
		}
		
		try {
			new IBEKeyParameters(mDigest, new String());
		} catch (IllegalArgumentException e) {
			assertTrue(true);
		}
		
		IBEKeyParameters parameters = new IBEKeyParameters(mDigest, id);
		assertTrue(parameters != null);
		
		String parameFile = "params/curves/a.properties";
	    PairingParameters params = PairingFactory.
		  		  getPairingParameters(parameFile);
	    Pairing pairing = PairingFactory.getPairing(params);
		Element privatekeyE = pairing.getG1().newRandomElement();
	    IBEPrivateKey privateKey = new IBEPrivateKey(privatekeyE);
	    
	    try {
			new IBEKeyParameters(mDigest, id, null);
		} catch (NullPointerException e) {
			assertTrue(true);
		}
	    
	    parameters = new IBEKeyParameters(mDigest, id, privateKey);
	    assertTrue(parameters != null);
	    
	    String masterKeyFile = "MasterSecretKey";
	    try {
			new IBEKeyParameters(mDigest, id, null , pairing);
		} catch (NullPointerException e) {
			assertTrue(true);
		}
	    
	    try {
			new IBEKeyParameters(mDigest, id, masterKeyFile , null);
		} catch (NullPointerException e) {
			assertTrue(true);
		}
	}
	
	public void testGet() {
		MessageDigest mDigest = null;
		try {
			mDigest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			assertTrue(true);
		}
		byte[] id = "qiuxiang.dong@asu.edu".getBytes();
		IBEKeyParameters ibeKeyParameters = new IBEKeyParameters(mDigest, new String(id));
        assertTrue(Arrays.equals(id, ibeKeyParameters.getPublicKey().getIdentity()));
        
        try {
			ibeKeyParameters.getPrivateKey();
		} catch (Exception e) {
			assertTrue(true);
		}
        
        String parameFile = "params/curves/a.properties";
	    PairingParameters params = PairingFactory.
		  		  getPairingParameters(parameFile);
	    Pairing pairing = PairingFactory.getPairing(params);
	    String masterKeyFile = "MasterSecretKey";
	    
	    ibeKeyParameters = new IBEKeyParameters(mDigest, new String(id), masterKeyFile, pairing);
	    assertTrue(Arrays.equals(id, ibeKeyParameters.getPublicKey().getIdentity()));
	    
	    Path path = Paths.get(masterKeyFile);
	    byte[] data = new byte[]{};
		try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			throw new NullPointerException("masterKey cannot be null");
		}
	    Element msk = pairing.getZr().newElementFromBytes(data);
		Element Qid = pairing.getG1().newElement().setFromHash(id, 0, id.length);
		Element privatekeyE = Qid.mulZn(msk);
		
		IBEPrivateKey ibePrivateKey = ibeKeyParameters.getPrivateKey();
		assertTrue(Arrays.equals(privatekeyE.toBytes(), ibePrivateKey.getPrivateKey()));

	}
}
