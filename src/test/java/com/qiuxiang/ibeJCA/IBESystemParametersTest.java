package com.qiuxiang.ibeJCA;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

public class IBESystemParametersTest extends TestCase{
	
	public void testConstructor1() {
		MessageDigest hash = null;
		try {
			hash = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			assertTrue(e.toString(), false);
		}
	    String parameters = "params/curves/a.properties";
	    
	    Pairing map = PairingFactory.getPairing(PairingFactory.
	  		  getPairingParameters(parameters));
	    
	    String mskFile = "MasterSecretKey";
	    
	    try {
	    	IBESystemParameters ibeSystemParameters = new IBESystemParameters(map, hash, mskFile);
	    	assertTrue(ibeSystemParameters != null);
		} catch (Exception e) {
			assertTrue(e.toString(), true);
		}
	    
        try {
            new IBESystemParameters(null, hash, mskFile);
        } catch (NullPointerException npe) {
            assertTrue(true);
        }
        
        try {
            new IBESystemParameters(map, null, mskFile);
        } catch (NullPointerException npe) {
            assertTrue(true);
        }
		
        try {
            new IBESystemParameters(map, hash, null);
        } catch (NullPointerException npe) {
            assertTrue(true);
        }
        
        try {
            new IBESystemParameters(map, hash, "mskFileNotExist");
        } catch (NullPointerException npe) {
            assertTrue(true);
        }
      
	}	
	
}
