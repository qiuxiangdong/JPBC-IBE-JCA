package com.qiuxiang.ibeJCA;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

public class IBEPrivateKeyTest extends TestCase{
	public void testIBEPrivateKey() {
	    String parameFile = "params/curves/a.properties";
	    PairingParameters params = PairingFactory.
		  		  getPairingParameters(parameFile);
	    Pairing pairing = PairingFactory.getPairing(params);
		Element privatekeyE = pairing.getG1().newRandomElement();
		
		try {
			new IBEPrivateKey(null);
		} catch ( NullPointerException e) {
			assertTrue(true);
		}
		
	    IBEPrivateKey privateKey = new IBEPrivateKey(privatekeyE);
		byte[] privatekeyB = privateKey.getPrivateKey();
		//System.out.println(new String(privatekeyB));
		//Element b2Element = pairing.getG1().newElementFromBytes(privatekeyB);
		//System.out.println(privatekeyE.isEqual(b2Element));
		//byte[] privatekeyB2 = privatekeyE.toBytes();
		//System.out.println(new String(privatekeyB2).equals(new String(privatekeyB)));
		Element b2Element2 = pairing.getG1().newElementFromBytes(privatekeyB);
		assertTrue(privatekeyE.isEqual(b2Element2));
	}
}
