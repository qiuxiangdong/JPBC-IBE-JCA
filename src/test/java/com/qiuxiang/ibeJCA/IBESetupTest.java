package com.qiuxiang.ibeJCA;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

public class IBESetupTest extends TestCase {
	public void testConstructor() {
	    String parameFile = "params/curves/a.properties";
	    String mskFile = "MSKFILE";
	    PairingParameters params = PairingFactory.
		  		  getPairingParameters(parameFile);
		IBESetup ibeSetup = new IBESetup(params, mskFile);
		assertTrue(ibeSetup != null);
		Element msk1 = ibeSetup.getMSK();
		Pairing pairing = ibeSetup.getPairing();
		Path path = Paths.get(mskFile);
		byte[] data = null;
		try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			assertTrue(e.toString(), false);
		}
		Element msk2 = pairing.getZr().newElementFromBytes(data);
		assertTrue(msk1.equals(msk2));
	}
}
