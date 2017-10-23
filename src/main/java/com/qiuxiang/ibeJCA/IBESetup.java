package com.qiuxiang.ibeJCA;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import sun.security.jca.GetInstance;

public class IBESetup {
	public Pairing pairing;
	private Element msk; 
	/**
	 * This method generates the master secret key of the whole system and store it
	 * into the master secret key file "mskFile"
	 * @param parameters: stores the pairing parameters in use
	 * @param mskFile: to store the generated master secret key
	 */
	public IBESetup(PairingParameters parameters, String mskFile) {
		this.pairing = PairingFactory.getPairing(parameters);
		msk = pairing.getZr().newRandomElement();
		byte[] bs = msk.toBytes();
	      
	    FileOutputStream fos;
		try {
			fos = new FileOutputStream(mskFile);
		    fos.write(bs);
		    fos.close();   
		} catch (FileNotFoundException e) {
			System.out.println("File Not Found");
		} catch (IOException e) {
			System.out.println("IO Exception");
		}   
	}
	public Element getMSK() {
		return msk;
	}
	public Pairing getPairing() {
		return pairing;
	}
	public void tryafunction(Element s) {
		
	}
}
