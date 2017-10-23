package com.qiuxiang.keymanagement;

import java.security.Provider;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Identity;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;

import javax.swing.text.MaskFormatter;

import com.qiuxiang.ibeJCA.*;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import junit.framework.TestCase;

public class KeyManagerTest extends TestCase{
	
	public void testKeyManager() {	
		String name = "Qiuxiang";
	    Provider provider = new IBEProvider();
	    assertTrue(provider != null);
	    IBEKeyPairGenerator kpg = new IBEKeyPairGenerator();
	    assertTrue(kpg != null);
	      
	    String identity = "qiuxiang.dong@asu.edu";
	    String parameters = "params/curves/a.properties";
	    Pairing pairing = PairingFactory.getPairing(PairingFactory.
	    		  getPairingParameters(parameters));
	    Path path = Paths.get("MasterSecretKey");
	    byte[] data = new byte[]{};
		try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			assertTrue(e.toString(), false);
		}
	    Element msk = pairing.getZr().newOneElement();
	    msk.setFromBytes(data);
	    MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			assertTrue(e.toString(), false);
		}
	      
	    IBEKeyParameters params = new IBEKeyParameters(md, identity, "MasterSecretKey", pairing);
	    assertTrue(params != null);
	    kpg.initialize(params);
	    KeyPair pair = kpg.generateKeyPair();
	    assertTrue(pair != null);
		KeyManager km = new KeyManager(name, pair);
		assertTrue(km != null);		
	}
	
	public void testcreate() {
		String name = "Qiuxiang";
	    String keyfile = "QIUXIANGIBE1.keystore";

	    IBEKeyPairGenerator kpg = new IBEKeyPairGenerator();
	    assertTrue(kpg != null);
	    
	    String identity = "qiuxiang.dong@asu.edu";
	    String parameters = "params/curves/a.properties";
	    Pairing pairing = PairingFactory.getPairing(PairingFactory.
	    		  getPairingParameters(parameters));
	      
	    Path path = Paths.get("MasterSecretKey");
	    byte[] data = new byte[]{};
		try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			assertTrue(e.toString(), false);
		}
	    Element msk = null;
	    msk = pairing.getZr().newOneElement();
	    msk.setFromBytes(data);
	    MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			assertTrue(e.toString(), false);
		}
	    
	    IBEKeyParameters params = new IBEKeyParameters(md, identity, "MasterSecretKey", pairing);
	    assertTrue(params != null);
	    kpg.initialize(params);
	    KeyPair pair = kpg.generateKeyPair();
	    assertTrue(pair != null);
		KeyManager km = KeyManager.create(keyfile, name, pair);
		assertTrue(km != null);
		
	}
	
	public void testsave() {
		String name = "Qiuxiang";
	    String keyfile = "QIUXIANGIBE1.keystore";

	    IBEKeyPairGenerator kpg = new IBEKeyPairGenerator();
	    assertTrue(kpg != null);
	    
	    String identity = "qiuxiang.dong@asu.edu";
	    String parameters = "params/curves/a.properties";
	    Pairing pairing = PairingFactory.getPairing(PairingFactory.
	    		  getPairingParameters(parameters));
	      
	    Path path = Paths.get("MasterSecretKey");
	    byte[] data = new byte[]{};
		try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			assertTrue(e.toString(), false);
		}
	    Element msk = pairing.getZr().newOneElement();
	    msk.setFromBytes(data);
	    MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			assertTrue(e.toString(), false);
		}
	      
	    IBEKeyParameters params = new IBEKeyParameters(md, identity, "MasterSecretKey", pairing);
	    assertTrue(params != null);
	    kpg.initialize(params);
	    KeyPair pair = kpg.generateKeyPair();
	    assertTrue(pair != null);
		KeyManager km = KeyManager.create(keyfile, name, pair);
		assertTrue(km != null);
		try {
		    km.save();
		} catch (Exception e) {
			assertTrue(e.toString(), false);
		}
	}
	
	public void testgetInstance() {
		String file = "QIUXIANGIBE1.keystore";
		try {
			KeyManager km = KeyManager.getInstance(file);
			assertTrue(km != null);
		} catch (ClassNotFoundException e) {
			assertTrue(e.toString(), false);
		} catch (IOException e) {
			assertTrue(e.toString(), false);
		}
	}
	
	public void testidentities() {
		String file = "QIUXIANGIBE1.keystore";
		try {
			KeyManager km = KeyManager.getInstance(file);
			assertTrue(km != null);
			Enumeration identities =  km.identities();
			assertTrue(identities != null);
		} catch (ClassNotFoundException e) {
			assertTrue(e.toString(), false);
		} catch (IOException e) {
			assertTrue(e.toString(), false);
		}

	}
	
	public void testaddIdentity() {
		try {
			KeyManager km = KeyManager.getInstance("QIUXIANGIBE1.keystore");
			String name1 = "example1";
			PublicKey key1 = new IBEPublicKey("example1@asu.edu".getBytes());
			km.addIdentity(name1, key1);		
			km.save();
		} catch (ClassNotFoundException e1) {
			assertTrue(e1.toString(), false);
		} catch (IOException e1) {
			assertTrue(e1.toString(), false);
		} catch (KeyManagementException e) {
			assertTrue(e.toString(), false);
		}
	}
	
	public void testgetIdentityWithName() {
		KeyManager km = null;
		try {
			km = KeyManager.getInstance("QIUXIANGIBE1.keystore");
		} catch (ClassNotFoundException e1) {
			assertTrue(e1.toString(), false);
		} catch (IOException e1) {
			assertTrue(e1.toString(), false);
		}
		String name1 = "example1";
		assertTrue(km.getIdentity(name1) != null);
		String name2 = "QX";
		assertTrue(km.getIdentity(name2) == null);
	}
	
	public void testgetIdentityWithKey() {
		try {
			KeyManager km = KeyManager.getInstance("QIUXIANGIBE1.keystore");
			String name = "example2";
			PublicKey key = new IBEPublicKey("example2@asu.edu".getBytes());
			km.addIdentity(name, key);
			assertTrue(km.getIdentity(key) != null);
		} catch (ClassNotFoundException e1) {
			assertTrue(e1.toString(), false);
		} catch (IOException e1) {
			assertTrue(e1.toString(), false);
		} catch (KeyManagementException e) {
			assertTrue(e.toString(), false);
		}
	}
	
	public void testgetPublicKey() {
		try {
			KeyManager km = KeyManager.getInstance("QIUXIANGIBE1.keystore");
			String name = "example1";
			PublicKey publicKey = km.getPublicKey(name);
			assertTrue(publicKey != null);
		} catch (ClassNotFoundException e) {
			assertTrue(e.toString(), false);
		} catch (IOException e) {
			assertTrue(e.toString(), false);
		}		
	}
	
	public void testgetPrivateKey() {
		try {
			KeyManager km = KeyManager.getInstance("QIUXIANGIBE1.keystore");
			PrivateKey privateKey = km.getPrivateKey();
			assertTrue(privateKey != null);
		} catch (ClassNotFoundException e) {
			assertTrue(e.toString(), false);
		} catch (IOException e) {
			assertTrue(e.toString(), false);
		}		
	}
	
	public void testremoveIdentity() {
		KeyManager km = null;
		try {
			km = KeyManager.getInstance("QIUXIANGIBE1.keystore");
		} catch (ClassNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		String name = "example1";
		Identity identity = km.getIdentity(name);
		try {
			km.removeIdentity(identity);
		} catch (KeyManagementException e) {
			assertTrue(e.toString(), false);
		}
	}	
	
}
