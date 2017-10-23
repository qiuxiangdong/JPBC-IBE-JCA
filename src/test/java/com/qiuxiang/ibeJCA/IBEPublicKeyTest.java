package com.qiuxiang.ibeJCA;

import junit.framework.TestCase;

public class IBEPublicKeyTest extends TestCase{
	public void testConstructor() {
		String id = "qiuxiang.dong@asu.edu";
		IBEPublicKey ibePublicKey = new IBEPublicKey(id.getBytes());
		assertTrue(ibePublicKey != null);
		try {
			new IBEPublicKey(null);
		} catch (NullPointerException e) {
			assertTrue(true);
		}
		
		try {
			new IBEPublicKey("".getBytes());
		} catch (IllegalArgumentException e) {
			assertTrue(true);
		}
		byte[] identity = ibePublicKey.getIdentity();
		assertTrue(new String(identity).equals(id));
	}
}
