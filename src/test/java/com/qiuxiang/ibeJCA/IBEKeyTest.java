package com.qiuxiang.ibeJCA;

import junit.framework.TestCase;

import com.qiuxiang.ibeJCA.IBEKey;

public class IBEKeyTest extends TestCase{
	public void testGetAlgorithm() {
		IBEKey ibeKey = new IBEKey();
        assertTrue(ibeKey.getAlgorithm() != null
                && ibeKey.getAlgorithm().length() > 0);
	}
	
	public void testGetEncoded() {
        IBEKey key = new IBEKey();
        assertTrue(key.getEncoded() == null);
    }

    public void testGetFormat() {
        IBEKey key = new IBEKey();
        assertTrue(key.getFormat() == null);
    }
}
