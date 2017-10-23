package com.qiuxiang.ibeJCA;
import java.security.Key;

public class IBEKey implements Key{

	/**
	 * Returns the standard algorithm name for this key. For example, "DSA" 
	 * would indicate that this key is a DSA key. See Appendix A in the Java 
	 * Cryptography Architecture API Specification & Reference for information 
	 * about standard algorithm names.
	 * 
	 * @return the name of the algorithm associated with this key.
	 */
	public String getAlgorithm() {
		// TODO Auto-generated method stub
		return new String("Identity Based Encryption");
	}
	
    /**
     * Returns the name of the primary encoding format of this key, or null if
     * this key does not support encoding. The primary encoding format is named
     * in terms of the appropriate ASN.1 data format, if an ASN.1 specification
     * for this key exists. For example, the name of the ASN.1 data format for
     * public keys is <I>SubjectPublicKeyInfo</I>, as defined by the X.509
     * standard; in this case, the returned format is <code>"X.509"</code>.
     * Similarly, the name of the ASN.1 data format for private keys is
     * <I>PrivateKeyInfo</I>, as defined by the PKCS #8 standard; in this case,
     * the returned format is <code>"PKCS#8"</code>.
     * 
     * @return the primary encoding format of the key.
     */
	public String getFormat() {
		return null;
	}

    /**
     * Returns the key in its primary encoding format, or null if this key does
     * not support encoding.
     * 
     * @return the encoded key, or null if the key does not support encoding.
     */
	public byte[] getEncoded() {
		return null;
	}

}
