package com.qiuxiang.ibeJCA;

import java.security.Provider;

/**
 * This class provides a key pair generator and an El-Gamal based cipher for
 * Identity Based Encryption (IBE).
 */
public class IBEProvider extends Provider {
    /** the name of the cipher and key pair generators for ibe */
    public static final String IBE = new String("ibeJCA");
    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    /**
     * Creates a new instance of the Crypto Group's provider for IBE.
     */
    public IBEProvider() {
        super("QiuxiangDong", 1.0, "QX IBE Crypto Provider");

        // clears the superclass provider - don't want any surprises
        clear();
        // add in our own implementations
        put("KeyPairGenerator." + IBE, IBEKeyPairGenerator.class.getName());
        put("Cipher." + IBE, IBECipher.class.getName());
    }
}