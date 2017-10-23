package com.qiuxiang.ibeJCA;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZElement;
import it.unisa.dia.gas.plaf.jpbc.field.z.ZrElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class IBEKeyParameters implements AlgorithmParameterSpec{
    // byte array to store user's identity, this identity could by of arbitrary length
	protected IBEPublicKey publicKey;
	// Element to store user's private key
    protected IBEPrivateKey privateKey;
    
    public IBEKeyParameters(MessageDigest hash, String identity) {
        if (hash == null) {
            throw new NullPointerException("hash cannot be null");
        }
        if (identity == null) {
            throw new NullPointerException("identity cannot be null");
        }
        if (identity.length() <= 0) {
            throw new IllegalArgumentException(
                                               "identity must be a string with length greater than zero");
        }
        hash.reset();
        publicKey = new IBEPublicKey(identity.getBytes());
    }
    
    public IBEKeyParameters(MessageDigest hash, String identity, IBEPrivateKey privateKey) {
        this(hash, identity);
        if (privateKey == null) {
            throw new NullPointerException("Did cannot be null");
        }
        this.privateKey = privateKey;
    }
    
    public IBEKeyParameters(MessageDigest hash, String identity,
            String masterKeyFile, Pairing map) {
		this(hash, identity);
		if (map == null) {
		throw new NullPointerException("map cannot be null");
		}
	    Path path = Paths.get(masterKeyFile);
	    byte[] data = new byte[]{};
		try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			throw new NullPointerException("masterKey cannot be null");
		}
	    Element msk = map.getZr().newElementFromBytes(data);
		Element Qid = map.getG1().newElement().setFromHash(publicKey.getIdentity(), 0, publicKey.getIdentity().length);
		this.privateKey = new IBEPrivateKey(Qid.mulZn(msk));
	}
    
    public IBEPrivateKey getPrivateKey() {
        if (this.privateKey == null) {
            throw new NullPointerException("private key not initialised");
        }
    	return privateKey;
    }
    
    public IBEPublicKey getPublicKey() {
        return publicKey;
    }
    
}
