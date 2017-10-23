package com.qiuxiang.ibeJCA;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
public class IBEKeyPairGenerator extends KeyPairGeneratorSpi{
	
    private IBEKeyParameters params;
    
	@Override
	public void initialize(int keysize, SecureRandom random) {
        throw new RuntimeException("method not implemented");
	}
	
    public void initialize(AlgorithmParameterSpec params) {
        initialize(params, null);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) {
        if (params == null) {
            throw new NullPointerException("params cannot be null");
        }
        if (!(params instanceof IBEKeyParameters)) {
            throw new IllegalArgumentException(
                                               "params must be an instance of IbeKeyParameters");
        }
        this.params = (IBEKeyParameters) params;
    }

	@Override
	public KeyPair generateKeyPair() {
        IBEPublicKey publicKey = params.getPublicKey();
        IBEPrivateKey privateKey = params.getPrivateKey();
        return new KeyPair(publicKey, privateKey);             
	}

}
