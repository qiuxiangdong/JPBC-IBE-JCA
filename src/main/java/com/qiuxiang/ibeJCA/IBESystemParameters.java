package com.qiuxiang.ibeJCA;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class IBESystemParameters implements AlgorithmParameterSpec{
    protected MessageDigest hash;
    protected Pairing map;
    protected Element P;
    protected Element Ppub;
    
    public IBESystemParameters(Pairing map, Element P, 
    						   Element Ppub, MessageDigest hash) {
        if (map == null) {
            throw new NullPointerException("map cannot be null");
        }
        if (P == null) {
            throw new NullPointerException("P cannot be null");
        }
        if (Ppub == null) {
            throw new NullPointerException("Ppub cannot be null");
        }
        if (hash == null) {
            throw new NullPointerException("hash cannot be null");
        }
        this.map = map;
        this.P = map.getG1().newElement();
        this.P = P;
        this.Ppub = map.getG1().newElement();
        this.Ppub = Ppub;
        setHash(hash);
    }
    
    public IBESystemParameters(Pairing map, MessageDigest hash,
            String mskFile) {
		if (map == null) {
			throw new NullPointerException("map cannot be null");
		}
		if (hash == null) {
			throw new NullPointerException("hash cannot be null");
		}
		Path path = Paths.get(mskFile);
		byte[] data = null;
		try {
			data = Files.readAllBytes(path);
		} catch (IOException e) {
			throw new NullPointerException("master secret key cannot be null");
		}
		this.map = map;
		Element masterKey = map.getZr().newElementFromBytes(data);
		this.P = map.getG1().newRandomElement().getImmutable();
		this.Ppub = P.mulZn(masterKey);
		setHash(hash);
    }
    
    
    public MessageDigest getHash() {
        return hash;
    }

    public Pairing getMap() {
        return map;
    }

    public Element getP() {
        return P;
    }

    public Element getPpub() {
        return Ppub;
    }
    
    public void setHash(MessageDigest hash) {
        if (hash == null) {
            throw new NullPointerException("hash cannot be null");
        }
        this.hash = hash;
    }
}
