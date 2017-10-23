package com.qiuxiang.ibeJCA;

import java.security.PrivateKey;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class IBEPrivateKey extends IBEKey implements PrivateKey{
    protected byte[] privateKey;

    public IBEPrivateKey(Element privateKey) {
        if (privateKey == null) {
            throw new NullPointerException("privateKey cannot be null");
        }
        this.privateKey = privateKey.toBytes();
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }
}
