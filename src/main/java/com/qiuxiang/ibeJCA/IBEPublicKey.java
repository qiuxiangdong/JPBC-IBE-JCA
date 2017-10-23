package com.qiuxiang.ibeJCA;

import java.security.PrivateKey;
import java.security.PublicKey;

public class IBEPublicKey extends IBEKey implements PublicKey{
    protected byte identity[];
    public IBEPublicKey(byte identity[]) {
        if (identity == null) {
            throw new NullPointerException("identity cannot be null");
        }
        if (identity.length <= 0) {
            throw new IllegalArgumentException(
                                               "identity must be a string with length greater than zero");
        }
        this.identity = identity;
    }

    public byte[] getIdentity() {
        return identity;
    }

}
