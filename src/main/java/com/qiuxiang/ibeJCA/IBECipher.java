package com.qiuxiang.ibeJCA;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingPreProcessing;
import it.unisa.dia.gas.jpbc.Element;

public class IBECipher extends CipherSpi{

    protected Key                 key;
    protected IBESystemParameters parameters;
    protected SecureRandom        secureRandom;
    protected int                 state;
    
    public byte[] encryptBlock(byte input[]) {
        // get the system parameters
        Pairing pair = parameters.getMap();
        // get the public key
        IBEPublicKey publicKey = (IBEPublicKey) key;
        // hash of identity (h1)
        byte id[] = publicKey.getIdentity();        
        Element Qid = pair.getG1().newElement().setFromHash(id, 0, id.length);
        // Gid = t(Qid,Ppub)
        Element Ppub = parameters.getPpub();
        Element Gid = pair.pairing(Qid, Ppub);
        // get the random r        
        Element r = pair.getZr().newRandomElement();
        Gid = Gid.powZn(r);      
        // hash of Gid^r (h2)
        byte[] h2 = Gid.toBytes();
        Element P = parameters.getP();
        Element U = P.mulZn(r);
        		
        byte V[] = hashBlock(input, h2);

        ArrayList<Object> list = new ArrayList<Object>();
        list.add(U.toBytes());
        list.add(V);

        return BitUtility.toBytes(list);
    }
    
    public byte[] decryptBlock(byte input[]) {
        // get the system parameters
        Pairing pair = parameters.getMap();
        ArrayList<?> arrayList = (ArrayList<?>) BitUtility.fromBytes(input);
        Element U = pair.getG1().newElementFromBytes((byte[]) arrayList.get(0));
        byte V[] = (byte[]) arrayList.get(1);
        // get the private key
        IBEPrivateKey privateKey = (IBEPrivateKey) key;
        Element Did = pair.getG1().newElement();
        Did.setFromBytes(privateKey.getPrivateKey());
        // W = t(Did,U)
        Element W = pair.pairing(Did, U);
        byte P[] = hashBlock(V, W.toBytes());
        
        return P;
    }


    public byte[] hashBlock(byte input[], byte hash[]) {
        byte output[] = new byte[input.length];
        // the block size depends on the hash
        int blockSize = hash.length;

        for (int i = 0; i < output.length; i += blockSize) {
            for (int j = 0; j < hash.length && i + j < output.length; j++) {
                output[i + j] = (byte) (input[i + j] ^ hash[j]);
            }
        }

        return output;
    }
	@Override
	public byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {
		// TODO Auto-generated method stub
        byte i[] = new byte[inputLen];
        System.arraycopy(input, inputOffset, i, 0, i.length);
        if (state == Cipher.ENCRYPT_MODE) {
            return encryptBlock(i);
        } else if (state == Cipher.DECRYPT_MODE) {
            return decryptBlock(i);
        }
        return new byte[0];
	}

	@Override
	public int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte o[] = engineDoFinal(input, inputOffset, inputLen);
        System.arraycopy(o, 0, output, outputOffset, output.length);

        return output.length;		
	}

	@Override
	protected int engineGetBlockSize() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	protected byte[] engineGetIV() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected int engineGetOutputSize(int inputLen) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	protected AlgorithmParameters engineGetParameters() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void engineInit(int opmode, Key key, AlgorithmParameterSpec params, 
			SecureRandom random) throws InvalidKeyException, 
										InvalidAlgorithmParameterException {
	       if (key == null) {
	            throw new NullPointerException("key cannot be null");
	        }
	        if (opmode == Cipher.ENCRYPT_MODE) {
	            if (!(key instanceof IBEPublicKey)) {
	                throw new IllegalArgumentException(
	                                                   "key must be instance of "
	                                                           + IBEPublicKey.class.getName());
	            }
	        } else if (opmode == Cipher.DECRYPT_MODE) {
	            if (!(key instanceof IBEPrivateKey)) {
	                throw new IllegalArgumentException(
	                                                   "key must be instance of "
	                                                           + IBEPrivateKey.class.getName());
	            }
	        }
	        state = opmode;
	        this.key = key;

	        if (params == null) {
	            throw new NullPointerException(
	                                           "algorithmParameterSpec cannot be null");
	        }
	        if (params instanceof IBESystemParameters) {
	            parameters = (IBESystemParameters) params;
	        } else {
	            throw new IllegalArgumentException(
	                                               "algorithmParameterSpec must be an instance of "
	                                                       + IBESystemParameters.class.getName());
	        }
	        if (secureRandom == null) {
	            this.secureRandom = new SecureRandom();
	        } else {
	            this.secureRandom = secureRandom;
	        }		
	}

	@Override
	public void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new IllegalArgumentException(
                                               "algorithmParameters should be null as there are no known "
                                                       + "AlgorithmParameters for this cipher");
        }		
	}

	@Override
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
		// TODO Auto-generated method stub
		
	}

	@Override
	protected void engineSetPadding(String padding) throws NoSuchPaddingException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        try {
            return engineDoFinal(input, inputOffset, inputLen);
        } catch (IllegalBlockSizeException ibse) {
            throw new RuntimeException(ibse);
        } catch (BadPaddingException bpe) {
            throw new RuntimeException(bpe);
        }
	}

	@Override
	public int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException {
        try {
            return engineDoFinal(input, inputOffset, inputLen, output,
                                 outputOffset);
        } catch (IllegalBlockSizeException ibse) {
            throw new RuntimeException(ibse);
        } catch (BadPaddingException bpe) {
            throw new RuntimeException(bpe);
        }
	}

}
