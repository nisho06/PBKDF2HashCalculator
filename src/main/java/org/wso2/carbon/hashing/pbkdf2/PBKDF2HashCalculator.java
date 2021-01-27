package org.wso2.carbon.hashing.pbkdf2;

import org.wso2.carbon.hashing.pbkdf2.constants.Constants;
import org.wso2.carbon.user.core.hashing.HashCalculator;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Map;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * This class contains the implementation for the PBKDF2 hashing algorithm.
 */
public class PBKDF2HashCalculator implements HashCalculator {

    public PBKDF2HashCalculator() {

    }

    @Override
    public String calculateHash(String value, String salt, Map<String, Object> metaProperties)
            throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {

        PBEKeySpec spec = new PBEKeySpec(value.toCharArray(), base64ToByteArray(salt),
                (int) (metaProperties.get(Constants.PBKDF2Constants.ITERATION_NAME)),
                (int) (metaProperties.get(Constants.PBKDF2Constants.DERIVED_KEY_LENGTH_NAME)));
        SecretKeyFactory skf = SecretKeyFactory.getInstance(Constants.PBKDF2Constants.PBKDF2_PRF);
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return new String(Base64.getEncoder().encode(hash));
    }

    @Override
    public String getAlgorithm() {

        return Constants.PBKDF2Constants.PBKDF2_PRF;
    }

    /**
     * this method is responsible for converting the base64 string value value of salt to byte array.
     *
     * @param salt The salt value which needs to be converted into byte array.
     * @return The converted byte array from base64 Salt value.
     * @throws UnsupportedEncodingException when the base64 encoding does not support.
     */
    private byte[] base64ToByteArray(String salt) throws UnsupportedEncodingException {

        byte[] name = Base64.getEncoder().encode(salt.getBytes());
        return (Base64.getDecoder().decode(new String(name).getBytes(Constants.PBKDF2Constants.CHARSET_UTF_8)));
    }
}