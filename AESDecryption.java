package com.cards.auth.util;

import com.cards.auth.exceptions.BizException;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;

@Slf4j
public class AESDecryption {


    private static final String secret = "FB11C9EE72F91DE312AE6312F9E678F90CA49D24";
    private static final String salt = "MTU2ODkwMTI0MjExNVBSR01DMks0S1JEUkFE";

    public static String decrypt(String strToDecrypt) {
        try {
            byte[] iv = {'C', 'h', 'A', 'c', 'H', 'a', 'v', 'I', 'd', 'H', 'a', 'Y', 'a', 'k', 'H', 'h'};
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(secret.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            log.error("error while response encryption...{}", strToDecrypt);
            throw new BizException("invalid request!no data found");
        }
    }
}
