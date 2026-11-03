package com.simcomms.otp.domain;

import com.simcomms.otp.config.OtpProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/** HMACs for codes and mobile numbers: what is stored, never the value itself. */
@Component
public class Keys {

    private final byte[] key;

    public Keys(OtpProperties properties) {
        this.key = properties.hmacKey().getBytes(StandardCharsets.UTF_8);
    }

    public String hmac(String... parts) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (String part : parts) {
                mac.update(part.getBytes(StandardCharsets.UTF_8));
                mac.update((byte) 0);
            }
            return HexFormat.of().formatHex(mac.doFinal());
        } catch (Exception e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    /** The mobile number's HMAC: the key for its send log and its simulated inbox. */
    public String msisdn(String msisdn) {
        return hmac("msisdn", msisdn);
    }

    public static boolean sameHex(String a, String b) {
        return a != null && b != null && MessageDigest.isEqual(a.getBytes(StandardCharsets.US_ASCII),
                b.getBytes(StandardCharsets.US_ASCII));
    }

    /** {@code +91XXXXXX1234}: what logs and the phone UI may show. */
    public static String masked(String msisdn) {
        return msisdn.substring(0, 3) + "XXXXXX" + msisdn.substring(msisdn.length() - 4);
    }
}
