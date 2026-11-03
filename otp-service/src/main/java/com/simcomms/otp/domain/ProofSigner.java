package com.simcomms.otp.domain;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.simcomms.otp.config.OtpProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Signs the proof that a code was verified (an ES256 JWS, {@code typ: otp-proof+jwt}). The BFF, and
 * later the platform, verify it against {@code GET /otp/v1/jwks.json} instead of trusting a boolean.
 */
@Component
public class ProofSigner {

    private static final Logger log = LoggerFactory.getLogger(ProofSigner.class);

    private final ECKey key;
    private final OtpProperties properties;
    private final Clock clock;

    public ProofSigner(OtpProperties properties, Clock clock) throws Exception {
        this.properties = properties;
        this.clock = clock;
        String pem = properties.signingKeyPem();
        if (pem == null || pem.isBlank()) {
            log.warn("No signing key configured: generating one for this process only (proofs die with it)");
            this.key = new ECKeyGenerator(Curve.P_256).keyID(properties.keyId()).keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.ES256).generate();
        } else {
            this.key = new ECKey.Builder(Curve.P_256, (ECPublicKey) pem(properties.signingPublicPem(), false))
                    .privateKey((ECPrivateKey) pem(pem, true))
                    .keyID(properties.keyId()).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256).build();
        }
    }

    /** PKCS#8 private or X.509 public key in PEM, parsed with the JDK alone. */
    static java.security.Key pem(String pem, boolean isPrivate) throws Exception {
        String base64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        byte[] der = java.util.Base64.getDecoder().decode(base64);
        KeyFactory factory = KeyFactory.getInstance("EC");
        return isPrivate ? factory.generatePrivate(new PKCS8EncodedKeySpec(der))
                : factory.generatePublic(new X509EncodedKeySpec(der));
    }

    public String sign(String audience, String subjectRef, Purpose purpose, String challengeId, String bindingHash) {
        Instant now = clock.instant();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(properties.issuer())
                .audience(audience)
                .subject(subjectRef)
                .claim("pur", purpose.name())
                .claim("cid", challengeId)
                .claim("bnd", bindingHash)
                .claim("amr", List.of("otp", "sms"))
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(properties.proofValidity())))
                .jwtID(UUID.randomUUID().toString())
                .build();
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID())
                    .type(new JOSEObjectType("otp-proof+jwt")).build(), claims);
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Proof could not be signed", e);
        }
    }

    /** Public keys only. */
    public Map<String, Object> jwks() {
        return new JWKSet(key.toPublicJWK()).toJSONObject();
    }
}
