package com.simcomms.otp;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import com.simcomms.otp.config.OtpProperties;
import com.simcomms.otp.domain.ProofSigner;
import com.simcomms.otp.domain.Purpose;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/** A key pair from the Kubernetes Secret (PEM, as `make secrets` writes it) signs proofs the JWKS verifies. */
class ProofSignerTest {

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }

    @Test
    void aConfiguredKeyPairSignsAndTheJwksVerifies() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        var pair = gen.generateKeyPair();
        OtpProperties props = new OtpProperties(Duration.ofMinutes(10), Duration.ofSeconds(30), 3, 5, Duration.ofMinutes(30), 6,
                Duration.ofMinutes(5), "k", pem("PRIVATE KEY", pair.getPrivate().getEncoded()),
                pem("PUBLIC KEY", pair.getPublic().getEncoded()), "otp-test-1", "test", "Ondaro Bank", 20, Duration.ofHours(24));

        ProofSigner signer = new ProofSigner(props, Clock.systemUTC());
        SignedJWT proof = SignedJWT.parse(signer.sign("channel-web-test", "cust_12345678", Purpose.SIGN_IN, "cid", "bnd"));

        ECKey published = JWKSet.parse(signer.jwks()).getKeyByKeyId("otp-test-1").toECKey();
        assertThat(published.isPrivate()).isFalse();
        assertThat(proof.verify(new ECDSAVerifier(published))).isTrue();
        assertThat(published.toECPublicKey().getW()).isEqualTo(((java.security.interfaces.ECPublicKey) pair.getPublic()).getW());
        assertThat(proof.getJWTClaimsSet().getIssuer()).isEqualTo("urn:sim-comms:otp-service:test");
    }
}
