package com.simcomms.otp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Limits from the journey timings (docs/channels/README.md ruling R2 in card-onboarding-platform):
 * a code is valid 10 minutes, can be resent after 30 seconds, allows 3 wrong tries, and one
 * mobile number gets at most 5 codes in any 30 minutes.
 *
 * @param hmacKey       keys the HMACs of codes and mobile numbers; never logged
 * @param signingKeyPem PKCS#8 PEM of the EC P-256 key that signs proofs; generated at start when empty
 * @param signingPublicPem its public key (X.509 SubjectPublicKeyInfo PEM)
 * @param environment   dev, uat, prod: part of the issuer and the key id
 */
@ConfigurationProperties(prefix = "app.otp")
public record OtpProperties(
        Duration validity,
        Duration resendAfter,
        int maxAttempts,
        int maxSendsPerWindow,
        Duration sendWindow,
        int codeLength,
        Duration proofValidity,
        String hmacKey,
        String signingKeyPem,
        String signingPublicPem,
        String keyId,
        String environment,
        String brand,
        int inboxSize,
        Duration inboxRetention) {

    public String issuer() {
        return "urn:sim-comms:otp-service:" + environment;
    }
}
