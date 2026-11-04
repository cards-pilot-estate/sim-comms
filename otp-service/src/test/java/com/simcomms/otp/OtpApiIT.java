package com.simcomms.otp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The OTP rules (ruling R2) against a real Redis, with a clock the test can move. */
@SpringBootTest(properties = {"app.phone.enabled=true", "app.iam.jwks-uri=http://localhost:1/unused"})
@AutoConfigureMockMvc
@ActiveProfiles("test-hooks")
@Testcontainers
class OtpApiIT {

    @Container
    static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);

    @DynamicPropertySource
    static void redis(DynamicPropertyRegistry r) {
        r.add("spring.data.redis.host", REDIS::getHost);
        r.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
    }

    /** A clock tests can move forward. */
    static final class MovableClock extends Clock {
        private Instant now = Instant.parse("2026-11-04T10:00:00Z");
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
        void advance(Duration d) { now = now.plus(d); }
    }

    @TestConfiguration
    static class Clocks {
        @Bean @Primary MovableClock movableClock() { return new MovableClock(); }
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired MovableClock clock;
    @Autowired StringRedisTemplate redis;

    String msisdn;
    final String binding = "bnd_" + UUID.randomUUID().toString().replace("-", "");
    final String subject = "cust_" + UUID.randomUUID().toString().replace("-", "");

    @BeforeEach
    void number() {
        msisdn = "+919" + String.format("%09d", ThreadLocalRandom.current().nextInt(1_000_000_000));
    }

    private ResultActions send(String client, String key) throws Exception {
        return mvc.perform(post("/otp/v1/challenges").with(jwt().jwt(j -> j.claim("azp", client)))
                .header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("purpose", "SIGN_IN", "msisdn", msisdn,
                        "subjectRef", subject, "bindingHash", binding))));
    }

    private String challenge(String client) throws Exception {
        String body = send(client, UUID.randomUUID().toString()).andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(body).get("challengeId").asText();
    }

    private ResultActions verify(String client, String id, String code, String bnd) throws Exception {
        return mvc.perform(post("/otp/v1/challenges/{id}/verification", id).with(jwt().jwt(j -> j.claim("azp", client)))
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("code", code, "bindingHash", bnd))));
    }

    private String lastCode() throws Exception {
        String body = mvc.perform(get("/sim-admin/v1/test/last-code").param("msisdn", msisdn))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return json.readTree(body).get("code").asText();
    }

    private static String wrong(String code) {
        return code.equals("000000") ? "111111" : "000000";
    }

    @Test
    void theRightCodeGivesASignedProofThatVerifiesAgainstTheJwks() throws Exception {
        String id = challenge("channel-web-test");
        String body = verify("channel-web-test", id, lastCode(), binding).andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("VERIFIED")).andReturn().getResponse().getContentAsString();

        SignedJWT proof = SignedJWT.parse(json.readTree(body).get("proof").asText());
        String jwks = mvc.perform(get("/otp/v1/jwks.json")).andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "max-age=600")).andReturn().getResponse().getContentAsString();
        JWKSet keys = JWKSet.parse(jwks);
        assertThat(keys.getKeys()).allSatisfy(k -> assertThat(k.isPrivate()).isFalse());
        assertThat(proof.verify(new ECDSAVerifier(keys.getKeyByKeyId(proof.getHeader().getKeyID()).toECKey()))).isTrue();
        assertThat(proof.getHeader().getType().getType()).isEqualTo("otp-proof+jwt");
        var claims = proof.getJWTClaimsSet();
        assertThat(claims.getAudience()).containsExactly("channel-web-test");
        assertThat(claims.getSubject()).isEqualTo(subject);
        assertThat(claims.getStringClaim("pur")).isEqualTo("SIGN_IN");
        assertThat(claims.getStringClaim("cid")).isEqualTo(id);
        assertThat(claims.getStringClaim("bnd")).isEqualTo(binding);
        assertThat(Duration.between(claims.getIssueTime().toInstant(), claims.getExpirationTime().toInstant()))
                .isEqualTo(Duration.ofMinutes(5));
    }

    @Test
    void aCodeWorksOnce() throws Exception {
        String id = challenge("channel-web-test");
        String code = lastCode();
        verify("channel-web-test", id, code, binding).andExpect(status().isOk());
        verify("channel-web-test", id, code, binding).andExpect(status().isNotFound());
    }

    @Test
    void threeWrongTriesVoidTheCode() throws Exception {
        String id = challenge("channel-web-test");
        String code = lastCode();
        verify("channel-web-test", id, wrong(code), binding).andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.errorCode").value("OTP_INCORRECT")).andExpect(jsonPath("$.attemptsRemaining").value(2));
        verify("channel-web-test", id, wrong(code), binding).andExpect(jsonPath("$.attemptsRemaining").value(1));
        verify("channel-web-test", id, wrong(code), binding).andExpect(status().isGone())
                .andExpect(jsonPath("$.errorCode").value("OTP_ATTEMPTS_EXHAUSTED"));
        verify("channel-web-test", id, code, binding).andExpect(status().isGone());
    }

    @Test
    void aCodeExpiresAfterTenMinutes() throws Exception {
        String id = challenge("channel-web-test");
        String code = lastCode();
        clock.advance(Duration.ofMinutes(10).plusSeconds(1));
        verify("channel-web-test", id, code, binding).andExpect(status().isGone())
                .andExpect(jsonPath("$.errorCode").value("OTP_EXPIRED"));
    }

    @Test
    void anotherClientOrAnotherBindingCannotUseTheChallenge() throws Exception {
        String id = challenge("channel-web-test");
        String code = lastCode();
        verify("channel-branch-test", id, code, binding).andExpect(status().isNotFound());
        verify("channel-web-test", id, code, "bnd_another_binding_value_xyz").andExpect(status().isNotFound());
        verify("channel-web-test", id, code, binding).andExpect(status().isOk());
    }

    @Test
    void resendWaitsThirtySecondsAndSendsANewCode() throws Exception {
        String id = challenge("channel-web-test");
        String first = lastCode();
        var resend = post("/otp/v1/challenges/{id}/resend", id).with(jwt().jwt(j -> j.claim("azp", "channel-web-test")))
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("msisdn", msisdn, "bindingHash", binding)));
        mvc.perform(resend).andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.errorCode").value("OTP_RESEND_TOO_SOON")).andExpect(header().string("Retry-After", "30"));
        clock.advance(Duration.ofSeconds(30));
        mvc.perform(resend).andExpect(status().isAccepted());
        String second = lastCode();
        if (!second.equals(first)) {
            verify("channel-web-test", id, first, binding).andExpect(status().isUnprocessableEntity());
        }
        verify("channel-web-test", id, second, binding).andExpect(status().isOk());
    }

    @Test
    void aVerifiedChallengeCannotBeResent() throws Exception {
        String id = challenge("channel-web-test");
        verify("channel-web-test", id, lastCode(), binding).andExpect(status().isOk());
        clock.advance(Duration.ofSeconds(31));
        mvc.perform(post("/otp/v1/challenges/{id}/resend", id).with(jwt().jwt(j -> j.claim("azp", "channel-web-test")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("msisdn", msisdn, "bindingHash", binding))))
                .andExpect(status().isNotFound()).andExpect(jsonPath("$.errorCode").value("OTP_NOT_FOUND"));
        String inbox = mvc.perform(get("/phone/v1/inbox").param("msisdn", msisdn)).andReturn().getResponse().getContentAsString();
        assertThat(json.readTree(inbox)).as("no second SMS").hasSize(1);
    }

    @Test
    void aSixthCodeForOneNumberInThirtyMinutesFails() throws Exception {
        for (int i = 0; i < 5; i++) {
            challenge("channel-web-test");
            clock.advance(Duration.ofMinutes(1));
        }
        send("channel-web-test", UUID.randomUUID().toString()).andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.errorCode").value("OTP_SEND_LIMIT"))
                .andExpect(header().string("Retry-After", String.valueOf(Duration.ofMinutes(25).toSeconds())));
        clock.advance(Duration.ofMinutes(25));
        send("channel-web-test", UUID.randomUUID().toString()).andExpect(status().isAccepted());
    }

    @Test
    void aRepeatedSendWithTheSameKeySendsNothingNew() throws Exception {
        String key = UUID.randomUUID().toString();
        JsonNode a = json.readTree(send("channel-web-test", key).andExpect(status().isAccepted()).andReturn().getResponse().getContentAsString());
        JsonNode b = json.readTree(send("channel-web-test", key).andExpect(status().isAccepted()).andReturn().getResponse().getContentAsString());
        assertThat(b.get("challengeId")).isEqualTo(a.get("challengeId"));
        String inbox = mvc.perform(get("/phone/v1/inbox").param("msisdn", msisdn)).andReturn().getResponse().getContentAsString();
        assertThat(json.readTree(inbox)).hasSize(1);
    }

    @Test
    void thePhoneShowsTheMessageAndNothingStoredHoldsTheNumberOrTheCode() throws Exception {
        String id = challenge("channel-web-test");
        String code = lastCode();
        String inbox = mvc.perform(get("/phone/v1/inbox").param("msisdn", msisdn)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertThat(inbox).contains(code + " is your code to sign in").contains("-ONDARO")
                .doesNotContain(msisdn).contains(msisdn.substring(msisdn.length() - 4));
        Map<Object, Object> stored = redis.opsForHash().entries("otp:ch:" + id);
        assertThat(stored.values().toString()).doesNotContain(msisdn).doesNotContain(code);
    }

    @Test
    void theApiWantsAToken() throws Exception {
        mvc.perform(post("/otp/v1/challenges").header("Idempotency-Key", "k").contentType(MediaType.APPLICATION_JSON)
                .content("{}")).andExpect(status().isUnauthorized());
        mvc.perform(post("/otp/v1/challenges").with(jwt().jwt(j -> j.claim("azp", "channel-web-test")))
                .header("Idempotency-Key", "k").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("purpose", "SIGN_IN", "msisdn", "12345", "subjectRef", subject,
                        "bindingHash", binding)))).andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("INVALID_MSISDN"));
    }
}
