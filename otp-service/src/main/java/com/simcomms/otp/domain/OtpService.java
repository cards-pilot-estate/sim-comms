package com.simcomms.otp.domain;

import com.simcomms.otp.config.OtpProperties;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Sends and verifies one-time codes. A challenge belongs to the client that created it (the token's
 * azp) and to the binding the caller gave (a hash of a nonce kept in the caller's session), so a
 * challenge id alone is useless to anyone else. Only HMACs of codes and numbers are stored.
 */
@Service
public class OtpService {

    private static final Logger log = LoggerFactory.getLogger(OtpService.class);
    private static final Pattern MSISDN = Pattern.compile("^\\+91[6-9][0-9]{9}$");
    private static final Pattern BINDING = Pattern.compile("^[A-Za-z0-9_-]{22,128}$");
    private static final Pattern SUBJECT = Pattern.compile("^[A-Za-z0-9_-]{8,128}$");

    public record Challenge(String challengeId, Instant expiresAt, Instant resendAvailableAt, int codeLength) { }

    private final StringRedisTemplate redis;
    private final OtpProperties properties;
    private final Keys keys;
    private final SmsInbox inbox;
    private final ProofSigner signer;
    private final MeterRegistry meters;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public OtpService(StringRedisTemplate redis, OtpProperties properties, Keys keys, SmsInbox inbox,
                      ProofSigner signer, MeterRegistry meters, Clock clock) {
        this.redis = redis;
        this.properties = properties;
        this.keys = keys;
        this.inbox = inbox;
        this.signer = signer;
        this.meters = meters;
        this.clock = clock;
    }

    public Challenge send(String client, String idempotencyKey, Purpose purpose, String msisdn, String subjectRef,
                          String bindingHash) {
        if (msisdn == null || !MSISDN.matcher(msisdn).matches()) {
            throw new OtpException(HttpStatus.BAD_REQUEST, "INVALID_MSISDN", "msisdn must be +91 and 10 digits", null, null);
        }
        if (bindingHash == null || !BINDING.matcher(bindingHash).matches()
                || subjectRef == null || !SUBJECT.matcher(subjectRef).matches()) {
            throw new OtpException(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", "subjectRef and bindingHash are required", null, null);
        }
        String idemKey = "otp:idem:" + client + ":" + keys.hmac("idem", idempotencyKey);
        String replay = redis.opsForValue().get(idemKey);
        if (replay != null) {
            Map<Object, Object> existing = redis.opsForHash().entries(challengeKey(replay));
            if (!existing.isEmpty()) {
                return view(replay, existing);
            }
        }
        String msisdnKey = keys.msisdn(msisdn);
        takeSendAllowance(msisdnKey);

        String challengeId = UUID.randomUUID().toString();
        String code = newCode();
        Instant now = clock.instant();
        Map<String, String> fields = new HashMap<>();
        fields.put("purpose", purpose.name());
        fields.put("client", client);
        fields.put("subject", subjectRef);
        fields.put("binding", bindingHash);
        fields.put("msisdn", msisdnKey);
        fields.put("code", keys.hmac("code", challengeId, code));
        fields.put("attempts", "0");
        fields.put("expiresAt", String.valueOf(now.plus(properties.validity()).toEpochMilli()));
        fields.put("lastSentAt", String.valueOf(now.toEpochMilli()));
        redis.opsForHash().putAll(challengeKey(challengeId), fields);
        redis.expire(challengeKey(challengeId), properties.validity().plus(Duration.ofMinutes(5)));
        redis.opsForValue().setIfAbsent(idemKey, challengeId, properties.validity());

        inbox.deliver(msisdn, purpose.name(), purpose.sms(code, properties.brand()));
        meters.counter("otp.sent", "purpose", purpose.name(), "kind", "first").increment();
        log.info("OTP sent challenge={} purpose={} client={} to={}", challengeId, purpose, client, Keys.masked(msisdn));
        return view(challengeId, new HashMap<>(fields));
    }

    /**
     * A new code for the same challenge. The mobile number is never sent again: the challenge knows
     * it only as an HMAC, so the caller passes it back and it must match.
     */
    public Challenge resend(String client, String challengeId, String msisdn, String bindingHash) {
        Map<Object, Object> c = owned(client, challengeId, bindingHash);
        if (msisdn == null || !Keys.sameHex(keys.msisdn(msisdn), (String) c.get("msisdn"))) {
            throw OtpException.notFound();
        }
        Instant now = clock.instant();
        Instant resendAt = Instant.ofEpochMilli(Long.parseLong((String) c.get("lastSentAt"))).plus(properties.resendAfter());
        if (now.isBefore(resendAt)) {
            throw new OtpException(HttpStatus.TOO_MANY_REQUESTS, "OTP_RESEND_TOO_SOON", "A new code can be requested later",
                    seconds(Duration.between(now, resendAt)), null);
        }
        takeSendAllowance((String) c.get("msisdn"));
        Purpose purpose = Purpose.valueOf((String) c.get("purpose"));
        String code = newCode();
        Map<String, String> fields = Map.of(
                "code", keys.hmac("code", challengeId, code),
                "attempts", "0",
                "expiresAt", String.valueOf(now.plus(properties.validity()).toEpochMilli()),
                "lastSentAt", String.valueOf(now.toEpochMilli()));
        redis.opsForHash().putAll(challengeKey(challengeId), fields);
        redis.expire(challengeKey(challengeId), properties.validity().plus(Duration.ofMinutes(5)));
        inbox.deliver(msisdn, purpose.name(), purpose.sms(code, properties.brand()));
        meters.counter("otp.sent", "purpose", purpose.name(), "kind", "resend").increment();
        log.info("OTP resent challenge={} client={}", challengeId, client);
        Map<Object, Object> updated = new HashMap<>(c);
        updated.putAll(fields);
        return view(challengeId, updated);
    }

    /** @return the signed proof */
    public String verify(String client, String challengeId, String code, String bindingHash) {
        Map<Object, Object> c = owned(client, challengeId, bindingHash);
        if (c.containsKey("usedAt")) {
            throw OtpException.notFound();
        }
        if (clock.millis() > Long.parseLong((String) c.get("expiresAt"))) {
            meters.counter("otp.verified", "result", "expired").increment();
            throw new OtpException(HttpStatus.GONE, "OTP_EXPIRED", "That code has expired. Request a new code", null, null);
        }
        int attempts = Integer.parseInt((String) c.get("attempts"));
        if (attempts >= properties.maxAttempts()) {
            throw new OtpException(HttpStatus.GONE, "OTP_ATTEMPTS_EXHAUSTED", "Too many wrong codes. Request a new code", null, null);
        }
        boolean right = code != null && code.matches("[0-9]{" + properties.codeLength() + "}")
                && Keys.sameHex(keys.hmac("code", challengeId, code), (String) c.get("code"));
        if (!right) {
            long now = redis.opsForHash().increment(challengeKey(challengeId), "attempts", 1);
            int remaining = (int) Math.max(0, properties.maxAttempts() - now);
            meters.counter("otp.verified", "result", "incorrect").increment();
            log.info("OTP incorrect challenge={} attemptsRemaining={}", challengeId, remaining);
            if (remaining == 0) {
                throw new OtpException(HttpStatus.GONE, "OTP_ATTEMPTS_EXHAUSTED", "Too many wrong codes. Request a new code", null, 0);
            }
            throw new OtpException(HttpStatus.UNPROCESSABLE_ENTITY, "OTP_INCORRECT", "That code is not right", null, remaining);
        }
        // Single use, even under a race: only the first verifier sets usedAt.
        if (!redis.opsForHash().putIfAbsent(challengeKey(challengeId), "usedAt", String.valueOf(clock.millis()))) {
            throw OtpException.notFound();
        }
        meters.counter("otp.verified", "result", "verified").increment();
        log.info("OTP verified challenge={} client={}", challengeId, client);
        return signer.sign(client, (String) c.get("subject"), Purpose.valueOf((String) c.get("purpose")), challengeId,
                (String) c.get("binding"));
    }

    /** The challenge, if this client created it with this binding; otherwise "not found" (no oracle). */
    private Map<Object, Object> owned(String client, String challengeId, String bindingHash) {
        Map<Object, Object> c = redis.opsForHash().entries(challengeKey(challengeId));
        if (c.isEmpty() || !client.equals(c.get("client")) || !Keys.sameHex(bindingHash, (String) c.get("binding"))) {
            throw OtpException.notFound();
        }
        return c;
    }

    /** At most {@code maxSendsPerWindow} codes per mobile number in any rolling window, across purposes. */
    private void takeSendAllowance(String msisdnKey) {
        String key = "otp:sends:" + msisdnKey;
        long now = clock.millis();
        long windowStart = now - properties.sendWindow().toMillis();
        redis.opsForZSet().removeRangeByScore(key, Double.NEGATIVE_INFINITY, windowStart);
        Long sent = redis.opsForZSet().zCard(key);
        if (sent != null && sent >= properties.maxSendsPerWindow()) {
            var oldest = redis.opsForZSet().rangeWithScores(key, 0, 0);
            long oldestAt = oldest == null || oldest.isEmpty() ? now : oldest.iterator().next().getScore().longValue();
            meters.counter("otp.refused", "reason", "send_limit").increment();
            throw new OtpException(HttpStatus.TOO_MANY_REQUESTS, "OTP_SEND_LIMIT", "Too many codes for this number",
                    seconds(Duration.ofMillis(oldestAt + properties.sendWindow().toMillis() - now)), null);
        }
        redis.opsForZSet().add(key, UUID.randomUUID().toString(), now);
        redis.expire(key, properties.sendWindow());
    }

    private Challenge view(String challengeId, Map<?, ?> fields) {
        Instant lastSent = Instant.ofEpochMilli(Long.parseLong((String) fields.get("lastSentAt")));
        return new Challenge(challengeId, Instant.ofEpochMilli(Long.parseLong((String) fields.get("expiresAt"))),
                lastSent.plus(properties.resendAfter()), properties.codeLength());
    }

    private String newCode() {
        int bound = (int) Math.pow(10, properties.codeLength());
        return String.format("%0" + properties.codeLength() + "d", random.nextInt(bound));
    }

    private static long seconds(Duration d) {
        return Math.max(1, (d.toMillis() + 999) / 1000);
    }

    private static String challengeKey(String id) {
        return "otp:ch:" + id;
    }
}
