package com.simcomms.otp.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.simcomms.otp.config.OtpProperties;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.List;

/**
 * The simulated phone: what a real handset would receive. Kept per mobile number (by its HMAC) for
 * a day, newest first. In a bank this is the SMS aggregator; here a tester reads it in the phone UI.
 */
@Component
public class SmsInbox {

    public record Message(String to, String text, String template, long sentAt) { }

    private final StringRedisTemplate redis;
    private final ObjectMapper json;
    private final Keys keys;
    private final OtpProperties properties;
    private final Clock clock;

    public SmsInbox(StringRedisTemplate redis, ObjectMapper json, Keys keys, OtpProperties properties, Clock clock) {
        this.redis = redis;
        this.json = json;
        this.keys = keys;
        this.properties = properties;
        this.clock = clock;
    }

    public void deliver(String msisdn, String template, String text) {
        String key = "sms:inbox:" + keys.msisdn(msisdn);
        try {
            redis.opsForList().leftPush(key, json.writeValueAsString(
                    new Message(Keys.masked(msisdn), text, template, clock.millis())));
        } catch (Exception e) {
            throw new IllegalStateException("SMS could not be queued", e);
        }
        redis.opsForList().trim(key, 0, properties.inboxSize() - 1);
        redis.expire(key, properties.inboxRetention());
    }

    public List<Message> read(String msisdn) {
        List<String> raw = redis.opsForList().range("sms:inbox:" + keys.msisdn(msisdn), 0, -1);
        return raw == null ? List.of() : raw.stream().map(this::parse).toList();
    }

    private Message parse(String raw) {
        try {
            return json.readValue(raw, Message.class);
        } catch (Exception e) {
            return new Message("?", "(unreadable)", "?", 0);
        }
    }

}
