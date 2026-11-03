package com.simcomms.otp.api;

import com.simcomms.otp.domain.SmsInbox;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** For automated end-to-end tests only (profile test-hooks): the last code sent to a number. Never routed. */
@RestController
@Profile("test-hooks")
public class TestHookController {

    private static final Pattern CODE = Pattern.compile("^([0-9]{4,8}) ");

    private final SmsInbox inbox;

    public TestHookController(SmsInbox inbox) {
        this.inbox = inbox;
    }

    @GetMapping("/sim-admin/v1/test/last-code")
    public ResponseEntity<Map<String, String>> lastCode(@RequestParam String msisdn) {
        return inbox.read(msisdn).stream().findFirst()
                .map(m -> CODE.matcher(m.text()))
                .filter(Matcher::find)
                .map(m -> ResponseEntity.ok(Map.of("code", m.group(1))))
                .orElse(ResponseEntity.notFound().build());
    }
}
