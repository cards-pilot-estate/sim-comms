package com.simcomms.otp.api;

import com.simcomms.otp.domain.SmsInbox;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * The simulated phone's inbox, for testers (phone.<env>.localtest.me, dev and uat only). Never routed
 * by the API gateway. It shows codes on purpose: that is what a phone does.
 */
@RestController
@ConditionalOnProperty(name = "app.phone.enabled", havingValue = "true")
public class PhoneController {

    private final SmsInbox inbox;

    public PhoneController(SmsInbox inbox) {
        this.inbox = inbox;
    }

    @GetMapping("/phone/v1/inbox")
    public List<SmsInbox.Message> inbox(@RequestParam String msisdn) {
        return inbox.read(msisdn);
    }
}
