package com.simcomms.otp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;

import java.time.Clock;

/**
 * Simulated OTP and SMS service (sim-comms). Channels reach it only through the API gateway
 * (route class "comms"); the simulated phone UI shows the messages a real phone would receive.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class OtpServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(OtpServiceApplication.class, args);
    }

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
