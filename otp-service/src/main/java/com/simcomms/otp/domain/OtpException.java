package com.simcomms.otp.domain;

import org.springframework.http.HttpStatus;

/** A refusal with its HTTP status, error code and, where useful, a retry time or tries left. */
public class OtpException extends RuntimeException {

    private final HttpStatus status;
    private final String errorCode;
    private final Long retryAfterSeconds;
    private final Integer attemptsRemaining;

    public OtpException(HttpStatus status, String errorCode, String message, Long retryAfterSeconds,
                        Integer attemptsRemaining) {
        super(message);
        this.status = status;
        this.errorCode = errorCode;
        this.retryAfterSeconds = retryAfterSeconds;
        this.attemptsRemaining = attemptsRemaining;
    }

    public static OtpException notFound() {
        return new OtpException(HttpStatus.NOT_FOUND, "OTP_NOT_FOUND", "No such code request", null, null);
    }

    public HttpStatus status() { return status; }
    public String errorCode() { return errorCode; }
    public Long retryAfterSeconds() { return retryAfterSeconds; }
    public Integer attemptsRemaining() { return attemptsRemaining; }
}
