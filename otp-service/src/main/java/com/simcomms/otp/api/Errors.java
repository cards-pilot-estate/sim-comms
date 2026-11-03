package com.simcomms.otp.api;

import com.simcomms.otp.domain.OtpException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.LinkedHashMap;
import java.util.Map;

/** Error bodies carry a code and a message, never the number or the code. */
@RestControllerAdvice
public class Errors {

    @ExceptionHandler(OtpException.class)
    ResponseEntity<Map<String, Object>> otp(OtpException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("errorCode", e.errorCode());
        body.put("message", e.getMessage());
        if (e.attemptsRemaining() != null) {
            body.put("attemptsRemaining", e.attemptsRemaining());
        }
        var response = ResponseEntity.status(e.status());
        if (e.retryAfterSeconds() != null) {
            response.header("Retry-After", String.valueOf(e.retryAfterSeconds()));
        }
        return response.body(body);
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class,
            MissingRequestHeaderException.class, MethodArgumentTypeMismatchException.class})
    ResponseEntity<Map<String, Object>> invalid(Exception e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("errorCode", "INVALID_REQUEST", "message", "The request is missing a field or has a wrong one"));
    }
}
