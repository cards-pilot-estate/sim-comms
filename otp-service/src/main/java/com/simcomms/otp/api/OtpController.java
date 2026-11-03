package com.simcomms.otp.api;

import com.simcomms.otp.domain.OtpService;
import com.simcomms.otp.domain.Purpose;
import com.simcomms.otp.domain.ProofSigner;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

/** The OTP API (contracts/otp-service.openapi.yaml). Reached by channels through the API gateway only. */
@RestController
public class OtpController {

    public record SendRequest(@NotNull Purpose purpose, @NotBlank String msisdn, @NotBlank String subjectRef,
                              @NotBlank String bindingHash, String locale) { }

    public record ResendRequest(@NotBlank String msisdn, @NotBlank String bindingHash) { }

    public record VerifyRequest(@NotBlank @Size(max = 12) String code, @NotBlank String bindingHash) { }

    public record Verified(String result, String proof) { }

    private final OtpService otp;
    private final ProofSigner signer;

    public OtpController(OtpService otp, ProofSigner signer) {
        this.otp = otp;
        this.signer = signer;
    }

    @PostMapping("/otp/v1/challenges")
    public ResponseEntity<OtpService.Challenge> send(@AuthenticationPrincipal Jwt caller,
                                                     @RequestHeader("Idempotency-Key") @Size(max = 128) String idempotencyKey,
                                                     @Valid @RequestBody SendRequest body) {
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(otp.send(client(caller), idempotencyKey, body.purpose(),
                body.msisdn(), body.subjectRef(), body.bindingHash()));
    }

    @PostMapping("/otp/v1/challenges/{challengeId}/resend")
    public ResponseEntity<OtpService.Challenge> resend(@AuthenticationPrincipal Jwt caller, @PathVariable UUID challengeId,
                                                       @Valid @RequestBody ResendRequest body) {
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(otp.resend(client(caller), challengeId.toString(), body.msisdn(), body.bindingHash()));
    }

    @PostMapping("/otp/v1/challenges/{challengeId}/verification")
    public Verified verify(@AuthenticationPrincipal Jwt caller, @PathVariable UUID challengeId,
                           @Valid @RequestBody VerifyRequest body) {
        return new Verified("VERIFIED", otp.verify(client(caller), challengeId.toString(), body.code(), body.bindingHash()));
    }

    @GetMapping(value = "/otp/v1/jwks.json", produces = "application/json")
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok().header("Cache-Control", "max-age=600").body(signer.jwks());
    }

    /** The calling client: the token's azp (the API gateway has already checked it is allowed). */
    static String client(Jwt caller) {
        String azp = caller.getClaimAsString("azp");
        return azp != null ? azp : caller.getSubject();
    }
}
