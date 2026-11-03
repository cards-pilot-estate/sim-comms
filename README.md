# sim-comms

Simulated communications services for the card onboarding estate, owned by the (simulated) comms team. The first is **otp-service**: one-time codes for customer sign-in and step-up, signed proofs, and a **simulated phone** where testers read the SMS a real handset would get.

Design: `card-onboarding-platform/docs/channels/web-channel.md` §3.4 and README rulings R2 and R11.

## otp-service

| | |
| --- | --- |
| API | `contracts/otp-service.openapi.yaml`: send, resend, verify, JWKS |
| Who calls it | Channel BFFs, **only through the API gateway** (route class `comms`, token audience `comms-api-<env>`, client `channel-web-<env>`) |
| Limits (R2) | a code is valid 10 min; resend after 30 s; 3 wrong tries; at most 5 codes per mobile in any 30 min. The gateway adds 10 sends and 30 verifications per customer per hour |
| Proof | ES256 JWS (`typ: otp-proof+jwt`): `aud` is the caller's `azp`, `sub` the caller's customer key, `pur`, `cid`, `bnd` (binding hash), 5-minute expiry. Verify with `GET /otp/v1/jwks.json` |
| State | Its own Redis (`otp-redis`): challenges 15 min, send logs 30 min, the simulated inbox 24 h. Only HMACs of numbers and codes are stored |
| Keys | Secret `otp-service-secrets` (`make secrets`): `hmac-key`, `signing-key-pem` (PKCS#8 EC P-256), `signing-public-pem`. Never rotated by the Makefile |
| Simulated phone | `http://phone.<env>.localtest.me/phone/`: enter a number, see its messages (dev and uat only) |
| Test hook | `GET /sim-admin/v1/test/last-code?msisdn=` under profile `test-hooks` (dev only). Never routed by the gateway; reach it with a port-forward |
| Logs | ids only: challenge id, client, masked number (`+91XXXXXX1234`); never the number or the code |

A challenge belongs to the client that created it and to the binding hash the caller sent. Another client, a different binding or a wrong number gets 404, the same as an unknown id, so a challenge id alone is useless.

## Use

```bash
make verify                 # build and all tests (Docker for Testcontainers Redis)
make load                   # build the image and load it into kind (cards-pilot)
make deploy ENV=dev         # creates the secret if missing, then helm upgrade into comms-dev
```

Network: ingress to `otp-service:8080` only from the gateway proxy namespace, Traefik (the phone host routes `/phone` only) and Prometheus. `otp-redis` admits only `otp-service`.
