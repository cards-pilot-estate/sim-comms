# Working on this repository (assisted sessions)

Read first: `README.md`, `contracts/otp-service.openapi.yaml`, then in the platform repository `docs/channels/web-channel.md` §3.4.

## Rules
- One issue, one branch `<type>/<issue#>-<slug>`, one PR `type(scope): summary` with `Closes #<issue>`. Squash-merge after CI is green. Record the PR in the platform's `docs/bank-grade/next-steps.md` § MG.
- The API changes only with the contract file in the same PR; consumers (channel-web, api-gateway) pin it.
- Never store or log a mobile number or a code: HMACs and masked numbers only. The simulated phone is the one place a code is shown, and only in dev and uat.
- Test hooks live only under profile `test-hooks` and are never routed by the gateway.
- No secrets, no real vendor or bank names (the brand is the fictional "Ondaro Bank").

## Commands
`make verify` · `make load` · `make deploy ENV=dev`. Build with JDK 25 (`JAVA_HOME=/Users/rohitbehera/Library/Java/JavaVirtualMachines/openjdk-25.0.2/Contents/Home`), target Java 21; set `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock` on Colima.
