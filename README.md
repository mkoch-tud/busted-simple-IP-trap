Simple IP trap; yep...AI generated, I don't waste my time for malicious people.

# busted-simple-IP-trap

The Compose stack runs the Python app behind Nginx on ports 80 and 443. A
separate container continuously extracts IP addresses and nonces from the raw
visitor log, and registered nonces can be activated with one command. The custom
Nginx image includes Certbot and automatically requests, installs, and renews a
certificate using the HTTP-01 challenge.

## Public HTTPS setup

Requirements:

- A public domain with its A and/or AAAA record pointing at this host.
- Inbound TCP ports 80 and 443 forwarded to this host and not used by another
  service.
- Docker with the Compose plugin.

Create the runtime configuration and replace both example values:

```sh
cp .env.example .env
```

For a first deployment, leave `CERTBOT_STAGING=false`. If you are repeatedly
testing certificate issuance, use `true` until the setup works to avoid Let's
Encrypt production rate limits; staging certificates are not browser-trusted.

Build and start the stack:

```sh
docker compose up -d --build
docker compose logs -f nginx
```

Nginx initially serves HTTP so Certbot can complete the challenge. After the
certificate is issued, the entrypoint validates the HTTPS configuration,
reloads Nginx, and redirects normal HTTP requests to HTTPS. Failed certificate
requests leave HTTP available and are retried after five minutes.

Each page request is appended to `/data/visitors.log` in the bind-mounted log
directory. Any path after the domain is treated as an identifier, displayed on
the page, and included in the same log entry. For example:

```text
https://trap.example.com/2347865gbkewfhbdkj
```

The query string is not part of the identifier. To view the log:

```sh
docker compose exec app sh -c 'tail -f /data/visitors.log'
```

By default, all application data is persistently stored in the host's
`./logfiles` directory:

- `visitors.log`: raw page visits.
- `processed_visitors.jsonl`: normalized visits.
- `nonces.json`: activated nonces, activation times, and hit counts.
- `.processor.offset`: the processor's restart position.

Set `LOGFILES_DIR` in `.env` to mount a different host directory. Set `PUID` and
`PGID` if the default `1000:1000` user cannot write to it.

The `log-processor` container converts raw entries into
`./logfiles/processed_visitors.jsonl`. Each line is an independent JSON object:

```json
{"timestamp":"2026-09-21 13:53:46,105","ip":"203.0.113.42","nonce":"2347865gbkewfhbdkj"}
{"timestamp":"2026-09-21 13:54:02,910","ip":"203.0.113.43","nonce":null}
```

View processed entries with:

```sh
docker compose exec log-processor sh -c 'tail -f /data/processed_visitors.jsonl'
```

The processor stores its last-read position in `/data/.processor.offset`, so
restarting the container does not normally duplicate previously processed
entries. Existing log lines from older versions that have no identifier are
also emitted with `"nonce": null`.

## Activate and track a nonce

With the stack running, activate a new nonce using the helper command:

```sh
./activate-nonce
```

The default length is 24 alphanumeric characters. Change `NONCE_LENGTH` in
`.env`, or override it for one activation with
`./activate-nonce --nonce-length 32`.

It prints only the generated nonce, making it easy to capture from another
program or shell:

```sh
nonce=$(./activate-nonce)
echo "https://trap.example.com/$nonce"
```

Generation uses cryptographically secure randomness and checks the nonce
registry, processed visits, and raw visits before activating it. A generated
nonce is therefore never knowingly reused. The registry resembles:

```json
{
  "2347865gbkewfhbdkj": {
    "activated_at": "2026-09-21T14:00:00Z",
    "first_hit_at": "2026-09-21 16:01:05,120",
    "hit_count": 3,
    "last_hit_at": "2026-09-21 16:07:42,918"
  }
}
```

Arbitrary, unregistered URL identifiers still display and appear in the
processed visit log, but only activated nonces receive counters in
`nonces.json`.

The app service is only reachable on the private Compose network. Nginx
overwrites `X-Real-IP` with the connecting client's address, which is the value
logged and displayed by the app. Treat IP addresses and logs according to the
privacy rules applicable to your deployment.

## Local Python run

No third-party Python packages are required:

```sh
python3 server.py
```

Then open <http://localhost:8000>. Use `--port` or `--log-file` to override the
defaults.
