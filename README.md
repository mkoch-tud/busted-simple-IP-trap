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

### Delete a stored certificate

Stop Nginx before deleting its certificate so the certificate worker cannot
immediately issue it again:

```sh
docker compose stop nginx
./delete-certificate
```

The helper derives the lineage from `CERTBOT_CERT_NAME`, or from
`SERVER_DOMAIN` and `CERTBOT_CA` when no explicit name is configured. It asks
for confirmation before running `certbot delete`. For unattended use:

```sh
./delete-certificate --yes
```

If `.env` already contains a new domain, pass the old certificate lineage
explicitly:

```sh
./delete-certificate old.example.com
```

Restarting Nginx with the deleted domain still configured will request a new
certificate. Change the domain configuration or leave Nginx stopped if the site
is being retired. Deleting local files does not revoke the certificate.

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
- `ipinfo_cache.json`: cached IPinfo responses when enrichment is enabled.
- `.processor.offset`: the processor's restart position.

Set `LOGFILES_DIR` in `.env` to mount a different host directory. The Python
containers run as container root so they can write to bind mounts regardless of
the host account's numeric UID; they have no privileged mode or host filesystem
access beyond this directory.

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

### Optional IPinfo enrichment

Set an IPinfo token in `.env` to enable enrichment:

```env
IPINFO_TOKEN=your-token
```

The processor then adds `country`, `city`, `postal`, `org`, and `timezone` to
new processed records and caches successful lookups by IP in
`./logfiles/ipinfo_cache.json`:

```json
{"timestamp":"2026-09-21 13:53:46,105","ip":"45.83.64.1","nonce":"2347865gbkewfhbdkj","country":"DE","city":"Berlin","postal":"10119","org":"AS208843 Alpha Strike Labs GmbH","timezone":"Europe/Berlin"}
```

The default endpoint matches the `ipinfo.io/<IP>` response shape. IPinfo's
[official Lite endpoint](https://ipinfo.io/developers/lite-api) can be selected
instead:

```env
IPINFO_API_URL=https://api.ipinfo.io/lite/{ip}
```

Lite provides country and ASN/organization data but does not provide city,
postal code, or timezone, so those fields will be `null`. Lookups are disabled
entirely when `IPINFO_TOKEN` is empty. Failed lookups do not interrupt log
processing and are retried after the processor restarts. Enabling this feature
sends visitor IP addresses to IPinfo; account for that in your privacy policy.

Cache entries expire after 24 hours (`IPINFO_CACHE_TTL=86400`) and are pruned
periodically. A later visit from that IP triggers a new lookup, so reassigned IP
addresses do not retain old organization or geolocation data indefinitely.

Restart the processor after changing these settings:

```sh
docker compose up -d --build --force-recreate log-processor
```

### Visitor reports

Show the ten most frequently connected IPs across all page hits, regardless of
whether they used a nonce:

```sh
./visitor-report
```

Show the top three IPs separately for every activated nonce:

```sh
./visitor-report --require-nonce
```

Both reports include cached country, city, postal code, timezone, and
organization details when present in the processed records.

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
