#!/bin/sh
# Adapted from netd-tud/dns-resilience-observatory (MIT); see
# THIRD_PARTY_NOTICES.md.
set -eu

CONFIG_PATH=/etc/nginx/conf.d/default.conf
HTTP_TEMPLATE=/etc/nginx/observatory-templates/http.conf.template
HTTPS_TEMPLATE=/etc/nginx/observatory-templates/https.conf.template
CERTBOT_WEBROOT=/var/www/certbot
TU_DRESDEN_ACME_SERVER=https://acme.pki.cert.tu-dresden.de/

SERVER_DOMAIN=${SERVER_DOMAIN:-localhost}
HTTPS_ENABLED=${HTTPS_ENABLED:-false}
CERTBOT_EMAIL=${CERTBOT_EMAIL:-}
CERTBOT_CA=${CERTBOT_CA:-letsencrypt}
CERTBOT_SERVER_URL=${CERTBOT_SERVER_URL:-}
CERTBOT_CERT_NAME=${CERTBOT_CERT_NAME:-}
CERTBOT_STAGING=${CERTBOT_STAGING:-false}
CERTBOT_RENEW_INTERVAL=${CERTBOT_RENEW_INTERVAL:-43200}
CERTBOT_RETRY_INTERVAL=${CERTBOT_RETRY_INTERVAL:-300}

NGINX_PID=
CERTBOT_PID=
ACME_CONFIGURATION_VALID=true

cert_log() {
    log_level=$1
    log_stage=$2
    shift 2
    printf '%s [certificate] [level=%s] [stage=%s] %s\n' \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$log_level" "$log_stage" "$*"
}

is_true() {
    case "$1" in
        1|true|TRUE|yes|YES|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

certificate_is_available() {
    [ -s "/etc/letsencrypt/live/${CERTBOT_CERT_NAME}/fullchain.pem" ] &&
        [ -s "/etc/letsencrypt/live/${CERTBOT_CERT_NAME}/privkey.pem" ]
}

configure_certificate_authority() {
    case "$CERTBOT_CA" in
        letsencrypt)
            if [ -z "$CERTBOT_CERT_NAME" ]; then
                CERTBOT_CERT_NAME=$SERVER_DOMAIN
            fi
            ;;
        tu-dresden)
            if [ -z "$CERTBOT_SERVER_URL" ]; then
                CERTBOT_SERVER_URL=$TU_DRESDEN_ACME_SERVER
            fi
            if [ -z "$CERTBOT_CERT_NAME" ]; then
                CERTBOT_CERT_NAME="${SERVER_DOMAIN}-tu-dresden"
            fi
            ;;
        custom)
            if [ -z "$CERTBOT_SERVER_URL" ]; then
                cert_log ERROR configuration "CERTBOT_CA=custom requires CERTBOT_SERVER_URL; continuing with HTTP only" >&2
                ACME_CONFIGURATION_VALID=false
            fi
            if [ -z "$CERTBOT_CERT_NAME" ]; then
                CERTBOT_CERT_NAME="${SERVER_DOMAIN}-custom"
            fi
            ;;
        *)
            cert_log ERROR configuration "Unsupported CERTBOT_CA '${CERTBOT_CA}'; use letsencrypt, tu-dresden, or custom" >&2
            ACME_CONFIGURATION_VALID=false
            if [ -z "$CERTBOT_CERT_NAME" ]; then
                CERTBOT_CERT_NAME=$SERVER_DOMAIN
            fi
            ;;
    esac
}

render_config() {
    template=$1
    envsubst '${SERVER_DOMAIN} ${CERTBOT_CERT_NAME}' < "$template" > "${CONFIG_PATH}.new"
    mv "${CONFIG_PATH}.new" "$CONFIG_PATH"
}

activate_https() {
    previous_config="${CONFIG_PATH}.previous"
    cert_log INFO installation "Installing certificate lineage '${CERTBOT_CERT_NAME}' into the nginx HTTPS configuration"
    cp "$CONFIG_PATH" "$previous_config"
    render_config "$HTTPS_TEMPLATE"

    cert_log INFO installation "Validating the generated nginx HTTPS configuration"
    if nginx -t; then
        cert_log INFO installation "Nginx configuration validation succeeded; reloading nginx"
        if nginx -s reload; then
            rm -f "$previous_config"
            cert_log INFO installation "Certificate installation succeeded; HTTPS is active for ${SERVER_DOMAIN}"
            return 0
        fi

        cert_log ERROR installation "Nginx reload failed; restoring the previous configuration" >&2
        mv "$previous_config" "$CONFIG_PATH"
        nginx -s reload || true
        return 1
    fi

    cert_log ERROR installation "Nginx configuration validation failed; restoring the previous configuration" >&2
    mv "$previous_config" "$CONFIG_PATH"
    return 1
}

request_initial_certificate() {
    set -- certbot certonly \
        --webroot \
        --webroot-path "$CERTBOT_WEBROOT" \
        --domain "$SERVER_DOMAIN" \
        --cert-name "$CERTBOT_CERT_NAME" \
        --email "$CERTBOT_EMAIL" \
        --agree-tos \
        --non-interactive \
        --verbose \
        --verbose \
        --keep-until-expiring

    if [ -n "$CERTBOT_SERVER_URL" ]; then
        set -- "$@" --server "$CERTBOT_SERVER_URL"
    elif is_true "$CERTBOT_STAGING"; then
        set -- "$@" --staging
    fi

    "$@"
}

certificate_loop() {
    while kill -0 "$NGINX_PID" 2>/dev/null; do
        if certificate_is_available; then
            cert_log INFO renewal "Starting scheduled renewal check for certificate lineage '${CERTBOT_CERT_NAME}'"
            if certbot renew \
                --webroot \
                --webroot-path "$CERTBOT_WEBROOT" \
                --non-interactive \
                --verbose \
                --verbose; then
                cert_log INFO renewal "Certbot renewal check succeeded; see the Certbot output above for renewal status"
                if activate_https; then
                    delay=$CERTBOT_RENEW_INTERVAL
                else
                    cert_log ERROR renewal "Certificate was available, but deployment to nginx failed" >&2
                    delay=$CERTBOT_RETRY_INTERVAL
                fi
            else
                certbot_status=$?
                cert_log ERROR renewal "Certbot renewal check failed with exit status ${certbot_status}" >&2
                delay=$CERTBOT_RETRY_INTERVAL
            fi
        else
            cert_log INFO request "Starting certificate request: domain='${SERVER_DOMAIN}', ca='${CERTBOT_CA}', lineage='${CERTBOT_CERT_NAME}', challenge='http-01', webroot='${CERTBOT_WEBROOT}'"
            if request_initial_certificate; then
                cert_log INFO request "Certbot reported that the certificate request succeeded"
                cert_log INFO verification "Checking that fullchain.pem and privkey.pem were created for lineage '${CERTBOT_CERT_NAME}'"
                if certificate_is_available; then
                    cert_log INFO verification "Certificate files are present; displaying stored certificate metadata"
                    certbot certificates || cert_log WARN verification "Certbot could not display certificate metadata"
                    if activate_https; then
                        delay=$CERTBOT_RENEW_INTERVAL
                    else
                        cert_log ERROR installation "Certificate request succeeded, but installation into nginx failed" >&2
                        delay=$CERTBOT_RETRY_INTERVAL
                    fi
                else
                    cert_log ERROR verification "Certbot exited successfully, but the expected certificate files are missing" >&2
                    delay=$CERTBOT_RETRY_INTERVAL
                fi
            else
                certbot_status=$?
                cert_log ERROR request "Certbot certificate request failed with exit status ${certbot_status}" >&2
                delay=$CERTBOT_RETRY_INTERVAL
            fi

            if [ "$delay" = "$CERTBOT_RETRY_INTERVAL" ]; then
                cert_log WARN retry "HTTP remains available; the next certificate attempt will run in ${CERTBOT_RETRY_INTERVAL}s"
            fi
        fi

        cert_log INFO scheduling "Next certificate lifecycle check scheduled in ${delay}s"
        sleep "$delay" &
        wait $! || true
    done
}

shutdown() {
    if [ -n "$CERTBOT_PID" ]; then
        kill "$CERTBOT_PID" 2>/dev/null || true
    fi
    if [ -n "$NGINX_PID" ]; then
        kill -TERM "$NGINX_PID" 2>/dev/null || true
        wait "$NGINX_PID" 2>/dev/null || true
    fi
    exit 0
}

trap shutdown INT TERM

mkdir -p "$CERTBOT_WEBROOT" /etc/letsencrypt/live
configure_certificate_authority

cert_log INFO configuration "HTTPS_ENABLED='${HTTPS_ENABLED}', domain='${SERVER_DOMAIN}', ca='${CERTBOT_CA}', lineage='${CERTBOT_CERT_NAME}'"
if [ -n "$CERTBOT_SERVER_URL" ]; then
    cert_log INFO configuration "Configured ACME server: ${CERTBOT_SERVER_URL}"
else
    cert_log INFO configuration "Configured ACME server: Certbot default (Let's Encrypt)"
fi

if is_true "$HTTPS_ENABLED" && certificate_is_available; then
    cert_log INFO bootstrap "Existing certificate files found; preparing the HTTPS nginx configuration"
    render_config "$HTTPS_TEMPLATE"
else
    cert_log INFO bootstrap "No active certificate selected; preparing the HTTP nginx configuration"
    render_config "$HTTP_TEMPLATE"
fi

cert_log INFO bootstrap "Validating the initial nginx configuration"
if nginx -t; then
    cert_log INFO bootstrap "Initial nginx configuration validation succeeded"
else
    cert_log ERROR bootstrap "Initial nginx configuration validation failed; nginx will not start" >&2
    exit 1
fi
nginx -g 'daemon off;' &
NGINX_PID=$!
cert_log INFO bootstrap "Nginx started with process ID ${NGINX_PID}"

if is_true "$HTTPS_ENABLED"; then
    if [ "$SERVER_DOMAIN" = "localhost" ] || [ -z "$SERVER_DOMAIN" ]; then
        cert_log ERROR configuration "HTTPS_ENABLED is true, but SERVER_DOMAIN is not a public domain; continuing with HTTP only" >&2
    elif [ -z "$CERTBOT_EMAIL" ]; then
        cert_log ERROR configuration "HTTPS_ENABLED is true, but CERTBOT_EMAIL is empty; continuing with HTTP only" >&2
    elif ! is_true "$ACME_CONFIGURATION_VALID"; then
        cert_log ERROR configuration "The ACME certificate authority configuration is invalid; continuing with HTTP only" >&2
    else
        if [ -n "$CERTBOT_SERVER_URL" ]; then
            cert_log INFO configuration "Certificate automation enabled with ACME server ${CERTBOT_SERVER_URL} (${CERTBOT_CA})"
        else
            cert_log INFO configuration "Certificate automation enabled with Certbot's default Let's Encrypt ACME server"
        fi
        certificate_loop &
        CERTBOT_PID=$!
        cert_log INFO bootstrap "Certificate lifecycle worker started with process ID ${CERTBOT_PID}"
    fi
else
    cert_log INFO configuration "HTTPS is disabled; serving HTTP only"
fi

wait "$NGINX_PID"
