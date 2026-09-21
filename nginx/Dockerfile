FROM nginx:1.27-alpine

RUN apk add --no-cache certbot gettext

COPY templates/ /etc/nginx/observatory-templates/
COPY docker-entrypoint.sh /usr/local/bin/observatory-nginx-entrypoint

RUN chmod 0755 /usr/local/bin/observatory-nginx-entrypoint

ENTRYPOINT ["/usr/local/bin/observatory-nginx-entrypoint"]
