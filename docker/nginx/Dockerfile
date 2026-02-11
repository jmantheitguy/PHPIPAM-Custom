FROM nginx:alpine

LABEL maintainer="IPAM System"
LABEL description="Nginx reverse proxy for PHPIPAM"

# Install dependencies
RUN apk add --no-cache \
    curl \
    openssl \
    bash

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Create directories
RUN mkdir -p /var/cache/nginx \
    && mkdir -p /var/log/nginx \
    && mkdir -p /etc/nginx/ssl

# Copy health check script
COPY healthcheck.sh /healthcheck.sh
RUN chmod +x /healthcheck.sh

# Set proper permissions
RUN chown -R nginx:nginx /var/cache/nginx \
    && chown -R nginx:nginx /var/log/nginx

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /healthcheck.sh || exit 1

CMD ["nginx", "-g", "daemon off;"]
