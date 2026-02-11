FROM php:8.1-fpm-alpine

LABEL maintainer="IPAM System"
LABEL description="PHP-FPM with extensions for PHPIPAM"

# Install system dependencies
RUN apk add --no-cache \
    bash \
    curl \
    git \
    libzip-dev \
    libpng-dev \
    libjpeg-turbo-dev \
    freetype-dev \
    icu-dev \
    openldap-dev \
    libxml2-dev \
    oniguruma-dev \
    gmp-dev \
    iputils \
    net-snmp-dev \
    pcre-dev \
    netcat-openbsd \
    gettext-dev \
    libintl \
    $PHPIZE_DEPS

# Configure and install PHP extensions
RUN docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-configure ldap \
    && docker-php-ext-install -j$(nproc) \
        pdo \
        pdo_mysql \
        mysqli \
        gd \
        zip \
        intl \
        ldap \
        mbstring \
        xml \
        gmp \
        pcntl \
        sockets \
        snmp \
        opcache \
        gettext

# Install Redis extension
RUN pecl install redis \
    && docker-php-ext-enable redis

# Install APCu for caching
RUN pecl install apcu \
    && docker-php-ext-enable apcu

# Copy PHP configuration
COPY php.ini /usr/local/etc/php/conf.d/99-custom.ini
COPY php-fpm.conf /usr/local/etc/php-fpm.d/zz-custom.conf

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set working directory
WORKDIR /var/www/html/phpipam

# Create www-data user directories
RUN mkdir -p /var/www/html/phpipam \
    && chown -R www-data:www-data /var/www/html

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD php-fpm -t || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["php-fpm"]
