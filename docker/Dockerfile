# PHP 8.4 — composer.lock pins Symfony 8 / Illuminate 13, which require PHP >= 8.4.
FROM php:8.4-cli

RUN apt-get update && apt-get install -y --no-install-recommends \
        git unzip libzip-dev libicu-dev libxml2-dev openssl ca-certificates \
    && docker-php-ext-install -j"$(nproc)" zip intl dom xml \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app

# Install dependencies first so they are cached independently of the source.
COPY composer.json composer.lock ./
RUN composer install --no-interaction --no-progress --no-scripts --no-autoloader

COPY src ./src
RUN composer dump-autoload --optimize
