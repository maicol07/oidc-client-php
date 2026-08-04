<?php
/*
 * Copyright © 2023 Maicol07 (https://maicol07.it)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may get a copy of the License at
 *
 *             http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Maicol07\OpenIDConnect;

enum ClientAuthMethod: string
{
    case CLIENT_SECRET_BASIC = 'client_secret_basic';
    case CLIENT_SECRET_POST = 'client_secret_post';
    case CLIENT_SECRET_JWT = 'client_secret_jwt';
    case PRIVATE_KEY_JWT = 'private_key_jwt';

    /**
     * PKI mutual-TLS client authentication.
     *
     * @see https://tools.ietf.org/html/rfc8705#section-2.1
     */
    case TLS_CLIENT_AUTH = 'tls_client_auth';

    /**
     * Self-signed certificate mutual-TLS client authentication.
     *
     * @see https://tools.ietf.org/html/rfc8705#section-2.2
     */
    case SELF_SIGNED_TLS_CLIENT_AUTH = 'self_signed_tls_client_auth';
    case NONE = 'none';

    /**
     * Whether this method authenticates the client through the TLS layer
     * rather than through a shared secret or an assertion.
     *
     * @see https://tools.ietf.org/html/rfc8705#section-2
     */
    public function isMutualTls(): bool
    {
        return $this === self::TLS_CLIENT_AUTH || $this === self::SELF_SIGNED_TLS_CLIENT_AUTH;
    }
}
