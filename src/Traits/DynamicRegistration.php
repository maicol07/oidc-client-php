<?php
/*
 * Copyright © 2024 Maicol07 (https://maicol07.it)
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

namespace Maicol07\OpenIDConnect\Traits;

use Illuminate\Http\Client\ConnectionException;
use Maicol07\OpenIDConnect\OIDCClientException;

trait DynamicRegistration
{
    /**
     * Dynamic registration
     *
     * @throws OIDCClientException|ConnectionException
     */
    public function register(?array $params = null): void
    {
        $data = collect($params)
            ->put('redirect_uris', [$this->redirect_uri])
            ->put('client_name', $this->client_name);

        $response = $this->client()->post($this->registration_endpoint, $data->all())->collect();

        $error = $response->get('error_description');
        if ($error) {
            throw new OIDCClientException($error);
        }

        $this->client_id = $response->get('client_id');

        // The OpenID Connect Dynamic registration protocol makes the client secret optional
        // and provides a registration access token and URI endpoint if it is not present
        $secret = $response->get('client_secret');
        if ($secret) {
            $this->client_secret = $secret;
        } else {
            throw new OIDCClientException('Error registering: Please contact the OpenID Connect provider
             and obtain a Client ID and Secret directly from them');
        }
    }
}
