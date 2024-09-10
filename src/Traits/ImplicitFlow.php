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

use cse\helpers\Session;
use Illuminate\Http\Request;
use JsonException;
use Maicol07\OpenIDConnect\OIDCClientException;
use SensitiveParameter;

trait ImplicitFlow
{
    /**
     * Requests Access token with implicit flow
     * @throws JsonException
     */
    private function implicitFlow(Request $request, #[SensitiveParameter] string $id_token): bool
    {
        $this->access_token = $request->get('access_token');

        // Do an OpenID Connect session check
        if ($request->get('state') !== Session::get('oidc_state')) {
            throw new OIDCClientException('Unable to determine state');
        }
        Session::remove('oidc_state');

        /** @noinspection UnusedFunctionResultInspection */
        $this->loadAndValidateJWT($id_token);

        // Save the id token
        $this->id_token = $id_token;

        return true;
    }
}
