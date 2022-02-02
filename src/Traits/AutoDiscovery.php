<?php
/*
 * Copyright 2022 Maicol07 (https://maicol07.it)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Maicol07\OpenIDConnect\Traits;

use Illuminate\Support\Collection;
use Illuminate\Support\Str;

trait AutoDiscovery
{
    private string $DISCOVERY_PATH = '.well-known/openid-configuration';

    private function autoDiscovery(string $provider_url, array|string|null $query_params = null): ?Collection
    {
        if ($provider_url) {
            $response = $this->http_client
                ->get($this->getDiscoveryEndpoint($provider_url), $query_params);

            if ($response->ok()) {
                return $response->collect();
            }
        }

        return null;
    }

    private function getDiscoveryEndpoint(string $provider_url): string
    {
        return Str::endsWith($provider_url, $this->DISCOVERY_PATH)
            ? $provider_url
            : "$provider_url/$this->DISCOVERY_PATH";
    }

    private function trimDiscoveryPath(string $provider_url): string
    {
        return Str::endsWith($provider_url, $this->DISCOVERY_PATH)
            ? Str::replace($provider_url, $this->DISCOVERY_PATH, '')
            : $provider_url;
    }
}
