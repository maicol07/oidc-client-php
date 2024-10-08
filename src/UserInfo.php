<?php /*
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
/** @noinspection PhpUnused */

/** @noinspection MagicMethodsValidityInspection */

/** @noinspection InterfacesAsConstructorDependenciesInspection */

namespace Maicol07\OpenIDConnect;

use Illuminate\Support\Collection;
use JetBrains\PhpStorm\Pure;

/**
 * OIDC Claims
 * ---
 * @property-read string $sub Subject — Identifier for the End-User at the Issuer.
 * @property-read string $name End-User's full name in displayable form including all name parts,
 * possibly including titles and suffixes, ordered according to the End-User's locale and preferences.
 * @property-read string $given_name Given name(s) or first name(s) of the End-User. Note that in some cultures,
 * people can have multiple given names; all can be present, with the names being separated by space characters.
 * @property-read string $family_name Surname(s) or last name(s) of the End-User. Note that in some cultures,
 * people can have multiple family names or no family name; all can be present,
 * with the names being separated by space characters.
 * @property-read string $middle_name Middle name(s) of the End-User. Note that in some cultures,
 * people can have multiple middle names; all can be present, with the names being separated by space characters.
 * Also note that in some cultures, middle names are not used.
 * @property-read string $nickname Casual name of the End-User that may or may not be the same as the given_name.
 * For instance, a nickname value of Mike might be returned alongside a given_name value of Michael.
 * @property-read string $preferred_username Shorthand name by which the End-User wishes to be referred to at the RP,
 * such as janedoe or j.doe. This value MAY not be unique.
 * @property-read string $profile URL of End-User's profile page.
 * @property-read string $picture URL of the End-User's profile picture.
 * This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF image file),
 * rather than to a Web page containing an image.
 * Note that this URL SHOULD specifically reference a profile photo of the End-User suitable for displaying when
 * describing the End-User, rather than an arbitrary photo taken by the End-User.
 * @property-read string $website URL of the End-User's Web page or blog.
 * This Web page SHOULD contain information published by the End-User or an organization that the End-User is
 * affiliated with.
 * @property-read string $email End-User's preferred e-mail address.
 * Its value MUST conform to the RFC 5322 [RFC5322] addr-spec syntax.
 * The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
 * @property-read bool $email_verified True if the End-User's e-mail address has been verified; otherwise false.
 * When this Claim Value is true, this means that the OP took affirmative steps to ensure that this e-mail address was
 * controlled by the End-User at the time the verification was performed.
 * The means by which an e-mail address is verified is context-specific, and dependent upon the trust framework or
 * contractual agreements within which the parties are operating.
 * @property-read string $gender End-User's gender. Values defined by this specification are female and male.
 * Other values MAY be used when neither of the defined values are applicable.
 * @property-read string $birthdate End-User's birthday,
 * represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format.
 * The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed.
 * Note that depending on the underlying platform's date related function,
 * providing just year can result in varying month and day,
 * so the implementers need to take this factor into account to correctly process the dates.
 * @property-read string $zoneinfo String from zoneinfo [zoneinfo] time zone database representing the End-User's
 * time zone.
 * For example, Europe/Paris or America/Los_Angeles.
 * @property-read string $locale End-User's locale, represented as a BCP47 [RFC5646] language tag.
 * This is typically an ISO 639-1 Alpha-2 [ISO639‑1] language code in lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1]
 * country code in uppercase, separated by a dash. For example, en-US or fr-CA.
 * As a compatibility note, some implementations have used an underscore as the separator rather than a dash,
 * for example, en_US; Relying Parties MAY choose to accept this locale syntax as well.
 * @property-read string $phone_number  End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as the
 * format of this Claim, for example, +1 (425) 555-1212 or +56 (2) 687 2400. If the phone number contains an extension,
 * it is RECOMMENDED that the extension be represented using the RFC 3966 [RFC3966] extension syntax,
 * for example, +1 (604) 555-1234;ext=5678.
 * @property-read bool $phone_number_verified  True if the End-User's phone number has been verified; otherwise false.
 * When this Claim Value is true, this means that the OP took affirmative steps to ensure that this phone number was
 * controlled by the End-User at the time the verification was performed. The means by which a phone number is verified
 * is context-specific,
 * and dependent upon the trust framework or contractual agreements within which the parties areoperating.
 * When true, the phone_number Claim MUST be in E.164 format and any extensions MUST be represented in RFC 3966 format.
 * @property-read array{
 *     formatted: string,
 *     street_address: string,
 *     locality: string,
 *     region: string,
 *     postal_code: int,
 *     country: string
 * } $address End-User's preferred postal address. The value of the address member is a JSON [RFC4627] structure
 * containing some or all of the members defined in Section 5.1.1.
 * @property-read int $updated_at  Time the End-User's information was last updated.
 * Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in
 * UTC until the date/time.
 *
 * Custom items
 * ---
 * @property-read string $id_token ID Token returned from the token request (requested for this user)
 */
class UserInfo
{
    private Collection $attrs;

    public function __construct(Collection $attrs)
    {
        $this->attrs = $attrs;
    }

    public function __get(string $name): mixed
    {
        return $this->attrs->get($name);
    }

    #[Pure] public function all(): array
    {
        return $this->attrs->all();
    }

    public function attrs(): Collection
    {
        return $this->attrs;
    }
}
