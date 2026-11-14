<?php
declare(strict_types=1);

/**
 * Copyright 2010 - 2023, Cake Development Corporation (https://www.cakedc.com)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright Copyright 2010 - 2023, Cake Development Corporation (https://www.cakedc.com)
 * @license MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

namespace CakeDC\Users\Webauthn;

use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\PublicKeyCredential;

/**
 * Loads the browser response (`PublicKeyCredential`) with the webauthn-lib 5 serializer. Before loading, it makes the
 * base64 of `clientDataJSON` and `authenticatorData` compliant (some browsers send it with padding or in base64 instead
 * of base64url).
 */
class PublicKeyCredentialLoader
{
    /**
     * @param \Symfony\Component\Serializer\SerializerInterface $serializer Serializer of webauthn-lib.
     */
    public function __construct(protected SerializerInterface $serializer)
    {
    }

    /**
     * @param array<string, mixed> $json Response sent by the browser.
     * @return \Webauthn\PublicKeyCredential
     */
    public function loadArray(array $json): PublicKeyCredential
    {
        if (
            isset($json['response']['clientDataJSON'])
            && is_string($json['response']['clientDataJSON'])
        ) {
            $json['response']['clientDataJSON'] =
                Base64Utility::complyEncodedNoPadding($json['response']['clientDataJSON']);
        }
        if (
            isset($json['response']['authenticatorData'])
            && is_string($json['response']['authenticatorData'])
        ) {
            $json['response']['authenticatorData'] =
                Base64Utility::complyEncodedNoPadding($json['response']['authenticatorData']);
        }

        return $this->serializer->deserialize(
            json_encode($json, JSON_THROW_ON_ERROR),
            PublicKeyCredential::class,
            'json',
        );
    }
}
