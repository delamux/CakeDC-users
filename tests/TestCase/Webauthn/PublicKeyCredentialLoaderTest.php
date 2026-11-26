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

namespace CakeDC\Users\Test\TestCase\Webauthn;

use Cake\TestSuite\TestCase;
use CakeDC\Users\Webauthn\PublicKeyCredentialLoader;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

/**
 * webauthn-lib 5 only accepts base64url for the binary members of an assertion response. Clients that send standard
 * base64 (with "+", "/" and padding) keep working: the loader normalizes them first.
 */
class PublicKeyCredentialLoaderTest extends TestCase
{
    /**
     * @return void
     */
    public function testAssertionWithStandardBase64IsLoaded(): void
    {
        $signature = str_repeat("\xfb\xff\xfe", 24);
        $userHandle = '00000000-0000-0000-0000-000000000001';
        $authenticatorData = hash('sha256', 'localhost', true) . "\x05\x00\x00\x00\x01";
        $clientData = (string)json_encode([
            'type' => 'webauthn.get',
            'challenge' => 'Y2hhbGxlbmdl',
            'origin' => 'https://localhost',
        ]);
        $this->assertStringContainsString('+', base64_encode($signature));
        $this->assertStringContainsString('/', base64_encode($signature));

        $loader = new PublicKeyCredentialLoader(
            (new WebauthnSerializerFactory(new AttestationStatementSupportManager()))->create(),
        );
        $credential = $loader->loadArray([
            'id' => rtrim(strtr(base64_encode('credential-id'), '+/', '-_'), '='),
            'rawId' => base64_encode('credential-id'),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => base64_encode($clientData),
                'authenticatorData' => base64_encode($authenticatorData),
                'signature' => base64_encode($signature),
                'userHandle' => base64_encode($userHandle),
            ],
        ]);

        $this->assertInstanceOf(AuthenticatorAssertionResponse::class, $credential->response);
        $this->assertSame($signature, $credential->response->signature);
        $this->assertSame($userHandle, $credential->response->userHandle);
        $this->assertSame('credential-id', $credential->rawId);
    }
}
