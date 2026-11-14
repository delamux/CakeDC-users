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

namespace CakeDC\Users\Webauthn\Repository;

use Cake\Datasource\EntityInterface;
use Cake\ORM\Table;
use CakeDC\Users\Webauthn\Base64Utility;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Credential records of one user, stored in `additional_data.webauthn_credentials` indexed by the base64url id. The
 * stored JSON is the one webauthn-lib normalizes a credential record to, the same shape the 4.x
 * `PublicKeyCredentialSource::jsonSerialize()` wrote, so credentials saved before webauthn-lib 5 keep working.
 */
class UserCredentialSourceRepository
{
    /**
     * @var \Cake\Datasource\EntityInterface
     */
    private EntityInterface $user;

    /**
     * @var \Cake\ORM\Table|null
     */
    private ?Table $usersTable;

    /**
     * @var \Symfony\Component\Serializer\SerializerInterface
     */
    private SerializerInterface $serializer;

    /**
     * @param \Cake\Datasource\EntityInterface $user The user.
     * @param \Cake\ORM\Table|null $usersTable The users table.
     * @param \Symfony\Component\Serializer\SerializerInterface|null $serializer Serializer of webauthn-lib.
     */
    public function __construct(
        EntityInterface $user,
        ?Table $usersTable = null,
        ?SerializerInterface $serializer = null,
    ) {
        $this->user = $user;
        $this->usersTable = $usersTable;
        if ($serializer === null) {
            $attestationStatementSupportManager = new AttestationStatementSupportManager();
            $attestationStatementSupportManager->add(new NoneAttestationStatementSupport());
            $serializer = (new WebauthnSerializerFactory($attestationStatementSupportManager))->create();
        }
        $this->serializer = $serializer;
    }

    /**
     * @param string $publicKeyCredentialId Binary credential id.
     * @return \Webauthn\CredentialRecord|null
     */
    public function findOneByCredentialId(string $publicKeyCredentialId): ?CredentialRecord
    {
        $encodedId = Base64Utility::basicEncode($publicKeyCredentialId);
        $credential = $this->user['additional_data']['webauthn_credentials'][$encodedId] ?? null;

        return $credential
            ? $this->denormalize($credential)
            : null;
    }

    /**
     * @param \Webauthn\PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity The user entity.
     * @return array<\Webauthn\CredentialRecord>
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        if ($publicKeyCredentialUserEntity->id != $this->user->get('id')) {
            return [];
        }
        $credentials = $this->user['additional_data']['webauthn_credentials'] ?? [];
        $list = [];
        foreach ($credentials as $credential) {
            $list[] = $this->denormalize($credential);
        }

        return $list;
    }

    /**
     * @param \Webauthn\CredentialRecord $credentialRecord The credential record to add or update.
     * @return void
     */
    public function saveCredentialSource(CredentialRecord $credentialRecord): void
    {
        $credentials = $this->user['additional_data']['webauthn_credentials'] ?? [];
        $id = Base64Utility::basicEncode($credentialRecord->publicKeyCredentialId);
        $credentials[$id] = json_decode($this->serializer->serialize($credentialRecord, 'json'), true);
        $this->user['additional_data'] = $this->user['additional_data'] ?? [];
        $this->user['additional_data']['webauthn_credentials'] = $credentials;
        $this->usersTable->saveOrFail($this->user);
    }

    /**
     * @param array<string, mixed> $credential Stored credential.
     * @return \Webauthn\CredentialRecord
     */
    protected function denormalize(array $credential): CredentialRecord
    {
        return $this->serializer->deserialize(
            json_encode($credential, JSON_THROW_ON_ERROR),
            CredentialRecord::class,
            'json',
        );
    }
}
