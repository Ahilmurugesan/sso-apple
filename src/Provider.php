<?php

namespace Ahilan\Apple;

use Illuminate\Support\Arr;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\InvalidStateException;
use Firebase\JWT\JWK;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Ahilan\Apple\Exceptions\InvalidTokenException;

class Provider extends AbstractProvider implements ProviderInterface
{
    /**
     * Unique Provider Identifier.
     */
    const IDENTIFIER = 'APPLE';

    /**
     * {@inheritdoc}
     */
    protected $scopes = [
        'name',
        'email'
    ];

    /**
     * The separating character for the requested scopes.
     *
     * @var string
     */
    protected $scopeSeparator = ' ';

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase('https://appleid.apple.com/auth/authorize', $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getCodeFields($state = null)
    {
        $fields = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUrl,
            'scope' => $this->formatScopes($this->getScopes(), $this->scopeSeparator),
            'response_type' => 'code',
            'response_mode' => 'form_post',
        ];

        if ($this->usesState()) {
            $fields['state'] = $state;
            $fields['nonce'] = strtotime('12:00:00')."-".$state;
        }

        return array_merge($fields, $this->parameters);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return 'https://appleid.apple.com/auth/token';
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenResponse($code)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            'headers' => ['Authorization' => 'Basic ' . base64_encode($this->clientId . ':' . $this->clientSecret)],
            'form_params'    => $this->getTokenFields($code),
        ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * {@inheritDoc}
     */
    protected function getTokenFields($code)
    {
        return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code',
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        static::verify($token);
        $claims = explode('.', $token)[1];

        return json_decode(base64_decode($claims), true);
    }

    /**
     * Verify apple jwt
     *
     * @param $jwt
     *
     * @return object
     * @see https://appleid.apple.com/auth/keys
     */
    public static function verify($jwt)
    {
        $signer = new Sha256();

        $token = (new Parser())->parse((string) $jwt);

        if($token->getClaim('iss') !== 'https://appleid.apple.com'){
            throw new InvalidTokenException("Invalid Issuer");
        }
        if($token->getClaim('aud') !== config('services.apple.client_id')){
            throw new InvalidTokenException("Invalid Client ID");
        }
        if($token->isExpired()){
            throw new InvalidTokenException("Token Expired");
        }

        $data = json_decode(file_get_contents('https://appleid.apple.com/auth/keys'), true);

        $public_keys = JWK::parseKeySet($data);

        $signature_verified = false;

        foreach ($public_keys as $res) {
            $publicKey = openssl_pkey_get_details($res);
            if($token->verify($signer, $publicKey['key'])){
                $signature_verified = true;
            }

        }
        if(!$signature_verified) {
            throw new InvalidTokenException("Invalid JWT Signature");
        }
    }

    /**
     * {@inheritDoc}
     */
    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        $user = $this->mapUserToObject($this->getUserByToken(
            $token = Arr::get($response, 'id_token')
        ));

        return $user->setToken($token)
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'));
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {

        if (request()->filled("user")) {
            $userRequest = json_decode(request("user"), true);

            if (array_key_exists("name", $userRequest)) {
                $user["name"] = $userRequest["name"];
                $fullName = trim(
                    ($user["name"]['firstName'] ?? "")
                    . " "
                    . ($user["name"]['lastName'] ?? "")
                );
            }
        }

        return (new User)
            ->setRaw($user)
            ->map([
                "id" => $user["sub"],
                "name" => $fullName ?? null,
                "email" => $user["email"] ?? null,
            ]);
    }
}
