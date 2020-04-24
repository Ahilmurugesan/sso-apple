<?php

namespace Ahilan\Apple;

use Illuminate\Support\Arr;
use Laravel\Socialite\Two\InvalidStateException;
use SocialiteProviders\Manager\OAuth2\User;
use Laravel\Socialite\Two\ProviderInterface;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;

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
        'email',
    ];

    /**
     * The separating character for the requested scopes.
     * scope:name and email
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

    protected function buildAuthUrlFromBase($url, $state)
    {
        return $url.'?'.http_build_query($this->getCodeFields($state), '', '&', $this->encodingType);
    }

    protected function getCodeFields($state = null)
    {
        $fields = [
            'response_type' => 'code',
            'response_mode' => 'form_post',
            'client_id'     => 'com.vonec.siwa.api',
            'redirect_uri'  => 'https://siwa.vonectech.com/socialite/apple/callback',
            //'state'         => $state,
            'scope'         => 'name email',
        ];

        if ($this->usesState()) {
            $fields['state'] = $state;
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
        $fields = [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => 'https://siwa.vonectech.com/socialite/apple/callback',
            'client_id'     => 'com.vonec.siwa.api',
            //'client_secret' => $client_secret->__toString(),
            'client_secret' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IkE2OTQ2SExDODQiLCJ0eXBlIjoiSldUIn0.eyJpc3MiOiJVWVRDUUtFQURYIiwiYXVkIjoiaHR0cHM6XC9cL2FwcGxlaWQuYXBwbGUuY29tIiwiaWF0IjoxNTg3NjY5NDU2LCJleHAiOjE2MDMyMjE0NTYsInN1YiI6ImNvbS52b25lYy5zaXdhLmFwaSJ9.65Q7CrbE6NROctVmDKtKXikqBt4nn947Cczxhw8XzkqdXP7q4n2SFIgLLAaAy8w6ZUCna7581VgcfCQDe2GDzg',
        ];
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            /*'headers' => ['Authorization' => 'Basic ' . base64_encode($this->clientId . ':' . $this->clientSecret)],*/
            'form_params'    => $fields,
        ]);
        return $this->parseAccessToken(json_decode($response->getBody(), true));
    }

    protected function parseAccessToken($body)
    {
        return Arr::get($body, 'id_token');
    }

    protected function getTokenFields($code)
    {
        $fields = [
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'redirect_uri'  => 'https://siwa.vonectech.com/socialite/apple/callback',
            'client_id'     => 'com.vonec.siwa.api',
            //'client_secret' => $client_secret->__toString(),
            'client_secret' => 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IkE2OTQ2SExDODQiLCJ0eXBlIjoiSldUIn0.eyJpc3MiOiJVWVRDUUtFQURYIiwiYXVkIjoiaHR0cHM6XC9cL2FwcGxlaWQuYXBwbGUuY29tIiwiaWF0IjoxNTg3NjY5NDU2LCJleHAiOjE2MDMyMjE0NTYsInN1YiI6ImNvbS52b25lYy5zaXdhLmFwaSJ9.65Q7CrbE6NROctVmDKtKXikqBt4nn947Cczxhw8XzkqdXP7q4n2SFIgLLAaAy8w6ZUCna7581VgcfCQDe2GDzg',
        ];
        /*$fields = parent::getTokenFields($code);
        $fields["grant_type"] = "authorization_code";*/
//dd($fields);
        return $fields;
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        /*$response = $this->getHttpClient()->get('https://appleid.apple.com', [
            'headers' => [
                'Authorization' => 'Bearer ' . $token,
            ],
        ]);

        return json_decode($response->getBody(), true);*/
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        dd($user);
        return (new User)->setRaw($user)->map([
            'id'       => $user['id'],
            'nickname' => $user['display_name'],
            'name'     => $user['display_name'],
            'avatar'   => !empty($user['images']) ? $user['images'][0]['url'] : null,
        ]);
    }

    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());

        $user = $this->mapUserToObject($this->getUserByToken(
            $token = Arr::get($response, 'access_token')
        ));

        return $user->setToken($token)
            ->setRefreshToken(Arr::get($response, 'refresh_token'))
            ->setExpiresIn(Arr::get($response, 'expires_in'));
    }
}
