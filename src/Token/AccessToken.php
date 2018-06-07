<?php

namespace League\OAuth2\Client\Token;

use InvalidArgumentException;

class AccessToken
{
    /**
     * @var  string  accessToken
     */
    public $accessToken;

    /**
     * @var  int  expires
     */
    public $expires;

    /**
     * @var  string  refreshToken
     */
    public $refreshToken;

    /**
     * @var  string  uid
     */
    public $uid;

    /**
     * @var  string  tokenId
     */
    public $tokenid;

    /**
     * @var  string  iss
     */
    public $iss;

    /**
     * @var  string  sub
     */
    public $sub;

    /**
     * @var  string  aud
     */
    public $aud;

    /**
     * @var  string  nonce
     */
    public $nonce;

    /**
     * @var  string  exp
     */
    public $exp;

    /**
     * @var  string  iat
     */
    public $iat;

    /**
     * @var  string  auth_time
     */
    public $auth_time;

    /**
     * @var  string  acr
     */
    public $acr;
    /**
     * @var  string  azp
     */
    public $azp;


    /**
     * Sets the token, expiry, etc values.
     *
     * @param  array $options token options
     * @return void
     */
    public function __construct(array $options = null)
    {
        if (! isset($options['access_token'])) {
            throw new \InvalidArgumentException(
                'Required option not passed: access_token'.PHP_EOL
                .print_r($options, true)
            );
        }

        $this->accessToken = $options['access_token'];

        if (!empty($options['uid'])) {
            $this->uid = $options['uid'];
        }

        if (!empty($options['refresh_token'])) {
            $this->refreshToken = $options['refresh_token'];
        }

        // We need to know when the token expires. Show preference to
        // 'expires_in' since it is defined in RFC6749 Section 5.1.
        // Defer to 'expires' if it is provided instead.
        if (!empty($options['expires_in'])) {
            $this->expires = time() + ((int) $options['expires_in']);
        } elseif (!empty($options['expires'])) {
            // Some providers supply the seconds until expiration rather than
            // the exact timestamp. Take a best guess at which we received.
            $expires = $options['expires'];
            $expiresInFuture = $expires > time();
            $this->expires = $expiresInFuture ? $expires : time() + ((int) $expires);
        }

        if(!empty($options['id_token'])){
            $this->tokenid = $options['id_token'];
        }
    }

    /**
     * Returns the token key.
     *
     * @return string
     */
    public function __toString()
    {
        return (string) $this->accessToken;
    }

    /**
     * Setting Calims
     *
     * @param  array $claims ID token claims
     */
     public function setClaims($claims = array())
     {
            $this->iss = isset($claims['iss']) ? $claims['iss'] : null;
            $this->sub = isset($claims['sub']) ? $claims['sub'] : null;
            $this->aud = isset($claims['aud']) ? $claims['aud'] : null;
            $this->nonce = isset($claims['nonce']) ? $claims['nonce'] : null;
            $this->exp = isset($claims['exp']) ? $claims['exp'] : null;
            $this->iat = isset($claims['iat']) ? $claims['iat'] : null;
            $this->auth_time = isset($claims['auth_time']) ? $claims['auth_time'] : null;
            $this->acr = isset($claims['acr']) ? $claims['acr'] : null;
            $this->azp = isset($claims['azp']) ? $claims['azp'] : null;
     }

    /**
     * Returns the token key.
     *
     * @return string
     */
    public function getSub()
    {
        return $this->sub;
    }
}
