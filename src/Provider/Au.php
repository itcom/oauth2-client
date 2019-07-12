<?php

namespace League\OAuth2\Client\Provider;

use League\OAuth2\Client\Token\AccessToken;
use JOSE_JWE;
use League\OAuth2\Client\Entity\User;

class Au extends AbstractProvider
{
    public $scopes = ['apass4web'];
    public $responseType = 'json';
    public $authorizationHeader = 'Bearer';
    public $response_type = 'code';
    public $redirectUri = '';
    public $headers = [];

    public function urlAuthorize()
    {
        return 'https://oa.connect.auone.jp/net/opi/hny_oauth_rt_net/cca?ID=OpenAPIAcpt';
    }

    public function urlAccessToken()
    {
        return 'https://oa.connect.auone.jp/net/opi/hny_oauth_rt_net/cca?ID=OpenAPITokenCodeReq';
    }

    public function urlUserDetails(AccessToken $token)
    {
        return 'https://auth.au-market.com/pass/AuthSpUser';
    }


    public function getAuthorizationUrl($options = [])
    {
        $this->state = isset($options['state']) ? $options['state'] : md5(uniqid(rand(), true));
        $_SESSION ['oauth2state'] = $this->state;

        $params = [
            'client_id' => \Config::get('site.accounting.wbsmpass.clientId', null),
            'redirect_uri' => \Config::get('site.accounting.wbsmpass.redirectUrl', null),
            'state' => $this->state,
            'scope' => is_array($this->scopes) ? implode($this->scopeSeparator, $this->scopes) : $this->scopes,
            'response_type' => isset($options['response_type']) ? $options['response_type'] : 'code',
            'approval_prompt' => isset($options['approval_prompt']) ? $options['approval_prompt'] : 'auto',
        ];

        return $this->urlAuthorize().'&'.$this->httpBuildQuery($params, '', '&');
    }

    public function userDetails($response, AccessToken $token)
    {
        try {

        $client = $this->getHttpClient();
        $client->setBaseUrl($this->urlUserDetails($token));
        $requestParams = ['ver' => '1.0'];
        $this->headers = ['x-sr-id' => \Config::get('site.accounting.wbsmpass.srId', null)];
        $response = $client->post(null
            , $this->getHeaders($token->accessToken)
            , $requestParams
        )->send();
        $result = $this->prepareResponse($response);
        } catch (BadResponseException $e) {
            // @codeCoverageIgnoreStart
            $response = $e->getResponse();
            // @codeCoverageIgnoreEnd
        } catch (Exception $e) {
            throw $e;
        }
        if($response->getStatusCode() !== null && $response->getStatusCode() !==200){
            $header = $response->getHeader("WWW-Authenticate");
            if(!empty($header)){
                preg_match('/error="(\w+)"/', $header, $match);
                $error_response = $this->prepareErrorResponse(json_encode(array('error'=>$match[1])));
            } else {
                $error_response = $this->prepareErrorResponse($response->getBody());
            }
            throw new Exception($error_response['message'], $error_response['code']);
        }

        logger(\Fuel::L_DEBUG, var_export( $result, true), __METHOD__);

        $user = new User();

        switch(true)
        {
        case $result['status'] == 'success':
            $user->exchangeArray([
                'uid' => \Cookie::get('wbsmU', null),
                'aspuser' => $result['aspuser'],
            ]);
            break;
        case $result['status'] == 'error':
            $user->exchangeArray([
                'uid' => \Cookie::get('wbsmU', null),
                'aspuser' => 'true',
            ]);
            break;
        }


        return $user;
    }

    public function getVerificationKey() {
        if (isset ( $_SESSION ['oauth2state'] )) {
            return $_SESSION ['oauth2state'];
        }
        return null;
    }


    public function getAccessToken($grant = 'authorization_code', $params = [])
    {
        if (is_string($grant)) {
            // PascalCase the grant. E.g: 'authorization_code' becomes 'AuthorizationCode'
            $className = str_replace(' ', '', ucwords(str_replace(['-', '_'], ' ', $grant)));
            $grant = 'League\\OAuth2\\Client\\Grant\\'.$className;
            if (! class_exists($grant)) {
                throw new \InvalidArgumentException('Unknown grant "'.$grant.'"');
            }
            $grant = new $grant();
        } elseif (! $grant instanceof GrantInterface) {
            $message = get_class($grant).' is not an instance of League\OAuth2\Client\Grant\GrantInterface';
            throw new \InvalidArgumentException($message);
        }

        if (isset ( $_SESSION ['redirectUri'] )) {
            $this->redirectUri = $_SESSION ['redirectUri'];
        }

        $defaultParams = [
            'redirect_uri' => \Config::get('site.accounting.wbsmpass.redirectUrl', null),
            'grant_type'    => $grant,
            'client_id' => \Config::get('site.accounting.wbsmpass.clientId', null),
            'client_secret' => \Config::get('site.accounting.wbsmpass.clientSecret', null),
        ];

        $requestParams = $grant->prepRequestParams($defaultParams, $params);

        try {
            switch (strtoupper($this->method)) {
                case 'GET':
                    // @codeCoverageIgnoreStart
                    // No providers included with this library use get but 3rd parties may
                    $client = $this->getHttpClient();
                    $client->setBaseUrl($this->urlAccessToken() . '?' . $this->httpBuildQuery($requestParams, '', '&'));
                    $response = $client->get(null, null, $requestParams)->send();

                    break;
                    // @codeCoverageIgnoreEnd
                case 'POST':
                    $client = $this->getHttpClient();
                    $client->setBaseUrl($this->urlAccessToken());
                    $response = $client->post(null, null, $requestParams)->send();
                    break;
                // @codeCoverageIgnoreStart
                default:
                    throw new \InvalidArgumentException('Neither GET nor POST is specified for request');
                // @codeCoverageIgnoreEnd
            }

        } catch (BadResponseException $e) {
            // @codeCoverageIgnoreStart
            $response = $e->getResponse();
            // @codeCoverageIgnoreEnd
        } catch (Exception $e) {
            throw $e;
        }

        if($response->getStatusCode() !== null && $response->getStatusCode() !==200){
            $header = $response->getHeader("WWW-Authenticate");
            if(!empty($header)){
                preg_match('/error="(\w+)"/', $header, $match);
                $error_response = $this->prepareErrorResponse(json_encode(array('error'=>$match[1])));
            } else {
                $error_response = $this->prepareErrorResponse($response->getBody());
            }
            throw new Exception($error_response['message'], $error_response['code']);
        }
        $result = $this->prepareResponse($response);
        $result = $this->prepareAccessTokenResult($result);

        // for JWE token
        try {
            $accesstoken = $grant->handleResponse($result);

            return $accesstoken;
        } catch (BadMethodCallException $e) {
            throw $e;
        } catch (Exception $e) {
            throw $e;
        }
    }
}


