<?php

namespace League\OAuth2\Client\Provider;

use Closure;
use Guzzle\Http\Exception\BadResponseException;
use Guzzle\Service\Client as GuzzleClient;
use League\OAuth2\Client\Exception\IDPException as IDPException;
use League\OAuth2\Client\Grant\GrantInterface;
use League\OAuth2\Client\Token\AccessToken as AccessToken;
use League\OAuth2\Client\Exception\RPException;
use JOSE_JWE;
use Jose\Factory\LoaderFactory;
use Jose\Factory\DecrypterFactory;
use Jose\Object\JWEInterface;
use Jose\Object\JWK;
use Jose\Object\JWKSet;
use Base64Url\Base64Url;

abstract class AbstractProvider implements ProviderInterface
{
    public $clientId = '';

    public $clientSecret = '';

    public $redirectUri = '';

    public $state;

    public $nonce;

    public $name;

    public $uidKey = 'uid';

    public $scopes = [];

    public $method = 'post';

    public $scopeSeparator = ',';

    public $responseType = 'json';

    public $headers = [];

    public $authorizationHeader;

    public $auth_uri = '';

    public $token_uri = '';

    public $info_uri = '';

    /**
     * @var GuzzleClient
     */
    protected $httpClient;

    protected $redirectHandler;

    /**
     * @var int This represents: PHP_QUERY_RFC1738, which is the default value for php 5.4
     *          and the default encoding type for the http_build_query setup
     */
    protected $httpBuildEncType = PHP_QUERY_RFC3986;

    public function __construct($options = [])
    {
    	$target = "scopes";
        foreach ($options as $option => $value) {
            if (property_exists($this, $option)) {
                if(strcmp($option,$target) === 0){
                    $scope_array = explode(",", $value);
                    $this->{$option} = $scope_array;
                } else {
                    $this->{$option} = $value;
                }
            }
        }
        $this->setHttpClient(new GuzzleClient());
    }

    public function setHttpClient(GuzzleClient $client)
    {
        $this->httpClient = $client;

        return $this;
    }

    public function getHttpClient()
    {
        $client = clone $this->httpClient;

        return $client;
    }

    /**
     * Get the URL that this provider uses to begin authorization.
     *
     * @return string
     */
    abstract public function urlAuthorize();

    /**
     * Get the URL that this provider uses to request an access token.
     *
     * @return string
     */
    abstract public function urlAccessToken();

    /**
     * Get the URL that this provider uses to request user details.
     *
     * Since this URL is typically an authorized route, most providers will require you to pass the access_token as
     * a parameter to the request. For example, the google url is:
     *
     * 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token='.$token
     *
     * @param AccessToken $token
     * @return string
     */
    abstract public function urlUserDetails(AccessToken $token);

    /**
     * Given an object response from the server, process the user details into a format expected by the user
     * of the client.
     *
     * @param object $response
     * @param AccessToken $token
     * @return mixed
     */
    abstract public function userDetails($response, AccessToken $token);

    public function getScopes()
    {
        return $this->scopes;
    }

    public function setScopes(array $scopes)
    {
        $this->scopes = $scopes;
    }

    public function getAuthorizationUrl($options = [])
    {
        $this->state = isset($options['state']) ? $options['state'] : md5(uniqid(rand(), true));

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'state' => $this->state,
            'scope' => is_array($this->scopes) ? implode($this->scopeSeparator, $this->scopes) : $this->scopes,
            'response_type' => isset($options['response_type']) ? $options['response_type'] : 'code',
            'approval_prompt' => isset($options['approval_prompt']) ? $options['approval_prompt'] : 'auto',
        ];

        return $this->urlAuthorize().'?'.$this->httpBuildQuery($params, '', '&');
    }

    // @codeCoverageIgnoreStart
    public function authorize($options = [])
    {
        $url = $this->getAuthorizationUrl($options);
        if ($this->redirectHandler) {
            $handler = $this->redirectHandler;
            return $handler($url);
        }
        // @codeCoverageIgnoreStart
        header('Location: ' . $url);
        exit;
        // @codeCoverageIgnoreEnd
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
            'redirect_uri'  => $this->redirectUri,
            'grant_type'    => $grant,
        ];

        $requestParams = $grant->prepRequestParams($defaultParams, $params);

        try {
            switch (strtoupper($this->method)) {
                case 'GET':
                    // @codeCoverageIgnoreStart
                    // No providers included with this library use get but 3rd parties may
                    $client = $this->getHttpClient();
                    $client->setBaseUrl($this->urlAccessToken() . '?' . $this->httpBuildQuery($requestParams, '', '&'));
                    $response = $client->get(null, $this->getHeaders(base64_encode($this->clientId.':'.$this->clientSecret)), $requestParams)->send();
                    break;
                    // @codeCoverageIgnoreEnd
                case 'POST':
                    $client = $this->getHttpClient();
                    $client->setBaseUrl($this->urlAccessToken());
                    $response = $client->post(null, $this->getHeaders(base64_encode($this->clientId.':'.$this->clientSecret)), $requestParams)->send();
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
            throw new RPException($error_response['message'], $error_response['code'], $response->getStatusCode());
        }
        $result = $this->prepareResponse($response);
        $result = $this->prepareAccessTokenResult($result);

        // for JWE token
        try {
            $accesstoken = $grant->handleResponse($result);
            $jwe = JOSE_JWE::decode($accesstoken->tokenid);
            if(isset($jwe->header['enc'])){
                $shared_key = new JWK([
                    'kty' => 'oct',
                    'k' => Base64Url::encode(hash("sha256",$this->clientSecret,true)),
                ]);

                $keyset = new JWKSet();
                $keyset = $keyset->addKey($shared_key);

                $loader = LoaderFactory::createLoader();

                $decrypter = DecrypterFactory::createDecrypter(
                    [
                        'A256KW',
                        'A256CBC-HS512',
                    ]
                );

                $jwe = $loader->load($accesstoken->tokenid);

                $is_decrypted = $decrypter->decrypt($jwe, $keyset);

                $jwt = JOSE_JWE::decode($jwe->getPayload());
                $json = $jwt->claims;
            }else{
                $json = $jwe->claims;
            }
            $accesstoken->setClaims($json);

            return $accesstoken;
        } catch (RPException $e) {
            throw $e;
        } catch (Exception $e) {
            throw new RPException($e->__toString, 'E0900');
        }
    }

    public function refleshToken($grant = 'refresh_token', $params = [])
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
        'redirect_uri'  => $this->redirectUri,
        'grant_type'    => $grant,
        ];

        $requestParams = $grant->prepRequestParams($defaultParams, $params);

        try {
            switch (strtoupper($this->method)) {
                case 'GET':
                    // @codeCoverageIgnoreStart
                    // No providers included with this library use get but 3rd parties may
                    $client = $this->getHttpClient();
                    $client->setBaseUrl($this->urlAccessToken() . '?' . $this->httpBuildQuery($requestParams, '', '&'));
                    $response = $client->get(null, $this->getHeaders(base64_encode($this->clientId.':'.$this->clientSecret)), $requestParams)->send();
                    break;
                    // @codeCoverageIgnoreEnd
                case 'POST':
                    $client = $this->getHttpClient();
                    $client->setBaseUrl($this->urlAccessToken());
                    $response = $client->post(null, $this->getHeaders(base64_encode($this->clientId.':'.$this->clientSecret)), $requestParams)->send();
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
        } catch (\Exception $e) {
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
            throw new RPException($error_response['message'], $error_response['code'], $response->getStatusCode());
        }
        $result = $this->prepareResponse($response);
        $result = $this->prepareAccessTokenResult($result);

        // for JWE token
        $accesstoken = $grant->handleResponse($result);
        if(!is_null($accesstoken->tokenid)){
            $jwe = JOSE_JWE::decode($accesstoken->tokenid);
            if(!isset($jwe->header['enc'])){
                $json = $jwe->claims;
            }else{
                $shared_key = new JWK([
                    'kty' => 'oct',
                    'k' => Base64Url::encode(hash("sha256",$this->clientSecret,true)),
                ]);

                $keyset = new JWKSet();
                $keyset = $keyset->addKey($shared_key);

                $loader = LoaderFactory::createLoader();

                $decrypter = DecrypterFactory::createDecrypter(
                    [
                        'A256KW',
                        'A256CBC-HS512',
                    ]
                );
                $jwe = $loader->load($accesstoken->tokenid);

                $is_decrypted = $decrypter->decrypt($jwe, $keyset);

                $jwt = JOSE_JWE::decode($jwe->getPayload());
                $json = $jwt->claims;

            }
            $accesstoken->setClaims($json);
        }
        return $accesstoken;
    }

    /**
     * Prepare the response, parsing according to configuration and returning
     * the response as an array.
     *
     * @param  string $response
     * @return array
     */
    protected function prepareResponse($response)
    {
        $contentType = explode(';', $response->getContentType());

        try {
            $result = [];

            switch ($contentType[0]) {
                case 'application/json':
                    $json = json_decode($response->getBody(), true);

                    if (JSON_ERROR_NONE === json_last_error()) {
                        $result = $json;
                    }
                    break;
                case 'application/jwt':
                    $jwe = JOSE_JWE::decode($response->getBody());
                    if(isset($jwe->header['enc'])){
                        $shared_key = new JWK([
                            'kty' => 'oct',
                            'k' => Base64Url::encode(hash("sha256",$this->clientSecret,true)),
                        ]);

                        $keyset = new JWKSet();
                        $keyset = $keyset->addKey($shared_key);

                        $loader = LoaderFactory::createLoader();

                        $decrypter = DecrypterFactory::createDecrypter(
                            [
                                'A256KW',
                                'A256CBC-HS512',
                            ]
                        );
                        $jwe = $loader->load((string)$jwe->raw);

                        $is_decrypted = $decrypter->decrypt($jwe, $keyset);

                        $jwt = JOSE_JWE::decode($jwe->getPayload());
                        $result = $jwt->claims;
                    }else{
                        $result = $jwe->claims;
                    }
                    break;
                default:
                    parse_str($response->getBody(), $result);
                    break;
            }
            return $result;
        } catch (DomainException $e){
            throw new RPException('The signature is invalid', 'E0200');
        } catch (\Exception $e){
            throw $e;
        }
    }

    /**
     * Prepare the access token response for the grant. Custom mapping of
     * expirations, etc should be done here.
     *
     * @param  array $result
     * @return array
     */
    protected function prepareAccessTokenResult(array $result)
    {
        $this->setResultUid($result);
        return $result;
    }

    protected function prepareErrorResponse ($response){
        $json = json_decode($response, true);
        $error_message = $json['error'];
        $error_code;
        switch($error_message){
            case 'invalid_request':
                $error_code = 'E0300';
                break;
            case 'invalid_scope':
                $error_code = 'E0305';
                break;
            case 'server_error':
                $error_code = 'E0306';
                break;
            case 'invalid_client':
                $error_code = 'E0310';
                break;
            case 'invalid_grant':
                $error_code = 'E0311';
                break;
            case 'unauthorized_client':
                $error_code = 'E0312';
                break;
            case 'unsupported_grant_type':
                $error_code = 'E0313';
                break;
            case 'invalid_token':
                $error_code = 'E0314';
                break;
            case 'insufficient_scope':
                $error_code = 'E0315';
                break;
            default:
                $error_message = empty($error_message) ? 'The unexpected error was detected' : $error_message;
                $error_code = 'E0900';
                break;
        }
        return array('code' => $error_code,'message' =>$error_message);
    }

    /**
     * Sets any result keys we've received matching our provider-defined uidKey to the key "uid".
     *
     * @param array $result
     */
    protected function setResultUid(array &$result)
    {
        // If we're operating with the default uidKey there's nothing to do.
        if ($this->uidKey === "uid") {
            return;
        }

        if (isset($result[$this->uidKey])) {
            // The AccessToken expects a "uid" to have the key "uid".
            $result['uid'] = $result[$this->uidKey];
        }
    }

    public function getUserDetails(AccessToken $token)
    {
        $response = $this->fetchUserDetails($token);
        return $this->userDetails($response, $token);
    }

    public function getUserUid(AccessToken $token)
    {
        $response = $this->fetchUserDetails($token, true);

        return $this->userUid(json_decode($response), $token);
    }

    public function getUserEmail(AccessToken $token)
    {
        $response = $this->fetchUserDetails($token, true);

        return $this->userEmail(json_decode($response), $token);
    }

    public function getUserScreenName(AccessToken $token)
    {
        $response = $this->fetchUserDetails($token, true);

        return $this->userScreenName(json_decode($response), $token);
    }

    public function userUid($response, AccessToken $token)
    {
        return isset($response->id) && $response->id ? $response->id : null;
    }

    public function userEmail($response, AccessToken $token)
    {
        return isset($response->email) && $response->email ? $response->email : null;
    }

    public function userScreenName($response, AccessToken $token)
    {
        return isset($response->name) && $response->name ? $response->name : null;
    }

    /**
     * Build HTTP the HTTP query, handling PHP version control options
     *
     * @param  array        $params
     * @param  integer      $numeric_prefix
     * @param  string       $arg_separator
     * @param  null|integer $enc_type
     *
     * @return string
     * @codeCoverageIgnoreStart
     */
    protected function httpBuildQuery($params, $numeric_prefix = 0, $arg_separator = '&', $enc_type = null)
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !defined('HHVM_VERSION')) {
            if ($enc_type === null) {
                $enc_type = $this->httpBuildEncType;
            }
            $url = http_build_query($params, $numeric_prefix, $arg_separator, $enc_type);
        } else {
            $url = http_build_query($params, $numeric_prefix, $arg_separator);
        }

        return $url;
    }

    protected function fetchUserDetails(AccessToken $token)
    {
        $url = $this->urlUserDetails($token);

        $headers = $this->getHeaders($token);

        return $this->fetchProviderData($url, $headers);
    }

    protected function fetchProviderData($url, array $headers = [])
    {
        try {
            $client = $this->getHttpClient();
            $client->setBaseUrl($url);

            if ($headers) {
                $client->setDefaultOption('headers', $headers);
            }

            $response = $client->get()->send();
        } catch (BadResponseException $e) {
            // @codeCoverageIgnoreStart
            $response = $e->getResponse();
            // @codeCoverageIgnoreEnd
        }

        if($response->getStatusCode() !== null && $response->getStatusCode() !==200){
            $header = $response->getHeader("WWW-Authenticate");
            if(!empty($header)){
                preg_match('/error="(\w+)"/', $header, $match);
                $error_response = $this->prepareErrorResponse(json_encode(array('error'=>$match[1])));
            } else {
                $error_response = $this->prepareErrorResponse($response->getBody());
            }
            throw new RPException($error_response['message'], $error_response['code'], $response->getStatusCode());
        }
        $result = $this->prepareResponse($response);

        return $result;
    }

    protected function getAuthorizationHeaders($token)
    {
        $headers = [];
        if ($this->authorizationHeader) {
            $headers['Authorization'] = $this->authorizationHeader . ' ' . $token;
        }
        return $headers;
    }

    public function getHeaders($token)
    {
        $headers = $this->headers;
        if ($token) {
            $headers = array_merge($headers, $this->getAuthorizationHeaders($token));
        }
        return $headers;
    }

    public function setRedirectHandler(Closure $handler)
    {
        $this->redirectHandler = $handler;
    }

    public function  setAuthorizationHeader($header)
    {
        $this->authorizationHeader = $header;
    }
}
