<?php

namespace League\OAuth2\Client\Provider;

use League\OAuth2\Client\Exception;
use League\OAuth2\Client\Provider;
use League\OAuth2\Client\Exception\RPException;
use InvalidArgumentException;
use Guzzle\Http\Exception\CurlException;

class Docomo extends AbstractProvider
{
    /**
     * @var string The Graph API version to use for requests.
     */
    public $scopes = [];

    public $responseType = 'json';

    public $scopeSeparator = ' ';

    public $authorizationHeader = 'Bearer';

    public $response_type = 'code';

    public $prompt = false;
    public $authif = false;
    public $idauth = false;
    public $authsp = false;
    public $authiden = false;

    public $debug = false;
    public $debug_path;

    public function __construct($file = '/rp/conf/rplib.conf')
    {
        try{
           if(!file_exists($file)){
               throw new RPException("sg file not found", "E0100", "");
           } else {
               //require $file;
               $ini_array = parse_ini_file($file,true);
               if ($ini_array == false) {
                   throw new RPException("permission denied ", "E0100", "");
               }
               $openid = $ini_array['openid'];
               $api = $ini_array['api'];
               $proxy = $ini_array['proxy'];

               if(isset($api['log_error'])){
                   if(file_exists($api['log_error'])){
                       if(is_writable($api['log_error'])){
                           putenv("X-RP-BACKTRACE=" . $api['log_error']);
                       } else {
                           putenv("X-RP-BACKTRACE=/tmp/debug.log");
                       }
                   } else {
                       $dir = substr($api['log_error'], 0, strrpos($api['log_error'], "/"));
                       if(is_writable($dir)){
                           putenv("X-RP-BACKTRACE=" . $api['log_error']);
                       } else {
                           putenv("X-RP-BACKTRACE=/tmp/debug.log");
                       }
                   }
               }

               $options = [
               'clientId'      => $openid['client_id'],
               'clientSecret'  => $openid['client_secret'],
               'nonce'         => md5(uniqid(rand(),true)),
               'redirectUri'   => $openid['redirect_uri'],
               'scopes'        => $openid['scopes'],
               'auth_uri'     => $api['auth_uri'],
               'token_uri'     => $api['token_uri'],
               'info_uri' => $api['info_uri'],
               'response_type' => isset($openid['response_type']) ? $openid['response_type'] : 'code',
               ];

               if(isset($openid['prompt'])){
                   $options['prompt'] = $openid['prompt'];
               }

               if(isset($openid['authif'])){
                   $options['authif'] = $openid['authif'];
               }

               if(isset($openid['idauth'])){
                   if($openid['idauth'] == 1){
                       $options['idauth'] = $openid['idauth'];
                   }else{
                       throw new RPException("Unsupported value: idauth[".$openid['idauth']."]", "E0201","");
                   }
               }

               if(isset($openid['authsp'])){
                   if($openid['authsp'] == 1){
                       $options['authsp'] = $openid['authsp'];
                   }else{
                       throw new RPException("Unsupported value: authsp[".$openid['authsp']."]", "E0201","");
                   }
               }

               if(isset($openid['authiden'])){
                   if($openid['authiden'] == 1){
                       $options['authiden'] = $openid['authiden'];
                   }else{
                       throw new RPException("Unsupported value: authiden[".$openid['authiden']."]", "E0201","");
                   }
               }

               parent::__construct($options);

               if($proxy['proxy']){
                   if(isset($proxy['protocol']) && !is_null($proxy['protocol'])){
                       if(isset($proxy['userid']) && !is_null($proxy['userid'])){
                           $proxy_url = $proxy['protocol'] . '://' . $proxy['userid'] . ':' . $proxy['password'] . '@' . $proxy['host'] . ':' . $proxy['port'] . '/';
                       }else{
                           $proxy_url = $proxy['protocol'] . '://' . $proxy['host'] . ':' . $proxy['port'] . '/';
                       }
                       $this->httpClient->setDefaultOption('proxy', $proxy_url);
                   }
               }
               if(isset($api['log_com'])){
                   if(file_exists($api['log_com'])){
                       if(is_writable($api['log_com'])){
                           $this->debug_path = $api['log_com'];
                       } else {
                           $this->debug_path = '/tmp/debug.log';
                       }
                   } else {
                       $dir = substr($api['log_com'], 0, strrpos($api['log_com'], "/"));
                       if(is_writable($dir)){
                           $this->debug_path = $api['log_com'];
                       } else {
                           $this->debug_path = '/tmp/debug.log';
                       }
                   }
                   $this->debug = true;
                   $this->getHttpClient()->setDefaultOption('debug',true);
               }
           }
        } catch (Exception $e){
            throw new RPException("The unexpected error was detected", "E0900");
        }
    }

    public function getAuthorizationUrl($options = [])
    {
        try{
            $this->state = isset($options['state']) ? $options['state'] : md5(uniqid(rand(), true));
            if(isset($options['scopes'])){
                $this->scopes = $options['scopes'];
            }

            // SG取得値設定
            $params = [
            'client_id' => isset($options['client_id']) ? $options['client_id'] : $this->clientId,
            'redirect_uri' => isset($options['redirect_uri']) ? $options['redirect_uri'] : $this->redirectUri,
            'state' => isset($options['state']) ? $options['state'] : $this->state,
            'nonce' => isset($options['nonce']) ? $options['nonce'] : $this->nonce,
            'scope' => is_array($this->scopes) ? implode($this->scopeSeparator, $this->scopes) : $this->scopes,
            'response_type' => isset($options['response_type']) ? $options['response_type'] : $this->response_type,
            ];
            if(isset($options['redirect_uri'])){
                $_SESSION ['redirectUri'] = $options['redirect_uri'];
            }

            // SG取得値設定
            if(!($this->prompt === false) || isset($options['prompt'])){
                $params['prompt'] = isset($options['prompt']) ? $options['prompt'] : $this->prompt;
            }
            if(!($this->authif === false) || isset($options['authif'])){
                $params['authif'] = isset($options['authif']) ? $options['authif'] : $this->authif;
            }
            if(!($this->idauth === false) || isset($options['idauth'])){
                if(isset($options['idauth']) && !($options['idauth'] == 1)){
                       throw new RPException("Unsupported value: idauth[".$options['idauth']."]", "E0201","");
                }
                $params['idauth'] = isset($options['idauth']) ? $options['idauth'] : $this->idauth;
            }
            if(!($this->authsp === false) || isset($options['authsp'])){
                if(isset($options['authsp']) && !($options['authsp'] == 1)){
                       throw new RPException("Unsupported value: authsp[".$options['authsp']."]", "E0201","");
                }
                $params['authsp'] = isset($options['authsp']) ? $options['authsp'] : $this->authsp;
            }
            if(!($this->authiden === false) || isset($options['authiden'])){
                if(isset($options['authiden']) && !($options['authiden'] == 1)){
                       throw new RPException("Unsupported value: authiden[".$options['authiden']."]", "E0201","");
                }
                $params['authiden'] = isset($options['authiden']) ? $options['authiden'] : $this->authiden;
            }
            if($this->debug){
                error_log("\n" . date('r') . " " . var_export($params,true) . "\n",3,$this->debug_path);
            }
            return $this->urlAuthorize().'?'.$this->httpBuildQuery($params, '', '&');
        } catch (Exception $e){
            throw new RPException("The unexpected error was detected", "E0900");
        }
    }

    public function checkResponse($target = [])
    {
        $session_state;
        if($target['session'] != null){
            $session_state = explode(";", $target['session']);
        }else{
            throw new RPException("The authentication response is invalid: Invalid session.", 'E0201', '');
        }
        if(!empty($target['error']) || empty($target['state']) || ($target['state'] !== $session_state[0])){
            $error;
            $code;
            if(!empty($target['error'])){
                $error = $target['error'];
                switch($error){
                    case 'invalid_request':
                        $code = 'E0300';
                        break;
                    case 'access_denied':
                        $code = 'E0301';
                        break;
                    case 'invalid_auth':
                        $code = 'E0302';
                        break;
                    case 'timestamp_refused':
                        $code = 'E0303';
                        break;
                    case 'unsupported_response_type':
                        $code = 'E0304';
                        break;
                    case 'invalid_scope':
                        $code = 'E0305';
                        break;
                    case 'server_error':
                        $code = 'E0306';
                        break;
                    case 'request_not_supported':
                        $code = 'E0307';
                        break;
                    case 'request_uri_not_supported':
                        $code = 'E0308';
                        break;
                    case 'registration_not_supported':
                        $code = 'E0309';
                        break;
                    case 'invalid_client':
                        $code = 'E0310';
                        break;
                    case 'unauthorized_client':
                        $code = 'E0312';
                        break;
                    default:
                        $error = 'The unexpected error was detected';
                        $code = 'E0900';
                        break;
                }
            }else {
                $error = 'The authentication response is invalid';
                $code = 'E0201';
            }
            throw new RPException($error, $code, '');
        }
        return true;
    }

    public function getAccessToken($grant = 'authorization_code', $params = [])
    {
        try{
            parent::setAuthorizationHeader('Basic');
            if($this->debug){
                error_log("\n" . date('r') . " " . var_export($params,true) ."\n",3,$this->debug_path);
            }

            $response = parent::getAccessToken($grant,$params);

            if($this->debug){
                error_log("\n" . date('r') . " " . var_export($response,true) ."\n",3,$this->debug_path);
            }

            return $response;
        } catch (InvalidArgumentException $e){
            throw new RPException("The unexpected error was detected: ".$e->getMessage(), "E0900");
        } catch (RPException $e){
            throw $e;
        } catch (Exception $e){
            throw new RPException("The unexpected error was detected", "E0900");
        }
    }

    public function getUserDetails(\League\OAuth2\Client\Token\AccessToken $token)
    {
         try{
            parent::setAuthorizationHeader('Bearer');

            if($this->debug){
                error_log("\n" . date('r') . " " . var_export($token,true) ."\n",3,$this->debug_path);
            }

            $response = parent::getUserDetails($token);

            if($this->debug){
                error_log("\n" . date('r') . " " . var_export($response,true) ."\n",3,$this->debug_path);
            }

            return $response;
        } catch (RPException $e){
            throw $e;
        } catch (CurlException $e){
            throw new RPException($e->getMessage(), "E0900");
        } catch (Exception $e){
            throw new RPException("The unexpected error was detected", "E0900");
        }
    }

    public function refleshToken($grant = 'refresh_token', $params = [])
    {
        try{
            parent::setAuthorizationHeader('Basic');

            if($this->debug){
                error_log("\n" . date('r') . " " . var_export($params,true) ."\n",3,$this->debug_path);
            }

            $response = parent::refleshToken($grant,$params);

            if($this->debug){
                error_log("\n" . date('r') . " " . var_export($response,true) ."\n",3,$this->debug_path);
            }

            return $response;
        } catch (RPException $e){
            throw $e;
        } catch (Exception $e){
            throw new RPException("The unexpected error was detected", "E0900");
        }
    }

    public function checkTokenResponse($response ,$session)
    {
        if($response->aud !== $this->clientId){
            throw new RPException("The aud is invalid[aud=". $response->aud."]",'E0202','');
        }

        $now = new \DateTime();
        $now->setTimeZone( new \DateTimeZone('UTC'));
        $exp = new \DateTime();
        $exp->setTimestamp($response->exp);
        $exp->setTimezone(new \DateTimeZone('UTC'));
        if($exp < $now){
            throw new RPException("The exp is invalid[exp=".$response->exp."]",'E0202','');
        }

        $session_nonce=null;
        if(!empty($session)){
            $session_nonce = explode(";", $session);
        }

        if(!is_null($response->nonce) && $response->nonce !== $session_nonce[1]){
            throw new RPException("The nonce is invalid[nonce=".$response->nonce."]",'E0202','');
        }
    }

    public function urlAuthorize()
    {
        return $this->auth_uri;
    }

    public function urlAccessToken()
    {
        return $this->token_uri;
    }

    public function urlUserDetails(\League\OAuth2\Client\Token\AccessToken $token)
    {
          return $this->info_uri;
    }

    public function userDetails($response, \League\OAuth2\Client\Token\AccessToken $token)
    {
        // return (array)json_decode($response[0]);
        // return isset($response[0]) ? (array)json_decode($response[0]) : null;
        return is_array($response) ? json_encode($response) : null;
    }

    public function checkResponseAndGetToken($target = [])
    {
        try {
            if($this->checkResponse($target)) {
                // Try to get an access token (using the authorization code grant)
                $token = $this->getAccessToken('authorization_code', [
                'code' => $_GET['code'],
                ]);

                $this->checkTokenResponse($token, $target['session']);

                return $token;
            }
        } catch (RPException $e) {
            throw $e;
        } catch (CurlException $e){
            throw new RPException($e->getMessage(), "E0900");
        } catch (Exception $e) {
            throw new RPException("The unexpected error was detected", "E0900");
        }
    }
}
