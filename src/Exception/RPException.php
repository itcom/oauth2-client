<?php

namespace League\OAuth2\Client\Exception;

class RPException extends \Exception
{
    protected $status_code;
    protected $error_message;
    protected $error_code;

    // 例外を再定義し、メッセージをオプションではなくする
    public function __construct($message, $code, $status = '') {
        $this->error_message = $message;
        $this->error_code = $code;
        $this->status_code = $status;

        \Log::error(print_r(debug_backtrace(),TRUE));
        /*
        if(($file = getenv('X-RP-BACKTRACE'))){
            $fp = fopen($file, 'a+');
            fwrite($fp, "\n[".date(DATE_RFC2822)."]\n");
            fwrite($fp, print_r(debug_backtrace(),TRUE));
            fclose($fp);
        }
         */
    }

    // オブジェクトの文字列表現を独自に定義する
    public function __toString() {
        return __CLASS__ . ": [{$this->error_code}]: {$this->error_message}\n";
    }

    public function getErrorCode(){
        return $this->error_code;
    }

    public function getErrorMessage(){
        return $this->error_message;
    }

    public function getStatusCode(){
        return $this->status_code;
    }
}
