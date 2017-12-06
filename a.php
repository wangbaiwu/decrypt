<?php

$e='C517E827509F6A4D640E1A0BB87794067059E5E56659FBBE6E6591DAD6C867DCEF9325AD88BB67AFA596E60818373C3E775EBC41CF70EB387266A0ED85820D4808693B280903908E37AC3219431AAE7D3919A7985313652C3021DEFD7DC434DFBF996F08AFDE8DAA';
$k='TATAPASS';

class App{

public function setKey($key)
{
    $this->key=$key;
}

public function setIv($iv)
{
    $this->iv=$iv;
}

function encrypt($str) {  
        //加密，返回大写十六进制字符串  
        $size = mcrypt_get_block_size (MCRYPT_DES, MCRYPT_MODE_CBC);  
        $str = $this->pkcs5Pad ( $str, $size );  
        return strtoupper( bin2hex( mcrypt_cbc(MCRYPT_DES, $this->key, $str, MCRYPT_ENCRYPT, $this->iv ) ) );  
    }  
  
    function decrypt($str) {  
        //解密    
        $strBin = $this->hex2bin( strtolower( $str ) );    
        $str = mcrypt_cbc( MCRYPT_DES, $this->key, $strBin, MCRYPT_DECRYPT, $this->iv );  
        $str = $this->pkcs5Unpad( $str );  
       
       
       
        return $str;  
    }  
function hex2bin($hexData) {    
        $binData = "";    
        for($i = 0; $i  < strlen ( $hexData ); $i += 2) {    
            $binData .= chr ( hexdec ( substr ( $hexData, $i, 2 ) ) );    
        }  
        return $binData;  
    }  
  
    function pkcs5Pad($text, $blocksize) {  
        $pad = $blocksize - (strlen ( $text ) % $blocksize);  
        return $text . str_repeat ( chr ( $pad ), $pad );  
    }  
  
    function pkcs5Unpad($text) {  
        $pad = ord ( $text {strlen ( $text ) - 1} );    
        if ($pad > strlen ( $text )) return false;  
  
        if (strspn ( $text, chr ( $pad ), strlen ( $text ) - $pad ) != $pad)   return false;    
  
        return substr ( $text, 0, - 1 * $pad );  
    }  


}


$a= new App();
$a->setKey($k);
$a->setIv('12345678');
var_dump($a->decrypt($e));




