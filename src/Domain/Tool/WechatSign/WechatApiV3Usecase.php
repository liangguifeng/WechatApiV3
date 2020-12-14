<?php

namespace WechatApiV3\Domain\Tool\WechatSign;

class WechatApiV3Usecase
{
    /**
     * 微信v3签名方法
     *
     * @param $url              string
     *                          请求地址（全称）'https://api.mch.weixin.qq.com/v3/businesscircle/points/notify'
     * @param $http_method      string  请求方法（大写）POST
     * @param $timestamp        string  时间戳 time()
     * @param $nonce            string  随机字符串   我用订单是时间戳代替了
     * @param $body             string  数组转json要带着空行，方法为json_encode($requestData, JSON_PRETTY_PRINT)
     * @param $mch_private_key  string  商户私钥，apiclient_key.pem
     * @param $merchant_id      string  商户id    1586222052
     * @param $serial_no        string  商户证书id  154C1XXC2FAD3585A9C3E6B5743F35DD69500B62
     *
     * @return string
     */
    protected function sign(
        $url,
        $http_method,
        $timestamp,
        $nonce,
        $body,
        $mch_private_key,
        $merchant_id,
        $serial_no
    )
    {
        $url_parts = parse_url($url);

        $canonical_url = ($url_parts['path'] . (!empty($url_parts['query']) ? "?${url_parts['query']}" : ""));

        $message = $http_method . "\n" .
            $canonical_url . "\n" .
            $timestamp . "\n" .
            $nonce . "\n" .
            $body . "\n";

        openssl_sign($message, $raw_sign, $mch_private_key, 'sha256WithRSAEncryption');

        $sign = base64_encode($raw_sign);

        $schema = 'WECHATPAY2-SHA256-RSA2048 ';

        $token = sprintf('mchid="%s",serial_no="%s",nonce_str="%s",timestamp="%d",signature="%s"',
            $merchant_id, $serial_no, $nonce, $timestamp, $sign);

        return $schema . $token;
    }

    /**
     * 获取私钥内容（文件地址）
     *
     * @param  $filepath
     *
     * @return bool|resource
     */
    public function loadPrivateKey($filepath)
    {
        return \openssl_get_privatekey(\file_get_contents($filepath));
    }
}
