<?php

namespace App\Tool;

/**
 * JSON Web Token - Simple:
 *
 * @category Authentication
 * @author   Gigoland <Gigoland.com>
 * @license  MIT License
 * @link     https://github.com/Gigoland/Simple-JWT
 */
class SimpleJwt
{
    // One day timestemp
    const ONE_DAY = 86400;
    // Patern
    const PATERN_JWT = '/^[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+$/';

    /**
     * Get generate JWT
     */
    public static function getGeneratedToken(
        array $header,
        array $payload,
        string $secret,
        int $exp = self::ONE_DAY
    ): string {
        // Date validity
        if ($exp > 0) {
            $now = new \DateTime();
            $payload['iat'] = $now->getTimestamp();
            $payload['exp'] = $now->getTimestamp() + $exp;
        }

        // Base64
        $base64Header = base64_encode(json_encode($header));
        $base64Payload = base64_encode(json_encode($payload));

        // Replace '+', '/', '='
        $base64Header = str_replace(['+', '/', '='], ['-', '_', ''], $base64Header);
        $base64Payload = str_replace(['+', '/', '='], ['-', '_', ''], $base64Payload);

        // Signature
        $signature = hash_hmac(
            'sha256',
            $base64Header . '.' . $base64Payload,
            base64_encode($secret),
            true
        );

        // Replace '+', '/', '='
        $signature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

        // Generated token
        return sprintf(
            '%s.%s.%s',
            $base64Header,
            $base64Payload,
            $signature
        );
    }

    /**
     * Check complet
     */
    public static function isNotValid(string $token, string $secret): bool
    {
        return !self::isValid($token, $secret);
    }

    /**
     * Check complet
     */
    public static function isValid(string $token, string $secret): bool
    {
        return self::isMatch($token)
            && !self::isExpired($token)
            && self::isAuthentic($token, $secret)
        ;
    }

    /**
     * Check format validity
     */
    public static function isMatch(string $token): bool
    {
        return 1 === preg_match(
            self::PATERN_JWT,
            $token
        );
    }

    /**
     * Check expiration
     */
    public static function isExpired(string $token): bool
    {
        $payload = self::getPayload($token);

        if (!isset($payload['exp'])) {
            return false;
        }

        $now = new \DateTime();

        return $payload['exp'] < $now->getTimestamp();
    }

    /**
     * Check authentic validuty
     */
    public static function isAuthentic(string $token, string $secret): bool
    {
        // Get header & payload
        $header = self::getHeader($token);
        $payload = self::getPayload($token);

        // Generate new authentic token
        $verifToken = self::getGeneratedToken(
            $header,
            $payload,
            $secret,
            0 // 0 important
        );

        return $token === $verifToken;
    }

    /**
     * Get header data
     */
    public static function getHeader(string $token): ?array
    {
        return self::getData($token, 0);
    }

    /**
     * Get payload data
     */
    public static function getPayload(string $token): ?array
    {
        return self::getData($token, 1);
    }

    /**
     * Get data from token
     */
    private static function getData(string $token, int $index): ?array
    {
        $array = explode('.', $token);

        if (!isset($array[$index])) {
            return null;
        }

        return json_decode(base64_decode($array[$index]), true);
    }
}
