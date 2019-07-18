<?php

namespace SuperDuperAuthentication;

use SuperDuperAuthentication\Exceptions\AuthenticationException;
use SuperDuperAuthentication\Exceptions\MaxAttemptsException;

/**
 * Class SuperDuperSecureAuthentication
 *
 * We do NOT advise using this as an authentication library as this was written with a known vulnerability and is
 * being used as part of a CTF.
 */
class SuperDuperSecureAuthentication
{
    const DATE_FORMAT = 'Y-m-d H:i:s';

    const MAX_ATTEMPTS = 5;

    const MAX_ATTEMPTS_DURATION_IN_SECONDS = 30;

    /**
     * @var array|false|string
     */
    private $secret;

    /**
     * SuperDuperSecureLogin constructor.
     */
    public function __construct()
    {
        $this->secret = getenv('SECRET');
    }

    /**
     * @param $password
     * @param $passwordHash
     * @param $nonce
     * @return boolean
     * @throws AuthenticationException
     * @throws MaxAttemptsException
     */
    public function authenticate($password, $passwordHash, $nonce)
    {
        if (empty($password) || empty($passwordHash)) {
            throw new AuthenticationException();
        }

        $this->rateLimitCheck();

        $nonceVerification = hash_hmac('sha256', $nonce, $this->secret);

        $passwordVerification = hash_hmac('sha256', $password, $nonceVerification);

        return ($passwordVerification === $passwordHash);
    }

    /**
     * @return bool
     * @throws MaxAttemptsException
     */
    private function rateLimitCheck()
    {
        $currentTime = new \DateTime();
        $filePath = '/tmp/' . sha1($_SERVER['REMOTE_ADDR']);

        $jsonEncoded = file_get_contents($filePath);

        $loginAttempts = [];

        if ($jsonEncoded) {
            $loginAttempts = json_decode($jsonEncoded);
        }

        $trueLoginAttempts = [
            (new \DateTime())->format(self::DATE_FORMAT)
        ];

        foreach ($loginAttempts as $attempt) {
            $pastAttemptTime = \DateTime::createFromFormat(self::DATE_FORMAT, $attempt);
            if ($currentTime->diff($pastAttemptTime)->s < self::MAX_ATTEMPTS_DURATION_IN_SECONDS) {
                $trueLoginAttempts [] = $pastAttemptTime->format(self::DATE_FORMAT);
            }
        }

        if (sizeof($trueLoginAttempts) > self::MAX_ATTEMPTS) {
            throw new MaxAttemptsException();
        }

        file_put_contents($filePath, json_encode($trueLoginAttempts, JSON_PRETTY_PRINT));

        return true;
    }
}
