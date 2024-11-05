<?php

namespace App\Utils;

use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;

class User {
    public static function getUser() {
        try {
            if (!$user = JWTAuth::parseToken()->authenticate()) {
                return null;
            }
        } catch (JWTException $e) {
            return null;
        }

        return $user;
    }

    public static function getId() {
        try {
            if (!$user = JWTAuth::parseToken()->authenticate()) {
                return null;
            }
        } catch (JWTException $e) {
            return null;
        }

        return $user['id'];
    }
}
