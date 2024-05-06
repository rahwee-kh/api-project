<?php

namespace App\Services\jwt;

use App\Models\User;
use App\Enums\Constants;
use App\Services\SVUser;
use Carbon\CarbonInterface;
use Illuminate\Http\Response;
use App\Exceptions\POSException;
use App\Services\Auth\JwtBuilder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

class AppManagerLogin
{
    public function authenticateAndGetToken($params)
    {
        $email      = $params['credential']['email'];
        $password   = $params['credential']['password'];
        $login_type = $params['login_type'];
        $extra      = [];

        $user = (new SVUser)->getByEmail($email);
        if(!isset($user) || !Hash::check($password, $user->password))
        {
            throw new POSException('Incorrect email or password', "WRONG_PASSWORD", [], Response::HTTP_BAD_REQUEST);
        }
        return $this->generateToken($login_type, $user, $extra);
    }


    public function generateToken($login_type, $user, $extra)
    {
        $extra['timezone'] = config('app.timezone');
        $expired_at        = now()->addMinutes(1440);
        $user              = User::where("id", $user->id)->first();
        $token             = $this->createJwtToken($login_type, $user, $extra, 1440);
        
        return [
            "expire_at" => $expired_at,
            "token"     => $token,
        ];
    }

    /**
     * Base function for generate standard JWT Token
     * more data can be added in $extraData
     * */
    public function createJwtToken($loginType, User $user = null, array $extraData = [], $ttl = null): string
    {
        $exp = $this->getExpirationAt($ttl);
        $exp = $ttl < 0 ? null : $exp;
        return $this->getSetupJwtBuilder($user, $loginType, $exp, Constants::TOKEN_TYPE_BEARER, $extraData);
    }

    /**
     * Base function for generate standard Refresh Token
     * more data can be added in $extraData
     * When using refresh token please include with IJWTContractinType, $exp, Constants::TOKEN_TYPE_REFRESH, $extraData);\
     * */
    public function createJwtRefreshToken(string $loginType, User $user = null, array $extraData = [], CarbonInterface $ttl = null): string
    {
        $exp = $ttl ?? now()->addMinutes(config('jwt.refresh_ttl'));
        return $this->getSetupJwtBuilder($user, $loginType, $exp, Constants::TOKEN_TYPE_REFRESH, $extraData);
    }

    public function getExpirationAt($ttl = null)
    {
        return $ttl ? now()->addMinutes(intval($ttl)) : now()->addMinutes(config('jwt.ttl'));
    }

    /**
     * Get setup builder types
     * */
    public function getSetupJwtBuilder(User $user = null, string $loginType, $exp, string $token_type, array $extraData = [])
    {
        $builder = new JwtBuilder();
        $builder->setUniqid(uniqid(gmdate("YmdHis")))
            ->setTokenType($token_type)
            ->setAuthType($loginType)
            ->withClaims($extraData)
            ->issuedAt(now())
            ->expiresAt($exp)
            ->relatedTo($user->id)
            ->getToken();

        if ($token_type == Constants::TOKEN_TYPE_BEARER) {
            $builder->issuedBy(config('app.url'));
            $builder->audience(config('app.name'));
            $builder->issuedAt(now());
        }

        if ($exp) {
            $builder->expiresAt($exp);
        }

        // if ($user) {
        //     $builder->setDbName($user->account->db_name);
        //     $builder->relatedTo(@$user->global_id);
        // }

        return $builder->getToken();
    }
}