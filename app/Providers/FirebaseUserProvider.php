<?php

namespace App\Providers;

use Illuminate\Contracts\Auth\UserProvider;
use App\Models\FirebaseUser;
use Kreait\Firebase\Factory;
use Kreait\Firebase\ServiceAccount;
use Kreait\Firebase\Auth;
use Illuminate\Contracts\Auth\Authenticatable;
use App\Services\Auth\FirebaseAuthService;
use Kreait\Firebase\Exception\Auth\UserNotFound;

class FirebaseUserProvider implements UserProvider
{
    private $model;

    private $firebase;

    /**
     * Create a new mongo user provider.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     * @return void
     */
    public function __construct(FirebaseUser $userModel, FirebaseAuthService $firebase)
    {
        $this->model = $userModel;

        $this->firebase = $firebase;
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param  mixed  $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveById($identifier)
    {
        return $this->firebase->getFirebaseUser($this->getAuth()->getUser($identifier));
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param  mixed  $identifier
     * @param  string  $token
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByToken($identifier, $token)
    {
        //   
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  string  $token
     * @return void
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        //
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array  $credentials
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        if (empty($credentials)) {
            return;
        }

        $user = null;

        try {
            //Due to limitations of the SDK, we'll only be able to retrieve user by
            //their email addresses and phone numbers.
            if (array_key_exists('email', $credentials)) {
                $user = $this->firebase->getFirebaseUser($this->getAuth()->getUserByEmail($credentials['email']));
            }
    
            /*
            if (array_key_exists('phoneNumber', $credentials)) {
                return $this->firebase->getFirebaseUser($this->getAuth()->getUserByPhoneNumber($credentials['phoneNumber']));
            }
            */
        } catch (UserNotFound $ex) {
            return $user;
        }

        return $user;
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array  $credentials
     * @return bool
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        $isValidCredentials = false;

        try {
            $this->getAuth()->verifyPassword($credentials['email'], $credentials['password']);

            $isValidCredentials = true;
        } catch (\Kreait\Firebase\Exception\Auth\InvalidPassword $e) {
            return $isValidCredentials;
        }

        return $isValidCredentials;
    }

    /**
     * Returns the auth component of Firebase SDK
     *
     * @return Kreait\Firebase\Auth
     */
    private function getAuth()
    {
        return $this->firebase->getAuth();
    }
}