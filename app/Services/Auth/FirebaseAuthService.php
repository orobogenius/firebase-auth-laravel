<?php

namespace App\Services\Auth;

use Kreait\Firebase\Factory;
use Kreait\Firebase\ServiceAccount;
use Kreait\Firebase\Auth;
use App\Models\FirebaseUser;

class FirebaseAuthService
{
    /**
     * The firebase SDK instance.
    */
    protected $firebase;

    /**
     * Create a new FirebaseAuthService instance
     * 
     * @return void
    */
    public function __construct()
    {
        $serviceAccount = ServiceAccount::fromJsonFile(storage_path('firebase_credentials.json'));

        $this->firebase = (new Factory)
                    ->withServiceAccount($serviceAccount)
                    ->create();
    }

    /**
     * Returns the auth component of Firebase SDK
     *
     * @return Kreait\Firebase\Auth
     */
    public function getAuth()
    {
        return $this->firebase->getAuth();
    }

    /**
     * Get the firebase user.
     *
     * @param  mixed  $user
     * @return \App\Models\FirebaseUser
     */
    public function getFirebaseUser($user)
    {
        if (! is_null($user)) {
            return new FirebaseUser($user->toArray());
        }
    }

    /**
     * Get Laravel Session component
     * @return \Illuminate\Contracts\Session\Session
    */
    public function getSession()
    {
        return session();
    }
}