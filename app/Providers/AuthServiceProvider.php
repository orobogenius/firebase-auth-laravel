<?php

namespace App\Providers;

use App\Services\Auth\FirebaseGuard;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Auth;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * The policy mappings for the application.
     *
     * @var array
     */
    protected $policies = [
        'App\Model' => 'App\Policies\ModelPolicy',
    ];

    /**
     * Register any authentication / authorization services.
     *
     * @return void
     */
    public function boot()
    {
        $this->registerPolicies();

        Auth::extend('firebase', function ($app, $name, array $config) {
            return new FirebaseGuard(Auth::createUserProvider($config['provider']), $app->make('App\Services\Auth\FirebaseAuthService'));
        });

        Auth::provider('firebase', function ($app, array $config) {
            return new FirebaseUserProvider($app->make('App\Models\FirebaseUser'), $app->make('App\Services\Auth\FirebaseAuthService'));
        });
    }
}
