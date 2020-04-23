<?php

namespace Ahilan\Apple;

use Ahilan\Apple\commands\AppleKeyGenerate;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory;

class AppleServiceProvider extends ServiceProvider
{
    protected $commands = [
        AppleKeyGenerate::class,
    ];

    public function boot()
    {
        $this->bootAppleProvide();
    }

    public function register()
    {

    }

    private function bootAppleProvide()
    {
        $socialite = $this->app->make(Factory::class);
        $socialite->extend(
            'apple',
            function ($app) use ($socialite) {
                $config = $app['config']['services.apple'];
                return $socialite->buildProvider(Provider::class, $config);
            }
        );

        $this->commands($this->commands);
    }
}
