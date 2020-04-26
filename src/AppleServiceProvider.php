<?php

namespace Ahilan\Apple;

use Ahilan\Apple\console\commands\AppleKeyGenerate;
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
        $this->registerAppleScheduler();
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

    private function registerAppleScheduler()
    {
        $this->app->singleton('ahilan.apple.console.kernel', function($app) {
            $dispatcher = $app->make(\Illuminate\Contracts\Events\Dispatcher::class);
            return new \Ahilan\Apple\console\Kernel($app, $dispatcher);
        });

        $this->app->make('ahilan.apple.console.kernel');
    }
}
