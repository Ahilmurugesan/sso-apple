<?php

namespace Ahilan\Apple\commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;

class AppleKeyGenerate extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'socailite:apple';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate the client secret for apple login';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $key = $this->generateClientSecret();
        //validation
        $this->writeNewEnvironmentFileWith($key);
    }

    public function generateClientSecret()
    {
        $team_id = $this->ask('Enter Team Id: ');
        $key_id = $this->ask('Enter Key Id: ');
        $client_id = $this->ask('Enter Client Id: ');
        $auth_key = $this->ask('Enter Auth Key: ');
        config('apple.key_id',$key_id);
        config('apple.team_id',$team_id);
        config('apple.client_id',$client_id);
        config('apple.auth_key',$auth_key); //ensure auth file is there
        $privateKeyFile = Storage::disk('local')->get(config('services.apple.auth_key'));

        //$team_id = config('services.sign_in_with_apple.team_id'); //value got from apple
        //$key_id = config('services.sign_in_with_apple.key_id'); //value got from apple

        $signer = new \Lcobucci\JWT\Signer\Ecdsa\Sha256();
        $privateKey = new Key($privateKeyFile);
        $token = (new Builder())->issuedBy($team_id)// Configures the issuer (iss claim)
        ->permittedFor("https://appleid.apple.com")// Configures the audience (aud claim)
        ->issuedAt(time())// Configures the time that the token was issue (iat claim)
        ->expiresAt(time() + 86400 * 180)// Configures the expiration time of the token (exp claim)
        ->relatedTo(config('services.sign_in_with_apple.client_id')) //Configures the subject
        ->withHeader('kid', $key_id)
            ->withHeader('type', 'JWT')
            ->withHeader('alg', 'ES256')
            ->getToken($signer, $privateKey); // Retrieves the generated token
        //$a = $token->getHeaders(); // Retrieves the token headers
        //$b = $token->getClaims(); // Retrieves the token claims


        return $token->__toString();
    }

    protected function writeNewEnvironmentFileWith($key)
    {
        file_put_contents($this->laravel->environmentFilePath(), preg_replace(
            $this->keyReplacementPattern(),
            'APPLE_CLIENT_SECRET='.$key,
            file_get_contents($this->laravel->environmentFilePath())
        ));
    }

    /**
     * Get a regex pattern that will match env APPLE_CLIENT_SECRET with any random key.
     *
     * @return string
     */
    protected function keyReplacementPattern()
    {
        $escaped = preg_quote('='.$this->laravel['services']['apple.client_secret'], '/');

        return "/^APPLE_CLIENT_SECRET{$escaped}/m";
    }
}
