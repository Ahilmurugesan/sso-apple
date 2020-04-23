<?php

namespace Ahilan\Apple\commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Storage;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key;

class AppleKeyGenerate extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'socialite:apple';

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
        self::generateClientSecret();
    }

    /**
     * Function to generate apple client secret
     *
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function generateClientSecret()
    {
        $team_id = $this->ask('Enter Team Id ');
        $key_id = $this->ask('Enter Key Id ');
        $client_id = $this->ask('Enter Client Id ');
        $auth_key = $this->ask('Enter Auth Key ');
        config([
            'services.apple.key_id' => $key_id,
            'services.apple.team_id' => $team_id,
            'services.apple.client_id' => $client_id,
            'services.apple.auth_key' => $auth_key,
        ]);

        $exists = Storage::disk('local')->exists(config('services.apple.auth_key').'.txt');

        if($exists){
            $privateKeyFile = Storage::disk('local')->get(config('services.apple.auth_key').'.txt');

            try{
                $signer = new Sha256();
                $privateKey = new Key($privateKeyFile);
                $token = (new Builder())->issuedBy($team_id)// Configures the issuer (iss claim)
                ->permittedFor("https://appleid.apple.com")// Configures the audience (aud claim)
                ->issuedAt(time())// Configures the time that the token was issue (iat claim)
                ->expiresAt(time() + 86400 * 180)// Configures the expiration time of the token (exp claim)
                ->relatedTo(config('services.apple.client_id')) //Configures the subject
                ->withHeader('kid', $key_id)
                    ->withHeader('type', 'JWT')
                    ->withHeader('alg', 'ES256')
                    ->getToken($signer, $privateKey); // Retrieves the generated token

                $key = $token->__toString();

                self::writeNewAppleSecretKeyWith($key);

            }catch (\Exception $exception){
                $this->error($exception->getMessage());
            }
        }else {

            $this->error(config('services.apple.auth_key').'.txt'.' - '.'File not found in the local driver path');

        }
    }

    /**
     * Write a new environment app secret key with the given key.
     *
     * @param $key
     */
    protected function writeNewAppleSecretKeyWith($key)
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
        $escaped = preg_quote('='.$this->laravel['config']['apple.client_secret'], '/');

        return "/^APPLE_CLIENT_SECRET{$escaped}/m";
    }
}
