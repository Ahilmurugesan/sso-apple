<?php

namespace Ahilan\Apple\console;

use App\Console\Kernel as ConsoleKernel;
use Illuminate\Console\Scheduling\Schedule;

class Kernel extends ConsoleKernel
{
    /**
     * Command schedule for package.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return void
     */
    protected function schedule(Schedule $schedule)
    {
        parent::schedule($schedule);

        $schedule->command('socialite:apple --refresh')->everyMinute()->appendOutputTo(base_path('schedule.log'));
    }
}
