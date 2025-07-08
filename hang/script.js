class IntervalTrainer {
    constructor(config) {
        this.config = config;
        this.initializeDOM();
        this.setupEventListeners();
    }

    initializeDOM() {
        this.startBtn = document.getElementById('startBtn');
        this.startScreen = document.getElementById('startScreen');
        this.timerScreen = document.getElementById('timerScreen');
        this.timerDisplay = document.getElementById('timer');
        this.phaseText = document.getElementById('phaseText');
        this.intervalCounter = document.getElementById('intervalCounter');
    }

    setupEventListeners() {
        this.startBtn.addEventListener('click', () => this.runWorkout());
    }

    formatTime(milliseconds) {
        const totalSeconds = Math.floor(milliseconds / 1000);
        const remainingMilliseconds = milliseconds % 1000;
        return `${totalSeconds.toString().padStart(2, '0')}:${remainingMilliseconds.toString().padStart(3, '0')}`;
    }

    async startTimer(duration, color, text) {
        return new Promise((resolve) => {
            this.timerDisplay.className = color;
            this.phaseText.textContent = text;
            
            const startTime = Date.now();
            const timerInterval = setInterval(() => {
                const elapsedTime = Date.now() - startTime;
                const remainingTime = Math.max(duration - elapsedTime, 0);
                
                this.timerDisplay.textContent = this.formatTime(remainingTime);
                
                if (remainingTime <= 0) {
                    clearInterval(timerInterval);
                    resolve();
                }
            }, 10);
        });
    }

    async runWorkout() {
        this.startScreen.classList.add('hidden');
        this.timerScreen.classList.remove('hidden');

        // Lock the screen so that the screen always displays the timer.
        let wakeLock = null;
        // create an async function to request a wake lock
        try {
          wakeLock = await navigator.wakeLock.request("screen");
          console.log("Wake Lock is active!");
        } catch (err) {
          // The Wake Lock request has failed - usually system related, such as battery.
          console.log(`${err.name}, ${err.message}`);
        }

        try {
            // Initial gold countdown
            const firstWorkoutName = this.config.workout_plan[0].name;
            await this.startTimer(5000, 'gold', `Get Ready: ${firstWorkoutName}`);

            let totalIntervalCount = 0;
            let totalWorkoutIntervals = this.config.workout_plan.reduce((sum, plan) => sum + plan.repeat, 0);

            for (let planIndex = 0; planIndex < this.config.workout_plan.length; planIndex++) {
                const currentWorkout = this.config.workout_plan[planIndex];
                
                // Repeat the workout
                for (let i = 0; i < currentWorkout.repeat; i++) {

                    // Determine the next workout name, which is 
                    let nextWorkoutName;

                    // If we're on the final rep of the set, we need the next name.
                    if (i == currentWorkout.repeat - 1) {
                        const nextWorkout = this.config.workout_plan[planIndex + 1];
                        nextWorkoutName = nextWorkout 
                        ? nextWorkout.name 
                        : 'Finish';
                    } else {
                        nextWorkoutName = currentWorkout.name;
                    }


                    // Hang interval
                    this.intervalCounter.textContent = `${totalIntervalCount + 1}/${totalWorkoutIntervals}`;
                    await this.startTimer(
                        currentWorkout.hang_duration, 
                        'blue', 
                        `${currentWorkout.name}`
                    );

                    // Rest interval
                    this.intervalCounter.textContent = `${totalIntervalCount + 1}/${totalWorkoutIntervals}`;
                    await this.startTimer(
                        currentWorkout.rest_duration, 
                        'green', 
                        `Up Next: ${nextWorkoutName}`
                    );

                    totalIntervalCount++;
                }
            }
        } catch (error) {
            console.error("Workout interrupted:", error);
        } finally {
            // Reset display after workout
            this.timerDisplay.textContent = '05:000';
            this.timerDisplay.className = 'gold';
            this.phaseText.textContent = '';
            this.intervalCounter.textContent = '';
            
            // Hide timer screen and show start screen
            this.timerScreen.classList.add('hidden');
            this.startScreen.classList.remove('hidden');

            // Release the wakelock
            wakeLock.release().then(() => {
                  wakeLock = null;
            });
        }
    }
}

// Load configuration and initialize trainer
document.addEventListener('DOMContentLoaded', async () => {
    try {
        const response = await fetch('config.json');
        const config = await response.json();
        new IntervalTrainer(config);
    } catch (error) {
        console.error("Failed to load configuration:", error);
    }
});
