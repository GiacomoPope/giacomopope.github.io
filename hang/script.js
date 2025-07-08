class IntervalTrainer {
    constructor(workout_data) {
        this.workout_data = workout_data;
        this.initializeDOM();
        this.runWorkout();
    }

    initializeDOM() {
        this.startScreen = document.getElementById('startScreen');
        this.timerScreen = document.getElementById('timerScreen');
        this.timerDisplay = document.getElementById('timer');
        this.phaseText = document.getElementById('phaseText');
        this.intervalCounter = document.getElementById('intervalCounter');
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
        } catch (err) {
          // The Wake Lock request has failed - usually system related, such as battery.
          console.log(`${err.name}, ${err.message}`);
        }

        try {
            // Initial gold countdown
            const firstWorkoutName = this.workout_data[0].name;
            await this.startTimer(5000, 'gold', `Get Ready: ${firstWorkoutName}`);

            let totalIntervalCount = 0;
            let totalWorkoutIntervals = this.workout_data.reduce((sum, plan) => sum + plan.repeat, 0);

            for (let planIndex = 0; planIndex < this.workout_data.length; planIndex++) {
                const currentWorkout = this.workout_data[planIndex];
                
                // Repeat the workout
                for (let i = 0; i < currentWorkout.repeat; i++) {

                    // Determine the next workout name, which is 
                    let nextWorkoutName;

                    // If we're on the final rep of the set, we need the next name.
                    if (i == currentWorkout.repeat - 1) {
                        const nextWorkout = this.workout_data[planIndex + 1];
                        nextWorkoutName = nextWorkout 
                        ? nextWorkout.name 
                        : 'Finish';
                    } else {
                        nextWorkoutName = currentWorkout.name;
                    }

                    let restPrompt;
                    if (currentWorkout.name == "Hang") {
                        restPrompt = "Rest";
                    } else {
                        restPrompt = `Up Next: ${nextWorkoutName}`;
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
                        restPrompt
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
    const noHangBtn = document.getElementById('noHangBtn');
    const sixTenBtn = document.getElementById('sixTenBtn');
    const onOffBtn = document.getElementById('sixSixSixBtn');

    // Load the workout data from json.
    var workout_data = null;
    try {
        const response = await fetch('config.json');
        workout_data = await response.json();

        // Load the data, this should maybe be done in a loop with button ID in the JSON?
        noHangBtn.onclick = () => {
            new IntervalTrainer(workout_data.no_hang);
        };

        sixTenBtn.onclick = () => {
            new IntervalTrainer(workout_data.six_ten);
        };

        onOffBtn.onclick = () => {
            new IntervalTrainer(workout_data.six_six_six);
        };

    }
    catch (error) {
        console.error("Failed to load configuration:", error);
    }
});
