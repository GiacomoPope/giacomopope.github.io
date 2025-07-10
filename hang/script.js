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
        this.timerCircle = document.getElementById('circle');
        this.phaseText = document.getElementById('phaseText');
        this.intervalCounter = document.getElementById('intervalCounter');
    }

    formatTime(seconds) {
        return `${(seconds + 1).toString().padStart(2, '0')}`;

    }

    createRing() {
        const vw = Math.max(document.documentElement.clientWidth || 0, window.innerWidth || 0)

        const ringContainer = document.getElementById('ringContainer');
        const radius = Math.min(Math.floor(vw * 0.45) - 40, 260);
        const totalLines = 100;

        // Create lines
        for (let i = 0; i < totalLines; i++) {
            const line = document.createElement('div');
            line.classList.add('line');
            
            const angle = (i / totalLines) * (2 * Math.PI);
            line.style.transform = `
                translate(-50%, -100%) 
                rotate(${angle * (180 / Math.PI)}deg)
                translate(0, -${radius}px)
            `;
            
            ringContainer.appendChild(line);
        }
    }

    toggleLines() {
        const lines = document.querySelectorAll('.line');

        let currentIndex = 0;
        const animateRing = () => {
            if (currentIndex == 100) {
                clearInterval(this.ringInterval);
                return;
            }
        
            else {
                lines[currentIndex].classList.toggle("gone");
                currentIndex += 1;
            }
        }

        // Clear any existing interval first
        if (this.ringInterval) {
            clearInterval(this.ringInterval);
        }

        this.ringInterval = setInterval(animateRing, 8);
    }

    async startTimer(duration, color, text) {
        return new Promise((resolve) => {
            var get_ready = false;
            var seconds = 0;
            
            this.timerCircle.className = color;
            this.phaseText.textContent = text;
            
            const startTime = Date.now();
            const timerInterval = setInterval(() => {
                const elapsedTime = Date.now() - startTime;
                const remainingTime = Math.max(duration - elapsedTime, 0);
                
                // Update wheel and timer.
                const currentSeconds = Math.floor(remainingTime / 1000);
                if (currentSeconds != seconds) {
                    this.toggleLines();
                    seconds = currentSeconds;
                }
                this.timerDisplay.textContent = this.formatTime(currentSeconds);
                
                // Set rest circle to gold when 3 seconds are left
                if (!get_ready && remainingTime <= 3000 && color == "green") {
                    get_ready = true;
                    this.timerCircle.className = 'gold';
                }
                
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

        // Create a ring of dashes
        this.createRing();

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

            let totalIntervalCount = 0;
            let totalWorkoutIntervals = this.workout_data.reduce((sum, plan) => sum + plan.repeat, 0);
            this.intervalCounter.textContent = `${totalIntervalCount}/${totalWorkoutIntervals}`;

            await this.startTimer(5000, 'gold', `Get Ready: ${firstWorkoutName}`);

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
            this.timerCircle.className = 'gold';
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
    const maxHangBtn = document.getElementById('maxHangBtn');

    // Load the workout data from json.
    var workout_data = null;
    try {
        const response = await fetch('config.json');
        workout_data = await response.json();

        noHangBtn.onclick = () => {
            new IntervalTrainer(workout_data.no_hang);
        };

        sixTenBtn.onclick = () => {
            new IntervalTrainer(workout_data.six_ten);
        };

        onOffBtn.onclick = () => {
            new IntervalTrainer(workout_data.six_six_six);
        };

        maxHangBtn.onclick = () => {
            new IntervalTrainer(workout_data.max_hang);
        };

    }
    catch (error) {
        console.error("Failed to load configuration:", error);
    }
});
