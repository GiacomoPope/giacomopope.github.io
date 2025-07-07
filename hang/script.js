document.addEventListener('DOMContentLoaded', () => {
    const startBtn = document.getElementById('startBtn');
    const startScreen = document.getElementById('startScreen');
    const timerScreen = document.getElementById('timerScreen');
    const timerDisplay = document.getElementById('timer');
    const phaseText = document.getElementById('phaseText');
    const intervalCounter = document.createElement('div');
    intervalCounter.id = 'intervalCounter';
    timerScreen.appendChild(intervalCounter);

    const intervals = [
        { duration: 10000, color: 'blue', text: '' },
        { duration: 20000, color: 'green', text: '' }
    ];

    let currentInterval = 0;
    let intervalCount = 0;

    function getNextGripType(count) {
    	if (count == 19) return 'All Done';
        if (count < 5) return 'Up Next: Half Crimp';
        if (count < 11) return 'Up Next: Open Crimp';
        if (count < 15) return 'Up Next: Two Finger Half Crimp';
        return 'Up Next: Two Finger Open Crimp';
    }

    function getGripType(count) {
        if (count < 6) return 'Half Crimp';
        if (count < 12) return 'Open Crimp';
        if (count < 16) return 'Two Finger Half Crimp';
        return 'Two Finger Open Crimp';
    }

    function formatTime(milliseconds) {
        const totalSeconds = Math.floor(milliseconds / 1000);
        const remainingMilliseconds = milliseconds % 1000;
        const formattedSeconds = totalSeconds.toString().padStart(2, '0');
        const formattedMilliseconds = remainingMilliseconds.toString().padStart(3, '0');
        return `${formattedSeconds}:${formattedMilliseconds}`;
    }

    function startTimer(duration, color, text) {
        return new Promise((resolve) => {
            timerDisplay.className = color;
            phaseText.textContent = text;
            
            const startTime = Date.now();
            const timerInterval = setInterval(() => {
                const elapsedTime = Date.now() - startTime;
                const remainingTime = Math.max(duration - elapsedTime, 0);
                
                timerDisplay.textContent = formatTime(remainingTime);
                
                if (remainingTime <= 0) {
                    clearInterval(timerInterval);
                    resolve();
                }
            }, 10);
        });
    }

    async function runWorkout() {
        startScreen.classList.add('hidden');
        timerScreen.classList.remove('hidden');

        try {
            await startTimer(5000, 'gold', 'Get Ready: Half Crimp');

            while (intervalCount < 20) {
                for (const [index, interval] of intervals.entries()) {
                    intervalCounter.textContent = `${intervalCount + 1}/20`;
                    
                    const intervalText = interval.color === 'blue' 
                        ? getGripType(intervalCount) 
                        : getNextGripType(intervalCount);
                    
                    await startTimer(interval.duration, interval.color, intervalText);
                }
                intervalCount++;
            }
        } catch (error) {
            console.error("Workout interrupted:", error);
        } finally {
            // Reset display after workout
            timerDisplay.textContent = '05:000';
            timerDisplay.className = 'gold';
            phaseText.textContent = '';
            intervalCounter.textContent = '';
            
            // Hide timer screen and show start screen
            timerScreen.classList.add('hidden');
            startScreen.classList.remove('hidden');
            
            // Reset interval count
            intervalCount = 0;
        }
    }

    startBtn.addEventListener('click', runWorkout);
});
