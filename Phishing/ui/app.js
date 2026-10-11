document.getElementById('scanBtn').addEventListener('click', async () => {
    const urlInput = document.getElementById('urlInput').value.trim();
    const loader = document.getElementById('loader');
    const resultPanel = document.getElementById('resultPanel');
    
    if (!urlInput) {
        alert("CRITICAL: Enter a valid target URL before firing the analyzer.");
        return;
    }

    loader.classList.remove('hidden');
    resultPanel.classList.add('hidden');

    try {
        // Send request cleanly to our relative internal API route
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });

        const data = await response.json();
        loader.classList.add('hidden');

        if (!response.ok) {
            alert(`Error: ${data.detail || 'Analysis aborted.'}`);
            return;
        }

        // Trigger interactive UI changes
        resultPanel.classList.remove('hidden');
        document.getElementById('verdictLabel').innerText = `VERDICT: ${data.verdict}`;
        document.getElementById('scoreLabel').innerText = `SCORE: ${data.risk_score}/100`;
        document.getElementById('ipLabel').innerText = data.ip;
        document.getElementById('ageLabel').innerText = data.age;

        // Apply theme colors dynamically depending on systemic risk tiers
        const banner = document.getElementById('verdictBanner');
        const meter = document.getElementById('meterBar');
        meter.style.width = `${data.risk_score}%`;

        if (data.verdict === "SAFE") {
            banner.style.backgroundColor = "rgba(0, 255, 102, 0.15)";
            banner.style.color = "#00ff66";
            meter.style.backgroundColor = "#00ff66";
        } else if (data.verdict === "LOW RISK" || data.verdict === "MODERATE RISK") {
            banner.style.backgroundColor = "rgba(255, 153, 0, 0.15)";
            banner.style.color = "#ff9900";
            meter.style.backgroundColor = "#ff9900";
        } else {
            banner.style.backgroundColor = "rgba(255, 0, 85, 0.15)";
            banner.style.color = "#ff0055";
            meter.style.backgroundColor = "#ff0055";
        }

        const list = document.getElementById('indicatorsList');
        list.innerHTML = "";
        data.indicators.forEach(ind => {
            const li = document.createElement('li');
            li.innerText = `💥 ${ind}`;
            list.appendChild(li);
        });

    } catch (err) {
        loader.classList.add('hidden');
        alert("Pipeline Break: Failed to connect to server backend registry.");
    }
});
