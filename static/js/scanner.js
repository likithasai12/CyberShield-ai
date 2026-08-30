// CyberShield AI — Scanner Controller (URL, Message, Email, QR)

document.addEventListener('DOMContentLoaded', () => {
    initScannerTabs();
    initScanForms();
    initQRDropzone();
});

function initScannerTabs() {
    const scanTabBtns = document.querySelectorAll('.scan-type-btn');
    const scanForms = document.querySelectorAll('.scan-form-container');

    scanTabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const type = btn.getAttribute('data-scan-type');

            scanTabBtns.forEach(b => {
                b.classList.remove('bg-cyan-500/20', 'text-cyan-300', 'border-cyan-500/50');
                b.classList.add('bg-slate-800/40', 'text-slate-400', 'border-slate-700/50');
            });

            btn.classList.remove('bg-slate-800/40', 'text-slate-400', 'border-slate-700/50');
            btn.classList.add('bg-cyan-500/20', 'text-cyan-300', 'border-cyan-500/50');

            scanForms.forEach(form => {
                if (form.id === `form-${type}`) {
                    form.classList.remove('hidden');
                } else {
                    form.classList.add('hidden');
                }
            });
        });
    });
}

function initScanForms() {
    // 1. URL Form
    const urlForm = document.getElementById('url-scan-form');
    if (urlForm) {
        urlForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const urlInput = document.getElementById('scan-url-input').value.trim();
            if (!urlInput) return;

            await executeScan('/api/v1/scan/url', { url: urlInput }, 'json');
        });
    }

    // 2. Message Form
    const msgForm = document.getElementById('msg-scan-form');
    if (msgForm) {
        msgForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const msgInput = document.getElementById('scan-msg-input').value.trim();
            if (!msgInput) return;

            await executeScan('/api/v1/scan/message', { message: msgInput }, 'json');
        });
    }

    // 3. Email Form
    const emailForm = document.getElementById('email-scan-form');
    if (emailForm) {
        emailForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const subject = document.getElementById('scan-email-subject').value.trim();
            const body = document.getElementById('scan-email-body').value.trim();
            if (!body) return;

            await executeScan('/api/v1/scan/email', { subject, body }, 'json');
        });
    }

    // 4. QR Form
    const qrForm = document.getElementById('qr-scan-form');
    if (qrForm) {
        qrForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const fileInput = document.getElementById('qr-file-input');
            if (!fileInput.files || fileInput.files.length === 0) return;

            const formData = new FormData();
            formData.append('file', fileInput.files[0]);

            await executeScan('/api/v1/scan/qr', formData, 'multipart');
        });
    }
}

function initQRDropzone() {
    const dropzone = document.getElementById('qr-dropzone');
    const fileInput = document.getElementById('qr-file-input');
    const fileNameDisplay = document.getElementById('qr-file-name');

    if (!dropzone || !fileInput) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
        }, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, () => {
            dropzone.classList.add('border-cyan-400', 'bg-cyan-500/10');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, () => {
            dropzone.classList.remove('border-cyan-400', 'bg-cyan-500/10');
        }, false);
    });

    dropzone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files && files.length > 0) {
            fileInput.files = files;
            if (fileNameDisplay) fileNameDisplay.innerText = `Selected File: ${files[0].name}`;
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files && fileInput.files.length > 0 && fileNameDisplay) {
            fileNameDisplay.innerText = `Selected File: ${fileInput.files[0].name}`;
        }
    });
}

async function executeScan(endpoint, payload, type) {
    const loader = document.getElementById('scan-loader');
    const resultsContainer = document.getElementById('scan-results-container');
    const errorContainer = document.getElementById('scan-error-container');

    if (loader) loader.classList.remove('hidden');
    if (resultsContainer) resultsContainer.classList.add('hidden');
    if (errorContainer) errorContainer.classList.add('hidden');

    try {
        let options = { method: 'POST' };
        if (type === 'json') {
            options.headers = { 'Content-Type': 'application/json' };
            options.body = JSON.stringify(payload);
        } else {
            options.body = payload;
        }

        const response = await fetch(endpoint, options);
        const data = await response.json();

        if (loader) loader.classList.add('hidden');

        if (!response.ok) {
            if (errorContainer) {
                errorContainer.innerText = data.detail || 'Analysis request failed. Please check input.';
                errorContainer.classList.remove('hidden');
            }
            return;
        }

        renderScanResults(data);

    } catch (err) {
        if (loader) loader.classList.add('hidden');
        if (errorContainer) {
            errorContainer.innerText = `Network Error: ${err.message}. Ensure CyberShield server is running.`;
            errorContainer.classList.remove('hidden');
        }
    }
}

function renderScanResults(result) {
    const resultsContainer = document.getElementById('scan-results-container');
    if (!resultsContainer) return;

    // 1. Classification & Secondary Percentage Calculation
    let emoji = '🟢';
    let label = 'SAFE';
    let mainColor = 'text-emerald-400';
    let secondaryText = '';

    const score = result.risk_score;

    if (score <= 25) {
        emoji = '🟢';
        label = 'SAFE';
        mainColor = 'text-emerald-400';
        secondaryText = `${100 - score}% safe`;
    } else if (score <= 65) {
        emoji = '🟠';
        label = 'SUSPICIOUS';
        mainColor = 'text-amber-400';
        secondaryText = `${score}% risk`;
    } else {
        emoji = '🔴';
        label = 'SCAM';
        mainColor = 'text-rose-500';
        secondaryText = `${score}% risk`;
    }

    const mainElem = document.getElementById('res-classification-main');
    if (mainElem) {
        mainElem.innerHTML = `<span>${emoji}</span> <span>${label}</span>`;
        mainElem.className = `text-3xl sm:text-4xl font-black ${mainColor} flex items-center gap-2`;
    }

    const secElem = document.getElementById('res-classification-secondary');
    if (secElem) {
        secElem.innerText = secondaryText;
    }

    document.getElementById('res-threat-category').innerText = result.threat_category;
    document.getElementById('res-normalized-input').innerText = result.normalized_input;

    // 2. Stored Intelligence Badge
    const intelBox = document.getElementById('res-stored-intel-box');
    if (result.stored_intel_found && result.stored_intel_details) {
        intelBox.innerHTML = `
            <div class="p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-lg flex items-start gap-3">
                <span class="text-xl">🔎</span>
                <div>
                    <h5 class="text-sm font-semibold text-cyan-300">CyberShield Persistent Memory Match</h5>
                    <p class="text-xs text-slate-300">
                        This content signature was previously observed 
                        <span class="font-bold text-white">${result.stored_intel_details.scan_count || 1} time(s)</span>. 
                        Prior intelligence was incorporated into this fresh analysis cycle.
                    </p>
                </div>
            </div>
        `;
        intelBox.classList.remove('hidden');
    } else {
        intelBox.innerHTML = '';
        intelBox.classList.add('hidden');
    }

    // 3. Detected Indicators List
    const indicatorsList = document.getElementById('res-indicators-list');
    indicatorsList.innerHTML = '';

    if (result.detected_indicators && result.detected_indicators.length > 0) {
        result.detected_indicators.forEach(ind => {
            let indBadge = 'bg-slate-700 text-slate-300';
            if (ind.severity === 'medium') indBadge = 'bg-amber-500/20 text-amber-300 border border-amber-500/30';
            if (ind.severity === 'high') indBadge = 'bg-orange-500/20 text-orange-300 border border-orange-500/30';
            if (ind.severity === 'critical') indBadge = 'bg-rose-500/20 text-rose-300 border border-rose-500/30';

            const li = document.createElement('li');
            li.className = 'p-3 bg-slate-800/50 rounded-lg border border-slate-700/50 flex flex-col gap-1';
            li.innerHTML = `
                <div class="flex items-center justify-between">
                    <span class="font-medium text-slate-200 text-sm">⚠️ ${ind.label}</span>
                    <span class="text-xs px-2 py-0.5 rounded ${indBadge} font-mono">+${ind.weight} pts</span>
                </div>
                <p class="text-xs text-slate-400">${ind.description}</p>
            `;
            indicatorsList.appendChild(li);
        });
    } else {
        indicatorsList.innerHTML = `<li class="text-xs text-slate-400 italic">No suspicious indicators detected.</li>`;
    }

    // 4. Why Risky & Possible Impact
    document.getElementById('res-why-risky').innerText = result.explanation.why_risky;

    const impactList = document.getElementById('res-impact-list');
    impactList.innerHTML = '';
    result.explanation.possible_impact.forEach(imp => {
        const li = document.createElement('li');
        li.innerText = `• ${imp}`;
        impactList.appendChild(li);
    });

    // 5. Recommended Actions
    const recsList = document.getElementById('res-recommendations-list');
    recsList.innerHTML = '';
    result.recommendations.forEach(rec => {
        const li = document.createElement('li');
        li.className = 'flex items-start gap-2 text-sm text-slate-200';
        li.innerHTML = `<span>${rec}</span>`;
        recsList.appendChild(li);
    });

    // Attach scan ID / hash to Report Threat button
    window.currentScanResult = result;

    resultsContainer.classList.remove('hidden');
    resultsContainer.scrollIntoView({ behavior: 'smooth' });
}
