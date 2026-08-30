// CyberShield AI — "I've Already Interacted" Recovery Guidance Wizard

document.addEventListener('DOMContentLoaded', () => {
    initRecoveryWizard();
});

function initRecoveryWizard() {
    const recoveryBtns = document.querySelectorAll('.recovery-option-btn');
    const recoveryOutput = document.getElementById('recovery-output');

    if (!recoveryBtns || !recoveryOutput) return;

    const RECOVERY_GUIDES = {
        clicked_link: {
            title: "🔗 I Clicked a Suspicious Link",
            steps: [
                "1. Immediately close the opened browser tab and do NOT download any files.",
                "2. Disconnect your device from Wi-Fi / Mobile Data temporarily.",
                "3. Run an anti-malware scan on your smartphone or desktop device.",
                "4. Clear your browser cache and cookies.",
                "5. Monitor your online accounts for unexpected login sessions."
            ]
        },
        entered_password: {
            title: "🔐 I Entered Personal Information or Password",
            steps: [
                "1. Change your password IMMEDIATELY on the legitimate official website.",
                "2. If you re-used this password on other services, change it on those platforms too.",
                "3. Enable Two-Factor Authentication (2FA) using an Authenticator App.",
                "4. Check active login sessions on your account settings and terminate unknown devices."
            ]
        },
        shared_otp: {
            title: "🔑 I Shared an OTP Code",
            steps: [
                "1. Contact your bank or service provider IMMEDIATELY to freeze the session.",
                "2. Check if unauthorized financial transactions or account changes occurred.",
                "3. Re-secure your account by resetting credentials from an official device.",
                "4. Note down the time and caller number to report to national cybercrime authorities."
            ]
        },
        entered_card: {
            title: "💳 I Entered Debit/Credit Card or Banking Details",
            steps: [
                "1. Call your bank's 24x7 customer helpline or use your official banking app to BLOCK the card immediately.",
                "2. Temporarily freeze or lower your international & online transaction limits in your banking app.",
                "3. File a dispute/chargeback claim with your bank for any unauthorized charges.",
                "4. Request a replacement card with a new CVV and expiry date."
            ]
        },
        transferred_money: {
            title: "🚨 I Transferred Money (UPI / NetBanking / Fraud)",
            steps: [
                "1. Call the official National Cyber Crime Helpline at 1930 (India) IMMEDIATELY to request transaction freezing.",
                "2. Log a complaint on the official portal: https://cybercrime.gov.in within the golden hour.",
                "3. Contact your bank's cyber fraud node officer with UTR / Transaction Reference numbers.",
                "4. File a formal police FIR at your local Cyber Crime Police Station."
            ]
        },
        unsure: {
            title: "❓ I'm Not Sure What Data Was Exposed",
            steps: [
                "1. Check your recent bank statements and SMS alerts for unexpected debits.",
                "2. Scan your device for unauthorized apps or profile downloads.",
                "3. Update your critical email & banking passwords as a protective measure.",
                "4. Enable multi-factor authentication (2FA) across all sensitive accounts."
            ]
        }
    };

    recoveryBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const key = btn.getAttribute('data-recovery-key');
            const guide = RECOVERY_GUIDES[key];
            if (!guide) return;

            recoveryBtns.forEach(b => b.classList.remove('border-cyan-400', 'bg-cyan-500/20'));
            btn.classList.add('border-cyan-400', 'bg-cyan-500/20');

            let stepsHTML = guide.steps.map(step => `
                <li class="p-3 bg-slate-800/60 rounded-lg border border-slate-700/50 text-sm text-slate-200">
                    ${step}
                </li>
            `).join('');

            recoveryOutput.innerHTML = `
                <div class="glass-panel p-6 border border-cyan-500/30">
                    <h3 class="text-xl font-bold text-cyan-400 mb-4">${guide.title}</h3>
                    <h4 class="text-sm font-semibold text-slate-300 mb-3">Immediate Required Actions:</h4>
                    <ul class="space-y-2 mb-6">
                        ${stepsHTML}
                    </ul>
                    <div class="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-xs text-amber-300">
                        <strong>Important Notice:</strong> CyberShield AI is an educational cybersecurity decision-support tool. It does not replace official bank fraud reporting or law enforcement agencies.
                    </div>
                </div>
            `;
            recoveryOutput.classList.remove('hidden');
            recoveryOutput.scrollIntoView({ behavior: 'smooth' });
        });
    });
}
