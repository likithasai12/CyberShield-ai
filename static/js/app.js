// CyberShield AI — Main SPA Application Controller

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    checkHealth();
});

function initNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    const tabPanels = document.querySelectorAll('.tab-panel');

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetTab = link.getAttribute('data-tab');

            navLinks.forEach(l => {
                l.classList.remove('text-cyan-400', 'border-cyan-400', 'bg-slate-800/60');
                l.classList.add('text-slate-400', 'border-transparent');
            });

            link.classList.remove('text-slate-400', 'border-transparent');
            link.classList.add('text-cyan-400', 'border-cyan-400', 'bg-slate-800/60');

            tabPanels.forEach(panel => {
                if (panel.id === `tab-${targetTab}`) {
                    panel.classList.remove('hidden');
                } else {
                    panel.classList.add('hidden');
                }
            });
        });
    });
}

async function checkHealth() {
    try {
        await fetch('/health');
    } catch (e) {
        console.warn('Health check failed:', e);
    }
}
