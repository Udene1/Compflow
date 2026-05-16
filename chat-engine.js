/**
 * ComplianceFlow AI | Chat Interrogation Engine
 * Governance Architect AI — Conversational Cloud Intelligence
 */

const ChatEngine = {
    isOpen: false,

    toggle() {
        this.isOpen = !this.isOpen;
        const drawer = document.getElementById('chat-drawer');
        const toggle = document.getElementById('chat-toggle');
        
        if (this.isOpen) {
            drawer.classList.add('open');
            if (toggle) toggle.style.background = 'var(--secondary)';
            document.getElementById('chat-input').focus();
        } else {
            drawer.classList.remove('open');
            if (toggle) toggle.style.background = 'var(--primary)';
        }
    },

    // Assemble live infrastructure context from dashboard state
    _getContext() {
        const resources = window.Scanner ? Scanner.getResources() : [];
        const fw = window.Frameworks ? Frameworks.getCurrent() : { name: 'SOC2 Type II' };
        const score = document.getElementById('sidebar-score')?.textContent || 'N/A';

        // Get maturity data from DOM
        const maturityData = ['soc2', 'gdpr', 'hipaa', 'iso'].map(id => {
            const el = document.getElementById(`maturity-${id}`);
            return el ? `- ${id.toUpperCase()}: ${el.textContent}` : null;
        }).filter(Boolean).join('\n');

        // Classify resources
        const passing = resources.filter(r => r.severity === 'pass').length;
        const warnings = resources.filter(r => r.severity === 'warning').length;
        const critical = resources.filter(r => r.severity === 'critical').length;

        // Get connected providers
        const providers = window.CloudConnect ? CloudConnect.getProviders().join(', ') : 'None';

        return {
            providers,
            totalResources: resources.length,
            passing,
            warnings,
            critical,
            readinessScore: score,
            activeFramework: fw.name,
            maturityScores: maturityData || 'Not yet calculated',
            resources: resources.map(r => ({
                name: r.name,
                type: r.type,
                region: r.region,
                severity: r.severity,
                issue: r.issue || 'No issues',
                control: r.control || 'N/A'
            }))
        };
    },

    async send() {
        const input = document.getElementById('chat-input');
        const query = input.value.trim();
        if (!query) return;

        input.value = '';
        this.addMessage('user', query);
        const loadingId = this.addMessage('ai', `<span class="spinner"></span> Analyzing infrastructure...`);

        try {
            const context = this._getContext();

            const res = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query, context })
            });

            const data = await res.json();
            
            if (data.error) throw new Error(data.error);

            // Simple markdown rendering
            const formatted = this._renderMarkdown(data.response);
            this.updateMessage(loadingId, formatted);

        } catch (error) {
            console.error("[CHAT] Error:", error);
            this.updateMessage(loadingId, "⚠️ I'm having trouble accessing the reasoning engine. Please verify your Gemini API key and try again.");
        }
    },

    _renderMarkdown(text) {
        return text
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`(.*?)`/g, '<code>$1</code>')
            .replace(/^- (.+)$/gm, '<li>$1</li>')
            .replace(/(<li>.*<\/li>)/gs, '<ul>$1</ul>')
            .replace(/\n/g, '<br>');
    },

    addMessage(role, text) {
        const id = 'msg-' + Date.now();
        const container = document.getElementById('chat-messages');
        const div = document.createElement('div');
        div.className = `chat-msg ${role}`;
        div.id = id;
        div.innerHTML = text;
        container.appendChild(div);
        container.scrollTop = container.scrollHeight;
        return id;
    },

    updateMessage(id, text) {
        const el = document.getElementById(id);
        if (el) {
            el.innerHTML = text;
            const container = document.getElementById('chat-messages');
            container.scrollTop = container.scrollHeight;
        }
    }
};

// Enter key to send
document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('chat-input');
    if (input) {
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                ChatEngine.send();
            }
        });
    }
});

window.ChatEngine = ChatEngine;
