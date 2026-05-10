/**
 * ComplianceFlow AI | Chat Engine
 * Handles Infrastructure Interrogation via Gemini
 */

const ChatEngine = {
    isOpen: false,
    messages: [],

    toggle() {
        this.isOpen = !this.isOpen;
        const drawer = document.getElementById('chat-drawer');
        const toggle = document.getElementById('chat-toggle');
        
        if (this.isOpen) {
            drawer.classList.add('open');
            toggle.style.background = 'var(--text-muted)';
            document.getElementById('chat-input').focus();
        } else {
            drawer.classList.remove('open');
            toggle.style.background = 'var(--primary)';
        }
    },

    async send() {
        const input = document.getElementById('chat-input');
        const query = input.value.trim();
        if (!query) return;

        // Reset input
        input.value = '';

        // Add user message
        this.addMessage('user', query);

        // Add loading state
        const loadingId = this.addMessage('ai', `<span class="spinner"></span> Consulting the Audit Brain...`);

        try {
            // Collect context from existing objects
            const contextData = {
                resources: window.Scanner ? Scanner.allResources : [],
                framework: window.Frameworks ? Frameworks.getCurrent() : 'SOC2',
                readiness: document.getElementById('sidebar-score')?.textContent || '0%'
            };

            const res = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query, contextData })
            });

            const data = await res.json();
            
            if (data.error) throw new Error(data.error);

            // Update AI message
            this.updateMessage(loadingId, data.response);

        } catch (error) {
            console.error("[CHAT] Error:", error);
            this.updateMessage(loadingId, "I'm having trouble accessing my audit logs right now. Please verify your connection settings.");
        }
    },

    addMessage(role, text) {
        const id = 'msg-' + Date.now();
        const container = document.getElementById('chat-messages');
        const div = document.createElement('div');
        div.className = `chat-msg ${role}`;
        div.id = id;
        div.innerHTML = text;
        container.appendChild(div);
        
        // Scroll to bottom
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

window.ChatEngine = ChatEngine;
