/**
 * SecureVote — Interactive UI & Cryptographic Preview Scripts
 */

document.addEventListener("DOMContentLoaded", () => {
    // 1. Initialize Copy to Clipboard
    initCopyButtons();

    // 2. Initialize Ballot Selection & Live AES-256-GCM Preview
    initBallotBooths();

    // 3. Initialize Quick Demo Login Switcher
    initDemoLoginHelper();
});

/**
 * Copies hash/key to clipboard with visual feedback
 */
function initCopyButtons() {
    document.querySelectorAll(".copy-btn").forEach(btn => {
        btn.addEventListener("click", async (e) => {
            e.stopPropagation();
            const textToCopy = btn.getAttribute("data-copy") || btn.parentElement.innerText;
            try {
                await navigator.clipboard.writeText(textToCopy.trim());
                const originalText = btn.innerHTML;
                btn.innerHTML = "✓ Скопировано";
                btn.style.color = "#10b981";
                setTimeout(() => {
                    btn.innerHTML = originalText;
                    btn.style.color = "";
                }, 2000);
            } catch (err) {
                console.error("Ошибка копирования:", err);
            }
        });
    });
}

/**
 * Handles candidate card selection and live cryptographic preview
 */
function initBallotBooths() {
    const candidateCards = document.querySelectorAll(".candidate-card");
    const previewContainer = document.getElementById("crypto-live-preview");
    const previewNonce = document.getElementById("preview-nonce");
    const previewCipher = document.getElementById("preview-cipher");
    const previewTag = document.getElementById("preview-tag");
    const selectedInput = document.getElementById("selected-candidate-id");

    if (!candidateCards.length) return;

    candidateCards.forEach(card => {
        card.addEventListener("click", () => {
            candidateCards.forEach(c => c.classList.remove("selected"));
            card.classList.add("selected");

            const candidateId = card.getAttribute("data-candidate-id");
            const candidateName = card.getAttribute("data-candidate-name");
            if (selectedInput) selectedInput.value = candidateId;

            // Update live simulation preview if available
            if (previewContainer) {
                previewContainer.style.display = "block";
                simulateAesGcmEncryption(candidateId, candidateName);
            }
        });
    });

    function simulateAesGcmEncryption(candidateId, candidateName) {
        // Generate pseudo random 12-byte IV and 16-byte tag preview
        const pseudoNonce = Array.from({length: 12}, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');
        const pseudoTag = Array.from({length: 16}, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join('');
        
        // Pseudo ciphertext representing candidate_id payload
        const payloadText = JSON.stringify({ candidate_id: Number(candidateId), name: candidateName, ts: Date.now() });
        const pseudoCipher = Array.from(new TextEncoder().encode(payloadText))
            .map(b => (b ^ 0x5c).toString(16).padStart(2, '0')).join('');

        if (previewNonce) previewNonce.innerText = pseudoNonce;
        if (previewCipher) previewCipher.innerText = pseudoCipher;
        if (previewTag) previewTag.innerText = pseudoTag;
    }
}

/**
 * Quick-fill login form for testing and presentation
 */
function initDemoLoginHelper() {
    const demoButtons = document.querySelectorAll(".demo-login-btn");
    const userInput = document.getElementById("username");
    const passInput = document.getElementById("password");

    if (!demoButtons.length || !userInput || !passInput) return;

    demoButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const user = btn.getAttribute("data-user");
            const pass = btn.getAttribute("data-pass");
            userInput.value = user;
            passInput.value = pass;

            // Highlight form
            userInput.style.borderColor = "var(--accent-cyan)";
            passInput.style.borderColor = "var(--accent-cyan)";
            setTimeout(() => {
                userInput.style.borderColor = "";
                passInput.style.borderColor = "";
            }, 800);
        });
    });
}
