/**
 * SecureVote — Cryptographic Audit & Tamper Detection Scripts
 * Conforms to Section 3.5 of UI/UX Technical Specification
 */

document.addEventListener("DOMContentLoaded", () => {
    const verifyBtn = document.getElementById("btn-verify-chain");
    const tamperBtn = document.getElementById("btn-tamper-test");
    const restoreBtn = document.getElementById("btn-restore-chain");
    const auditStatusBox = document.getElementById("audit-status-badge");
    const chainIntegrityIndicator = document.getElementById("chain-integrity-indicator");
    const receiptSearchBtn = document.getElementById("btn-search-receipt");
    const receiptInput = document.getElementById("input-search-receipt");
    const receiptResultBox = document.getElementById("receipt-result-box");

    // 1. Verify Audit Chain (Section 3.5 Verifier Tool)
    if (verifyBtn) {
        verifyBtn.addEventListener("click", async () => {
            verifyBtn.disabled = true;
            verifyBtn.innerHTML = "⏳ Проверка SHA-256 и Ed25519...";

            try {
                const response = await fetch("/api/audit/verify");
                const res = await response.json();

                if (res.valid) {
                    auditStatusBox.className = "alert alert-success";
                    auditStatusBox.innerHTML = `
                        <div>
                            <strong>✓ Аудит успешно пройден:</strong><br>
                            Все ${res.chain_length} блоков хэш-цепочки SHA-256 и цифровые подписи Ed25519 проверены и являются подлинными. База данных не подвергалась подделке.
                        </div>
                    `;
                    if (chainIntegrityIndicator) {
                        chainIntegrityIndicator.innerHTML = `
                            <span class="badge badge-success" style="font-size: 0.88rem; padding: 8px 16px;">
                                ✓ Целостность цепи подтверждена (Valid Chain)
                            </span>
                        `;
                    }
                    document.querySelectorAll(".audit-block-row").forEach(b => {
                        b.style.backgroundColor = "";
                    });
                } else {
                    auditStatusBox.className = "alert alert-danger";
                    auditStatusBox.innerHTML = `
                        <div>
                            <strong>⚠️ ОБНАРУЖЕНО НАРУШЕНИЕ ЦЕЛОСТНОСТИ ДАННЫХ:</strong><br>
                            Поврежденный блок: <strong>#${res.broken_index}</strong>.<br>
                            Причина: ${res.error}
                        </div>
                    `;
                    if (chainIntegrityIndicator) {
                        chainIntegrityIndicator.innerHTML = `
                            <span class="badge badge-danger" style="font-size: 0.88rem; padding: 8px 16px;">
                                ✗ ВНИМАНИЕ: Нарушена целостность данных!
                            </span>
                        `;
                    }
                    // Highlight the tampered row in red
                    const tamperedRow = document.getElementById(`audit-row-${res.broken_index}`);
                    if (tamperedRow) {
                        tamperedRow.style.backgroundColor = "rgba(220, 38, 38, 0.15)";
                        tamperedRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    }
                }
            } catch (err) {
                console.error("Verification error:", err);
                alert("Ошибка сетевого запроса при проверке аудита.");
            } finally {
                verifyBtn.disabled = false;
                verifyBtn.innerHTML = "🛡️ Ручная проверка целостности цепи";
            }
        });
    }

    // 2. Tamper Test (Section 3.5 Simulation)
    if (tamperBtn) {
        tamperBtn.addEventListener("click", async () => {
            if (!confirm("Внимание: Начать симуляцию подделки данных в блоке #0 для демонстрации работы системы обнаружения нарушений?")) {
                return;
            }

            try {
                const response = await fetch("/api/audit/tamper_test", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ block_index: 0 })
                });
                const res = await response.json();
                if (res.success) {
                    alert(res.message + "\n\nНажмите 'Ручная проверка целостности цепи' для демонстрации выявления подделки.");
                    window.location.reload();
                } else {
                    alert("Ошибка: " + res.error);
                }
            } catch (err) {
                alert("Ошибка запроса: " + err);
            }
        });
    }

    // 3. Restore Clean Database
    if (restoreBtn) {
        restoreBtn.addEventListener("click", async () => {
            if (!confirm("Восстановить эталонное криптографическое состояние базы данных?")) {
                return;
            }

            try {
                const response = await fetch("/api/audit/restore", { method: "POST" });
                const res = await response.json();
                if (res.success) {
                    alert(res.message);
                    window.location.reload();
                }
            } catch (err) {
                alert("Ошибка: " + err);
            }
        });
    }

    // 4. Receipt Lookup (Section 3.5 Bulletin Board)
    if (receiptSearchBtn && receiptInput) {
        receiptSearchBtn.addEventListener("click", async () => {
            const hash = receiptInput.value.trim();
            if (!hash) {
                alert("Пожалуйста, введите SHA-256 хэш квитанции.");
                return;
            }

            receiptResultBox.style.display = "block";
            receiptResultBox.innerHTML = "<div class='text-muted'>🔍 Поиск записи в неизменяемом журнале...</div>";

            try {
                const res = await fetch(`/api/receipt/${encodeURIComponent(hash)}`);
                const data = await res.json();

                if (data.found) {
                    const r = data.receipt;
                    receiptResultBox.innerHTML = `
                        <div class="alert alert-success">
                            <div>
                                <h4 style="margin-bottom: 6px; font-size: 1.05rem;">✓ Квитанция подтверждена и включена в реестр!</h4>
                                <p style="margin-bottom: 4px;"><strong>Выборы:</strong> ${r.election_title}</p>
                                <p style="margin-bottom: 4px;"><strong>Временная метка (UTC):</strong> ${r.timestamp}</p>
                                <p style="margin-bottom: 4px;"><strong>Запись в аудите:</strong> Блок #${r.audit_index !== undefined ? r.audit_index : 'Включен'}</p>
                                <p style="margin-bottom: 6px;"><strong>AES-GCM Auth Tag:</strong> <code>${r.auth_tag}</code></p>
                                <small style="color: var(--text-dim);">Голос сохранен в зашифрованном виде и полностью отделен от вашей личности (Zero-Knowledge Privacy).</small>
                            </div>
                        </div>
                    `;
                } else {
                    receiptResultBox.innerHTML = `
                        <div class="alert alert-danger">
                            <div>
                                <strong>✗ Квитанция не найдена в реестре.</strong><br>
                                ${data.error}
                            </div>
                        </div>
                    `;
                }
            } catch (err) {
                receiptResultBox.innerHTML = `<div class="alert alert-danger">Ошибка при поиске квитанции.</div>`;
            }
        });
    }
});
