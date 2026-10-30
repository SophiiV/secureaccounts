// Індикатор сили пароля і перевірка правил політики під час введення (дублює серверну перевірку для зручності).
(function () {
    const input = document.querySelector("[data-password-meter]");
    if (input) {
        const bar = document.getElementById("strength-bar");
        const label = document.getElementById("strength-label");
        const rules = {
            length: v => v.length >= 8,
            upper: v => /\p{Lu}/u.test(v),
            lower: v => /\p{Ll}/u.test(v),
            digit: v => /\d/.test(v),
            symbol: v => /[^\p{L}\p{N}]/u.test(v)
        };
        const levels = [
            { text: "дуже слабкий", color: "#dc3545" },
            { text: "слабкий", color: "#fd7e14" },
            { text: "середній", color: "#ffc107" },
            { text: "добрий", color: "#20c997" },
            { text: "сильний", color: "#198754" }
        ];
        const update = () => {
            const v = input.value;
            let passed = 0;
            for (const [name, test] of Object.entries(rules)) {
                const ok = test(v);
                if (ok) passed++;
                const li = document.querySelector(`[data-rule="${name}"]`);
                if (li) li.classList.toggle("ok", ok);
            }
            let score = passed;                      // 0..5
            if (v.length >= 12) score++;
            if (v.length >= 16) score++;
            if (/(.)\1\1/.test(v)) score--;           // три однакові символи поспіль
            const level = v.length === 0 ? null : levels[Math.max(0, Math.min(4, score - 2))];
            bar.style.width = v.length === 0 ? "0" : `${Math.max(10, Math.min(100, score * 15))}%`;
            bar.style.backgroundColor = level ? level.color : "transparent";
            label.textContent = level ? `Сила пароля: ${level.text}` : "";
        };
        input.addEventListener("input", update);
        update();
    }

    const refresh = document.getElementById("captcha-refresh");
    if (refresh) {
        refresh.addEventListener("click", e => {
            e.preventDefault();
            const img = document.getElementById("captcha-img");
            img.src = "/captcha?t=" + Date.now();
            const field = document.getElementById("captcha-input");
            if (field) { field.value = ""; field.focus(); }
        });
    }
})();
