const tabs = document.querySelectorAll('.tab');
const panels = document.querySelectorAll('.panel');
const themeToggle = document.getElementById('theme-toggle');

const applyTheme = (theme) => {
  const nextTheme = theme === 'dark' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', nextTheme);

  if (themeToggle) {
    themeToggle.setAttribute('aria-pressed', String(nextTheme === 'dark'));
    themeToggle.classList.toggle('is-dark', nextTheme === 'dark');
  }

  try {
    localStorage.setItem('cryptolab-theme', nextTheme);
  } catch (error) {
    // localStorage is optional in some browsing contexts.
  }
};

const initializeTheme = () => {
  let storedTheme = null;

  try {
    storedTheme = localStorage.getItem('cryptolab-theme');
  } catch (error) {
    storedTheme = null;
  }

  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const initialTheme = storedTheme || (prefersDark ? 'dark' : 'light');
  applyTheme(initialTheme);
};

if (themeToggle) {
  themeToggle.addEventListener('click', () => {
    const currentTheme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    applyTheme(currentTheme === 'dark' ? 'light' : 'dark');
  });
}

initializeTheme();

const buildVerdictBadge = (verdict = 'unknown') => {
  const normalized = String(verdict || 'unknown').toLowerCase();
  const label = normalized.charAt(0).toUpperCase() + normalized.slice(1);
  const icon = normalized === 'weak' ? '!' : normalized === 'moderate' ? '•' : normalized === 'strong' ? '✓' : '?';
  return `<span class="verdict ${normalized}"><span class="icon">${icon}</span>${label}</span>`;
};

const setActiveTab = (targetId) => {
  tabs.forEach((tab) => {
    tab.classList.toggle('active', tab.dataset.tab === targetId);
  });

  panels.forEach((panel) => {
    panel.classList.toggle('active', panel.id === `${targetId}-panel`);
  });
};

tabs.forEach((tab) => {
  tab.addEventListener('click', () => setActiveTab(tab.dataset.tab));
});

const setLoadingState = (form, isLoading) => {
  const button = form.querySelector('button[type="submit"]');
  if (!button) return;
  const buttonText = button.querySelector('.button-text');
  button.disabled = isLoading;
  button.classList.toggle('is-loading', isLoading);
  buttonText.textContent = isLoading ? 'Running…' : 'Run analysis';
};

const setEmptyState = (targetId, text) => {
  const resultElement = document.getElementById(targetId);
  resultElement.innerHTML = `<div class="result-placeholder">${text}</div>`;
};

const animateResult = (targetId) => {
  const resultElement = document.getElementById(targetId);
  const content = resultElement.querySelector('.result-content, .error-box');
  if (!content) return;
  content.classList.remove('is-animating');
  void content.offsetWidth;
  content.classList.add('is-animating');
};

const renderScore = (score = 0, verdict = 'unknown') => {
  const numeric = Number(score) || 0;
  const safeVerdict = String(verdict || 'unknown').toLowerCase();
  return `
    <div class="score-block">
      <div class="score-header">
        <span>Assessment</span>
        <span>${numeric}/100</span>
      </div>
      <div class="score-bar">
        <div class="score-fill ${safeVerdict}" style="width: ${Math.min(Math.max(numeric, 0), 100)}%"></div>
      </div>
    </div>
  `;
};

const renderGenericResult = (data, targetId, customHtml) => {
  const resultElement = document.getElementById(targetId);
  if (!data || data.error) {
    resultElement.innerHTML = `<div class="error-box">${data?.error || 'Request failed.'}</div>`;
    return;
  }
  resultElement.innerHTML = `<div class="result-content">${customHtml(data)}</div>`;
};

const fetchJson = async (url, payload) => {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `Request failed with status ${response.status}`);
  }
  return data;
};

const populateQuickFill = () => {
  const md5Value = '5f4dcc3b5aa765d61d8327deb882cf99';
  const sha1Value = 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d';
  const repeatedText = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

  document.querySelector('[data-fill="md5"]').addEventListener('click', () => {
    document.getElementById('hash-value').value = md5Value;
  });

  document.querySelector('[data-fill="sha1"]').addEventListener('click', () => {
    document.getElementById('hash-value').value = sha1Value;
  });

  document.querySelector('[data-fill="repeated"]').addEventListener('click', () => {
    document.getElementById('plaintext').value = repeatedText;
  });
};

const buildHashResultHtml = (data) => {
  const verdict = data.verdict || 'unknown';
  const explanation = data.explanation || 'No explanation available.';
  const plaintext = data.plaintext ? data.plaintext : 'Not recovered';
  const details = [
    ['Algorithm', data.algorithm || 'unknown'],
    ['Cracked', data.cracked ? 'Yes' : 'No'],
    ['Attempts', data.attempts ?? 0],
    ['Time', `${Number(data.time_seconds || 0).toFixed(6)}s`],
    ['Hash', data.input_hash || '—'],
    ['Recovered plaintext', plaintext],
  ];

  return `
    ${buildVerdictBadge(verdict)}
    ${renderScore(data.score || 0, verdict)}
    <div class="result-grid" style="margin-top: 18px;">
      ${details.map(([label, value]) => `
        <div class="result-item">
          <strong>${label}</strong>
          <span>${value}</span>
        </div>
      `).join('')}
    </div>
    <div class="output-block">
      <h3>Assessment</h3>
      <p>${explanation}</p>
    </div>
  `;
};

const buildEntropyResultHtml = (data) => {
  const verdict = data.verdict || 'unknown';
  const estimates = data.crack_time_estimates || {};
  const rows = [
    ['Length', data.length ?? 0],
    ['Charset size', data.charset_size ?? 0],
    ['Entropy bits', data.entropy_bits ?? 0],
    ['Common password', data.is_common_password ? 'Yes' : 'No'],
    ['Time (online)', estimates.online_throttled || '—'],
    ['Time (offline fast)', estimates.offline_fast_hash || '—'],
    ['Time (offline slow)', estimates.offline_slow_hash || '—'],
  ];

  return `
    ${buildVerdictBadge(verdict)}
    ${renderScore(data.score || 0, verdict)}
    <div class="result-grid" style="margin-top: 18px;">
      ${rows.map(([label, value]) => `
        <div class="result-item">
          <strong>${label}</strong>
          <span>${value}</span>
        </div>
      `).join('')}
    </div>
    <div class="output-block">
      <h3>Assessment</h3>
      <p>${data.explanation || 'No explanation available.'}</p>
    </div>
  `;
};

const buildAvalancheResultHtml = (data) => {
  const verdict = data.verdict || 'unknown';
  return `
    ${buildVerdictBadge(verdict)}
    ${renderScore(data.score || 0, verdict)}
    <div class="result-grid" style="margin-top: 18px;">
      <div class="result-item"><strong>Algorithm</strong><span>${data.algorithm || '—'}</span></div>
      <div class="result-item"><strong>Changed bits</strong><span>${data.changed_bits ?? 0} / ${data.total_bits ?? 0}</span></div>
      <div class="result-item"><strong>Percent changed</strong><span>${data.percent_changed ?? 0}%</span></div>
      <div class="result-item"><strong>Original</strong><span class="mono">${data.original_hash || '—'}</span></div>
      <div class="result-item"><strong>Flipped</strong><span class="mono">${data.flipped_hash || '—'}</span></div>
      <div class="result-item"><strong>Input</strong><span>${data.original_input || '—'}</span></div>
    </div>
    <div class="output-block">
      <h3>Assessment</h3>
      <p>${data.explanation || 'No explanation available.'}</p>
    </div>
  `;
};

const buildAesResultHtml = (data) => {
  const verdict = data.verdict || 'unknown';
  return `
    ${buildVerdictBadge(verdict)}
    <div class="result-grid" style="margin-top: 18px;">
      <div class="result-item"><strong>Plaintext blocks</strong><span>${data.plaintext_block_count ?? 0}</span></div>
      <div class="result-item"><strong>ECB repeats</strong><span>${data.ecb?.repeated_ciphertext_blocks ?? 0}</span></div>
      <div class="result-item"><strong>ECB pattern leak</strong><span>${data.ecb?.pattern_leaked ? 'Yes' : 'No'}</span></div>
      <div class="result-item"><strong>GCM repeats</strong><span>${data.gcm?.repeated_ciphertext_blocks ?? 0}</span></div>
      <div class="result-item"><strong>GCM pattern leak</strong><span>${data.gcm?.pattern_leaked ? 'Yes' : 'No'}</span></div>
      <div class="result-item"><strong>Nonce</strong><span class="mono">${data.gcm?.nonce_hex || '—'}</span></div>
    </div>
    <div class="output-block">
      <h3>ECB Ciphertext</h3>
      <pre class="mono">${data.ecb?.ciphertext_hex || '—'}</pre>
    </div>
    <div class="output-block">
      <h3>GCM Ciphertext</h3>
      <pre class="mono">${data.gcm?.ciphertext_hex || '—'}</pre>
    </div>
    <div class="output-block">
      <h3>Assessment</h3>
      <p>${data.explanation || 'No explanation available.'}</p>
    </div>
  `;
};

document.getElementById('hash-crack-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = { hash_value: form.hash_value.value.trim() };
  setLoadingState(form, true);

  try {
    const result = await fetchJson('/api/tests/hash-crack', payload);
    document.getElementById('hash-result').innerHTML = `<div class="result-content">${buildHashResultHtml(result)}</div>`;
    animateResult('hash-result');
  } catch (error) {
    document.getElementById('hash-result').innerHTML = `<div class="error-box">${error.message}</div>`;
    animateResult('hash-result');
  } finally {
    setLoadingState(form, false);
  }
});

document.getElementById('entropy-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = { password: form.password.value.trim() };
  setLoadingState(form, true);

  try {
    const result = await fetchJson('/api/tests/entropy', payload);
    document.getElementById('entropy-result').innerHTML = `<div class="result-content">${buildEntropyResultHtml(result)}</div>`;
    animateResult('entropy-result');
  } catch (error) {
    document.getElementById('entropy-result').innerHTML = `<div class="error-box">${error.message}</div>`;
    animateResult('entropy-result');
  } finally {
    setLoadingState(form, false);
  }
});

document.getElementById('avalanche-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = {
    text: form.text.value.trim(),
    algorithm: form.algorithm.value,
  };
  setLoadingState(form, true);

  try {
    const result = await fetchJson('/api/tests/avalanche', payload);
    document.getElementById('avalanche-result').innerHTML = `<div class="result-content">${buildAvalancheResultHtml(result)}</div>`;
    animateResult('avalanche-result');
  } catch (error) {
    document.getElementById('avalanche-result').innerHTML = `<div class="error-box">${error.message}</div>`;
    animateResult('avalanche-result');
  } finally {
    setLoadingState(form, false);
  }
});

document.getElementById('aes-mode-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = { plaintext: form.plaintext.value };
  setLoadingState(form, true);

  try {
    const result = await fetchJson('/api/tests/aes-mode', payload);
    document.getElementById('aes-result').innerHTML = `<div class="result-content">${buildAesResultHtml(result)}</div>`;
    animateResult('aes-result');
  } catch (error) {
    document.getElementById('aes-result').innerHTML = `<div class="error-box">${error.message}</div>`;
    animateResult('aes-result');
  } finally {
    setLoadingState(form, false);
  }
});

populateQuickFill();
setActiveTab('hash-crack');
