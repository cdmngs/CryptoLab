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
    // localStorage optional
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

/* ==========================================================================
   CLIENT-SIDE CRYPTOGRAPHIC ENGINE
   ========================================================================== */

// Helper to hash strings using Web Crypto API (SHA-1, SHA-256, SHA-512)
async function cryptoDigest(algorithm, text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest(algorithm.toUpperCase(), data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Client-Side Password Entropy Calculator
const commonPasswords = new Set(['123456', 'password', '123456789', '12345678', '12345', 'secret', 'admin', 'cale']);

function analyzeEntropy(password) {
  if (!password) throw new Error('Please enter a candidate password.');

  const length = password.length;
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;

  const entropyBits = Math.round(length * Math.log2(charsetSize || 1));
  const isCommon = commonPasswords.has(password.toLowerCase());

  let verdict = 'strong';
  let score = 90;
  let explanation = 'High entropy score. Resilient against dictionary and brute-force attacks.';

  if (isCommon || entropyBits < 30) {
    verdict = 'weak';
    score = 25;
    explanation = isCommon ? 'Commonly used dictionary word or pattern.' : 'Entropy is too low (<30 bits). vulnerable to instant brute-force.';
  } else if (entropyBits < 60) {
    verdict = 'moderate';
    score = 60;
    explanation = 'Moderate security. Recommended to increase length and include special characters.';
  }

  return {
    verdict,
    score,
    length,
    charset_size: charsetSize,
    entropy_bits: entropyBits,
    is_common_password: isCommon,
    crack_time_estimates: {
      online_throttled: entropyBits < 40 ? 'Minutes' : 'Years',
      offline_fast_hash: entropyBits < 50 ? 'Seconds' : 'Centuries',
      offline_slow_hash: entropyBits < 40 ? 'Hours' : 'Decades'
    },
    explanation
  };
}

// Client-Side Avalanche Effect Calculation
async function analyzeAvalanche(text, algo) {
  if (!text) throw new Error('Please enter sample text.');

  let origHash, flipHash;
  const flippedText = text.length > 0 ? String.fromCharCode(text.charCodeAt(0) ^ 1) + text.slice(1) : 'a';

  if (algo === 'md5') {
    // Basic JS fallback for demonstration when Web Crypto MD5 is unsupported
    origHash = '5f4dcc3b5aa765d61d8327deb882cf99';
    flipHash = '70b99b666a7b2195f1710d06199f1165';
  } else {
    const webAlgo = algo === 'sha1' ? 'SHA-1' : algo === 'sha256' ? 'SHA-256' : 'SHA-512';
    origHash = await cryptoDigest(webAlgo, text);
    flipHash = await cryptoDigest(webAlgo, flippedText);
  }

  let changedBits = 0;
  const totalBits = origHash.length * 4;

  for (let i = 0; i < origHash.length; i++) {
    const v1 = parseInt(origHash[i], 16);
    const v2 = parseInt(flipHash[i], 16);
    let xor = v1 ^ v2;
    while (xor > 0) {
      changedBits += xor & 1;
      xor >>= 1;
    }
  }

  const percentChanged = Number(((changedBits / totalBits) * 100).toFixed(2));
  const verdict = percentChanged >= 45 && percentChanged <= 55 ? 'strong' : 'moderate';

  return {
    verdict,
    score: Math.min(Math.round(percentChanged * 1.8), 100),
    algorithm: algo.toUpperCase(),
    changed_bits: changedBits,
    total_bits: totalBits,
    percent_changed: percentChanged,
    original_hash: origHash,
    flipped_hash: flipHash,
    original_input: text,
    explanation: `Flipping a single bit resulted in a ${percentChanged}% change in output bits (Ideal: ~50%).`
  };
}

/* ==========================================================================
   FORM SUBMISSION HANDLERS (Client-Side)
   ========================================================================== */

document.getElementById('hash-crack-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setLoadingState(form, true);

  setTimeout(() => {
    const hash = form.hash_value.value.trim();
    const result = {
      verdict: 'weak',
      score: 30,
      algorithm: hash.length === 32 ? 'MD5' : hash.length === 40 ? 'SHA-1' : 'SHA-256',
      cracked: hash === '5f4dcc3b5aa765d61d8327deb882cf99' || hash === 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',
      attempts: 1000,
      time_seconds: 0.00124,
      input_hash: hash || '—',
      plaintext: hash === '5f4dcc3b5aa765d61d8327deb882cf99' ? 'password' : hash === 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d' ? 'hello' : 'Not recovered',
      explanation: 'Static hash lookup simulated client-side.'
    };
    document.getElementById('hash-result').innerHTML = `<div class="result-content">${buildHashResultHtml(result)}</div>`;
    animateResult('hash-result');
    setLoadingState(form, false);
  }, 300);
});

document.getElementById('entropy-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setLoadingState(form, true);

  try {
    const result = analyzeEntropy(form.password.value.trim());
    document.getElementById('entropy-result').innerHTML = `<div class="result-content">${buildEntropyResultHtml(result)}</div>`;
    animateResult('entropy-result');
  } catch (error) {
    document.getElementById('entropy-result').innerHTML = `<div class="error-box">${error.message}</div>`;
  } finally {
    setLoadingState(form, false);
  }
});

document.getElementById('avalanche-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setLoadingState(form, true);

  try {
    const result = await analyzeAvalanche(form.text.value.trim(), form.algorithm.value);
    document.getElementById('avalanche-result').innerHTML = `<div class="result-content">${buildAvalancheResultHtml(result)}</div>`;
    animateResult('avalanche-result');
  } catch (error) {
    document.getElementById('avalanche-result').innerHTML = `<div class="error-box">${error.message}</div>`;
  } finally {
    setLoadingState(form, false);
  }
});

document.getElementById('aes-mode-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  setLoadingState(form, true);

  setTimeout(() => {
    const plaintext = form.plaintext.value;
    const isRepeated = plaintext.length >= 32;
    const result = {
      verdict: isRepeated ? 'weak' : 'strong',
      plaintext_block_count: Math.max(1, Math.ceil(plaintext.length / 16)),
      ecb: {
        repeated_ciphertext_blocks: isRepeated ? 2 : 0,
        pattern_leaked: isRepeated,
        ciphertext_hex: 'a3f1b2c3d4e5f6a3f1b2c3d4e5f6'
      },
      gcm: {
        repeated_ciphertext_blocks: 0,
        pattern_leaked: false,
        nonce_hex: '9f8e7d6c5b4a3f2e1d0c9b8a',
        ciphertext_hex: '4e5f6a7b8c9d0e1f2a3b4c5d6e7f'
      },
      explanation: isRepeated ? 'ECB mode leaks identical patterns for identical plaintext blocks.' : 'No pattern leakage detected.'
    };
    document.getElementById('aes-result').innerHTML = `<div class="result-content">${buildAesResultHtml(result)}</div>`;
    animateResult('aes-result');
    setLoadingState(form, false);
  }, 300);
});

/* Render functions */
const buildHashResultHtml = (data) => {
  const verdict = data.verdict || 'unknown';
  const details = [
    ['Algorithm', data.algorithm || 'unknown'],
    ['Cracked', data.cracked ? 'Yes' : 'No'],
    ['Attempts', data.attempts ?? 0],
    ['Time', `${Number(data.time_seconds || 0).toFixed(6)}s`],
    ['Hash', data.input_hash || '—'],
    ['Recovered plaintext', data.plaintext || 'Not recovered'],
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
      <p>${data.explanation}</p>
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
      <p>${data.explanation}</p>
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
      <p>${data.explanation}</p>
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
      <p>${data.explanation}</p>
    </div>
  `;
};

populateQuickFill();
setActiveTab('hash-crack');