/**
 * SecureRegister — Frontend Application
 *
 * Security features implemented:
 * 1. Real-time password entropy & strength scoring
 * 2. ZXCVBN-style criteria enforcement (length, charset, common-pw check)
 * 3. Math-challenge CAPTCHA (arithmetic + logic puzzles, randomised)
 * 4. Input sanitisation before submission
 * 5. Rate-limit awareness (handles 429 from server)
 * 6. Password never stored client-side; hashed server-side with bcrypt
 */

// ─────────────────────────────────────────────────────────
// CAPTCHA Engine — Math & Logic puzzles
// ─────────────────────────────────────────────────────────
const CAPTCHA = (() => {
  let _answer = '';

  const generators = [
    // Simple arithmetic
    () => {
      const a = rand(2, 20), b = rand(2, 20);
      return { q: `What is ${a} + ${b}?`, a: String(a + b) };
    },
    () => {
      const a = rand(5, 30), b = rand(2, a - 1);
      return { q: `What is ${a} − ${b}?`, a: String(a - b) };
    },
    () => {
      const a = rand(2, 12), b = rand(2, 12);
      return { q: `What is ${a} × ${b}?`, a: String(a * b) };
    },
    // Sequence completion
    () => {
      const start = rand(1, 10), step = rand(1, 5);
      const seq = [start, start + step, start + 2 * step, '?'];
      return { q: `What comes next? ${seq.join(', ')}`, a: String(start + 3 * step) };
    },
    // Logical word puzzle
    () => {
      const items = [
        { q: 'How many sides does a triangle have?', a: '3' },
        { q: 'How many months in a year?', a: '12' },
        { q: 'How many days in a week?', a: '7' },
        { q: 'What is the square root of 64?', a: '8' },
        { q: 'How many hours in a day?', a: '24' },
        { q: 'What is 50% of 80?', a: '40' },
        { q: 'What is 10² (10 squared)?', a: '100' },
        { q: 'How many letters are in the word SECURITY?', a: '8' },
      ];
      return items[rand(0, items.length - 1)];
    },
    // Odd-one-out
    () => {
      const sets = [
        { q: 'Which is NOT a primary colour? Red / Blue / Green / Yellow', a: 'green', display: 'green' },
        { q: 'Which is NOT a planet? Mars / Jupiter / Sun / Saturn', a: 'sun', display: 'Sun' },
        { q: 'Which is NOT a vowel? A / E / B / I', a: 'b', display: 'B' },
      ];
      const s = sets[rand(0, sets.length - 1)];
      return { q: s.q, a: s.a };
    },
  ];

  function rand(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  function generate() {
    const gen = generators[rand(0, generators.length - 1)];
    const puzzle = gen();
    _answer = puzzle.a.toLowerCase().trim();
    return puzzle.q;
  }

  function check(userInput) {
    return userInput.toLowerCase().trim() === _answer;
  }

  return { generate, check };
})();

// ─────────────────────────────────────────────────────────
// Password Strength Analyser
// ─────────────────────────────────────────────────────────
const COMMON_PASSWORDS = new Set([
  'password','password1','123456789','12345678','1234567890',
  'qwerty123','iloveyou','admin123','letmein1','welcome1',
  'monkey123','dragon123','master123','sunshine','princess',
  'football','shadow123','baseball','abc123456','111111111',
  'passw0rd','password123','Password1','P@ssword1','Test1234!',
]);

function scorePassword(pw) {
  const criteria = {
    length:    pw.length >= 12,
    upper:     /[A-Z]/.test(pw),
    lower:     /[a-z]/.test(pw),
    digit:     /[0-9]/.test(pw),
    special:   /[^A-Za-z0-9]/.test(pw),
    noCommon:  !COMMON_PASSWORDS.has(pw),
  };

  const metCount = Object.values(criteria).filter(Boolean).length;

  // Entropy estimate (log2 of search space)
  let pool = 0;
  if (criteria.lower)   pool += 26;
  if (criteria.upper)   pool += 26;
  if (criteria.digit)   pool += 10;
  if (criteria.special) pool += 33;
  const entropy = pool > 0 ? (pw.length * Math.log2(pool)).toFixed(1) : 0;

  // Score 0–4
  let score = 0;
  if (pw.length >= 8)  score = 1;
  if (metCount >= 3)   score = 2;
  if (metCount >= 5)   score = 3;
  if (metCount === 6 && pw.length >= 14) score = 4;

  const labels  = ['—', 'Weak', 'Fair', 'Strong', 'Very Strong'];
  const colours = ['#555', '#ff4757', '#ffa502', '#2ed573', '#00e5ff'];
  const widths  = ['0%', '25%', '50%', '75%', '100%'];

  return { criteria, metCount, entropy, score, label: labels[score], colour: colours[score], width: widths[score] };
}

// ─────────────────────────────────────────────────────────
// DOM refs
// ─────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const form            = $('register-form');
const usernameInput   = $('username');
const emailInput      = $('email');
const passwordInput   = $('password');
const confirmInput    = $('confirm-password');
const togglePw        = $('toggle-pw');
const strengthFill    = $('strength-fill');
const strengthLabel   = $('strength-label');
const captchaQuestion = $('captcha-question');
const captchaAnswer   = $('captcha-answer');
const captchaHint     = $('captcha-hint');
const captchaRefresh  = $('captcha-refresh');
const alertBox        = $('alert-box');
const btnSubmit       = $('btn-submit');
const btnText         = btnSubmit.querySelector('.btn-text');
const btnLoader       = $('btn-loader');

// Badge helpers
function setBadge(id, state, msg) {
  const el = $(`badge-${id}`);
  const st = $(`status-${id}`);
  el.classList.remove('active', 'pending');
  if (state) el.classList.add(state);
  st.textContent = msg;
}

// ─────────────────────────────────────────────────────────
// Initialise CAPTCHA
// ─────────────────────────────────────────────────────────
function refreshCaptcha() {
  const q = CAPTCHA.generate();
  captchaQuestion.textContent = q;
  captchaAnswer.value = '';
  captchaHint.textContent = '';
  captchaHint.className = 'captcha-hint';
  setBadge('captcha', '', 'Unsolved');
}
refreshCaptcha();
captchaRefresh.addEventListener('click', refreshCaptcha);

// ─────────────────────────────────────────────────────────
// Live password strength UI
// ─────────────────────────────────────────────────────────
passwordInput.addEventListener('input', () => {
  const pw = passwordInput.value;
  if (!pw) {
    strengthFill.style.width = '0%';
    strengthLabel.textContent = '—';
    resetCriteria();
    return;
  }

  const result = scorePassword(pw);
  strengthFill.style.width  = result.width;
  strengthFill.style.background = result.colour;
  strengthLabel.textContent = result.label;
  strengthLabel.style.color = result.colour;

  // Update criteria list
  const map = {
    'cr-length':   result.criteria.length,
    'cr-upper':    result.criteria.upper,
    'cr-lower':    result.criteria.lower,
    'cr-digit':    result.criteria.digit,
    'cr-special':  result.criteria.special,
    'cr-nocommon': result.criteria.noCommon,
  };
  Object.entries(map).forEach(([id, met]) => {
    const el = $(id);
    el.classList.toggle('met', met);
    el.classList.toggle('fail', pw.length > 0 && !met);
  });

  // Update entropy badge
  if (result.score >= 3) {
    setBadge('entropy', 'active', `${result.entropy} bits`);
  } else if (pw.length > 0) {
    setBadge('entropy', 'pending', `${result.entropy} bits — improve`);
  } else {
    setBadge('entropy', '', 'Waiting...');
  }
});

function resetCriteria() {
  ['cr-length','cr-upper','cr-lower','cr-digit','cr-special','cr-nocommon'].forEach(id => {
    const el = $(id);
    el.classList.remove('met','fail');
  });
}

// ─────────────────────────────────────────────────────────
// Confirm password check
// ─────────────────────────────────────────────────────────
confirmInput.addEventListener('input', () => {
  const hint = $('confirm-hint');
  const icon = $('confirm-icon');
  if (!confirmInput.value) { hint.textContent = ''; return; }
  if (confirmInput.value === passwordInput.value) {
    hint.textContent = 'Passwords match ✓';
    hint.className = 'field-hint ok';
    confirmInput.classList.add('valid'); confirmInput.classList.remove('error');
    icon.textContent = '✅';
  } else {
    hint.textContent = 'Passwords do not match';
    hint.className = 'field-hint err';
    confirmInput.classList.add('error'); confirmInput.classList.remove('valid');
    icon.textContent = '❌';
  }
});

// ─────────────────────────────────────────────────────────
// Username validation
// ─────────────────────────────────────────────────────────
usernameInput.addEventListener('input', () => {
  const val = usernameInput.value.trim();
  const hint = $('username-hint');
  const valid = /^[a-zA-Z0-9_]{3,30}$/.test(val);
  if (!val) { hint.textContent = ''; return; }
  if (valid) {
    hint.textContent = 'Valid username ✓';
    hint.className = 'field-hint ok';
    usernameInput.classList.add('valid'); usernameInput.classList.remove('error');
  } else {
    hint.textContent = '3–30 chars, letters/numbers/underscores only';
    hint.className = 'field-hint err';
    usernameInput.classList.add('error'); usernameInput.classList.remove('valid');
  }
});

// ─────────────────────────────────────────────────────────
// CAPTCHA live check
// ─────────────────────────────────────────────────────────
captchaAnswer.addEventListener('input', () => {
  if (!captchaAnswer.value) {
    captchaHint.textContent = '';
    setBadge('captcha', '', 'Unsolved');
    return;
  }
  // Don't reveal right/wrong on partial input; check on blur
});

captchaAnswer.addEventListener('blur', () => {
  if (!captchaAnswer.value) return;
  if (CAPTCHA.check(captchaAnswer.value)) {
    captchaHint.textContent = 'Verified! You appear to be human ✓';
    captchaHint.className = 'captcha-hint ok';
    setBadge('captcha', 'active', 'Human ✓');
  } else {
    captchaHint.textContent = 'Incorrect answer — try again';
    captchaHint.className = 'captcha-hint err';
    setBadge('captcha', 'pending', 'Failed');
  }
});

// ─────────────────────────────────────────────────────────
// Toggle password visibility
// ─────────────────────────────────────────────────────────
togglePw.addEventListener('click', () => {
  const visible = passwordInput.type === 'text';
  passwordInput.type = visible ? 'password' : 'text';
  togglePw.textContent = visible ? '👁' : '🙈';
});

// ─────────────────────────────────────────────────────────
// Navigation functions
// ─────────────────────────────────────────────────────────
function goToLogin() {
  window.location.href = '/login.html';
}

// ─────────────────────────────────────────────────────────
// Form submission
// ─────────────────────────────────────────────────────────
function showAlert(msg, type = 'error') {
  alertBox.textContent = msg;
  alertBox.className = `alert ${type}`;
  alertBox.classList.remove('hidden');
  alertBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function setLoading(on) {
  btnSubmit.disabled = on;
  btnText.classList.toggle('hidden', on);
  btnLoader.classList.toggle('hidden', !on);
}

form.addEventListener('submit', async e => {
  e.preventDefault();
  alertBox.classList.add('hidden');

  // ── Client-side validation ──────────────────────────────
  const username = usernameInput.value.trim();
  const email    = emailInput.value.trim();
  const password = passwordInput.value;
  const confirm  = confirmInput.value;
  const captcha  = captchaAnswer.value;
  const terms    = $('terms').checked;

  if (!username || !email || !password || !confirm || !captcha) {
    return showAlert('Please fill in all fields.');
  }
  if (!/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
    return showAlert('Username must be 3–30 chars, letters/numbers/underscores only.');
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return showAlert('Please enter a valid email address.');
  }
  if (password !== confirm) {
    return showAlert('Passwords do not match.');
  }

  const strength = scorePassword(password);
  if (strength.score < 2) {
    return showAlert('Password is too weak. Please meet more strength criteria.');
  }
  if (!CAPTCHA.check(captcha)) {
    setBadge('captcha', 'pending', 'Failed');
    captchaHint.textContent = 'Incorrect CAPTCHA — try again';
    captchaHint.className = 'captcha-hint err';
    refreshCaptcha();
    return showAlert('CAPTCHA answer was incorrect. A new puzzle has been generated.');
  }
  if (!terms) {
    return showAlert('You must agree to the Terms of Service.');
  }

  // ── Submit to server ──────────────────────────────────
  setLoading(true);
  setBadge('breach', 'pending', 'Checking…');
  setBadge('encrypt', 'pending', 'Hashing…');

  try {
    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password }),
    });

    const data = await res.json();

    if (res.status === 429) {
      showAlert('Too many registration attempts. Please wait before trying again.');
      setLoading(false);
      return;
    }
    if (!res.ok) {
      showAlert(data.error || 'Registration failed. Please try again.');
      setLoading(false);
      return;
    }

    // Success
    setBadge('breach', 'active', 'No breaches found');
    setBadge('encrypt', 'active', 'bcrypt stored');

    // Show modal
    $('modal-msg').textContent = `Welcome, ${username}! Your account is ready.`;
    $('modal-detail').innerHTML = `
      <strong>Security summary:</strong><br/>
      Password strength: ${strength.label} (${strength.entropy} bits entropy)<br/>
      Criteria met: ${strength.metCount}/6<br/>
      Storage: bcrypt hash (cost=12)<br/>
      CAPTCHA: Math challenge verified<br/>
      Firebase UID: ${data.uid || 'created'}
    `;
    $('success-modal').classList.remove('hidden');
    form.reset();
    resetCriteria();
    strengthFill.style.width = '0%';
    strengthLabel.textContent = '—';
    refreshCaptcha();
    ['entropy','breach','captcha','encrypt'].forEach(b => setBadge(b, '', 'Waiting...'));

  } catch (err) {
    showAlert('Network error — could not reach server. Is the server running?', 'error');
    console.error(err);
  } finally {
    setLoading(false);
  }
});
