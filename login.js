/**
 * SecureReg - Login Page JavaScript
 */

// ─────────────────────────────────────────────────────────
// DOM refs
// ─────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const form            = $('login-form');
const usernameInput   = $('username');
const passwordInput   = $('password');
const togglePw        = $('toggle-pw');
const alertBox        = $('alert-box');
const btnSubmit       = $('btn-submit');
const btnText         = btnSubmit.querySelector('.btn-text');
const btnLoader       = $('btn-loader');

// Initialize reCAPTCHA when page loads
document.addEventListener('DOMContentLoaded', function() {
  if (typeof grecaptcha !== 'undefined') {
    grecaptcha.render('recaptcha-container', {
      'sitekey': '6Ld_6K4sAAAAAB4Xj642z4SGVe_IzBL1wYLadUHF',
      'callback': function() {
        console.log('reCAPTCHA loaded successfully');
      },
      'expired-callback': function() {
        showAlert('reCAPTCHA expired. Please verify again.');
      }
    });
  }
});

// Badge helpers
function setBadge(id, state, msg) {
  const el = $(`badge-${id}`);
  const st = $(`status-${id}`);
  el.classList.remove('active', 'pending');
  if (state) el.classList.add(state);
  st.textContent = msg;
}

// ─────────────────────────────────────────────────────────
// Toggle password visibility
// ─────────────────────────────────────────────────────────
togglePw.addEventListener('click', () => {
  const visible = passwordInput.type === 'text';
  passwordInput.type = visible ? 'password' : 'text';
  togglePw.textContent = visible ? '👁' : '🙈';
});

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

  // Client-side validation
  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  if (!username || !password) {
    return showAlert('Please fill in all fields.');
  }

  // Check Google reCAPTCHA
  const recaptchaResponse = grecaptcha.getResponse();
  if (!recaptchaResponse) {
    return showAlert('Please complete the reCAPTCHA verification.');
  }

  // ── Submit to server ──────────────────────────────────
  setLoading(true);
  setBadge('auth', 'pending', 'Authenticating...');

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, recaptchaResponse }),
    });

    const data = await res.json();

    if (!res.ok) {
      showAlert(data.error || 'Login failed. Please check your credentials.');
      setBadge('auth', 'pending', 'Failed');
      grecaptcha.reset(); // Reset reCAPTCHA on failure
      setLoading(false);
      return;
    }

    // Success
    setBadge('auth', 'active', 'Authenticated ✓');
    
    // Redirect to success page
    window.location.href = '/success.html';

  } catch (err) {
    showAlert('Network error — could not reach server. Is the server running?', 'error');
    setBadge('auth', 'pending', 'Network error');
    console.error(err);
  } finally {
    setLoading(false);
  }
});

// ─────────────────────────────────────────────────────────
// Go back function
// ─────────────────────────────────────────────────────────
function goBack() {
  window.location.href = '/index.html';
}
