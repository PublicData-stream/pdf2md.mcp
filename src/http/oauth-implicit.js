'use strict';
const byId = id => document.getElementById(id);
const meta = name => document.querySelector(`meta[name="${name}"]`).content;
const cookieName = 'pdf2md_implicit_state';
function expectedState() {
  const entry = document.cookie.split(';').map(item => item.trim())
    .find(item => item.startsWith(`${cookieName}=`));
  return entry ? entry.slice(cookieName.length + 1) : '';
}
function duration(value) {
  const seconds = Number(value);
  if (!value || !Number.isInteger(seconds) || seconds < 0) {
    return 'Unknown';
  }
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const parts = [];
  if (hours) parts.push(`${hours} hour${hours === 1 ? '' : 's'}`);
  if (minutes) parts.push(`${minutes} minute${minutes === 1 ? '' : 's'}`);
  if (!parts.length) parts.push(`${seconds} second${seconds === 1 ? '' : 's'}`);
  return seconds < 60 ? parts.join(' ') : `${parts.join(' ')} (${seconds} s)`;
}
function fail(title, message) {
  return { ok: false, title, message };
}
function finish() {
  const response = new URLSearchParams(window.location.hash.slice(1));
  // Remove the token from the address bar and browser history entry.
  window.history.replaceState(null, '', window.location.pathname);
  const expected = expectedState();
  const secure = window.location.protocol === 'https:' ? '; Secure' : '';
  document.cookie = `${cookieName}=; Path=/oauth/implicit; Max-Age=0; SameSite=Lax${secure}`;
  if (!expected || response.get('state') !== expected) {
    return fail('Sign-in expired',
      'Rejected: unknown or expired sign-in. It may be older than ten minutes, already used, or from another browser. Start again.');
  }
  const issuer = response.get('iss');
  if ((issuer !== null && issuer !== meta('pdf2md-issuer')) ||
      (issuer === null && meta('pdf2md-require-iss') === 'true')) {
    return fail('Unexpected provider response', 'Rejected: unexpected authorization issuer.');
  }
  if (response.get('error')) {
    return response.get('error') === 'access_denied'
      ? fail('Access denied', 'Authorization was denied by you or the provider.')
      : fail('Sign-in failed', 'The provider rejected the authorization request.');
  }
  const token = response.get('access_token');
  if (!token || (response.get('token_type') || '').toLowerCase() !== 'bearer') {
    return fail('Sign-in failed', 'Rejected: the response has no Bearer access token.');
  }
  return { ok: true, token, expires: response.get('expires_in'), scope: response.get('scope') || '' };
}
function show(result) {
  const page = byId('page');
  if (!result.ok) {
    page.dataset.state = 'error';
    byId('title').textContent = result.title;
    byId('status').textContent = result.message;
    return;
  }
  page.dataset.state = 'success';
  byId('title').textContent = 'Signed in';
  byId('status').textContent = 'Your access token is ready. Copy it before you close this page.';
  byId('access-token').value = result.token;
  byId('expires').textContent = duration(result.expires);
  const scopes = result.scope.split(' ').filter(Boolean);
  const target = byId('scope');
  if (scopes.length) {
    const chips = document.createElement('span');
    chips.className = 'chips';
    for (const scope of scopes) {
      const chip = document.createElement('span');
      chip.className = 'chip';
      chip.textContent = scope;
      chips.append(chip);
    }
    target.replaceChildren(chips);
  }
  byId('result').hidden = false;
}
show(finish());
