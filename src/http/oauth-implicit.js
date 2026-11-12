'use strict';
const byId = id => document.getElementById(id);
const meta = name => document.querySelector(`meta[name="${name}"]`).content;
const cookieName = 'pdf2md_implicit_state';
function expectedState() {
  const entry = document.cookie.split(';').map(item => item.trim())
    .find(item => item.startsWith(`${cookieName}=`));
  return entry ? entry.slice(cookieName.length + 1) : '';
}
function finish() {
  const response = new URLSearchParams(window.location.hash.slice(1));
  // Remove the token from the address bar and browser history entry.
  window.history.replaceState(null, '', window.location.pathname);
  const expected = expectedState();
  const secure = window.location.protocol === 'https:' ? '; Secure' : '';
  document.cookie = `${cookieName}=; Path=/oauth/implicit; Max-Age=0; SameSite=Lax${secure}`;
  if (!expected || response.get('state') !== expected) {
    return 'Rejected: unknown or expired sign-in. Start again.';
  }
  const issuer = response.get('iss');
  if ((issuer !== null && issuer !== meta('pdf2md-issuer')) ||
      (issuer === null && meta('pdf2md-require-iss') === 'true')) {
    return 'Rejected: unexpected authorization issuer.';
  }
  if (response.get('error')) {
    return 'The provider rejected the authorization request.';
  }
  const token = response.get('access_token');
  if (!token || (response.get('token_type') || '').toLowerCase() !== 'bearer') {
    return 'Rejected: the response has no Bearer access token.';
  }
  byId('access-token').value = token;
  const expires = response.get('expires_in') || 'unknown';
  return `Signed in. Expires in: ${expires} seconds. Scope: ${response.get('scope') || ''}.`;
}
byId('status').textContent = finish();
