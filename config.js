// config — single source of truth for secrets.
// Root cause of the old bug: the HMAC secret was hard-coded ('dev-secret-123')
// in store.js AND leaked by /health, so anyone could forge admin tokens.
// Fix: the secret comes ONLY from the environment. No default, no fallback.
// The process fails fast at startup (and at first token use) when it is unset.
function getSecret() {
  const secret = process.env.API_SECRET;
  if (!secret || typeof secret !== 'string' || secret.length < 16) {
    throw new Error('API_SECRET environment variable is required (min 16 chars). See .env.example.');
  }
  return secret;
}

module.exports = { getSecret };
