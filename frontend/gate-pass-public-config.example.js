/*
 * Gate Pass cross-device / cross-network QR configuration.
 *
 * Production example (recommended):
 *   window.TNP_PUBLIC_BASE_URL = 'https://campus.example.edu';
 *
 * The QR will become:
 *   https://campus.example.edu/gate-pass-verify.html?id=...&token=...
 *
 * Every Internet-connected phone can open that page. The first successful scan is
 * atomically consumed in Supabase/Postgres and the same QR is rejected everywhere else.
 *
 * For local-only testing you can use a LAN URL, but that is NOT Internet-wide.
 */
window.TNP_PUBLIC_BASE_URL = '';
