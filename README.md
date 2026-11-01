# Login Limiter

WordPress-native brute-force protection — no fail2ban, no server module, no
third-party service required.

## How it works

- Counts failed logins per IP inside a sliding window (default: 5 failures in
  15 minutes).
- On crossing the threshold the IP is locked out (default: 60 minutes) and
  `wp-login.php` answers with a "too many failed attempts" error.
- A successful login resets the counter, so a typo streak never locks out a
  real user permanently.
- Lockouts are logged (last 100) and shown on the settings page.

## Settings (Settings → Login Limiter)

- Max failed attempts, counting window, lockout duration.
- **Allow-list**: IPs or CIDR ranges (e.g. `203.0.113.0/24`) that are never
  limited — put your office/home IP here.

## Filters

- `wll_client_ip` — override IP detection, e.g. to trust
  `X-Forwarded-For` behind a known proxy:
  ```php
  add_filter( 'wll_client_ip', function () {
      return $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
  } );
  ```
  Only use this behind a proxy you control — a spoofable header defeats the
  limiter.

## Installation

1. Upload the plugin folder to `wp-content/plugins/`.
2. Activate it and tune the thresholds under Settings → Login Limiter.

## License

MIT — see `LICENSE`.
