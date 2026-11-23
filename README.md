# BandUp

BandUp is a static learning site with same-origin Cloudflare Pages Functions and a D1 database. Student accounts, course progress, scores, and the public leaderboard are stored on the server so they work across devices. Telegram login is intentionally not part of this first deployment.

## Cloudflare setup

1. Create a Cloudflare Pages project connected to this repository. Use the repository root (`.`) as the build output directory and no build command.
2. Create a D1 database named `bandup`, then replace `REPLACE_WITH_CLOUDFLARE_D1_DATABASE_ID` in `wrangler.toml` with its database ID.
3. Apply `migrations/0001_initial.sql` to the new database before exposing the site. Bind it to the Pages project as `DB` if the dashboard did not import the binding from `wrangler.toml`.
4. In the Pages project settings, add the secret `ADMIN_SETUP_KEY` and choose a long, random value. Keep it private. `ADMIN_USERNAME` is configured as `Ali`; the owner must create that account first and enter the setup key in the optional administrator field on the registration screen. Once the admin account exists, the setup key may be removed.
5. Redeploy after configuring the D1 binding and secret.

Never put database credentials, admin passwords, or `ADMIN_SETUP_KEY` in the repository. Choose a strong account password on the registration page. The one-time admin setup key is not the account password.

## Account and score behavior

- Passwords are stored as salted PBKDF2-SHA-256 hashes; sessions use secure, HttpOnly cookies.
- The leaderboard lists all student accounts, sorted by points. Admin accounts are excluded.
- Each lesson is worth at most 10 points. A wrong answer reduces that attempt by one point; a retry can improve the best result up to 10. A lesson with a perfect result cannot be retried.
- Test results are checked against the server's answer key. Repeating a test only improves its best result, so it cannot add points indefinitely. Games are for practice and do not award leaderboard points.
- English and IELTS preparation progress is synced to the account.
- Admin controls are authorized by the session role on the server. The page is not protected by a password embedded in client code.

Cloudflare's free tier has request and database limits. If usage exceeds them, the API may pause until the limit resets or the plan is upgraded. Back up the D1 data before changing providers.
