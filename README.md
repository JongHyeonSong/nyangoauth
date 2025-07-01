# NyangOAuth

A simple OAuth 2.0 service for authentication and authorization.

## Features

- User registration and login
- Service registration
- OAuth 2.0 Authorization Code Grant flow
- Token issuance and validation

## Project Structure

- `app.js` — Main server code
- `public/` — Static frontend files (HTML, CSS, JS)
- `sessions/` — Session storage (excluded from git)
- `db.properties` — Simple key-value database (excluded from git)
- `generate-oauth-credentials.js` — Utility for generating OAuth credentials
- `outside/` — Example external service integration

## Getting Started

### Prerequisites

- Node.js (v16+)
- npm

### Installation

```sh
git clone <your-repo-url>
cd nyangoauth
npm install
```

### Running the Server

```sh
npm start
```

Visit [http://localhost:3000](http://localhost:3000) in your browser.

### Development

```sh
npm run dev
```

## Usage

- Register a user at `/signup.html`
- Register a service at `/register-service.html`
- Log in at `/login.html`
- Manage users/services at `/dashboard.html`
- OAuth endpoints:
  - `/oauth/authorize`
  - `/oauth/token`
  - `/oauth/userinfo`

## Notes

- `db.properties` and `sessions/` are excluded from version control for security.
- For demonstration and learning purposes only.

## License

MIT