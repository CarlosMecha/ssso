# Simple SSO

A homemade SSO system for your side projects.

## Endpoints

- `GET /authenticate`: Authenticates the incoming request and returns
200 if the request is valid, 403 otherwise. It can be used to authenticate
session cookies or access tokens. Headers:
    - `X-Auth-Access-Token` or
    - `X-Auth-Cookie-Token`
If the request was successful, the response contains:
    - `X-Auth-User` as the login name
    - `X-Auth-User-Email` as the user's email
    - `X-Auth-User-Name` as the user's name

- `GET /login`: Returns the HTML login form.
- `POST /login`: Validates the user credentials for the form and sets
the session cookie `ssso-session`.
- `POST /logout`: Invalidates the current opened session.
- `GET /me`: Returns the HTML page containing user's information. Can also
return the JSON representation for API calls.
- `POST /me`: Updates passwords, creates and deletes API Tokens.
- `GET /api/users/<login name>`: An internal (not public) API for retrieving
user information.

## Backend

A Postgres database containing:
- `users` table: Contains the user information.
- `sessions` table: Contains the opened user sessions.
- `access_tokens` table: Contains valid personal access tokens.

## Configuration

All parameters must be defined using environment variables:
- `SSSO_DB_HOST`: Database host
- `SSSO_DB_PORT`: Database port
- `SSSO_DB_NAME`: Database name
- `SSSO_DB_USERNAME`: Database username
- `SSSO_DB_PASSWORD`: Database password
- `SSSO_KEY`: Base64 encoded key for encrypt/decrypt text
- `SSSO_DOMAIN`: Cookie domain, where the cookie is valid

### Creating a encryption key

Use `$ bin/ssso generate-key`. The output is base64 encoded.

## Passwords

Passwords are stored using the algorithm BCrypt. To insert a new user,
use `$ bin/ssso insert-user` and follow the instructions.

## Nginx

This application is intended to be deployed behind a nginx server (u
other http server that allows access control). See [the nginx config file](/_nginx/nginx.conf)
for an example.

## Testing

Use docker compose to start all components and add to your `/etc/hosts`:
```
127.0.0.1 localhost-test.com ssso.localhost-test.com a.localhost-test.com b.localhost-test.com
```

## TODO

- Clean up the code
- Add some neat CSS
- Add user registration
