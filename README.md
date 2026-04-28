# Scouts Authentication and Authorization

This workspace now contains a small self-contained Node service that implements the agreed Scouts authentication and authorization model.

## What it does

- Email/password login with admin invite onboarding
- One account per person, with many simultaneous effective roles
- Anonymous requests always receive the `public` role
- Derived roles for `scout`, `parent`, `adult_leader`, `committee_member`, and global `administrator`
- Parent-to-scout inheritance for linked scouts only
- Unit-scoped role checks plus relationship-scoped scout checks
- Immediate role recomputation whenever troop assignments or parent links change
- MFA enforced for administrator accounts

## Run it

```bash
npm test
npm start
```

The service starts on `http://localhost:3000` by default.

## Docker deployment

Build and run the service with Docker Compose:

```bash
docker compose up --build -d
```

The container publishes `http://localhost:3000` and persists authentication data in the `scouts-auth-data` Docker volume. To use a different host port:

```bash
PORT=8080 docker compose up --build -d
```

Useful deployment commands:

```bash
docker compose ps
docker compose logs -f scouts-auth
docker compose down
```

For a direct Docker run without Compose:

```bash
docker build -t scouts-authentication-and-authorization .
docker run -d --name scouts-auth -p 3000:3000 -v scouts-auth-data:/data scouts-authentication-and-authorization
```

## Suggested bootstrap flow

1. `POST /bootstrap/admin`
2. `POST /auth/activate`
3. `POST /auth/login`
4. Use the returned bearer token for `/admin/*` routes

## Main endpoints

- `POST /bootstrap/admin`
- `POST /auth/activate`
- `POST /auth/login`
- `POST /auth/authorize`
- `GET /auth/me`
- `GET /portal/public`
- `GET /portal/member`
- `POST /admin/units`
- `POST /admin/people`
- `PATCH /admin/people/status`
- `POST /admin/relationships/parent-links`
- `DELETE /admin/relationships/parent-links`
- `POST /admin/roles/unit`
- `DELETE /admin/roles/unit`
- `POST /admin/roles/global`
- `DELETE /admin/roles/global`
- `POST /admin/invitations`
- `POST /admin/accounts/reset-password`
- `POST /admin/accounts/reset-mfa`
- `GET /admin/accounts`
- `GET /admin/access/:personId`

## scouts.landing integration

Use `GET /auth/me` to shape navigation and page chrome, then use `POST /auth/authorize` for route or data checks that depend on a specific role, unit, or scout relationship.

## Canonical person mapping

For data authorization, the auth service person id should match the `scouts.orm` person id when a person exists in both systems. Seed scouts with ids such as `scout-1` and adults with ids such as `adult-1`, or pass that value as `externalId` when creating a person. This lets `scouts.orm` enforce checks like "parent can read scout-7" without guessing across separate id spaces.

Example request:

```json
{
  "allowedRoles": ["scout", "parent", "adult_leader"],
  "unitId": "unit_123",
  "scoutPersonId": "person_456"
}
```

Example response:

```json
{
  "authorized": true,
  "actor": {
    "authenticated": true,
    "account": {
      "id": "acct_123",
      "personId": "person_789",
      "email": "parent@example.com",
      "status": "active",
      "mfaConfigured": false,
      "createdAt": "2026-04-25T12:00:00.000Z"
    },
    "person": {
      "id": "person_789",
      "name": "Parent Example",
      "type": "adult",
      "status": "active"
    },
    "globalRoles": ["public", "parent"],
    "unitRoles": [],
    "relationships": [
      {
        "scoutPersonId": "person_456",
        "relationship": "parent",
        "grantsRole": "scout"
      }
    ],
    "explanations": [
      {
        "role": "public",
        "reason": "Default role for every request"
      },
      {
        "role": "parent",
        "reason": "Active parent-to-scout relationship"
      },
      {
        "role": "scout",
        "reason": "Inherited for linked scout person_456"
      }
    ]
  }
}
```
