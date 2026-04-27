"use strict";

const http = require("node:http");
const path = require("node:path");
const { AuthSystem } = require("./auth-system");
const { ROLES } = require("./constants");
const { JsonStore } = require("./json-store");
const { syncLocalDemoAccounts } = require("./local-demo-sync");

const dataFile = path.join(__dirname, "..", "data", "store.json");
const authSystem = new AuthSystem(new JsonStore(dataFile));
syncLocalDemoAccounts(authSystem);

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, { "Content-Type": "application/json" });
  response.end(JSON.stringify(payload, null, 2));
}

function getBearerToken(request) {
  const header = request.headers.authorization || "";
  if (!header.startsWith("Bearer ")) {
    return null;
  }
  return header.slice("Bearer ".length);
}

function isLocalRequest(request) {
  const address = request.socket.remoteAddress || "";
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function isLocalDemoLogin(request) {
  return isLocalRequest(request) || request.headers["x-local-demo-login"] === "true";
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk.toString();
    });
    request.on("end", () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch (error) {
        reject(new Error("Request body must be valid JSON"));
      }
    });
    request.on("error", reject);
  });
}

function requireAuthorization(request, response, allowedRoles, options = {}) {
  const result = authSystem.authorize({
    token: getBearerToken(request),
    allowedRoles,
    unitId: options.unitId || null,
    scoutPersonId: options.scoutPersonId || null
  });
  if (!result.authorized) {
    sendJson(response, 403, { error: "Forbidden", actor: result.actor });
    return null;
  }
  return result.actor;
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url, "http://localhost");
    const body = ["POST", "PUT", "PATCH"].includes(request.method) ? await readBody(request) : {};

    if (request.method === "GET" && url.pathname === "/health") {
      return sendJson(response, 200, { ok: true });
    }

    if (request.method === "GET" && url.pathname === "/portal/public") {
      return sendJson(response, 200, {
        authorized: true,
        access: authSystem.authenticate(getBearerToken(request))
      });
    }

    if (request.method === "GET" && url.pathname === "/portal/member") {
      const actor = requireAuthorization(request, response, [
        ROLES.SCOUT,
        ROLES.PARENT,
        ROLES.ADULT_LEADER,
        ROLES.COMMITTEE_MEMBER,
        ROLES.ADMINISTRATOR
      ]);
      if (!actor) {
        return;
      }
      return sendJson(response, 200, { authorized: true, actor });
    }

    if (request.method === "POST" && url.pathname === "/bootstrap/admin") {
      if (authSystem.listAccounts().length > 0) {
        return sendJson(response, 409, {
          error: "Bootstrap is only available before the first account exists"
        });
      }
      const unit = authSystem.createUnit({ name: body.unitName || "Troop 1" });
      const person = authSystem.createPerson({
        name: body.name || "Bootstrap Administrator",
        email: body.email,
        type: "adult",
        unitIds: [unit.id]
      });
      authSystem.assignGlobalRole({ personId: person.id, role: ROLES.ADMINISTRATOR });
      const invitation = authSystem.inviteAccount({ personId: person.id, email: body.email });
      return sendJson(response, 201, { unit, person, invitation });
    }

    if (request.method === "POST" && url.pathname === "/auth/activate") {
      return sendJson(response, 201, authSystem.activateInvitation(body));
    }

    if (request.method === "POST" && url.pathname === "/auth/login") {
      const allowPasswordless = isLocalDemoLogin(request) && !body.password;
      if (allowPasswordless) {
        syncLocalDemoAccounts(authSystem);
      }
      return sendJson(response, 200, authSystem.login({
        ...body,
        allowPasswordless
      }));
    }

    if (request.method === "POST" && url.pathname === "/auth/authorize") {
      return sendJson(response, 200, authSystem.authorize({
        token: getBearerToken(request),
        allowedRoles: body.allowedRoles || [ROLES.PUBLIC],
        unitId: body.unitId || null,
        scoutPersonId: body.scoutPersonId || null
      }));
    }

    if (request.method === "GET" && url.pathname === "/auth/me") {
      return sendJson(response, 200, authSystem.authenticate(getBearerToken(request)));
    }

    if (request.method === "POST" && url.pathname === "/admin/units") {
      const actor = requireAuthorization(request, response, [ROLES.ADMINISTRATOR]);
      if (!actor) {
        return;
      }
      return sendJson(response, 201, authSystem.createUnit(body));
    }

    if (request.method === "POST" && url.pathname === "/admin/people") {
      const actor = requireAuthorization(request, response, [ROLES.ADMINISTRATOR]);
      if (!actor) {
        return;
      }
      return sendJson(response, 201, authSystem.createPerson(body));
    }

    if (request.method === "POST" && url.pathname === "/admin/relationships/parent-links") {
      const actor = requireAuthorization(request, response, [ROLES.ADMINISTRATOR]);
      if (!actor) {
        return;
      }
      return sendJson(response, 201, authSystem.linkParentToScout(body));
    }

    if (request.method === "DELETE" && url.pathname === "/admin/relationships/parent-links") {
      const actor = requireAuthorization(request, response, [ROLES.ADMINISTRATOR]);
      if (!actor) {
        return;
      }
      return sendJson(response, 200, authSystem.unlinkParentFromScout(body));
    }

    if (request.method === "POST" && url.pathname === "/admin/roles/unit") {
      const actor = requireAuthorization(request, response, [ROLES.ADMINISTRATOR]);
      if (!actor) {
        return;
      }
      return sendJson(response, 201, authSystem.assignUnitRole(body));
    }

    if (request.method === "DELETE" && url.pathname === "/admin/roles/unit") {
      const actor = requireAuthorization(request, response, [ROLES.ADMINISTRATOR]);
      if (!actor) {
        return;
      }
      return sendJson(response, 200, authSystem.removeUnitRole(body));
    }

    if (request.method === "POST" && url.pathname === "/admin/roles/global") {
      const actor = requireAuthorization(request, response, [ROLES.ADMINISTRATOR]);
      if (!actor) {
        return;
      }
      return sendJson(response, 201, authSystem.assignGlobalRole(body));
    }

    if (request.method === "DELETE" && url.pathname === "/admin/roles/global") {
      const actor = requireAuthorization(request, response, [ROLES.ADMINISTRATOR]);
      if (!actor) {
        return;
      }
      return sendJson(response, 200, authSystem.removeGlobalRole(body));
    }

    if (request.method === "POST" && url.pathname === "/admin/invitations") {
      const actor = requireAuthorization(request, response, [ROLES.ADMINISTRATOR]);
      if (!actor) {
        return;
      }
      return sendJson(response, 201, authSystem.inviteAccount(body));
    }

    if (request.method === "POST" && url.pathname === "/admin/accounts/reset-password") {
      const actor = requireAuthorization(request, response, [ROLES.ADMINISTRATOR]);
      if (!actor) {
        return;
      }
      return sendJson(response, 200, authSystem.resetPassword(body));
    }

    if (request.method === "POST" && url.pathname === "/admin/accounts/reset-mfa") {
      const actor = requireAuthorization(request, response, [ROLES.ADMINISTRATOR]);
      if (!actor) {
        return;
      }
      return sendJson(response, 200, authSystem.resetAdministratorMfa(body));
    }

    if (request.method === "PATCH" && url.pathname === "/admin/people/status") {
      const actor = requireAuthorization(request, response, [ROLES.ADMINISTRATOR]);
      if (!actor) {
        return;
      }
      return sendJson(response, 200, authSystem.updatePersonStatus(body));
    }

    if (request.method === "GET" && url.pathname === "/admin/accounts") {
      const actor = requireAuthorization(request, response, [ROLES.ADMINISTRATOR]);
      if (!actor) {
        return;
      }
      return sendJson(response, 200, authSystem.listAccounts());
    }

    if (request.method === "GET" && url.pathname.startsWith("/admin/access/")) {
      const actor = requireAuthorization(request, response, [ROLES.ADMINISTRATOR]);
      if (!actor) {
        return;
      }
      const personId = url.pathname.slice("/admin/access/".length);
      return sendJson(response, 200, authSystem.describeAccess(personId));
    }

    return sendJson(response, 404, { error: "Not found" });
  } catch (error) {
    const statusCode = error.statusCode || 500;
    return sendJson(response, statusCode, {
      error: error.message,
      details: {
        mfaSetupRequired: error.mfaSetupRequired || false,
        secret: error.secret || null
      }
    });
  }
});

if (require.main === module) {
  const port = process.env.PORT || 3000;
  server.listen(port, () => {
    console.log(`Scouts auth service listening on http://localhost:${port}`);
  });
}

module.exports = { authSystem, server };
