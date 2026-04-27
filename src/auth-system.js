"use strict";

const { GLOBAL_ASSIGNABLE_ROLES, PERSON_TYPES, ROLES, ROLE_ASSIGNABLE_BY_UNIT } = require("./constants");
const {
  createId,
  createToken,
  createTotpSecret,
  hashPassword,
  verifyPassword,
  verifyTotp
} = require("./security");

class AuthSystem {
  constructor(store) {
    this.store = store;
  }

  createUnit({ name }) {
    const unit = {
      id: createId("unit"),
      name,
      status: "active"
    };
    this.store.data.units.push(unit);
    this.store.save();
    return unit;
  }

  createPerson({ id, name, email, type, unitIds = [], externalId = null }) {
    this.assertPersonType(type);
    if (email) {
      this.assertUniqueEmail(email);
    }
    if (id && this.store.data.people.some((item) => item.id === id)) {
      throw this.error("Person id is already assigned", 409);
    }

    const person = {
      id: id || createId("person"),
      externalId: externalId || id || null,
      name,
      email: email ? this.normalizeEmail(email) : null,
      type,
      unitIds: [...new Set(unitIds)],
      status: "active"
    };
    this.store.data.people.push(person);
    this.store.save();
    return person;
  }

  updatePersonStatus({ personId, status }) {
    const person = this.requirePerson(personId);
    person.status = status;
    this.store.save();
    return person;
  }

  assignUnitRole({ personId, unitId, role }) {
    this.requirePerson(personId);
    this.requireUnit(unitId);
    if (!ROLE_ASSIGNABLE_BY_UNIT.has(role)) {
      throw this.error(`Role ${role} cannot be assigned to a unit`, 400);
    }

    const existing = this.store.data.unitRoleAssignments.find(
      (assignment) =>
        assignment.personId === personId &&
        assignment.unitId === unitId &&
        assignment.role === role
    );

    if (!existing) {
      this.store.data.unitRoleAssignments.push({
        id: createId("ura"),
        personId,
        unitId,
        role,
        status: "active"
      });
      this.store.save();
    }

    return this.describeAccess(personId);
  }

  removeUnitRole({ personId, unitId, role }) {
    const assignment = this.store.data.unitRoleAssignments.find(
      (item) =>
        item.personId === personId &&
        item.unitId === unitId &&
        item.role === role &&
        item.status === "active"
    );
    if (!assignment) {
      throw this.error("Unit role assignment not found", 404);
    }
    assignment.status = "inactive";
    this.store.save();
    return this.describeAccess(personId);
  }

  assignGlobalRole({ personId, role }) {
    this.requirePerson(personId);
    if (!GLOBAL_ASSIGNABLE_ROLES.has(role)) {
      throw this.error(`Role ${role} cannot be assigned globally`, 400);
    }

    const existing = this.store.data.globalRoleAssignments.find(
      (assignment) =>
        assignment.personId === personId &&
        assignment.role === role &&
        assignment.status === "active"
    );

    if (!existing) {
      this.store.data.globalRoleAssignments.push({
        id: createId("gra"),
        personId,
        role,
        status: "active"
      });
      const account = this.findAccountByPersonId(personId);
      if (account && !account.mfaSecret) {
        account.mfaSecret = createTotpSecret();
      }
      this.store.save();
    }

    return this.describeAccess(personId);
  }

  removeGlobalRole({ personId, role }) {
    const assignment = this.store.data.globalRoleAssignments.find(
      (item) => item.personId === personId && item.role === role && item.status === "active"
    );
    if (!assignment) {
      throw this.error("Global role assignment not found", 404);
    }
    assignment.status = "inactive";
    this.store.save();
    return this.describeAccess(personId);
  }

  linkParentToScout({ adultPersonId, scoutPersonId, relationship = "parent" }) {
    const adult = this.requirePerson(adultPersonId);
    const scout = this.requirePerson(scoutPersonId);
    if (adult.type !== PERSON_TYPES.ADULT) {
      throw this.error("Parent link requires an adult person", 400);
    }
    if (scout.type !== PERSON_TYPES.SCOUT) {
      throw this.error("Parent link requires a scout person", 400);
    }

    const existing = this.store.data.parentLinks.find(
      (link) =>
        link.adultPersonId === adultPersonId &&
        link.scoutPersonId === scoutPersonId &&
        link.status === "active"
    );
    if (!existing) {
      this.store.data.parentLinks.push({
        id: createId("plink"),
        adultPersonId,
        scoutPersonId,
        relationship,
        status: "active"
      });
      this.store.save();
    }

    return this.describeAccess(adultPersonId);
  }

  unlinkParentFromScout({ adultPersonId, scoutPersonId }) {
    const link = this.store.data.parentLinks.find(
      (item) =>
        item.adultPersonId === adultPersonId &&
        item.scoutPersonId === scoutPersonId &&
        item.status === "active"
    );
    if (!link) {
      throw this.error("Parent relationship not found", 404);
    }
    link.status = "inactive";
    this.store.save();
    return this.describeAccess(adultPersonId);
  }

  inviteAccount({ personId, email }) {
    const person = this.requirePerson(personId);
    const normalizedEmail = this.normalizeEmail(email);
    this.assertUniqueEmail(normalizedEmail, personId);
    if (person.type === PERSON_TYPES.SCOUT && !normalizedEmail) {
      throw this.error("Scout accounts require a unique email address", 400);
    }

    const priorAccount = this.findAccountByEmail(normalizedEmail);
    if (priorAccount && priorAccount.personId !== personId) {
      throw this.error("An account already exists for that email", 409);
    }

    const token = createToken();
    const invitation = {
      id: createId("invite"),
      personId,
      email: normalizedEmail,
      token,
      status: "pending",
      createdAt: new Date().toISOString()
    };

    person.email = normalizedEmail;
    this.store.data.invitations.push(invitation);
    this.store.save();

    return invitation;
  }

  activateInvitation({ token, password }) {
    const invitation = this.store.data.invitations.find(
      (item) => item.token === token && item.status === "pending"
    );
    if (!invitation) {
      throw this.error("Invitation token is invalid or already used", 404);
    }

    const person = this.requirePerson(invitation.personId);
    const existingAccount = this.findAccountByPersonId(person.id);
    if (existingAccount) {
      throw this.error("This person already has an account", 409);
    }

    const passwordRecord = hashPassword(password);
    const account = {
      id: createId("acct"),
      personId: person.id,
      email: invitation.email,
      passwordHash: passwordRecord.passwordHash,
      passwordSalt: passwordRecord.salt,
      status: "active",
      mfaSecret: this.personHasGlobalRole(person.id, ROLES.ADMINISTRATOR) ? createTotpSecret() : null,
      createdAt: new Date().toISOString()
    };

    invitation.status = "accepted";
    this.store.data.accounts.push(account);
    this.store.save();

    return {
      account: this.redactAccount(account),
      access: this.describeAccess(person.id),
      mfaSetup: account.mfaSecret
        ? {
            required: true,
            secret: account.mfaSecret
          }
        : {
            required: false
          }
    };
  }

  login({ email, credential, credentials, password, otp, allowPasswordless = false }) {
    const loginEmail = this.resolveLoginEmail({ email, credential, credentials });
    const account = this.findAccountByEmail(loginEmail);
    if (!account || account.status !== "active") {
      throw this.error("Invalid email or password", 401);
    }

    const person = this.requirePerson(account.personId);
    if (person.status !== "active") {
      throw this.error("This account is inactive", 403);
    }

    if (!allowPasswordless && !verifyPassword(password || "", account.passwordHash, account.passwordSalt)) {
      throw this.error("Invalid email or password", 401);
    }

    const access = this.describeAccess(person.id);
    const requiresMfa = access.globalRoles.includes(ROLES.ADMINISTRATOR) && !account.mfaExempt;
    if (requiresMfa) {
      if (!account.mfaSecret) {
        account.mfaSecret = createTotpSecret();
        this.store.save();
        throw this.error("MFA setup required for administrator accounts", 403, {
          mfaSetupRequired: true,
          secret: account.mfaSecret
        });
      }
      if (!otp || !verifyTotp(account.mfaSecret, otp)) {
        throw this.error("Administrator accounts require a valid MFA code", 401);
      }
    }

    const session = {
      id: createId("sess"),
      token: createToken(),
      accountId: account.id,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString(),
      status: "active"
    };

    this.store.data.sessions.push(session);
    this.store.save();

    return {
      session: {
        token: session.token,
        expiresAt: session.expiresAt
      },
      account: this.redactAccount(account),
      access
    };
  }

  authenticate(token) {
    if (!token) {
      return {
        authenticated: false,
        roles: [ROLES.PUBLIC],
        globalRoles: [ROLES.PUBLIC],
        unitRoles: [],
        relationships: []
      };
    }

    const session = this.store.data.sessions.find(
      (item) =>
        item.token === token &&
        item.status === "active" &&
        new Date(item.expiresAt).getTime() > Date.now()
    );
    if (!session) {
      throw this.error("Session is invalid or expired", 401);
    }

    const account = this.requireAccount(session.accountId);
    const access = this.describeAccess(account.personId);
    return {
      authenticated: true,
      account: this.redactAccount(account),
      ...access
    };
  }

  authorize({ token, allowedRoles = [ROLES.PUBLIC], unitId = null, scoutPersonId = null }) {
    const actor = this.authenticate(token);
    if (actor.globalRoles.includes(ROLES.ADMINISTRATOR)) {
      return { authorized: true, actor };
    }

    if (allowedRoles.includes(ROLES.PUBLIC)) {
      return { authorized: true, actor };
    }

    const hasGlobalRole = allowedRoles.some((role) => actor.globalRoles.includes(role));
    const hasUnitRole =
      unitId &&
      actor.unitRoles.some(
        (assignment) => assignment.unitId === unitId && allowedRoles.includes(assignment.role)
      );
    const hasRelationshipRole =
      scoutPersonId &&
      actor.relationships.some(
        (link) => link.scoutPersonId === scoutPersonId && allowedRoles.includes(link.grantsRole)
      );

    return {
      authorized: Boolean(hasGlobalRole || hasUnitRole || hasRelationshipRole),
      actor
    };
  }

  describeAccess(personId) {
    const person = this.requirePerson(personId);
    const unitRoles = this.store.data.unitRoleAssignments
      .filter((assignment) => assignment.personId === personId && assignment.status === "active")
      .map((assignment) => ({
        role: assignment.role,
        unitId: assignment.unitId
      }));

    const globalRoles = [ROLES.PUBLIC];
    const explanations = [
      {
        role: ROLES.PUBLIC,
        reason: "Default role for every request"
      }
    ];

    if (person.status === "active" && person.type === PERSON_TYPES.SCOUT) {
      globalRoles.push(ROLES.SCOUT);
      explanations.push({
        role: ROLES.SCOUT,
        reason: "Active scout person record"
      });
    }

    for (const assignment of this.store.data.globalRoleAssignments.filter(
      (item) => item.personId === personId && item.status === "active"
    )) {
      globalRoles.push(assignment.role);
      explanations.push({
        role: assignment.role,
        reason: "Active global role assignment"
      });
    }

    for (const assignment of unitRoles) {
      explanations.push({
        role: assignment.role,
        reason: `Active unit assignment in ${assignment.unitId}`
      });
    }

    const relationships = this.store.data.parentLinks
      .filter((link) => link.adultPersonId === personId && link.status === "active")
      .map((link) => ({
        scoutPersonId: link.scoutPersonId,
        relationship: link.relationship,
        grantsRole: ROLES.SCOUT
      }));

    if (relationships.length > 0) {
      globalRoles.push(ROLES.PARENT);
      explanations.push({
        role: ROLES.PARENT,
        reason: "Active parent-to-scout relationship"
      });
      for (const link of relationships) {
        explanations.push({
          role: ROLES.SCOUT,
          reason: `Inherited for linked scout ${link.scoutPersonId}`
        });
      }
    }

    return {
      person: {
        id: person.id,
        externalId: person.externalId || person.id,
        name: person.name,
        type: person.type,
        status: person.status
      },
      globalRoles: [...new Set(globalRoles)],
      unitRoles,
      relationships,
      explanations
    };
  }

  resetPassword({ accountId, newPassword }) {
    const account = this.requireAccount(accountId);
    const record = hashPassword(newPassword);
    account.passwordHash = record.passwordHash;
    account.passwordSalt = record.salt;
    this.expireSessionsForPerson(account.personId);
    this.store.save();
    return this.redactAccount(account);
  }

  resetAdministratorMfa({ accountId }) {
    const account = this.requireAccount(accountId);
    const access = this.describeAccess(account.personId);
    if (!access.globalRoles.includes(ROLES.ADMINISTRATOR)) {
      throw this.error("MFA reset is only available for administrators", 400);
    }
    account.mfaSecret = createTotpSecret();
    this.expireSessionsForPerson(account.personId);
    this.store.save();
    return {
      account: this.redactAccount(account),
      secret: account.mfaSecret
    };
  }

  listAccounts() {
    return this.store.data.accounts.map((account) => ({
      ...this.redactAccount(account),
      access: this.describeAccess(account.personId)
    }));
  }

  assertPersonType(type) {
    if (!Object.values(PERSON_TYPES).includes(type)) {
      throw this.error(`Unsupported person type: ${type}`, 400);
    }
  }

  personHasGlobalRole(personId, role) {
    return this.store.data.globalRoleAssignments.some(
      (assignment) => assignment.personId === personId && assignment.role === role && assignment.status === "active"
    );
  }

  assertUniqueEmail(email, samePersonId = null) {
    if (!email) {
      return;
    }

    const normalized = this.normalizeEmail(email);
    const conflictPerson = this.store.data.people.find(
      (person) => person.email === normalized && person.id !== samePersonId
    );
    if (conflictPerson) {
      throw this.error("Email is already assigned to another person", 409);
    }

    const conflictAccount = this.store.data.accounts.find(
      (account) =>
        account.email === normalized &&
        (!samePersonId || account.personId !== samePersonId)
    );
    if (conflictAccount) {
      throw this.error("Email is already assigned to another account", 409);
    }
  }

  normalizeEmail(email) {
    return String(email).trim().toLowerCase();
  }

  resolveLoginEmail({ email, credential, credentials }) {
    const candidate =
      email ??
      (typeof credential === "string" ? credential : credential?.email) ??
      (typeof credentials === "string" ? credentials : credentials?.email);
    const normalized = this.normalizeEmail(candidate || "");
    if (!normalized || !normalized.includes("@")) {
      throw this.error("Login requires an email address", 400);
    }
    return normalized;
  }

  requirePerson(personId) {
    const person = this.store.data.people.find((item) => item.id === personId);
    if (!person) {
      throw this.error("Person not found", 404);
    }
    return person;
  }

  requireUnit(unitId) {
    const unit = this.store.data.units.find((item) => item.id === unitId);
    if (!unit) {
      throw this.error("Unit not found", 404);
    }
    return unit;
  }

  requireAccount(accountId) {
    const account = this.store.data.accounts.find((item) => item.id === accountId);
    if (!account) {
      throw this.error("Account not found", 404);
    }
    return account;
  }

  findAccountByEmail(email) {
    const normalized = this.normalizeEmail(email);
    return this.store.data.accounts.find((item) => item.email === normalized) || null;
  }

  findAccountByPersonId(personId) {
    return this.store.data.accounts.find((item) => item.personId === personId) || null;
  }

  redactAccount(account) {
    return {
      id: account.id,
      personId: account.personId,
      email: account.email,
      status: account.status,
      mfaConfigured: Boolean(account.mfaSecret),
      createdAt: account.createdAt
    };
  }

  expireSessionsForPerson(personId) {
    const account = this.findAccountByPersonId(personId);
    if (!account) {
      return;
    }
    for (const session of this.store.data.sessions) {
      if (session.accountId === account.id) {
        session.status = "revoked";
      }
    }
  }

  error(message, statusCode, extra = {}) {
    const error = new Error(message);
    error.statusCode = statusCode;
    Object.assign(error, extra);
    return error;
  }
}

module.exports = { AuthSystem };
