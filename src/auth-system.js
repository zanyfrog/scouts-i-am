"use strict";

const {
  FIELD_SCOPES,
  GLOBAL_ASSIGNABLE_ROLES,
  PERMISSIONS,
  PERSON_TYPES,
  POSITIONS,
  POSITION_PERMISSIONS,
  ROLES,
  ROLE_ALIASES,
  ROLE_ASSIGNABLE_BY_UNIT,
  ROLE_PERMISSIONS
} = require("./constants");
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

  createUnit({ name, type = "troop" }) {
    const unit = {
      id: createId("unit"),
      name,
      type,
      status: "active"
    };
    this.store.data.units.push(unit);
    this.audit("unit.created", { targetType: "unit", targetId: unit.id });
    this.store.save();
    return unit;
  }

  createPerson({ id, name, email, type, unitIds = [], externalId = null, isMinor = null }) {
    this.assertPersonType(type);
    this.requireUnits(unitIds);
    if (email) {
      this.assertUniqueEmail(email, null, unitIds);
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
      isMinor: isMinor ?? type === PERSON_TYPES.SCOUT,
      unitIds: [...new Set(unitIds)],
      status: "active"
    };
    this.store.data.people.push(person);
    this.audit("person.created", { targetType: "person", targetId: person.id });
    this.store.save();
    return person;
  }

  updatePersonStatus({ personId, status }) {
    const person = this.requirePerson(personId);
    person.status = status;
    this.audit("person.status_updated", { targetType: "person", targetId: personId });
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
      this.audit("role.assigned", { actorUserId: personId, targetType: "unit", targetId: unitId });
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
    this.audit("role.removed", { actorUserId: personId, targetType: "unit", targetId: unitId });
    this.store.save();
    return this.describeAccess(personId);
  }

  assignUnitPosition({ personId, unitId, position }) {
    this.requirePerson(personId);
    this.requireUnit(unitId);
    this.assertPosition(position);

    const existing = this.store.data.unitPositionAssignments.find(
      (assignment) =>
        assignment.personId === personId &&
        assignment.unitId === unitId &&
        assignment.position === position
    );
    if (!existing) {
      this.store.data.unitPositionAssignments.push({
        id: createId("upa"),
        personId,
        unitId,
        position,
        status: "active"
      });
      this.audit("position.assigned", { actorUserId: personId, targetType: "unit", targetId: unitId });
      this.store.save();
    }
    return this.describeAccess(personId);
  }

  removeUnitPosition({ personId, unitId, position }) {
    const assignment = this.store.data.unitPositionAssignments.find(
      (item) =>
        item.personId === personId &&
        item.unitId === unitId &&
        item.position === position &&
        item.status === "active"
    );
    if (!assignment) {
      throw this.error("Unit position assignment not found", 404);
    }
    assignment.status = "inactive";
    this.audit("position.removed", { actorUserId: personId, targetType: "unit", targetId: unitId });
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
      this.audit("global_role.assigned", { actorUserId: personId, targetType: "person", targetId: personId });
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
    this.audit("global_role.removed", { actorUserId: personId, targetType: "person", targetId: personId });
    this.store.save();
    return this.describeAccess(personId);
  }

  assignRolePermission({ role, permission }) {
    const canonicalRole = this.canonicalRole(role);
    this.assertRole(canonicalRole);
    this.assertPermission(permission);
    const existing = this.store.data.rolePermissions.find(
      (item) => item.role === canonicalRole && item.permission === permission
    );
    if (!existing) {
      this.store.data.rolePermissions.push({
        id: createId("rp"),
        role: canonicalRole,
        permission,
        status: "active"
      });
      this.audit("permission.role_assigned", { targetType: "role", targetId: canonicalRole });
      this.store.save();
    } else if (existing.status !== "active") {
      existing.status = "active";
      this.audit("permission.role_assigned", { targetType: "role", targetId: canonicalRole });
      this.store.save();
    }
    return this.effectiveRolePermissions(canonicalRole);
  }

  removeRolePermission({ role, permission }) {
    const canonicalRole = this.canonicalRole(role);
    const assignment = this.store.data.rolePermissions.find(
      (item) =>
        item.role === canonicalRole &&
        item.permission === permission &&
        item.status === "active"
    );
    if (!assignment) {
      throw this.error("Role permission assignment not found", 404);
    }
    assignment.status = "inactive";
    this.audit("permission.role_removed", { targetType: "role", targetId: canonicalRole });
    this.store.save();
    return this.effectiveRolePermissions(canonicalRole);
  }

  assignPositionPermission({ position, permission }) {
    this.assertPosition(position);
    this.assertPermission(permission);
    const existing = this.store.data.positionPermissions.find(
      (item) => item.position === position && item.permission === permission
    );
    if (!existing) {
      this.store.data.positionPermissions.push({
        id: createId("pp"),
        position,
        permission,
        status: "active"
      });
      this.audit("permission.position_assigned", { targetType: "position", targetId: position });
      this.store.save();
    } else if (existing.status !== "active") {
      existing.status = "active";
      this.audit("permission.position_assigned", { targetType: "position", targetId: position });
      this.store.save();
    }
    return this.effectivePositionPermissions(position);
  }

  removePositionPermission({ position, permission }) {
    const assignment = this.store.data.positionPermissions.find(
      (item) =>
        item.position === position &&
        item.permission === permission &&
        item.status === "active"
    );
    if (!assignment) {
      throw this.error("Position permission assignment not found", 404);
    }
    assignment.status = "inactive";
    this.audit("permission.position_removed", { targetType: "position", targetId: position });
    this.store.save();
    return this.effectivePositionPermissions(position);
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
    if (!this.peopleShareUnit(adult, scout)) {
      throw this.error("Parent relationship requires a shared unit", 400);
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
      this.audit("relationship.linked", { actorUserId: adultPersonId, targetType: "person", targetId: scoutPersonId });
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
    this.audit("relationship.unlinked", { actorUserId: adultPersonId, targetType: "person", targetId: scoutPersonId });
    this.store.save();
    return this.describeAccess(adultPersonId);
  }

  createPatrol({ unitId, name }) {
    this.requireUnit(unitId);
    const patrol = {
      id: createId("patrol"),
      unitId,
      name,
      status: "active"
    };
    this.store.data.patrols.push(patrol);
    this.audit("patrol.created", { targetType: "unit", targetId: unitId });
    this.store.save();
    return patrol;
  }

  assignPatrolMembership({ personId, patrolId }) {
    const person = this.requirePerson(personId);
    const patrol = this.requirePatrol(patrolId);
    if (!person.unitIds.includes(patrol.unitId)) {
      throw this.error("Patrol membership requires membership in the patrol unit", 400);
    }
    const existing = this.store.data.patrolMemberships.find(
      (membership) =>
        membership.personId === personId &&
        membership.patrolId === patrolId &&
        membership.status === "active"
    );
    if (!existing) {
      this.store.data.patrolMemberships.push({
        id: createId("pm"),
        personId,
        patrolId,
        unitId: patrol.unitId,
        status: "active"
      });
      this.audit("patrol.membership_assigned", { actorUserId: personId, targetType: "patrol", targetId: patrolId });
      this.store.save();
    }
    return this.describeAccess(personId);
  }

  upsertScoutProfile({ scoutPersonId, firstName, lastName, dob }) {
    const scout = this.requireScout(scoutPersonId);
    const record = this.upsertByScoutId(this.store.data.scoutProfiles, scout.id, {
      firstName,
      lastName,
      dob
    });
    this.audit("scout_profile.upserted", { targetType: "person", targetId: scout.id });
    this.store.save();
    return record;
  }

  upsertScoutMedical({ scoutPersonId, medicalNotes = "", medical_notes, allergies = "" }) {
    const scout = this.requireScout(scoutPersonId);
    const record = this.upsertByScoutId(this.store.data.scoutMedical, scout.id, {
      medicalNotes: medical_notes ?? medicalNotes,
      allergies
    });
    this.audit("scout_medical.upserted", { targetType: "person", targetId: scout.id });
    this.store.save();
    return record;
  }

  upsertScoutAdvancement({ scoutPersonId, rank = "", badges = [] }) {
    const scout = this.requireScout(scoutPersonId);
    const record = this.upsertByScoutId(this.store.data.scoutAdvancement, scout.id, {
      rank,
      badges
    });
    this.audit("scout_advancement.upserted", { targetType: "person", targetId: scout.id });
    this.store.save();
    return record;
  }

  getScoutData({ token, scoutPersonId, fieldScope = FIELD_SCOPES.PROFILE }) {
    const check = this.authorize({
      token,
      permission: PERMISSIONS.VIEW_LINKED_SCOUT,
      scoutPersonId,
      targetUserId: scoutPersonId,
      fieldScope
    });
    if (!check.authorized) {
      throw this.error("Forbidden", 403);
    }

    this.audit("pii.read", {
      actorUserId: check.actor.person?.id || null,
      targetType: "person",
      targetId: scoutPersonId,
      details: { fieldScope }
    });
    this.store.save();

    if (fieldScope === FIELD_SCOPES.MEDICAL) {
      return this.store.data.scoutMedical.find((item) => item.scoutPersonId === scoutPersonId) || null;
    }
    if (fieldScope === FIELD_SCOPES.ADVANCEMENT) {
      return this.store.data.scoutAdvancement.find((item) => item.scoutPersonId === scoutPersonId) || null;
    }
    return this.store.data.scoutProfiles.find((item) => item.scoutPersonId === scoutPersonId) || null;
  }

  inviteAccount({ personId, email }) {
    const person = this.requirePerson(personId);
    const normalizedEmail = this.normalizeEmail(email);
    this.assertUniqueEmail(normalizedEmail, personId, person.unitIds);
    if (person.type === PERSON_TYPES.SCOUT && !normalizedEmail) {
      throw this.error("Scout accounts require a unique email address", 400);
    }

    const priorAccount = this.findAccountByEmail(normalizedEmail, person.unitIds[0] || null, { allowAmbiguous: true });
    if (priorAccount && priorAccount.personId !== personId && this.sameUnitScope(priorAccount.unitIds, person.unitIds)) {
      throw this.error("An account already exists for that email in this unit", 409);
    }

    const token = createToken();
    const invitation = {
      id: createId("invite"),
      personId,
      unitIds: [...person.unitIds],
      email: normalizedEmail,
      token,
      status: "pending",
      createdAt: new Date().toISOString()
    };

    person.email = normalizedEmail;
    this.store.data.invitations.push(invitation);
    this.audit("account.invited", { actorUserId: personId, targetType: "person", targetId: personId });
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
      unitIds: [...(invitation.unitIds || person.unitIds || [])],
      email: invitation.email,
      passwordHash: passwordRecord.passwordHash,
      passwordSalt: passwordRecord.salt,
      status: "active",
      mfaSecret: this.personHasGlobalRole(person.id, ROLES.ADMINISTRATOR) ? createTotpSecret() : null,
      createdAt: new Date().toISOString()
    };

    invitation.status = "accepted";
    this.store.data.accounts.push(account);
    this.audit("account.activated", { actorUserId: person.id, targetType: "person", targetId: person.id });
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

  login({ email, credential, credentials, password, otp, unitId = null, allowPasswordless = false }) {
    const loginEmail = this.resolveLoginEmail({ email, credential, credentials });
    const account = this.findAccountByEmail(loginEmail, unitId);
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
      unitId: unitId || account.unitIds?.[0] || null,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString(),
      status: "active"
    };

    this.store.data.sessions.push(session);
    this.audit("auth.login", { actorUserId: person.id, targetType: "account", targetId: account.id });
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
        unitPositions: [],
        patrols: [],
        relationships: [],
        permissions: []
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

  authorize({
    token,
    allowedRoles = [ROLES.PUBLIC],
    permission = null,
    unitId = null,
    scoutPersonId = null,
    targetUserId = null,
    fieldScope = FIELD_SCOPES.PROFILE
  }) {
    const actor = this.authenticate(token);
    if (actor.globalRoles.includes(ROLES.ADMINISTRATOR)) {
      return { authorized: true, actor };
    }

    const authorized = permission
      ? this.isPermissionAuthorized(actor, { permission, unitId, scoutPersonId, targetUserId, fieldScope })
      : this.isRoleAuthorized(actor, { allowedRoles, unitId, scoutPersonId });

    if (!authorized) {
      this.audit("authorization.denied", {
        actorUserId: actor.person?.id || null,
        targetType: targetUserId || scoutPersonId ? "person" : "permission",
        targetId: targetUserId || scoutPersonId || permission || allowedRoles.join(","),
        details: { allowedRoles, permission, unitId, scoutPersonId, targetUserId, fieldScope }
      });
      this.store.save();
    }

    return { authorized, actor };
  }

  describeAccess(personId) {
    const person = this.requirePerson(personId);
    const unitRoles = this.store.data.unitRoleAssignments
      .filter((assignment) => assignment.personId === personId && assignment.status === "active")
      .map((assignment) => ({
        role: assignment.role,
        unitId: assignment.unitId
      }));
    const unitPositions = this.store.data.unitPositionAssignments
      .filter((assignment) => assignment.personId === personId && assignment.status === "active")
      .map((assignment) => ({
        position: assignment.position,
        unitId: assignment.unitId
      }));
    const patrols = this.store.data.patrolMemberships
      .filter((membership) => membership.personId === personId && membership.status === "active")
      .map((membership) => ({
        patrolId: membership.patrolId,
        unitId: membership.unitId
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
      const relationshipRoles = new Set(
        relationships.map((link) => this.relationshipRole(link.relationship))
      );
      for (const role of relationshipRoles) {
        globalRoles.push(role);
        explanations.push({
          role,
          reason: "Active adult-to-scout relationship"
        });
      }
      for (const link of relationships) {
        explanations.push({
          role: ROLES.SCOUT,
          reason: `Inherited for linked scout ${link.scoutPersonId}`
        });
      }
    }

    const permissions = this.describePermissions({
      person,
      globalRoles: [...new Set(globalRoles)],
      unitRoles,
      unitPositions
    });

    return {
      person: {
        id: person.id,
        externalId: person.externalId || person.id,
        name: person.name,
        type: person.type,
        isMinor: Boolean(person.isMinor),
        status: person.status,
        unitIds: [...(person.unitIds || [])]
      },
      units: (person.unitIds || []).map((id) => this.store.data.units.find((unit) => unit.id === id)).filter(Boolean),
      globalRoles: [...new Set(globalRoles)],
      unitRoles,
      unitPositions,
      patrols,
      relationships,
      permissions,
      explanations
    };
  }

  resetPassword({ accountId, newPassword }) {
    const account = this.requireAccount(accountId);
    const record = hashPassword(newPassword);
    account.passwordHash = record.passwordHash;
    account.passwordSalt = record.salt;
    this.expireSessionsForPerson(account.personId);
    this.audit("account.password_reset", { actorUserId: account.personId, targetType: "account", targetId: account.id });
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
    this.audit("account.mfa_reset", { actorUserId: account.personId, targetType: "account", targetId: account.id });
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

  listAuditLogs() {
    return [...this.store.data.auditLogs];
  }

  isRoleAuthorized(actor, { allowedRoles, unitId, scoutPersonId }) {
    if (allowedRoles.includes(ROLES.PUBLIC)) {
      return true;
    }

    const allowed = new Set(allowedRoles);
    const allowedCanonical = new Set(allowedRoles.map((role) => this.canonicalRole(role)));
    const hasGlobalRole = actor.globalRoles.some(
      (role) => allowed.has(role) || allowedCanonical.has(this.canonicalRole(role))
    );
    const hasUnitRole =
      unitId &&
      actor.unitRoles.some(
        (assignment) =>
          assignment.unitId === unitId &&
          (allowed.has(assignment.role) || allowedCanonical.has(this.canonicalRole(assignment.role)))
      );
    const hasRelationshipRole =
      scoutPersonId &&
      actor.relationships.some(
        (link) => link.scoutPersonId === scoutPersonId && allowedRoles.includes(link.grantsRole)
      );

    return Boolean(hasGlobalRole || hasUnitRole || hasRelationshipRole);
  }

  isPermissionAuthorized(actor, { permission, unitId, scoutPersonId, targetUserId, fieldScope }) {
    const targetPersonId = targetUserId || scoutPersonId || null;
    const target = targetPersonId ? this.requirePerson(targetPersonId) : null;
    const effectiveUnitId = unitId || this.firstSharedUnit(actor.person, target) || actor.person?.unitIds?.[0] || null;
    const hasPermission = this.actorHasPermission(actor, permission, effectiveUnitId);

    if (permission === PERMISSIONS.VIEW_OWN) {
      return !targetPersonId || targetPersonId === actor.person?.id;
    }

    if (permission === PERMISSIONS.MANAGE_UNIT) {
      return Boolean(effectiveUnitId && hasPermission);
    }

    if (permission === PERMISSIONS.MESSAGING) {
      return this.canMessage(actor, { target, unitId: effectiveUnitId });
    }

    if (!hasPermission || !target || target.type !== PERSON_TYPES.SCOUT) {
      return false;
    }

    if (
      [PERMISSIONS.VIEW_LINKED_SCOUT, PERMISSIONS.EDIT_LINKED_SCOUT].includes(permission)
    ) {
      const linked = actor.relationships.some((link) => link.scoutPersonId === target.id);
      return linked && this.fieldScopeAllowedForLinkedAdult(fieldScope);
    }

    if (
      [PERMISSIONS.VIEW_ALL_SCOUTS, PERMISSIONS.EDIT_ALL_SCOUTS].includes(permission)
    ) {
      const sameUnit = effectiveUnitId && target.unitIds.includes(effectiveUnitId);
      if (!sameUnit) {
        return false;
      }
      return this.fieldScopeAllowedForAllScouts(actor, fieldScope, effectiveUnitId);
    }

    return false;
  }

  actorHasPermission(actor, permission, unitId) {
    if ((actor.permissions?.global || []).includes(permission)) {
      return true;
    }
    return (actor.permissions?.byUnit || []).some(
      (assignment) => assignment.unitId === unitId && assignment.permissions.includes(permission)
    );
  }

  canMessage(actor, { target, unitId }) {
    if (!target) {
      return this.actorHasPermission(actor, PERMISSIONS.MESSAGING, unitId);
    }
    if (actor.person?.id === target.id) {
      return true;
    }
    const hasLeaderScope =
      this.actorHasPermission(actor, PERMISSIONS.VIEW_ALL_SCOUTS, unitId) &&
      this.actorHasPermission(actor, PERMISSIONS.MESSAGING, unitId);
    if (hasLeaderScope && target.unitIds.includes(unitId)) {
      return true;
    }
    const linked = actor.relationships.some((link) => link.scoutPersonId === target.id);
    if (linked) {
      return true;
    }
    if (actor.person?.type === PERSON_TYPES.SCOUT && target.type === PERSON_TYPES.SCOUT) {
      return this.samePatrol(actor.person.id, target.id, unitId);
    }
    return false;
  }

  fieldScopeAllowedForLinkedAdult(fieldScope) {
    return [FIELD_SCOPES.PROFILE, FIELD_SCOPES.MEDICAL, FIELD_SCOPES.ADVANCEMENT].includes(fieldScope);
  }

  fieldScopeAllowedForAllScouts(actor, fieldScope, unitId) {
    if (fieldScope !== FIELD_SCOPES.MEDICAL) {
      return true;
    }
    return actor.unitPositions.some(
      (assignment) =>
        assignment.unitId === unitId &&
        [POSITIONS.SCOUTMASTER, POSITIONS.ASSISTANT_SCOUTMASTER].includes(assignment.position)
    );
  }

  describePermissions({ person, globalRoles, unitRoles, unitPositions }) {
    const globalPermissions = new Set();
    for (const role of globalRoles.map((role) => this.canonicalRole(role))) {
      for (const permission of this.effectiveRolePermissions(role)) {
        globalPermissions.add(permission);
      }
    }

    const unitIds = new Set(person.unitIds || []);
    for (const assignment of unitRoles) {
      unitIds.add(assignment.unitId);
    }
    for (const assignment of unitPositions) {
      unitIds.add(assignment.unitId);
    }

    const unitPermissions = [...unitIds].map((unitId) => {
      const permissions = new Set();
      for (const assignment of unitRoles.filter((item) => item.unitId === unitId)) {
        for (const permission of this.effectiveRolePermissions(assignment.role)) {
          permissions.add(permission);
        }
      }
      for (const assignment of unitPositions.filter((item) => item.unitId === unitId)) {
        for (const permission of this.effectivePositionPermissions(assignment.position)) {
          permissions.add(permission);
        }
      }
      return {
        unitId,
        permissions: [...permissions]
      };
    });

    return {
      global: [...globalPermissions],
      byUnit: unitPermissions,
      includes(permission) {
        return globalPermissions.has(permission);
      }
    };
  }

  assertPersonType(type) {
    if (!Object.values(PERSON_TYPES).includes(type)) {
      throw this.error(`Unsupported person type: ${type}`, 400);
    }
  }

  assertPosition(position) {
    if (!Object.values(POSITIONS).includes(position)) {
      throw this.error(`Unsupported position: ${position}`, 400);
    }
  }

  assertRole(role) {
    if (!Object.values(ROLES).includes(role)) {
      throw this.error(`Unsupported role: ${role}`, 400);
    }
  }

  assertPermission(permission) {
    if (!Object.values(PERMISSIONS).includes(permission)) {
      throw this.error(`Unsupported permission: ${permission}`, 400);
    }
  }

  personHasGlobalRole(personId, role) {
    return this.store.data.globalRoleAssignments.some(
      (assignment) => assignment.personId === personId && assignment.role === role && assignment.status === "active"
    );
  }

  assertUniqueEmail(email, samePersonId = null, unitIds = []) {
    if (!email) {
      return;
    }

    const normalized = this.normalizeEmail(email);
    const conflictPerson = this.store.data.people.find(
      (person) =>
        person.email === normalized &&
        person.id !== samePersonId &&
        this.sameUnitScope(person.unitIds, unitIds)
    );
    if (conflictPerson) {
      throw this.error("Email is already assigned to another person in this unit", 409);
    }

    const conflictAccount = this.store.data.accounts.find(
      (account) =>
        account.email === normalized &&
        (!samePersonId || account.personId !== samePersonId) &&
        this.sameUnitScope(account.unitIds, unitIds)
    );
    if (conflictAccount) {
      throw this.error("Email is already assigned to another account in this unit", 409);
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

  requireScout(personId) {
    const person = this.requirePerson(personId);
    if (person.type !== PERSON_TYPES.SCOUT) {
      throw this.error("Scout person required", 400);
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

  requireUnits(unitIds) {
    for (const unitId of unitIds || []) {
      this.requireUnit(unitId);
    }
  }

  requirePatrol(patrolId) {
    const patrol = this.store.data.patrols.find((item) => item.id === patrolId);
    if (!patrol) {
      throw this.error("Patrol not found", 404);
    }
    return patrol;
  }

  requireAccount(accountId) {
    const account = this.store.data.accounts.find((item) => item.id === accountId);
    if (!account) {
      throw this.error("Account not found", 404);
    }
    return account;
  }

  findAccountByEmail(email, unitId = null, options = {}) {
    const normalized = this.normalizeEmail(email);
    const candidates = this.store.data.accounts.filter(
      (item) => item.email === normalized && (!unitId || (item.unitIds || []).includes(unitId))
    );
    if (candidates.length > 1 && !unitId && !options.allowAmbiguous) {
      throw this.error("Login requires unitId when an email exists in multiple units", 400);
    }
    return candidates[0] || null;
  }

  findAccountByPersonId(personId) {
    return this.store.data.accounts.find((item) => item.personId === personId) || null;
  }

  redactAccount(account) {
    return {
      id: account.id,
      personId: account.personId,
      unitIds: [...(account.unitIds || [])],
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

  upsertByScoutId(collection, scoutPersonId, values) {
    let record = collection.find((item) => item.scoutPersonId === scoutPersonId);
    if (!record) {
      record = {
        scoutPersonId,
        createdAt: new Date().toISOString()
      };
      collection.push(record);
    }
    Object.assign(record, values, { updatedAt: new Date().toISOString() });
    return record;
  }

  canonicalRole(role) {
    return ROLE_ALIASES[role] || role;
  }

  effectiveRolePermissions(role) {
    const canonicalRole = this.canonicalRole(role);
    const permissions = new Set(ROLE_PERMISSIONS[canonicalRole] || []);
    for (const assignment of this.store.data.rolePermissions.filter(
      (item) => item.role === canonicalRole && item.status === "active"
    )) {
      permissions.add(assignment.permission);
    }
    return [...permissions];
  }

  effectivePositionPermissions(position) {
    const permissions = new Set(POSITION_PERMISSIONS[position] || []);
    for (const assignment of this.store.data.positionPermissions.filter(
      (item) => item.position === position && item.status === "active"
    )) {
      permissions.add(assignment.permission);
    }
    return [...permissions];
  }

  relationshipRole(relationship) {
    return String(relationship).toLowerCase().includes("guardian") ? ROLES.GUARDIAN : ROLES.PARENT;
  }

  sameUnitScope(left = [], right = []) {
    return (left || []).some((unitId) => (right || []).includes(unitId));
  }

  peopleShareUnit(left, right) {
    return this.sameUnitScope(left.unitIds, right.unitIds);
  }

  firstSharedUnit(left, right) {
    if (!left || !right) {
      return null;
    }
    return (left.unitIds || []).find((unitId) => (right.unitIds || []).includes(unitId)) || null;
  }

  samePatrol(leftPersonId, rightPersonId, unitId) {
    const left = this.store.data.patrolMemberships.filter(
      (membership) =>
        membership.personId === leftPersonId &&
        membership.unitId === unitId &&
        membership.status === "active"
    );
    return left.some((membership) =>
      this.store.data.patrolMemberships.some(
        (candidate) =>
          candidate.personId === rightPersonId &&
          candidate.patrolId === membership.patrolId &&
          candidate.status === "active"
      )
    );
  }

  audit(action, { actorUserId = null, targetType = null, targetId = null, details = {}, ipAddress = null } = {}) {
    this.store.data.auditLogs.push({
      id: createId("audit"),
      actorUserId,
      action,
      targetType,
      targetId,
      timestamp: new Date().toISOString(),
      ipAddress,
      details
    });
  }

  error(message, statusCode, extra = {}) {
    const error = new Error(message);
    error.statusCode = statusCode;
    Object.assign(error, extra);
    return error;
  }
}

module.exports = { AuthSystem };
