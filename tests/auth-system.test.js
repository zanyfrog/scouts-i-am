"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");
const { AuthSystem } = require("../src/auth-system");
const { ROLES } = require("../src/constants");
const { JsonStore } = require("../src/json-store");
const { syncLocalDemoAccounts } = require("../src/local-demo-sync");
const { generateTotp } = require("../src/security");

function createSystem() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "scouts-auth-"));
  const file = path.join(root, "store.json");
  return new AuthSystem(new JsonStore(file));
}

function bootstrapAdmin(system) {
  const unit = system.createUnit({ name: "Troop 1" });
  const person = system.createPerson({
    name: "Admin User",
    email: "admin@example.com",
    type: "adult",
    unitIds: [unit.id]
  });
  system.assignGlobalRole({ personId: person.id, role: ROLES.ADMINISTRATOR });
  const invitation = system.inviteAccount({ personId: person.id, email: person.email });
  const activated = system.activateInvitation({ token: invitation.token, password: "password123" });
  const otp = generateTotp(activated.mfaSetup.secret);
  const login = system.login({ email: person.email, password: "password123", otp });
  return { unit, person, login };
}

test("anonymous users keep only public access and cannot enter member routes", () => {
  const system = createSystem();
  const publicActor = system.authenticate(null);
  assert.equal(publicActor.authenticated, false);
  assert.deepEqual(publicActor.globalRoles, [ROLES.PUBLIC]);

  const memberCheck = system.authorize({
    token: null,
    allowedRoles: [ROLES.SCOUT, ROLES.PARENT]
  });
  assert.equal(memberCheck.authorized, false);
});

test("invited adult can activate account, log in, and receive derived leader access", () => {
  const system = createSystem();
  const { login: adminLogin, unit } = bootstrapAdmin(system);
  assert.ok(adminLogin.session.token);

  const leader = system.createPerson({
    name: "Leader",
    email: "leader@example.com",
    type: "adult",
    unitIds: [unit.id]
  });
  system.assignUnitRole({
    personId: leader.id,
    unitId: unit.id,
    role: ROLES.ADULT_LEADER
  });
  const invitation = system.inviteAccount({ personId: leader.id, email: leader.email });
  system.activateInvitation({ token: invitation.token, password: "leader-pass" });

  const login = system.login({ email: leader.email, password: "leader-pass" });
  assert.equal(login.access.globalRoles.includes(ROLES.PUBLIC), true);
  assert.deepEqual(login.access.unitRoles, [{ role: ROLES.ADULT_LEADER, unitId: unit.id }]);
});

test("parent gets parent role and scout access only for linked scouts", () => {
  const system = createSystem();
  const { unit } = bootstrapAdmin(system);
  const parent = system.createPerson({
    name: "Parent",
    email: "parent@example.com",
    type: "adult",
    unitIds: [unit.id]
  });
  const scoutA = system.createPerson({
    name: "Scout A",
    email: "scouta@example.com",
    type: "scout",
    unitIds: [unit.id]
  });
  const scoutB = system.createPerson({
    name: "Scout B",
    email: "scoutb@example.com",
    type: "scout",
    unitIds: [unit.id]
  });

  system.linkParentToScout({ adultPersonId: parent.id, scoutPersonId: scoutA.id });
  const invitation = system.inviteAccount({ personId: parent.id, email: parent.email });
  system.activateInvitation({ token: invitation.token, password: "parent-pass" });
  const login = system.login({ email: parent.email, password: "parent-pass" });

  assert.equal(login.access.globalRoles.includes(ROLES.PARENT), true);

  const allowedForLinkedScout = system.authorize({
    token: login.session.token,
    allowedRoles: [ROLES.SCOUT],
    scoutPersonId: scoutA.id
  });
  const deniedForUnlinkedScout = system.authorize({
    token: login.session.token,
    allowedRoles: [ROLES.SCOUT],
    scoutPersonId: scoutB.id
  });

  assert.equal(allowedForLinkedScout.authorized, true);
  assert.equal(deniedForUnlinkedScout.authorized, false);
});

test("login accepts email-only credential payloads", () => {
  const system = createSystem();
  const { unit } = bootstrapAdmin(system);
  const parent = system.createPerson({
    name: "Credential Parent",
    email: "credential-parent@example.com",
    type: "adult",
    unitIds: [unit.id]
  });
  const invitation = system.inviteAccount({ personId: parent.id, email: parent.email });
  system.activateInvitation({ token: invitation.token, password: "credential-pass" });

  const login = system.login({
    credentials: { email: "credential-parent@example.com" },
    password: "credential-pass"
  });

  assert.equal(login.account.email, "credential-parent@example.com");
  assert.throws(
    () => system.login({ credentials: "not-a-user-name", password: "credential-pass" }),
    /email address/
  );
});

test("passwordless login is available only when explicitly allowed", () => {
  const system = createSystem();
  const { unit } = bootstrapAdmin(system);
  const parent = system.createPerson({
    name: "Local Passwordless Parent",
    email: "passwordless-parent@example.com",
    type: "adult",
    unitIds: [unit.id]
  });
  const invitation = system.inviteAccount({ personId: parent.id, email: parent.email });
  system.activateInvitation({ token: invitation.token, password: "passwordless-pass" });

  assert.throws(
    () => system.login({ email: parent.email }),
    /Invalid email or password/
  );

  const login = system.login({ email: parent.email, allowPasswordless: true });

  assert.equal(login.account.email, "passwordless-parent@example.com");
});

test("local demo sync creates accounts for scout and adult emails", () => {
  const system = createSystem();
  const result = syncLocalDemoAccounts(system, {
    scouts: [
      {
        id: "demo-scout-1",
        name: "Demo Scout",
        email: "demo.scout@example.com"
      }
    ],
    adults: [
      {
        id: "demo-adult-1",
        name: "Demo Adult",
        email: "demo.adult@example.com"
      }
    ],
    adultLeaders: [
      {
        adultId: "demo-adult-1",
        role: "Scoutmaster"
      }
    ],
    adultScoutRelationships: [
      {
        adultId: "demo-adult-1",
        scoutId: "demo-scout-1",
        relationship: "parent"
      }
    ]
  });

  const adultLogin = system.login({
    email: "demo.adult@example.com",
    allowPasswordless: true
  });
  const scoutLogin = system.login({
    email: "demo.scout@example.com",
    allowPasswordless: true
  });

  assert.equal(result.accounts, 2);
  assert.equal(adultLogin.access.globalRoles.includes(ROLES.PARENT), true);
  assert.deepEqual(adultLogin.access.unitRoles.map((item) => item.role), [ROLES.ADULT_LEADER]);
  assert.equal(scoutLogin.access.globalRoles.includes(ROLES.SCOUT), true);
});

test("locally seeded administrator accounts can opt out of MFA", () => {
  const system = createSystem();
  const unit = system.createUnit({ name: "Troop 42" });
  const admin = system.createPerson({
    name: "Local Admin",
    email: "local-admin@example.com",
    type: "adult",
    unitIds: [unit.id]
  });
  system.assignGlobalRole({ personId: admin.id, role: ROLES.ADMINISTRATOR });
  const invitation = system.inviteAccount({ personId: admin.id, email: admin.email });
  system.activateInvitation({ token: invitation.token, password: "local-admin-pass" });
  const account = system.findAccountByEmail(admin.email);
  account.mfaExempt = true;
  system.store.save();

  const login = system.login({ email: admin.email, password: "local-admin-pass" });

  assert.equal(login.access.globalRoles.includes(ROLES.ADMINISTRATOR), true);
});

test("people can use canonical external ids for ORM authorization mapping", () => {
  const system = createSystem();
  const unit = system.createUnit({ name: "Troop 1" });
  const parent = system.createPerson({
    id: "adult-1",
    name: "Mapped Parent",
    email: "mapped-parent@example.com",
    type: "adult",
    unitIds: [unit.id]
  });
  const scout = system.createPerson({
    id: "scout-1",
    name: "Mapped Scout",
    email: "mapped-scout@example.com",
    type: "scout",
    unitIds: [unit.id]
  });

  system.linkParentToScout({ adultPersonId: parent.id, scoutPersonId: scout.id });
  const invitation = system.inviteAccount({ personId: parent.id, email: parent.email });
  system.activateInvitation({ token: invitation.token, password: "mapped-pass" });
  const login = system.login({ email: parent.email, password: "mapped-pass" });

  assert.equal(login.access.person.id, "adult-1");
  assert.equal(login.access.person.externalId, "adult-1");
  assert.equal(login.access.relationships[0].scoutPersonId, "scout-1");
  assert.equal(
    system.authorize({
      token: login.session.token,
      allowedRoles: [ROLES.SCOUT],
      scoutPersonId: "scout-1"
    }).authorized,
    true
  );
});

test("multi-role checks allow any listed role and unit scope does not leak", () => {
  const system = createSystem();
  const { unit: troop1 } = bootstrapAdmin(system);
  const troop2 = system.createUnit({ name: "Troop 2" });
  const member = system.createPerson({
    name: "Committee Scout",
    email: "combo@example.com",
    type: "scout",
    unitIds: [troop1.id, troop2.id]
  });
  system.assignUnitRole({
    personId: member.id,
    unitId: troop1.id,
    role: ROLES.COMMITTEE_MEMBER
  });
  const invitation = system.inviteAccount({ personId: member.id, email: member.email });
  system.activateInvitation({ token: invitation.token, password: "combo-pass" });
  const login = system.login({ email: member.email, password: "combo-pass" });

  const troop1Check = system.authorize({
    token: login.session.token,
    allowedRoles: [ROLES.ADULT_LEADER, ROLES.COMMITTEE_MEMBER],
    unitId: troop1.id
  });
  const troop2Check = system.authorize({
    token: login.session.token,
    allowedRoles: [ROLES.ADULT_LEADER, ROLES.COMMITTEE_MEMBER],
    unitId: troop2.id
  });

  assert.equal(troop1Check.authorized, true);
  assert.equal(troop2Check.authorized, false);
  assert.equal(login.access.globalRoles.includes(ROLES.SCOUT), true);
});

test("administrator requires MFA and receives global super-admin access", () => {
  const system = createSystem();
  const unit = system.createUnit({ name: "Troop 99" });
  const admin = system.createPerson({
    name: "Admin",
    email: "superadmin@example.com",
    type: "adult",
    unitIds: [unit.id]
  });
  system.assignGlobalRole({ personId: admin.id, role: ROLES.ADMINISTRATOR });
  const invitation = system.inviteAccount({ personId: admin.id, email: admin.email });
  const activation = system.activateInvitation({ token: invitation.token, password: "admin-pass" });

  assert.throws(
    () => system.login({ email: admin.email, password: "admin-pass" }),
    /valid MFA code/
  );

  const otp = generateTotp(activation.mfaSetup.secret);
  const login = system.login({ email: admin.email, password: "admin-pass", otp });
  const access = system.authorize({
    token: login.session.token,
    allowedRoles: [ROLES.ADMINISTRATOR]
  });

  assert.equal(access.authorized, true);
});

test("authorization checks support frontend-style role, unit, and scout queries", () => {
  const system = createSystem();
  const { unit } = bootstrapAdmin(system);
  const parent = system.createPerson({
    name: "Frontend Parent",
    email: "frontend-parent@example.com",
    type: "adult",
    unitIds: [unit.id]
  });
  const scout = system.createPerson({
    name: "Frontend Scout",
    email: "frontend-scout@example.com",
    type: "scout",
    unitIds: [unit.id]
  });

  system.linkParentToScout({ adultPersonId: parent.id, scoutPersonId: scout.id });
  const invitation = system.inviteAccount({ personId: parent.id, email: parent.email });
  system.activateInvitation({ token: invitation.token, password: "frontend-pass" });
  const login = system.login({ email: parent.email, password: "frontend-pass" });

  assert.equal(
    system.authorize({
      token: login.session.token,
      allowedRoles: [ROLES.PARENT, ROLES.ADULT_LEADER]
    }).authorized,
    true
  );

  assert.equal(
    system.authorize({
      token: login.session.token,
      allowedRoles: [ROLES.ADULT_LEADER],
      unitId: unit.id
    }).authorized,
    false
  );

  assert.equal(
    system.authorize({
      token: login.session.token,
      allowedRoles: [ROLES.SCOUT],
      scoutPersonId: scout.id
    }).authorized,
    true
  );
});

test("changing assignments immediately changes effective roles", () => {
  const system = createSystem();
  const { unit } = bootstrapAdmin(system);
  const leader = system.createPerson({
    name: "Rotating Leader",
    email: "rotate@example.com",
    type: "adult",
    unitIds: [unit.id]
  });
  const invitation = system.inviteAccount({ personId: leader.id, email: leader.email });
  system.activateInvitation({ token: invitation.token, password: "rotate-pass" });
  const login = system.login({ email: leader.email, password: "rotate-pass" });

  let access = system.authorize({
    token: login.session.token,
    allowedRoles: [ROLES.ADULT_LEADER],
    unitId: unit.id
  });
  assert.equal(access.authorized, false);

  system.assignUnitRole({ personId: leader.id, unitId: unit.id, role: ROLES.ADULT_LEADER });
  const refreshed = system.login({ email: leader.email, password: "rotate-pass" });
  access = system.authorize({
    token: refreshed.session.token,
    allowedRoles: [ROLES.ADULT_LEADER],
    unitId: unit.id
  });
  assert.equal(access.authorized, true);

  system.removeUnitRole({ personId: leader.id, unitId: unit.id, role: ROLES.ADULT_LEADER });
  const afterRemoval = system.authorize({
    token: refreshed.session.token,
    allowedRoles: [ROLES.ADULT_LEADER],
    unitId: unit.id
  });
  assert.equal(afterRemoval.authorized, false);
});

test("removing parent relationship immediately removes inherited scout access", () => {
  const system = createSystem();
  const { unit } = bootstrapAdmin(system);
  const parent = system.createPerson({
    name: "Linked Parent",
    email: "linkedparent@example.com",
    type: "adult",
    unitIds: [unit.id]
  });
  const scout = system.createPerson({
    name: "Linked Scout",
    email: "linkedscout@example.com",
    type: "scout",
    unitIds: [unit.id]
  });

  system.linkParentToScout({ adultPersonId: parent.id, scoutPersonId: scout.id });
  const invitation = system.inviteAccount({ personId: parent.id, email: parent.email });
  system.activateInvitation({ token: invitation.token, password: "link-pass" });
  const login = system.login({ email: parent.email, password: "link-pass" });

  assert.equal(
    system.authorize({
      token: login.session.token,
      allowedRoles: [ROLES.SCOUT],
      scoutPersonId: scout.id
    }).authorized,
    true
  );

  system.unlinkParentFromScout({ adultPersonId: parent.id, scoutPersonId: scout.id });

  assert.equal(
    system.authorize({
      token: login.session.token,
      allowedRoles: [ROLES.SCOUT],
      scoutPersonId: scout.id
    }).authorized,
    false
  );
});

test("inactive troop members keep accounts but lose access", () => {
  const system = createSystem();
  const { unit } = bootstrapAdmin(system);
  const scout = system.createPerson({
    name: "Inactive Scout",
    email: "inactive@example.com",
    type: "scout",
    unitIds: [unit.id]
  });
  const invitation = system.inviteAccount({ personId: scout.id, email: scout.email });
  system.activateInvitation({ token: invitation.token, password: "inactive-pass" });
  const login = system.login({ email: scout.email, password: "inactive-pass" });

  assert.equal(
    system.authorize({
      token: login.session.token,
      allowedRoles: [ROLES.SCOUT]
    }).authorized,
    true
  );

  system.updatePersonStatus({ personId: scout.id, status: "inactive" });

  assert.throws(
    () =>
      system.login({
        email: scout.email,
        password: "inactive-pass"
      }),
    /inactive/
  );
});
