"use strict";

const path = require("node:path");
const { PERSON_TYPES, ROLES } = require("./constants");
const { createId, hashPassword } = require("./security");

const LOCAL_DEMO_PASSWORD = "local-demo-password";

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function loadOrmData() {
  try {
    const orm = require(path.join(__dirname, "..", "..", "scouts.orm"));
    if (typeof orm.ensureDataFiles === "function") {
      orm.ensureDataFiles();
    }
    return typeof orm.getDataPayload === "function" ? orm.getDataPayload() : null;
  } catch (error) {
    return null;
  }
}

function getOrCreateUnit(authSystem) {
  const existing = authSystem.store.data.units.find((unit) => unit.status === "active");
  return existing || authSystem.createUnit({ name: "Troop 1" });
}

function ensurePerson(authSystem, { id, name, email, type, unitId }) {
  const normalizedEmail = normalizeEmail(email);
  let person =
    authSystem.store.data.people.find((item) => item.id === id) ||
    authSystem.store.data.people.find((item) => normalizedEmail && item.email === normalizedEmail);

  if (!person) {
    person = authSystem.createPerson({
      id,
      name,
      email: normalizedEmail || null,
      type,
      unitIds: [unitId]
    });
    return person;
  }

  person.name = name || person.name;
  person.type = type;
  person.status = "active";
  person.externalId = person.externalId || id;
  person.unitIds = [...new Set([...(person.unitIds || []), unitId])];
  if (normalizedEmail) {
    const emailOwner = authSystem.store.data.people.find(
      (item) => item.email === normalizedEmail && item.id !== person.id
    );
    if (!emailOwner) {
      person.email = normalizedEmail;
    }
  }
  authSystem.store.save();
  return person;
}

function ensureLocalAccount(authSystem, person, email) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail || !normalizedEmail.includes("@")) {
    return false;
  }

  let account = authSystem.findAccountByEmail(normalizedEmail) || authSystem.findAccountByPersonId(person.id);
  if (!account) {
    const passwordRecord = hashPassword(LOCAL_DEMO_PASSWORD);
    account = {
      id: createId("acct"),
      personId: person.id,
      email: normalizedEmail,
      passwordHash: passwordRecord.passwordHash,
      passwordSalt: passwordRecord.salt,
      status: "active",
      mfaSecret: null,
      mfaExempt: true,
      localDemoAccount: true,
      createdAt: new Date().toISOString()
    };
    authSystem.store.data.accounts.push(account);
  } else {
    account.personId = account.personId || person.id;
    account.email = normalizedEmail;
    account.status = "active";
    account.mfaExempt = true;
    account.localDemoAccount = true;
  }

  person.email = normalizedEmail;
  authSystem.store.save();
  return true;
}

function syncLocalDemoAccounts(authSystem, data = loadOrmData()) {
  if (!data) {
    return { synced: false, adults: 0, scouts: 0, accounts: 0 };
  }

  const unit = getOrCreateUnit(authSystem);
  const scouts = Array.isArray(data.scouts) ? data.scouts : [];
  const adults = Array.isArray(data.adults) ? data.adults : [];
  const adultLeaders = new Set(
    (Array.isArray(data.adultLeaders) ? data.adultLeaders : []).map((leader) => leader.adultId)
  );
  let accountCount = 0;

  scouts.forEach((scout) => {
    const person = ensurePerson(authSystem, {
      id: scout.id,
      name: scout.name || [scout.firstName, scout.lastName].filter(Boolean).join(" "),
      email: scout.email,
      type: PERSON_TYPES.SCOUT,
      unitId: unit.id
    });
    if (ensureLocalAccount(authSystem, person, scout.email)) {
      accountCount += 1;
    }
  });

  adults.forEach((adult) => {
    const person = ensurePerson(authSystem, {
      id: adult.id,
      name: adult.name,
      email: adult.email,
      type: PERSON_TYPES.ADULT,
      unitId: unit.id
    });
    if (ensureLocalAccount(authSystem, person, adult.email)) {
      accountCount += 1;
    }
    if (adultLeaders.has(adult.id)) {
      authSystem.assignUnitRole({
        personId: person.id,
        unitId: unit.id,
        role: ROLES.ADULT_LEADER
      });
    }
  });

  (Array.isArray(data.adultScoutRelationships) ? data.adultScoutRelationships : []).forEach((relationship) => {
    const adult = authSystem.store.data.people.find((person) => person.id === relationship.adultId);
    const scout = authSystem.store.data.people.find((person) => person.id === relationship.scoutId);
    if (adult && scout) {
      authSystem.linkParentToScout({
        adultPersonId: adult.id,
        scoutPersonId: scout.id,
        relationship: relationship.relationship || "parent"
      });
    }
  });

  return {
    synced: true,
    adults: adults.length,
    scouts: scouts.length,
    accounts: accountCount
  };
}

module.exports = {
  syncLocalDemoAccounts
};
