"use strict";

const { PERSON_TYPES, ROLES } = require("./constants");
const { createId, hashPassword } = require("./security");

const LOCAL_DEMO_PASSWORD = "local-demo-password";
const ormBaseUrl = String(process.env.ORM_BASE_URL || "http://127.0.0.1:4175").replace(/\/+$/, "");
const internalServiceToken = String(process.env.INTERNAL_SERVICE_TOKEN || "scouts-internal-service");

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

async function loadOrmData() {
  try {
    const response = await fetch(`${ormBaseUrl}/api/auth-sync-data`, {
      headers: {
        "X-Internal-Service-Token": internalServiceToken,
      },
    });
    if (!response.ok) {
      return null;
    }
    return response.json();
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

  let account =
    authSystem.findAccountByEmail(normalizedEmail, person.unitIds?.[0] || null, { allowAmbiguous: true }) ||
    authSystem.findAccountByPersonId(person.id);
  if (!account) {
    const passwordRecord = hashPassword(LOCAL_DEMO_PASSWORD);
    account = {
      id: createId("acct"),
      personId: person.id,
      unitIds: [...(person.unitIds || [])],
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
    account.unitIds = [...new Set([...(account.unitIds || []), ...(person.unitIds || [])])];
    account.email = normalizedEmail;
    account.status = "active";
    account.mfaExempt = true;
    account.localDemoAccount = true;
  }

  person.email = normalizedEmail;
  authSystem.store.save();
  return true;
}

async function syncLocalDemoAccounts(authSystem, data) {
  const sourceData = data || await loadOrmData();
  if (!sourceData) {
    return { synced: false, adults: 0, scouts: 0, accounts: 0 };
  }

  const unit = getOrCreateUnit(authSystem);
  const scouts = Array.isArray(sourceData.scouts) ? sourceData.scouts : [];
  const adults = Array.isArray(sourceData.adults) ? sourceData.adults : [];
  const adultLeaders = new Set(
    (Array.isArray(sourceData.adultLeaders) ? sourceData.adultLeaders : []).map((leader) => leader.adultId)
  );
  let accountCount = 0;

  scouts.forEach((scout) => {
    const person = ensurePerson(authSystem, {
      id: scout.id,
      name: scout.name,
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

  (Array.isArray(sourceData.adultScoutRelationships) ? sourceData.adultScoutRelationships : []).forEach((relationship) => {
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
  loadOrmData,
  syncLocalDemoAccounts
};
