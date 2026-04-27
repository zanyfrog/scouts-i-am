"use strict";

const fs = require("node:fs");
const path = require("node:path");

const DEFAULT_DATA = Object.freeze({
  people: [],
  units: [],
  parentLinks: [],
  unitRoleAssignments: [],
  globalRoleAssignments: [],
  accounts: [],
  invitations: [],
  sessions: []
});

class JsonStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.data = this.load();
  }

  load() {
    if (!fs.existsSync(this.filePath)) {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      fs.writeFileSync(this.filePath, JSON.stringify(DEFAULT_DATA, null, 2));
      return JSON.parse(JSON.stringify(DEFAULT_DATA));
    }

    const raw = fs.readFileSync(this.filePath, "utf8");
    const parsed = raw ? JSON.parse(raw) : {};

    return {
      people: parsed.people || [],
      units: parsed.units || [],
      parentLinks: parsed.parentLinks || [],
      unitRoleAssignments: parsed.unitRoleAssignments || [],
      globalRoleAssignments: parsed.globalRoleAssignments || [],
      accounts: parsed.accounts || [],
      invitations: parsed.invitations || [],
      sessions: parsed.sessions || []
    };
  }

  save() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2));
  }
}

module.exports = { JsonStore };
