"use strict";

const ROLES = Object.freeze({
  PUBLIC: "public",
  SCOUT: "scout",
  PARENT: "parent",
  ADULT_LEADER: "adult_leader",
  COMMITTEE_MEMBER: "committee_member",
  ADMINISTRATOR: "administrator"
});

const PERSON_TYPES = Object.freeze({
  ADULT: "adult",
  SCOUT: "scout"
});

const ROLE_ASSIGNABLE_BY_UNIT = new Set([
  ROLES.ADULT_LEADER,
  ROLES.COMMITTEE_MEMBER
]);

const GLOBAL_ASSIGNABLE_ROLES = new Set([ROLES.ADMINISTRATOR]);

module.exports = {
  GLOBAL_ASSIGNABLE_ROLES,
  PERSON_TYPES,
  ROLES,
  ROLE_ASSIGNABLE_BY_UNIT
};
