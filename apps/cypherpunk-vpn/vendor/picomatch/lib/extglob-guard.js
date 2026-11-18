'use strict';

// Local build-tool restriction for GHSA-fc5q-39xc-vjpf. The project has no need
// for repeating extglobs. Refuse them before generating a backtracking RegExp,
// irrespective of options, nesting, quoting or escapes. This intentionally
// rejects some otherwise literal patterns as well; no compatibility claim.
module.exports = input => {
  if (typeof input === 'string' && (input.includes('+(') || input.includes('*('))) {
    throw new SyntaxError('Repeated extglobs are disabled in the cypherpunk_vpn build toolchain');
  }
};
