const loggerSymbol = Symbol.for('@gasbuddy/kms-crypto::logger');
if (!global[loggerSymbol]) {
  global[loggerSymbol] = console;
}

export function setLogger(l) {
  global[loggerSymbol] = l;
}

export function getLogger() {
  return global[loggerSymbol] || console;
}
