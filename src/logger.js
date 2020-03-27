const loggerSymbol = Symbol.for('@gasbuddy/kms-crypto::logger');
if (!global[loggerSymbol]) {
  global[loggerSymbol] = console;
}

export function setLogger(l) {
  global[loggerSymbol] = l;
}

export function getLogger() {
  if (!global[loggerSymbol]) {
    return console;
  }
  return global[loggerSymbol];
}
