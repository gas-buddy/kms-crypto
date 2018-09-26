let logger = console;

export function setLogger(l) {
  logger = l;
}

export function getLogger() {
  return logger;
}
