export enum LogLevel {
  DEBUG = 10,
  INFO = 20,
  WARNING = 30,
  ERROR = 40,
  CRITICAL = 50,
}

const BULLETS: Record<number, string> = {
  [LogLevel.INFO]: '[*]',
  [LogLevel.DEBUG]: '[+]',
  [LogLevel.WARNING]: '[!]',
  [LogLevel.ERROR]: '[-]',
  [LogLevel.CRITICAL]: '[-]',
};

let currentLevel = LogLevel.INFO;
let useTimestamp = false;

function formatMessage(level: LogLevel, message: string): string {
  const bullet = BULLETS[level] ?? '[-]';
  if (useTimestamp) {
    const ts = new Date().toISOString().replace('T', ' ').substring(0, 19);
    return `[${ts}] ${bullet} ${message}`;
  }
  return `${bullet} ${message}`;
}

function log(level: LogLevel, message: string): void {
  if (level < currentLevel) return;
  const formatted = formatMessage(level, message);
  if (level >= LogLevel.ERROR) {
    process.stderr.write(formatted + '\n');
  } else {
    process.stdout.write(formatted + '\n');
  }
}

export function init(opts: { ts?: boolean; debug?: boolean } = {}): void {
  useTimestamp = opts.ts ?? false;
  currentLevel = opts.debug ? LogLevel.DEBUG : LogLevel.INFO;
}

export function debug(message: string): void { log(LogLevel.DEBUG, message); }
export function info(message: string): void { log(LogLevel.INFO, message); }
export function warning(message: string): void { log(LogLevel.WARNING, message); }
export function error(message: string): void { log(LogLevel.ERROR, message); }
export function critical(message: string): void { log(LogLevel.CRITICAL, message); }

export function setLevel(level: LogLevel): void { currentLevel = level; }
export function getLevel(): LogLevel { return currentLevel; }
