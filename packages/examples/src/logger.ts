import * as readline from 'node:readline';

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
let activeRl: import('node:readline').Interface | null = null;

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
  const stream = level >= LogLevel.ERROR ? process.stderr : process.stdout;
  if (activeRl) {
    const rl = activeRl as any;
    readline.cursorTo(stream, 0);
    readline.clearLine(stream, 0);
    stream.write(formatted + '\n');
    rl._refreshLine();
  } else {
    stream.write(formatted + '\n');
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
export function setReadline(rl: import('node:readline').Interface | null): void { activeRl = rl; }
