import * as fs from 'node:fs';
import { info, warning } from '@impacket/examples';
import type { ProtocolClientConstructor } from './config.js';

export class TargetsProcessor {
  originalTargets: URL[] = [];
  finishedAttacks: URL[] = [];
  failedAttacks: URL[] = [];
  generalCandidates: URL[] = [];
  namedCandidates: URL[] = [];
  filename: string | null = null;
  protocolClients: Record<string, ProtocolClientConstructor> | null = null;

  constructor(opts: {
    targetListFile?: string;
    singleTarget?: string;
    protocolClients?: Record<string, ProtocolClientConstructor>;
    randomize?: boolean;
  }) {
    this.protocolClients = opts.protocolClients ?? null;

    if (opts.targetListFile) {
      this.filename = opts.targetListFile;
      this.readTargets();
    } else if (opts.singleTarget) {
      this.originalTargets = TargetsProcessor.processTarget(opts.singleTarget, this.protocolClients);
    }

    if (opts.randomize) {
      for (let i = this.originalTargets.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [this.originalTargets[i], this.originalTargets[j]] = [this.originalTargets[j]!, this.originalTargets[i]!];
      }
    }

    this.reloadTargets(true);
  }

  static processTarget(
    target: string,
    protocolClients: Record<string, ProtocolClientConstructor> | null,
  ): URL[] {
    if (!target.includes('://')) {
      return [new URL(`smb://${target}`)];
    }

    if (target.slice(0, 3).toUpperCase() === 'ALL') {
      const stripped = target.slice(3);
      const results: URL[] = [];
      if (protocolClients) {
        for (const protocol of Object.keys(protocolClients)) {
          try {
            results.push(new URL(`${protocol}${stripped}`));
          } catch { /* skip invalid */ }
        }
      }
      return results;
    }

    try {
      return [new URL(target)];
    } catch {
      return [new URL(`smb://${target}`)];
    }
  }

  readTargets(): void {
    if (!this.filename) return;
    try {
      const content = fs.readFileSync(this.filename, 'utf-8');
      this.originalTargets = [];
      for (const line of content.split('\n')) {
        const target = line.trim();
        if (target && !target.startsWith('#')) {
          this.originalTargets.push(
            ...TargetsProcessor.processTarget(target, this.protocolClients),
          );
        }
      }
    } catch (e) {
      console.error(`Could not open file: ${this.filename} - ${e}`);
    }

    if (this.originalTargets.length === 0) {
      warning('No valid targets specified!');
    }

    this.reloadTargets();
  }

  reloadTargets(fullReload = false): void {
    if (fullReload) {
      this.finishedAttacks = [];
      this.failedAttacks = [];
    }

    const finishedUrls = new Set(this.finishedAttacks.map((u) => u.href));
    const failedUrls = new Set(this.failedAttacks.map((u) => u.href));

    this.generalCandidates = this.originalTargets.filter(
      (x) => !finishedUrls.has(x.href) && !failedUrls.has(x.href) && !x.username,
    );
    this.namedCandidates = this.originalTargets.filter(
      (x) => !finishedUrls.has(x.href) && !failedUrls.has(x.href) && !!x.username,
    );
  }

  registerTarget(target: URL, gotRelay: boolean, gotUsername: string | null): void {
    if (target.username) {
      (gotRelay ? this.finishedAttacks : this.failedAttacks).push(target);
    } else if (gotUsername) {
      let newUrl: URL;
      try {
        if (target.protocol.startsWith('http') && target.search) {
          newUrl = new URL(`${target.protocol}//${gotUsername.replace('/', '\\')}@${target.host}${target.pathname}${target.search}`);
        } else {
          newUrl = new URL(`${target.protocol}//${gotUsername.replace('/', '\\')}@${target.host}${target.pathname}`);
        }
      } catch {
        newUrl = target;
      }
      (gotRelay ? this.finishedAttacks : this.failedAttacks).push(newUrl);
    }
  }

  getTarget(identity?: string | null, multiRelay = true): URL | null {
    if (identity && this.namedCandidates.length > 0) {
      for (let i = 0; i < this.namedCandidates.length; i++) {
        const target = this.namedCandidates[i]!;
        if (target.username) {
          const upper = target.username.toUpperCase();
          if (upper === (identity ?? '').replace('/', '\\').toUpperCase()) {
            this.namedCandidates.splice(i, 1);
            return target;
          }
          if (!target.username.includes('\\')) {
            const idParts = identity.split('/');
            if (upper === (idParts[1] ?? '').toUpperCase()) {
              this.namedCandidates.splice(i, 1);
              return target;
            }
          }
        }
      }
    }

    if (this.generalCandidates.length > 0) {
      if (identity) {
        for (let i = 0; i < this.generalCandidates.length; i++) {
          const target = this.generalCandidates[i]!;
          const tmpTarget = `${target.protocol}//${identity.replace('/', '\\')}@${target.host}${target.pathname}`;
          const upperTmp = tmpTarget.toUpperCase();
          const isFinished = this.finishedAttacks.some((x) => x.href.toUpperCase() === upperTmp);
          const isFailed = this.failedAttacks.some((x) => x.href.toUpperCase() === upperTmp);
          if (!isFinished && !isFailed) {
            this.generalCandidates.splice(i, 1);
            return target;
          }
        }
        return null;
      }

      if (!multiRelay) {
        for (let i = 0; i < this.generalCandidates.length; i++) {
          const target = this.generalCandidates[i]!;
          const isFinished = this.finishedAttacks.some(
            (x) => x.hostname === target.hostname && x.protocol === target.protocol,
          );
          if (!isFinished) {
            this.generalCandidates.splice(i, 1);
            return target;
          }
        }
        return null;
      }

      return this.generalCandidates.pop() ?? null;
    }

    if (this.originalTargets.length > 0) {
      const finishedHosts = new Set(this.finishedAttacks.map((a) => `${a.hostname}:${a.protocol}`));
      const failedHosts = new Set(this.failedAttacks.map((a) => `${a.hostname}:${a.protocol}`));
      this.generalCandidates = this.originalTargets.filter(
        (x) =>
          !finishedHosts.has(`${x.hostname}:${x.protocol}`) &&
          !failedHosts.has(`${x.hostname}:${x.protocol}`) &&
          !x.username,
      );
    }

    if (this.generalCandidates.length === 0) {
      if (this.namedCandidates.length === 0) {
        info('All targets processed!');
      }
      return null;
    }

    return this.getTarget(identity, multiRelay);
  }
}

export class TargetsFileWatcher {
  private _processor: TargetsProcessor;
  private _lastMtime: number;
  private _interval: ReturnType<typeof setInterval> | null = null;

  constructor(processor: TargetsProcessor) {
    this._processor = processor;
    this._lastMtime = processor.filename
      ? fs.statSync(processor.filename).mtimeMs
      : 0;
  }

  start(): void {
    if (!this._processor.filename) return;
    this._interval = setInterval(() => {
      try {
        const mtime = fs.statSync(this._processor.filename!).mtimeMs;
        if (mtime > this._lastMtime) {
          info('Targets file modified - refreshing');
          this._lastMtime = mtime;
          this._processor.readTargets();
        }
      } catch { /* file gone */ }
    }, 1000);
  }

  stop(): void {
    if (this._interval) {
      clearInterval(this._interval);
      this._interval = null;
    }
  }
}
