#!/usr/bin/env node
/**
 * jspacket - Terminal Services manipulation tool (tstool)
 *
 * TypeScript port of impacket's examples/tstool.py.
 *
 * Provides similar functionality to the QWINSTA and other TS* Windows commands:
 *   qwinsta  - Display information about Remote Desktop Services sessions.
 *   tasklist - Display a list of currently running processes on the system.
 *   taskkill - Terminate tasks by process id (PID) or image name.
 *   tscon    - Attaches a user session to a remote desktop session.
 *   tsdiscon - Disconnects a Remote Desktop Services session.
 *   logoff   - Signs-out a Remote Desktop Services session.
 *   shutdown - Remote shutdown.
 *   msg      - Send a message to a Remote Desktop Services session (MSGBOX).
 *   shadow   - Shadow a Remote Desktop Services session.
 *
 * Reference: [MS-TSTS]
 *
 * Original impacket author: Alexander Korznikov (@nopernik)
 * shadow subcommand author: Ilya Yatsenko (@fulc2um)
 * TypeScript port for jspacket.
 */

import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline';
import { writeFileSync } from 'node:fs';
import {
  parseTarget,
  init as initLogger,
  initProxy,
  info,
  error as logError,
  debug,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';
import { SMBConnection } from '@impacket/smb-connection';
import {
  DCERPCTransportFactory,
  RPC_C_AUTHN_GSS_NEGOTIATE,
  RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
  MAXIMUM_ALLOWED,
  DCERPCException,
  // TSTS interface UUIDs
  TermSrvSession_UUID,
  TermSrvEnumeration_UUID,
  RCMPublic_UUID,
  SessEnvPublicRpc_UUID,
  LegacyAPI_UUID,
  // TSTS enums
  WINSTATIONSTATECLASS,
  SESSIONFLAGS,
  SHADOW_CONTROL_REQUEST,
  SHADOW_PERMISSION_REQUEST,
  SHADOW_REQUEST_RESPONSE,
  knownSid,
  // TSTS helper calls
  hRpcOpenEnum,
  hRpcGetEnumResult,
  hRpcCloseEnum,
  hRpcGetClientData,
  hRpcGetSessionInformationEx,
  hRpcWinStationOpenServer,
  hRpcWinStationGetAllProcesses,
  hRpcWinStationGetProcessSid,
  hRpcWinStationTerminateProcess,
  hRpcWinStationShutdownSystem,
  hRpcOpenSession,
  hRpcConnect,
  hRpcDisconnect,
  hRpcLogoff,
  hRpcShowMessageBox,
  hRpcShadow2,
  // lookupsid support
  MSRPC_UUID_LSAT,
  POLICY_LOOKUP_NAMES,
  LsapLookupLevel,
  hLsarLookupSids,
  hLsarOpenPolicy2,
} from '@impacket/dcerpc';


// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// Any DCERPC_v5 instance (kept loose to avoid deep type plumbing).
type Dce = any;

function padEndTo(s: string, n: number): string {
  return s.length >= n ? s : s + ' '.repeat(n - s.length);
}

function padStartTo(s: string, n: number): string {
  return s.length >= n ? s : ' '.repeat(n - s.length) + s;
}

function eq(n: number): string {
  return '='.repeat(Math.max(n, 0));
}

// Return the enum member name for a numeric value (impacket's enum2value).
function enum2value(
  enumClass: { enumItems: Record<number, string> },
  value: number,
): string {
  return enumClass.enumItems[value] ?? `UNKNOWN(${value})`;
}

// Adjust a computed column width against its header label, mirroring impacket.
function adjustWidth(computed: number, header: string): number {
  return header.length < computed ? computed : header.length + 1;
}

// Group an integer with thousands separators (impacket uses '{:,}').
function withCommas(n: number): string {
  return Math.trunc(n).toLocaleString('en-US');
}

// Convert a Windows FILETIME (100ns intervals since 1601-01-01) to a display
// string, returning 'None' when the year is <= 1601 (as impacket does).
function filetimeToStr(ft: unknown): string {
  let v: bigint;
  if (typeof ft === 'bigint') {
    v = ft;
  } else {
    v = BigInt(Math.trunc(Number(ft ?? 0)));
  }
  if (v <= 0n) return 'None';
  const ms = v / 10000n - 11644473600000n;
  const d = new Date(Number(ms));
  if (d.getFullYear() <= 1601) return 'None';
  const p = (x: number) => String(x).padStart(2, '0');
  return (
    `${d.getFullYear()}/${p(d.getMonth() + 1)}/${p(d.getDate())} ` +
    `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
  );
}

interface SessionRow {
  state: string;
  SessionName: string;
  RemoteIp: string;
  ClientName: string;
  Username: string;
  Domain: string;
  Resolution: string;
  ClientTimeZone: string;
  flags?: string;
  ConnectTime?: unknown;
  DisconnectTime?: unknown;
  LogonTime?: unknown;
  LastInputTime?: unknown;
}

interface Options {
  action: string;
  hashes: string | null;
  aesKey: string | null;
  k: boolean;
  dcIp: string | null;
  targetIp: string;
  port: number;
  verbose: boolean;
  // taskkill
  pid: number | null;
  name: string | null;
  // tscon / tsdiscon / logoff / msg / shadow
  source: number;
  dest: number;
  session: number;
  password: string | null;
  title: string | null;
  message: string | null;
  // shutdown
  logoff: boolean;
  shutdown: boolean;
  reboot: boolean;
  poweroff: boolean;
  // shadow
  control: boolean;
  prompt: boolean;
  file: string;
  debug: boolean;
}

// ---------------------------------------------------------------------------
// TSHandler
// ---------------------------------------------------------------------------

class TSHandler {
  private username: string;
  private password: string;
  private domain: string;
  private options: Options;
  private action: string;
  private lmhash: string;
  private nthash: string;
  private aesKey: string | null;
  private doKerberos: boolean;
  private kdcHost: string | null;
  private smb: SMBConnection | null = null;
  private sessions: Record<number, SessionRow> = {};
  private sids: Record<string, string> = {};

  constructor(username: string, password: string, domain: string, options: Options) {
    this.username = username;
    this.password = password;
    this.domain = domain;
    this.options = options;
    this.action = options.action.toLowerCase();
    this.lmhash = '';
    this.nthash = '';
    this.aesKey = options.aesKey;
    this.doKerberos = options.k;
    this.kdcHost = options.dcIp;
    if (options.hashes) {
      const parts = options.hashes.split(':');
      this.lmhash = parts[0] ?? '';
      this.nthash = parts[1] ?? '';
    }
  }

  private async connect(remoteName: string, remoteHost: string): Promise<void> {
    const smb = new SMBConnection(remoteName, remoteHost, { sessPort: this.options.port });
    await smb.negotiateSession();
    if (this.doKerberos) {
      await smb.kerberosLogin(
        this.username,
        this.password,
        this.domain,
        this.lmhash,
        this.nthash,
        this.aesKey ?? '',
        this.kdcHost,
      );
    } else {
      await smb.login(this.username, this.password, this.domain, this.lmhash, this.nthash);
    }
    this.smb = smb;
  }

  // Build a DCE/RPC binding to a named pipe over the existing SMB session, and
  // bind to the requested interface UUID. Mirrors tstool's TSTSEndpoint._bind.
  private async bindPipe(pipe: string, uuid: Buffer | undefined): Promise<Dce> {
    const stringBinding = `ncacn_np:${this.options.targetIp}[\\pipe\\${pipe}]`;
    const rpctransport = DCERPCTransportFactory(stringBinding);
    (rpctransport as any).setSmbConnection(this.smb);
    const dce = rpctransport.getDceRpc();
    if (this.doKerberos) {
      dce.setAuthType(RPC_C_AUTHN_GSS_NEGOTIATE);
    }
    dce.setAuthLevel(RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
    await dce.connect();
    await dce.bind(uuid as Buffer);
    return dce;
  }

  async run(remoteName: string, remoteHost: string): Promise<void> {
    if (this.action === 'shutdown') {
      const o = this.options;
      if (!(o.logoff || o.shutdown || o.reboot || o.poweroff)) {
        logError('At least one flag is required: -logoff, -shutdown, -reboot or -poweroff');
        process.exit(1);
      }
    }

    await this.connect(remoteName, remoteHost);

    switch (this.action) {
      case 'qwinsta':
        await this.doQwinsta();
        break;
      case 'tasklist':
        await this.doTasklist();
        break;
      case 'taskkill':
        await this.doTaskkill();
        break;
      case 'tscon':
        await this.doTscon();
        break;
      case 'tsdiscon':
        await this.doTsdiscon();
        break;
      case 'logoff':
        await this.doLogoff();
        break;
      case 'shutdown':
        await this.doShutdown();
        break;
      case 'msg':
        await this.doMsg();
        break;
      case 'shadow':
        await this.doShadow();
        break;
      default:
        logError(`Unknown action: ${this.action}`);
        process.exit(1);
    }
  }

  // -------------------------------------------------------------------------
  // Session enumeration
  // -------------------------------------------------------------------------

  private async getSessionList(): Promise<void> {
    const dce = await this.bindPipe('LSM_API_service', TermSrvEnumeration_UUID);
    try {
      const handle = await hRpcOpenEnum(dce);
      const resp: any = await hRpcGetEnumResult(dce, handle, 1);
      const rsessions = (resp.get('ppSessionEnumResult') as any[]) ?? [];
      await hRpcCloseEnum(dce, handle);
      this.sessions = {};
      for (const i of rsessions) {
        const sess = (i.get('SessionInfo') as any)?.get?.('SessionEnum_Level1');
        if (sess == null) continue;
        const stateVal = sess.get('State') as number;
        const state = (enum2value(WINSTATIONSTATECLASS, stateVal).split('_').pop()) ?? '';
        const id = sess.get('SessionId') as number;
        this.sessions[id] = {
          state,
          SessionName: String(sess.get('Name') ?? ''),
          RemoteIp: '',
          ClientName: '',
          Username: '',
          Domain: '',
          Resolution: '',
          ClientTimeZone: '',
        };
      }
    } finally {
      await dce.disconnect();
    }
  }

  private async enumerateSessionsConfig(): Promise<void> {
    if (Object.keys(this.sessions).length === 0) return;
    const dce = await this.bindPipe('TermSrv_API_service', RCMPublic_UUID);
    try {
      for (const idStr of Object.keys(this.sessions)) {
        const id = Number(idStr);
        const resp: any = await hRpcGetClientData(dce, id);
        if (resp != null) {
          const buff = resp.get('ppBuff') as any;
          this.sessions[id]!.RemoteIp = String(buff.get('ClientAddress') ?? '');
          this.sessions[id]!.ClientName = String(buff.get('ClientName') ?? '');
          const un = String(buff.get('UserName') ?? '');
          if (un.length && !this.sessions[id]!.Username.length) {
            this.sessions[id]!.Username = un;
          }
          const dm = String(buff.get('Domain') ?? '');
          if (dm.length && !this.sessions[id]!.Domain.length) {
            this.sessions[id]!.Domain = dm;
          }
          this.sessions[id]!.Resolution = `${buff.get('HRes')}x${buff.get('VRes')}`;
          const tz = buff.get('ClientTimeZone') as any;
          this.sessions[id]!.ClientTimeZone = String(tz.get('StandardName') ?? '');
        }
      }
    } finally {
      await dce.disconnect();
    }
  }

  private async enumerateSessionsInfo(): Promise<void> {
    if (Object.keys(this.sessions).length === 0) return;
    const dce = await this.bindPipe('LSM_API_service', TermSrvSession_UUID);
    try {
      for (const idStr of Object.keys(this.sessions)) {
        const id = Number(idStr);
        const sessdata: any = await hRpcGetSessionInformationEx(dce, id);
        const lvl = (sessdata.get('LSMSessionInfoExPtr') as any).get('LSM_SessionInfo_Level1');
        const flagsVal = lvl.get('SessionFlags') as number;
        this.sessions[id]!.flags = enum2value(SESSIONFLAGS, flagsVal);
        const domain = String(lvl.get('DomainName') ?? '');
        if (!this.sessions[id]!.Domain.length && domain.length) {
          this.sessions[id]!.Domain = domain;
        }
        const username = String(lvl.get('UserName') ?? '');
        if (!this.sessions[id]!.Username.length && username.length) {
          this.sessions[id]!.Username = username;
        }
        this.sessions[id]!.ConnectTime = lvl.get('ConnectTime');
        this.sessions[id]!.DisconnectTime = lvl.get('DisconnectTime');
        this.sessions[id]!.LogonTime = lvl.get('LogonTime');
        this.sessions[id]!.LastInputTime = lvl.get('LastInputTime');
      }
    } finally {
      await dce.disconnect();
    }
  }

  // -------------------------------------------------------------------------
  // qwinsta
  // -------------------------------------------------------------------------

  private async doQwinsta(): Promise<void> {
    const options = this.options;
    const desktopStates: Record<string, string> = {
      WTS_SESSIONSTATE_UNKNOWN: '',
      WTS_SESSIONSTATE_LOCK: 'Locked',
      WTS_SESSIONSTATE_UNLOCK: 'Unlocked',
    };

    await this.getSessionList();
    const ids = Object.keys(this.sessions).map(Number);
    if (ids.length === 0) {
      console.log('No sessions found...');
      return;
    }
    await this.enumerateSessionsInfo();
    if (options.verbose) {
      await this.enumerateSessionsConfig();
    }

    let maxSessionNameLen = Math.max(...ids.map((i) => this.sessions[i]!.SessionName.length + 1));
    maxSessionNameLen = adjustWidth(maxSessionNameLen, 'SESSIONNAME');

    let maxUsernameLen =
      Math.max(
        ...ids.map((i) => (this.sessions[i]!.Username + this.sessions[i]!.Domain).length + 1),
      ) + 1;
    maxUsernameLen = adjustWidth(maxUsernameLen, 'Username');

    let maxIdLen = Math.max(...ids.map((i) => String(i).length));
    maxIdLen = adjustWidth(maxIdLen, 'ID');

    let maxStateLen = Math.max(...ids.map((i) => this.sessions[i]!.state.length + 1));
    maxStateLen = adjustWidth(maxStateLen, 'STATE');

    let maxRemoteIp = Math.max(...ids.map((i) => this.sessions[i]!.RemoteIp.length + 1));
    maxRemoteIp = adjustWidth(maxRemoteIp, 'RemoteAddress');

    let maxClientName = Math.max(...ids.map((i) => this.sessions[i]!.ClientName.length + 1));
    maxClientName = adjustWidth(maxClientName, 'ClientName');

    const baseRow = (
      sessionName: string,
      username: string,
      id: string,
      state: string,
      dstate: string,
      conntime: string,
      disctime: string,
    ): string =>
      padEndTo(sessionName, maxSessionNameLen) + ' ' +
      padEndTo(username, maxUsernameLen) + ' ' +
      padEndTo(id, maxIdLen) + ' ' +
      padEndTo(state, maxStateLen) + ' ' +
      padEndTo(dstate, 9) + ' ' +
      padEndTo(conntime, 20) + ' ' +
      padEndTo(disctime, 20) + ' ';

    const baseUnderline =
      eq(maxSessionNameLen) + ' ' +
      eq(maxUsernameLen) + ' ' +
      eq(maxIdLen) + ' ' +
      eq(maxStateLen) + ' ' +
      eq(9) + ' ' +
      eq(20) + ' ' +
      eq(20) + ' ';

    const verboseRow = (
      clientName: string,
      remoteIp: string,
      resolution: string,
      timezone: string,
    ): string =>
      padEndTo(clientName, maxClientName) + ' ' +
      padEndTo(remoteIp, maxRemoteIp) + ' ' +
      padEndTo(resolution, 11) + ' ' +
      padEndTo(timezone, 15);

    const verboseUnderline =
      eq(maxClientName) + ' ' + eq(maxRemoteIp) + ' ' + eq(11) + ' ' + eq(15);

    let header = baseRow(
      'SESSIONNAME',
      'USERNAME',
      'ID',
      'STATE',
      'Desktop',
      'ConnectTime',
      'DisconnectTime',
    );
    let header2 = baseUnderline;
    let headerVerbose = '';
    let header2Verbose = '';
    if (options.verbose) {
      headerVerbose = verboseRow('ClientName', 'RemoteAddress', 'Resolution', 'ClientTimeZone');
      header2Verbose = verboseUnderline;
    }

    console.log(header + headerVerbose);
    console.log(header2 + header2Verbose);
    console.log('');

    for (const i of ids) {
      const s = this.sessions[i]!;
      const connectTime = filetimeToStr(s.ConnectTime);
      const disconnectTime = filetimeToStr(s.DisconnectTime);
      const userName = s.Username.length ? `${s.Domain}\\${s.Username}` : '';

      let row = baseRow(
        s.SessionName,
        userName,
        String(i),
        s.state,
        desktopStates[s.flags ?? 'WTS_SESSIONSTATE_UNKNOWN'] ?? '',
        connectTime,
        disconnectTime,
      );
      let rowVerbose = '';
      if (options.verbose) {
        rowVerbose = verboseRow(s.ClientName, s.RemoteIp, s.Resolution, s.ClientTimeZone);
      }
      console.log(row + rowVerbose);
    }
  }

  // -------------------------------------------------------------------------
  // lookupsid support (best-effort, mirrors lookupsid.py subset)
  // -------------------------------------------------------------------------

  private async lookupSids(): Promise<void> {
    try {
      const stringbinding = `ncacn_np:${this.options.targetIp}[\\pipe\\lsarpc]`;
      const rpctransport = DCERPCTransportFactory(stringbinding);
      (rpctransport as any).setSmbConnection(this.smb);
      const dce = rpctransport.getDceRpc();
      if (this.doKerberos) {
        dce.setAuthType(RPC_C_AUTHN_GSS_NEGOTIATE);
      }
      dce.setAuthLevel(RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
      await dce.connect();
      await dce.bind(MSRPC_UUID_LSAT as Buffer);

      let sids = Object.keys(this.sids);
      if (sids.length > 32) {
        sids = sids.slice(0, 32);
      }
      const openResp: any = await hLsarOpenPolicy2(dce as any, MAXIMUM_ALLOWED | POLICY_LOOKUP_NAMES);
      const policyHandle = openResp.get('PolicyHandle');

      let resp: any;
      try {
        resp = await hLsarLookupSids(
          dce as any,
          policyHandle,
          sids,
          LsapLookupLevel.enumValues.LsapLookupWksta!,
        );
      } catch (e) {
        if (
          e instanceof DCERPCException &&
          String((e as any).message ?? '').includes('STATUS_SOME_NOT_MAPPED')
        ) {
          resp = (e as any).getPacket ? (e as any).getPacket() : (e as any).packet;
        } else {
          throw e;
        }
      }

      const names = (resp.get('TranslatedNames') as any).get('Names') as any[];
      const domains = (resp.get('ReferencedDomains') as any).get('Domains') as any[];
      sids.forEach((sid, idx) => {
        const item = names[idx];
        if (!item) return;
        const domainIndex = item.get('DomainIndex') as number;
        if (domainIndex === -1) {
          this.sids[sid] = `???\\${item.get('Name')}`;
        } else if (domainIndex >= 0) {
          this.sids[sid] = `${domains[domainIndex]!.get('Name')}\\${item.get('Name')}`;
        }
      });

      await dce.disconnect();
    } catch (e) {
      debug(String(e));
    }
  }

  private sidToUser(sid: string): string {
    if (sid.startsWith('S-') && this.sids[sid]) {
      return this.sids[sid]!;
    }
    return sid;
  }

  // Best-effort per-process SID retrieval (impacket derives it from the same
  // GetAllProcesses response; jspacket returns TS_SYS_PROCESS_INFORMATION only,
  // so we resolve it with RpcWinStationGetProcessSid instead).
  private async getProcessSid(dce: Dce, handle: unknown, procInfo: any): Promise<string> {
    try {
      const pid = procInfo.get('UniqueProcessId') as number;
      const startTime = procInfo.fields['CreateTime'];
      const sid = await hRpcWinStationGetProcessSid(dce, handle, pid, startTime);
      return sid ? knownSid(sid) : '';
    } catch {
      return '';
    }
  }

  // -------------------------------------------------------------------------
  // tasklist
  // -------------------------------------------------------------------------

  private async doTasklist(): Promise<void> {
    const options = this.options;
    const dce = await this.bindPipe('Ctx_WinStation_API_service', LegacyAPI_UUID);
    try {
      const handle = await hRpcWinStationOpenServer(dce);
      const processEntryList = await hRpcWinStationGetAllProcesses(dce, handle);
      if (!processEntryList.length) {
        return;
      }

      // Resolve SIDs for each process (best-effort).
      const procSids: string[] = [];
      this.sids = {};
      for (const procInfo of processEntryList) {
        const sid = await this.getProcessSid(dce, handle, procInfo as any);
        procSids.push(sid);
        if (sid.startsWith('S-') && !this.sids[sid]) {
          this.sids[sid] = sid;
        }
      }
      await this.lookupSids();

      const imageNames = processEntryList.map((p: any) => String(p.get('ImageName') ?? ''));
      let maxImageNameLen = Math.max(...imageNames.map((n) => n.length), 1);
      let maxSidLen = Math.max(...procSids.map((s) => this.sidToUser(s).length), 1);

      if (options.verbose) {
        await this.getSessionList();
        await this.enumerateSessionsConfig();
        const sessIds = Object.keys(this.sessions).map(Number);
        let maxUserNameLen =
          Math.max(
            1,
            ...sessIds.map(
              (i) => (this.sessions[i]!.Username + this.sessions[i]!.Domain).length + 1,
            ),
          ) + 1;
        if (maxUserNameLen < 11) maxUserNameLen = 11;

        const vRow = (
          imagename: string,
          pid: string,
          sessid: string,
          sessionName: string,
          sessstate: string,
          sessionuser: string,
          sid: string,
          workingset: string,
        ): string =>
          padEndTo(imagename, maxImageNameLen) + ' ' +
          padEndTo(pid, 6) + ' ' +
          padEndTo(sessid, 6) + ' ' +
          padEndTo(sessionName, 16) + ' ' +
          padEndTo(sessstate, 11) + ' ' +
          padEndTo(sessionuser, maxUserNameLen) + ' ' +
          padEndTo(sid, maxSidLen) + ' ' +
          workingset;

        console.log(
          vRow('Image Name', 'PID', 'SessID', 'SessName', 'State', 'SessUser', 'SID', padEndTo('Mem Usage', 12)),
        );
        console.log(
          eq(maxImageNameLen) + ' ' +
            eq(6) + ' ' +
            eq(6) + ' ' +
            eq(16) + ' ' +
            eq(11) + ' ' +
            eq(maxUserNameLen) + ' ' +
            eq(maxSidLen) + ' ' +
            eq(12),
        );
        console.log('');

        processEntryList.forEach((procInfo: any, idx: number) => {
          const sessId = procInfo.get('SessionId') as number;
          const sess = this.sessions[sessId];
          let fullUserName = '';
          if (sess && sess.Domain.length) fullUserName += sess.Domain + '\\';
          if (sess && sess.Username.length) fullUserName += sess.Username;
          const memK = padStartTo(withCommas((procInfo.get('WorkingSetSize') as number) / 1000), 10) + ' K';
          console.log(
            vRow(
              String(procInfo.get('ImageName') ?? ''),
              String(procInfo.get('UniqueProcessId')),
              String(sessId),
              sess ? sess.SessionName : '',
              sess ? sess.state.replace('Disconnected', 'Disc') : '',
              fullUserName,
              this.sidToUser(procSids[idx] ?? ''),
              memK,
            ),
          );
        });
      } else {
        const row = (
          imageName: string,
          pid: string,
          session: string,
          sid: string,
          mem: string,
        ): string =>
          padEndTo(imageName, maxImageNameLen) + ' ' +
          padEndTo(pid, 8) + ' ' +
          padEndTo(session, 11) + ' ' +
          padEndTo(sid, maxSidLen) + ' ' +
          padStartTo(mem, 12);

        console.log(row('Image Name', 'PID', 'Session#', 'SID', 'Mem Usage'));
        console.log(
          eq(maxImageNameLen) + ' ' + eq(8) + ' ' + eq(11) + ' ' + eq(maxSidLen) + ' ' + eq(12),
        );
        console.log('');
        processEntryList.forEach((procInfo: any, idx: number) => {
          console.log(
            row(
              String(procInfo.get('ImageName') ?? ''),
              String(procInfo.get('UniqueProcessId')),
              String(procInfo.get('SessionId')),
              this.sidToUser(procSids[idx] ?? ''),
              `${withCommas((procInfo.get('WorkingSetSize') as number) / 1000)} K`,
            ),
          );
        });
      }
    } finally {
      await dce.disconnect();
    }
  }

  // -------------------------------------------------------------------------
  // taskkill
  // -------------------------------------------------------------------------

  private async doTaskkill(): Promise<void> {
    const options = this.options;
    if (options.pid === null && options.name === null) {
      logError('One of the following is required: -pid, -name');
      return;
    }
    let pidList: number[] = [];
    const dce = await this.bindPipe('Ctx_WinStation_API_service', LegacyAPI_UUID);
    try {
      const handle = await hRpcWinStationOpenServer(dce);
      if (options.pid === null && options.name !== null) {
        const r = await hRpcWinStationGetAllProcesses(dce, handle);
        if (!r.length) {
          logError('Could not get process list');
          return;
        }
        pidList = r
          .filter(
            (p: any) => String(p.get('ImageName') ?? '').toLowerCase() === options.name!.toLowerCase(),
          )
          .map((p: any) => p.get('UniqueProcessId') as number);
        if (!pidList.length) {
          logError(`Could not find '${options.name}' in process list`);
          return;
        }
      } else {
        pidList = [options.pid!];
      }

      for (const pid of pidList) {
        process.stdout.write(`Terminating PID: ${pid} ...`);
        try {
          const resp: any = await hRpcWinStationTerminateProcess(dce, handle, pid);
          if (resp.get('ErrorCode')) {
            console.log('OK');
          } else {
            console.log('FAIL');
          }
        } catch (e) {
          logError(`Error terminating pid: ${pid}`);
          logError(String(e));
        }
      }
    } finally {
      await dce.disconnect();
    }
  }

  // -------------------------------------------------------------------------
  // tscon
  // -------------------------------------------------------------------------

  private async doTscon(): Promise<void> {
    const options = this.options;
    const dce = await this.bindPipe('LSM_API_service', TermSrvSession_UUID);
    try {
      process.stdout.write(`Connecting SessionID ${options.source} to ${options.dest} ...`);
      let sessionHandle: unknown;
      try {
        sessionHandle = await hRpcOpenSession(dce, options.source);
      } catch (e) {
        console.log('FAIL');
        if ((e as any).error_code === 0x80070002) {
          logError(`Could not find source SessionID: ${options.source}`);
        } else {
          logError(String(e));
        }
        return;
      }
      try {
        const resp: any = await hRpcConnect(dce, sessionHandle, options.dest, options.password);
        if (resp.get('ErrorCode') === 0) {
          console.log('OK');
        } else {
          console.log('FAIL');
        }
      } catch (e) {
        console.log('FAIL');
        if ((e as any).error_code === 0x80070002) {
          logError(`Could not find destination SessionID: ${options.dest}`);
        } else if ((e as any).error_code === 0x8007139f) {
          logError(`Session in the invalid state. Did you mean ${options.dest} -> ${options.source}?`);
        } else {
          logError(String(e));
        }
      }
    } finally {
      await dce.disconnect();
    }
  }

  // -------------------------------------------------------------------------
  // tsdiscon
  // -------------------------------------------------------------------------

  private async doTsdiscon(): Promise<void> {
    const options = this.options;
    const dce = await this.bindPipe('LSM_API_service', TermSrvSession_UUID);
    try {
      process.stdout.write(`Disconnecting SessionID: ${options.session} ...`);
      try {
        const sessionHandle = await hRpcOpenSession(dce, options.session);
        const resp: any = await hRpcDisconnect(dce, sessionHandle);
        if (resp.get('ErrorCode') === 0) {
          console.log('OK');
        } else {
          console.log('FAIL');
        }
      } catch (e) {
        console.log('FAIL');
        if ((e as any).error_code === 1) {
          logError('Maybe it is already disconnected?');
        } else if ((e as any).error_code === 0x80070002) {
          logError(`Could not find SessionID: ${options.session}`);
        } else {
          logError(String(e));
        }
      }
    } finally {
      await dce.disconnect();
    }
  }

  // -------------------------------------------------------------------------
  // logoff
  // -------------------------------------------------------------------------

  private async doLogoff(): Promise<void> {
    const options = this.options;
    const dce = await this.bindPipe('LSM_API_service', TermSrvSession_UUID);
    try {
      process.stdout.write(`Signing-out SessionID: ${options.session} ...`);
      try {
        const sessionHandle = await hRpcOpenSession(dce, options.session);
        const resp: any = await hRpcLogoff(dce, sessionHandle);
        if (resp.get('ErrorCode') === 0) {
          console.log('OK');
        } else {
          console.log('FAIL');
        }
      } catch (e) {
        if ((e as any).error_code === 0x10000000) {
          console.log('OK');
          return;
        }
        console.log('FAIL');
        if ((e as any).error_code === 0x80070002) {
          logError(`Could not find SessionID: ${options.session}`);
        } else {
          logError(String(e));
        }
      }
    } finally {
      await dce.disconnect();
    }
  }

  // -------------------------------------------------------------------------
  // shutdown
  // -------------------------------------------------------------------------

  private async doShutdown(): Promise<void> {
    const options = this.options;
    const dce = await this.bindPipe('Ctx_WinStation_API_service', LegacyAPI_UUID);
    try {
      const handle = await hRpcWinStationOpenServer(dce);
      let flags = 0;
      const flagsList: string[] = [];
      const shutdownFlags = [options.logoff, options.shutdown, options.reboot, options.poweroff];
      const names = ['logoff', 'shutdown', 'reboot', 'poweroff'];
      const bits = [1, 2, 4, 8];
      shutdownFlags.forEach((v, idx) => {
        if (v) flagsList.push(names[idx]!);
      });
      shutdownFlags.forEach((v, idx) => {
        if (v) flags |= bits[idx]!;
      });
      process.stdout.write(`Sending shutdown (${flagsList.join('|')}) event ...`);
      try {
        const resp: any = await hRpcWinStationShutdownSystem(dce, handle, 0, flags);
        if (resp.get('ErrorCode')) {
          console.log('OK');
        } else {
          console.log('FAIL');
        }
      } catch (e) {
        console.log('FAIL');
        logError(String(e));
      }
    } finally {
      await dce.disconnect();
    }
  }

  // -------------------------------------------------------------------------
  // msg
  // -------------------------------------------------------------------------

  private async doMsg(): Promise<void> {
    const options = this.options;
    const dce = await this.bindPipe('LSM_API_service', TermSrvSession_UUID);
    try {
      process.stdout.write(`Sending message to SessionID: ${options.session} ...`);
      try {
        const sessionHandle = await hRpcOpenSession(dce, options.session);
        const resp: any = await hRpcShowMessageBox(dce, sessionHandle, options.title, options.message);
        if (resp.get('ErrorCode') === 0) {
          console.log('OK');
        } else {
          console.log('FAIL');
        }
      } catch (e) {
        console.log('FAIL');
        if ((e as any).error_code === 0x80070002) {
          logError(`Could not find SessionID: ${options.session}`);
        } else {
          logError(String(e));
        }
      }
    } finally {
      await dce.disconnect();
    }
  }

  // -------------------------------------------------------------------------
  // shadow
  // -------------------------------------------------------------------------

  private async doShadow(): Promise<void> {
    const options = this.options;
    const control = options.control
      ? SHADOW_CONTROL_REQUEST.enumValues.SHADOW_CONTROL_REQUEST_TAKECONTROL!
      : SHADOW_CONTROL_REQUEST.enumValues.SHADOW_CONTROL_REQUEST_VIEW!;
    const perm = options.prompt
      ? SHADOW_PERMISSION_REQUEST.enumValues.SHADOW_PERMISSION_REQUEST_REQUESTPERMISSION!
      : SHADOW_PERMISSION_REQUEST.enumValues.SHADOW_PERMISSION_REQUEST_SILENT!;

    info(
      `Calling RpcShadow2 (SessionId=${options.session}, Control=${options.control}, Permission=${options.prompt})`,
    );

    let permission: number | null = null;
    let invitation: string | null = null;
    const dce = await this.bindPipe('SessEnvPublicRpc', SessEnvPublicRpc_UUID);
    try {
      const response: any = await hRpcShadow2(dce, options.session, control, perm, 8192);
      if (options.debug) {
        debug(`Response: ${(response.getData() as Buffer).toString('hex')}`);
      }
      permission = response.get('pePermission') as number;
      invitation = response.get('pszInvitation') as string;
    } catch (e) {
      if (e instanceof DCERPCException) {
        logError(`RPC Exception: ${e}`);
        return;
      }
      throw e;
    } finally {
      await dce.disconnect();
    }

    if (permission !== null) {
      let desc = 'Unknown';
      const name = SHADOW_REQUEST_RESPONSE.enumItems[permission];
      if (name) desc = name;
      info(`Permission: ${permission} (${desc})`);
    }

    if (permission === SHADOW_REQUEST_RESPONSE.enumValues.SHADOW_REQUEST_RESPONSE_ALLOW) {
      info('RpcShadow2 call succeeded!');
      if (!invitation) {
        logError('RpcShadow2 failed: No invitation received');
        process.exit(1);
      }
      info(`Invitation received (${invitation.length} characters)`);

      // Trim trailing NUL / CR / LF and surrounding whitespace, then validate
      // that the payload looks like a complete XML element before saving.
      let inv = invitation.replace(/[\0\r\n]+$/g, '').trim();
      if (!(inv.startsWith('<') && inv.endsWith('>'))) {
        const endPos = inv.lastIndexOf('</E>');
        if (endPos >= 0) {
          inv = inv.slice(0, endPos + 4);
        } else {
          inv = '';
        }
      }
      if (inv.startsWith('<') && inv.endsWith('>')) {
        info('Invitation is well-formed XML');
        writeFileSync(options.file, inv, { encoding: 'utf-8' });
        info(`Saved to ${options.file} file`);
      } else {
        logError('Invitation does not appear to be well-formed XML');
      }
    } else {
      logError('RpcShadow2 failed: Permission denied');
      process.exit(1);
    }
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printUsage(): void {
  console.log(`Terminal Services manipulation tool.

usage: tstool [-h] [-debug] [-ts] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
              [-aesKey hex key] [-dc-ip ip address] [-target-ip ip address]
              [-port {139,445}]
              target
              {qwinsta,tasklist,taskkill,tscon,tsdiscon,logoff,shutdown,msg,shadow} ...

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

actions:
  qwinsta               Display information about Remote Desktop Services sessions.
                          -v                Turn VERBOSE output ON
  tasklist              Display a list of currently running processes on the system.
                          -v                Turn VERBOSE output ON
  taskkill              Terminate tasks by process id (PID) or image name.
                          -pid PID          Specifies process id (PID)
                          -name NAME        Specifies process name (ImageName)
  tscon                 Attaches a user session to a remote desktop session.
                          -source SessionID (required) Source SessionId
                          -dest SessionID   (required) Destination SessionId
                          -password PASS    Destination Session's password
  tsdiscon              Disconnects a Remote Desktop Services session.
                          -session SessionID (required) SessionId to disconnect
  logoff                Sign out a Remote Desktop Services session.
                          -session SessionID (required) SessionId to sign out
  shutdown              Remote shutdown, affects ALL sessions and logged-in users!
                          -logoff -shutdown -reboot -poweroff
  msg                   Send a message to Remote Desktop Services session (MSGBOX).
                          -session SessionID (required) Receiver SessionId
                          -title TITLE      Title of the MessageBox [Optional]
                          -message MESSAGE  (required) Contents of the MessageBox
  shadow                Shadow a Remote Desktop Services session.
                          -session SessionID (required) SessionId to shadow
                          -control          Request control of the session
                          -prompt           Request user permission
                          -file FILE        Save invitation to file

options:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output

authentication:
  -hashes LMHASH:NTHASH NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)

connection:
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port {139,445}       Destination port to connect to SMB Server`);
}

async function main(): Promise<void> {
  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: normalizeArgs(process.argv.slice(2)),
      options: {
        debug: { type: 'boolean', default: false },
        ts: { type: 'boolean', default: false },
        // qwinsta / tasklist
        v: { type: 'boolean', short: 'v', default: false },
        // taskkill
        pid: { type: 'string' },
        name: { type: 'string' },
        // tscon
        source: { type: 'string' },
        dest: { type: 'string' },
        password: { type: 'string' },
        // tsdiscon / logoff / msg / shadow
        session: { type: 'string' },
        // msg
        title: { type: 'string' },
        message: { type: 'string' },
        // shutdown
        logoff: { type: 'boolean', default: false },
        shutdown: { type: 'boolean', default: false },
        reboot: { type: 'boolean', default: false },
        poweroff: { type: 'boolean', default: false },
        // shadow
        control: { type: 'boolean', default: false },
        prompt: { type: 'boolean', default: false },
        file: { type: 'string', default: 'invite.msrcIncident' },
        // authentication
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', short: 'k', default: false },
        aesKey: { type: 'string' },
        // connection
        'dc-ip': { type: 'string' },
        'target-ip': { type: 'string' },
        port: { type: 'string', default: '445' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
      allowPositionals: true,
      strict: true,
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    printUsage();
    process.exit(1);
  }

  if (values.help || positionals.length === 0) {
    printUsage();
    process.exit(positionals.length === 0 ? 1 : 0);
  }

  console.log(`${BANNER}\n`);

  initProxy(values.proxy);
  initLogger({ ts: values.ts, debug: values.debug });

  const action = positionals[1];
  if (!action) {
    printUsage();
    logError('Too few arguments...');
    process.exit(1);
  }

  const target = positionals[0]!;
  const [domainRaw, username, passwordRaw, remoteName] = parseTarget(target);
  const domain = domainRaw || '';

  const targetIp = values['target-ip'] ?? remoteName;

  let doKerberos = values.k ?? false;
  if (values.aesKey) {
    doKerberos = true;
  }

  let password = passwordRaw;
  if (
    password === '' &&
    username !== '' &&
    !values.hashes &&
    !values['no-pass'] &&
    !values.aesKey
  ) {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    password = await new Promise<string>((resolve) => {
      rl.question('Password: ', (answer) => {
        rl.close();
        resolve(answer);
      });
    });
  }

  const options: Options = {
    action,
    hashes: values.hashes ?? null,
    aesKey: values.aesKey ?? null,
    k: doKerberos,
    dcIp: values['dc-ip'] ?? null,
    targetIp,
    port: parseInt(values.port!, 10),
    verbose: values.v ?? false,
    pid: values.pid !== undefined ? parseInt(values.pid, 10) : null,
    name: values.name ?? null,
    source: values.source !== undefined ? parseInt(values.source, 10) : 0,
    dest: values.dest !== undefined ? parseInt(values.dest, 10) : 0,
    session: values.session !== undefined ? parseInt(values.session, 10) : 0,
    password: values.password ?? null,
    title: values.title ?? null,
    message: values.message ?? null,
    logoff: values.logoff ?? false,
    shutdown: values.shutdown ?? false,
    reboot: values.reboot ?? false,
    poweroff: values.poweroff ?? false,
    control: values.control ?? false,
    prompt: values.prompt ?? false,
    file: values.file ?? 'invite.msrcIncident',
    debug: values.debug ?? false,
  };

  const handler = new TSHandler(username, password, domain, options);
  try {
    await handler.run(remoteName, targetIp);
  } catch (e) {
    logError(String(e));
    if (options.debug) {
      console.error(e);
    }
  }
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
