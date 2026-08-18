#!/usr/bin/env node
/**
 * jspacket - changepasswd
 *
 * Change or reset the password of a user over various protocols:
 *   - MS-SAMR over SMB or RPC transport (NetUserChangePassword / NetUserSetInfo)
 *   - Kerberos change-password and reset-password protocols (kpasswd, RFC3244)
 *   - LDAP password change and reset (unicodePwd over LDAPS)
 *
 * A password *change* can usually be initiated when the previous password (or
 * its hash) is known. A password *reset* requires additional privileges.
 *
 * Python implementation by @snovvcrash, @alef-burzmali, @bransh, @Oddvarmoe and
 * @p0dalirius (based on smbpasswd.py). TypeScript port.
 */

import { Buffer } from 'node:buffer';
import { parseArgs } from 'node:util';
import { createInterface } from 'node:readline';

import {
  parseTarget,
  EMPTY_LM_HASH,
  init as initLogger,
  info,
  error as logError,
  debug as logDebug,
  critical,
  warning,
  getLevel,
  LogLevel,
  normalizeArgs,
  initProxy,
  BANNER,
} from '@impacket/examples';

import {
  DCERPCTransportFactory,
  MSRPC_UUID_SAMR,
  MAXIMUM_ALLOWED,
  heptMap,
  hSamrConnect,
  hSamrLookupDomainInSamServer,
  hSamrOpenDomain,
  hSamrLookupNamesInDomain,
  hSamrOpenUser,
  hSamrUnicodeChangePasswordUser2,
  hSamrChangePasswordUser,
  hSamrSetNTInternal1,
} from '@impacket/dcerpc';

import { KPasswd, KerberosV5 } from '@impacket/krb5';

import {
  LDAPConnection,
  LDAPSessionError,
  Operation,
  ResultCode,
  Scope,
  type SearchResultEntry,
} from '@impacket/ldap';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/** Extract a plain number out of an NDR scalar (NDRULONG) or a raw number. */
function toNum(v: unknown): number {
  if (typeof v === 'number') return v;
  if (v && typeof (v as any).get === 'function') {
    const inner = (v as any).get('Data');
    return typeof inner === 'number' ? inner : Number(inner);
  }
  if (v && typeof (v as any).fields === 'object') return Number((v as any).fields['Data']);
  return Number(v);
}

/** Read a password interactively (not hidden - Node has no portable getpass). */
function prompt(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

// ---------------------------------------------------------------------------
// Generic password handler
// ---------------------------------------------------------------------------

interface HandlerOpts {
  address: string;
  domain?: string;
  authUsername?: string;
  authPassword?: string;
  authPwdHashLM?: string;
  authPwdHashNT?: string;
  doKerberos?: boolean;
  aesKey?: string;
  kdcHost?: string | null;
}

/** Generic interface for all the password protocols supported by this script. */
abstract class PasswordHandler {
  address: string;
  domain: string;
  username: string;
  password: string;
  pwdHashLM: string;
  pwdHashNT: string;
  doKerberos: boolean;
  aesKey: string;
  kdcHost: string | null;

  constructor(opts: HandlerOpts) {
    this.address = opts.address;
    this.domain = opts.domain ?? '';
    this.username = opts.authUsername ?? '';
    this.password = opts.authPassword ?? '';
    this.pwdHashLM = opts.authPwdHashLM ?? '';
    this.pwdHashNT = opts.authPwdHashNT ?? '';
    this.doKerberos = opts.doKerberos ?? false;
    this.aesKey = opts.aesKey ?? '';
    this.kdcHost = opts.kdcHost ?? null;
  }

  protected abstract _changePassword(
    targetUsername: string,
    targetDomain: string,
    oldPassword: string,
    newPassword: string,
    oldPwdHashLM: string,
    oldPwdHashNT: string,
    newPwdHashLM: string,
    newPwdHashNT: string,
  ): Promise<boolean>;

  async changePassword(
    targetUsername: string,
    targetDomain: string,
    oldPassword: string,
    newPassword: string,
    oldPwdHashLM: string,
    oldPwdHashNT: string,
    newPwdHashLM: string,
    newPwdHashNT: string,
  ): Promise<boolean> {
    info(`Changing the password of ${targetDomain}\\${targetUsername}`);
    return this._changePassword(
      targetUsername,
      targetDomain,
      oldPassword,
      newPassword,
      oldPwdHashLM,
      oldPwdHashNT,
      newPwdHashLM,
      newPwdHashNT,
    );
  }

  protected abstract _setPassword(
    targetUsername: string,
    targetDomain: string,
    newPassword: string,
    newPwdHashLM: string,
    newPwdHashNT: string,
  ): Promise<boolean>;

  async setPassword(
    targetUsername: string,
    targetDomain: string,
    newPassword: string,
    newPwdHashLM: string,
    newPwdHashNT: string,
  ): Promise<boolean> {
    info(`Setting the password of ${targetDomain}\\${targetUsername} as ${this.domain}\\${this.username}`);
    return this._setPassword(targetUsername, targetDomain, newPassword, newPwdHashLM, newPwdHashNT);
  }
}

// ---------------------------------------------------------------------------
// Kerberos Change-Password / Set-Password (RFC3244)
// ---------------------------------------------------------------------------

class KPassword extends PasswordHandler {
  protected async _changePassword(
    targetUsername: string,
    targetDomain: string,
    oldPassword: string,
    newPassword: string,
    oldPwdHashLM: string,
    oldPwdHashNT: string,
    _newPwdHashLM: string,
    _newPwdHashNT: string,
  ): Promise<boolean> {
    if (targetUsername !== this.username) {
      critical('KPassword does not support changing the password of another user (try setPassword instead)');
      return false;
    }

    if (!newPassword) {
      critical('KPassword requires the new password as plaintext');
      return false;
    }

    try {
      logDebug(
        JSON.stringify([targetUsername, targetDomain, '<newpass>', oldPassword ? '<oldpass>' : '', oldPwdHashLM, oldPwdHashNT]),
      );
      await KPasswd.changePassword(
        targetUsername,
        targetDomain,
        newPassword,
        oldPassword,
        oldPwdHashLM,
        oldPwdHashNT,
        this.aesKey,
        null,
        this.kdcHost,
      );
    } catch (e) {
      if (e instanceof KerberosV5.KerberosError || e instanceof KPasswd.KPasswdError) {
        logError(`Password not changed: ${e}`);
        return false;
      }
      throw e;
    }

    info('Password was changed successfully.');
    return true;
  }

  protected async _setPassword(
    targetUsername: string,
    targetDomain: string,
    newPassword: string,
    _newPwdHashLM: string,
    _newPwdHashNT: string,
  ): Promise<boolean> {
    if (!newPassword) {
      critical('KPassword requires the new password as plaintext');
      return false;
    }

    try {
      await KPasswd.setPassword(
        this.username,
        this.domain,
        targetUsername,
        targetDomain,
        newPassword,
        this.password,
        this.pwdHashLM,
        this.pwdHashNT,
        this.aesKey,
        null,
        this.kdcHost,
      );
    } catch (e) {
      if (e instanceof KerberosV5.KerberosError || e instanceof KPasswd.KPasswdError) {
        logError(`Password not changed for ${targetDomain}\\${targetUsername}: ${e}`);
        return false;
      }
      throw e;
    }

    info(`Password was set successfully for ${targetDomain}\\${targetUsername}.`);
    return true;
  }
}

// ---------------------------------------------------------------------------
// MS-SAMR (over SMB or RPC)
// ---------------------------------------------------------------------------

abstract class SamrPassword extends PasswordHandler {
  protected dce: any = null;
  protected anonymous = false;

  /** Return a new (unconnected) RPC transport for our DCE binding. */
  protected abstract rpctransport(): Promise<any>;

  /** Instantiate a new transport and try to authenticate, returning a bound DCE. */
  private async authenticate(anonymous: boolean): Promise<any> {
    const rpctransport = await this.rpctransport();

    if ('setCredentials' in rpctransport) {
      if (anonymous) {
        rpctransport.setCredentials('', '', '', '', '', null);
      } else {
        rpctransport.setCredentials(
          this.username,
          this.password,
          this.domain,
          this.pwdHashLM,
          this.pwdHashNT,
          this.aesKey,
        );
      }
    }

    if (anonymous) {
      this.anonymous = true;
      rpctransport.setKerberos(false, null);
    } else {
      this.anonymous = false;
      rpctransport.setKerberos(this.doKerberos, this.kdcHost);
    }

    const asUser = anonymous ? 'null session' : `${this.domain}\\${this.username}`;
    info(`Connecting to DCE/RPC as ${asUser}`);

    const dce = rpctransport.getDceRpc();
    await dce.connect();
    await dce.bind(MSRPC_UUID_SAMR);
    logDebug('Successfully bound to SAMR');
    return dce;
  }

  protected async connect(retryIfExpired: boolean): Promise<boolean> {
    if (this.dce) return true;

    try {
      this.dce = await this.authenticate(false);
    } catch (e) {
      const msg = String(e);
      if (msg.includes('STATUS_PASSWORD_MUST_CHANGE') || msg.includes('STATUS_PASSWORD_EXPIRED')) {
        if (retryIfExpired) {
          warning('Password is expired or must be changed, trying to bind with a null session.');
          this.dce = await this.authenticate(true);
        } else {
          critical(
            'Cannot set new NTLM hashes when current password is expired. Provide a plaintext value for the ' +
              'new password.',
          );
          logDebug(msg);
          return false;
        }
      } else if (msg.includes('STATUS_LOGON_FAILURE')) {
        critical('Authentication failure when connecting to RPC: wrong credentials?');
        logDebug(msg);
        return false;
      } else if (msg.includes('STATUS_ACCOUNT_RESTRICTION')) {
        critical(
          'Account restriction: username and credentials are valid, but some other restriction prevents' +
            "authentication, like 'Protected Users' group or time-of-day restriction",
        );
        logDebug(msg);
        return false;
      } else if (msg.includes('STATUS_ACCOUNT_DISABLED')) {
        critical('The account is currently disabled.');
        logDebug(msg);
        return false;
      } else {
        throw e;
      }
    }

    return true;
  }

  private async hSamrOpenUser(username: string): Promise<any | false> {
    try {
      const connResp = await hSamrConnect(this.dce, this.address + '\x00');
      const serverHandle = connResp.get('ServerHandle') as any;
      const domResp = await hSamrLookupDomainInSamServer(this.dce, serverHandle, this.domain);
      const domainSID = domResp.get('DomainId') as any;
      const openResp = await hSamrOpenDomain(this.dce, serverHandle, MAXIMUM_ALLOWED, domainSID);
      const domainHandle = openResp.get('DomainHandle') as any;
      const namesResp = await hSamrLookupNamesInDomain(this.dce, domainHandle, [username]);
      const relIds = namesResp.get('RelativeIds') as any;
      const element = relIds.get('Element') as any;
      const userRID = element[0];
      const userResp = await hSamrOpenUser(this.dce, domainHandle, MAXIMUM_ALLOWED, userRID);
      return userResp.get('UserHandle');
    } catch (e) {
      const msg = String(e);
      if (msg.includes('STATUS_NO_SUCH_DOMAIN')) {
        critical(
          'Wrong realm. Try to set the domain name for the target user account explicitly in format ' +
            'DOMAIN/username.',
        );
        logDebug(msg);
        return false;
      } else if (this.anonymous && msg.includes('STATUS_ACCESS_DENIED')) {
        critical(
          'Our anonymous session cannot get a handle to the target user. ' +
            'Retry with a user whose password is not expired.',
        );
        logDebug(msg);
        return false;
      } else if (msg.includes('STATUS_ACCESS_DENIED')) {
        critical('Access denied');
        logDebug(msg);
        return false;
      }
      throw e;
    }
  }

  /** Handles common errors around a SAMR password call, regardless of procedure. */
  private async samrWrapper(procName: string, call: () => Promise<any>, change: boolean): Promise<boolean> {
    logDebug(`Sending SAMR call ${procName}`);
    let resp: any;
    try {
      resp = await call();
    } catch (e) {
      const msg = String(e);
      if (msg.includes('STATUS_PASSWORD_RESTRICTION')) {
        critical(
          'Some password update rule has been violated. For example, the password history policy may prohibit the ' +
            'use of recent passwords or the password may not meet length criteria.',
        );
        logDebug(msg);
        return false;
      } else if (msg.includes('STATUS_ACCESS_DENIED')) {
        if (change) {
          critical('Target user is not allowed to change their own password');
        } else {
          critical(`${this.domain}\\${this.username} user is not allowed to set the password of the target`);
        }
        logDebug(msg);
        return false;
      }
      throw e;
    }

    if (toNum(resp.get('ErrorCode')) === 0) {
      info('Password was changed successfully.');
      return true;
    }

    logError('Non-zero return code, something weird happened.');
    return false;
  }

  private async doUnicodeChangePasswordUser2(
    username: string,
    oldPassword: string,
    newPassword: string,
    oldPwdHashLM: string,
    oldPwdHashNT: string,
  ): Promise<boolean> {
    return this.samrWrapper(
      'hSamrUnicodeChangePasswordUser2',
      () =>
        hSamrUnicodeChangePasswordUser2(
          this.dce,
          '\x00',
          username,
          oldPassword,
          newPassword,
          oldPwdHashLM,
          oldPwdHashNT,
        ),
      true,
    );
  }

  private async doChangePasswordUser(
    username: string,
    oldPassword: string,
    newPassword: string,
    oldPwdHashNT: string,
    newPwdHashLM: string,
    newPwdHashNT: string,
  ): Promise<boolean> {
    const userHandle = await this.hSamrOpenUser(username);
    if (!userHandle) return false;

    return this.samrWrapper(
      'hSamrChangePasswordUser',
      () =>
        hSamrChangePasswordUser(this.dce, userHandle, oldPassword, newPassword, oldPwdHashNT, newPwdHashLM, newPwdHashNT),
      true,
    );
  }

  private async doSetInformationUser(username: string, newPassword: string, newPwdHashNT: string): Promise<boolean> {
    const userHandle = await this.hSamrOpenUser(username);
    if (!userHandle) return false;

    return this.samrWrapper(
      'hSamrSetNTInternal1',
      () => hSamrSetNTInternal1(this.dce, userHandle, newPassword, newPwdHashNT),
      false,
    );
  }

  protected async _changePassword(
    targetUsername: string,
    _targetDomain: string,
    oldPassword: string,
    newPassword: string,
    oldPwdHashLM: string,
    oldPwdHashNT: string,
    newPwdHashLM: string,
    newPwdHashNT: string,
  ): Promise<boolean> {
    if (!(await this.connect(true))) return false;

    if (newPassword) {
      // Plaintext value for the new password
      return this.doUnicodeChangePasswordUser2(targetUsername, oldPassword, newPassword, oldPwdHashLM, oldPwdHashNT);
    }
    // NTLM hashes for the new password
    const res = await this.doChangePasswordUser(
      targetUsername,
      oldPassword,
      '',
      oldPwdHashNT,
      newPwdHashLM,
      newPwdHashNT,
    );
    if (res) {
      warning(
        'User might need to change their password at next logon because we set hashes (unless password never expires is set).',
      );
    }
    return res;
  }

  protected async _setPassword(
    targetUsername: string,
    _targetDomain: string,
    newPassword: string,
    _newPwdHashLM: string,
    newPwdHashNT: string,
  ): Promise<boolean> {
    if (!(await this.connect(false))) return false;

    const res = await this.doSetInformationUser(targetUsername, newPassword, newPwdHashNT);
    if (res) {
      warning('User no longer has valid AES keys for Kerberos, until they change their password again.');
    }
    return res;
  }
}

class RpcPassword extends SamrPassword {
  protected async rpctransport(): Promise<any> {
    const stringBinding = await heptMap(this.address, MSRPC_UUID_SAMR, undefined, 'ncacn_ip_tcp');
    if (!stringBinding) {
      throw new Error('Could not resolve SAMR endpoint via the endpoint mapper');
    }
    const rpctransport = DCERPCTransportFactory(stringBinding);
    rpctransport.setRemoteHost(this.address);
    return rpctransport;
  }

  protected override async _changePassword(
    targetUsername: string,
    targetDomain: string,
    oldPassword: string,
    newPassword: string,
    oldPwdHashLM: string,
    oldPwdHashNT: string,
    newPwdHashLM: string,
    newPwdHashNT: string,
  ): Promise<boolean> {
    if (!newPassword) {
      warning(
        'MS-RPC transport requires new password in plaintext in default Active Directory configuration. Trying anyway.',
      );
    }
    return super._changePassword(
      targetUsername,
      targetDomain,
      oldPassword,
      newPassword,
      oldPwdHashLM,
      oldPwdHashNT,
      newPwdHashLM,
      newPwdHashNT,
    );
  }

  protected override async _setPassword(
    targetUsername: string,
    targetDomain: string,
    newPassword: string,
    newPwdHashLM: string,
    newPwdHashNT: string,
  ): Promise<boolean> {
    warning('MS-RPC transport does not allow password reset in default Active Directory configuration. Trying anyway.');
    return super._setPassword(targetUsername, targetDomain, newPassword, newPwdHashLM, newPwdHashNT);
  }
}

class SmbPassword extends SamrPassword {
  protected async rpctransport(): Promise<any> {
    const stringBinding = `ncacn_np:${this.address}[\\pipe\\samr]`;
    const rpctransport = DCERPCTransportFactory(stringBinding);
    rpctransport.setRemoteHost(this.address);
    return rpctransport;
  }
}

// ---------------------------------------------------------------------------
// LDAP password change / set
// ---------------------------------------------------------------------------

class LdapPassword extends PasswordHandler {
  private ldapConnection: LDAPConnection | null = null;
  private baseDN = '';

  private async connect(targetDomain: string): Promise<boolean> {
    if (this.ldapConnection) return true;

    const ldapURI = 'ldaps://' + this.address;
    this.baseDN = 'DC=' + targetDomain.split('.').join(',DC=');

    logDebug(`Connecting to ${ldapURI} as ${this.domain}\\${this.username}`);
    try {
      const ldapConnection = new LDAPConnection({
        url: ldapURI,
        baseDN: this.baseDN,
        dstIp: this.kdcHost ?? undefined,
      });
      await ldapConnection.connect();
      if (!this.doKerberos) {
        await ldapConnection.login({
          user: this.username,
          password: this.password,
          domain: this.domain,
          lmhash: this.pwdHashLM,
          nthash: this.pwdHashNT,
        });
      } else {
        await ldapConnection.kerberosLogin({
          user: this.username,
          password: this.password,
          domain: this.domain,
          lmhash: this.pwdHashLM,
          nthash: this.pwdHashNT,
          aesKey: this.aesKey,
          kdcHost: this.kdcHost,
        });
      }
      this.ldapConnection = ldapConnection;
    } catch (e) {
      logError(`Cannot connect to ${ldapURI} as ${this.domain}\\${this.username}: ${e}`);
      return false;
    }

    return true;
  }

  /** Password must be surrounded by quotes and UTF-16LE encoded. */
  private encodeLdapPassword(password: string): Buffer {
    return Buffer.from(`"${password}"`, 'utf-16le');
  }

  private async findTargetDN(targetUsername: string): Promise<string | null> {
    const answers = await this.ldapConnection!.search({
      searchFilter: `(sAMAccountName=${targetUsername})`,
      searchBase: this.baseDN,
      attributes: ['distinguishedName'],
    });

    for (const item of answers as SearchResultEntry[]) {
      return item.objectName;
    }
    return null;
  }

  private async modifyPassword(
    change: boolean,
    targetUsername: string,
    targetDomain: string,
    oldPasswordEncoded: Buffer | null,
    newPasswordEncoded: Buffer,
  ): Promise<boolean> {
    if (!(await this.connect(targetDomain))) return false;

    const targetDN = await this.findTargetDN(targetUsername);
    if (!targetDN) {
      critical('Could not find the target user in LDAP');
      return false;
    }

    logDebug(`Found target distinguishedName: ${targetDN}`);

    try {
      if (change) {
        await this.ldapConnection!.modify(targetDN, [
          { operation: Operation.delete, modification: { type: 'unicodePwd', vals: [oldPasswordEncoded!] } },
          { operation: Operation.add, modification: { type: 'unicodePwd', vals: [newPasswordEncoded] } },
        ]);
      } else {
        await this.ldapConnection!.modify(targetDN, [
          { operation: Operation.replace, modification: { type: 'unicodePwd', vals: [newPasswordEncoded] } },
        ]);
      }
    } catch (e) {
      if (e instanceof LDAPSessionError) {
        // getErrorString() embeds the numeric resultCode, so match on the code.
        const code = e.getErrorCode();
        if (code === ResultCode.constraintViolation) {
          logError(
            `Could not change the password of ${targetDN}, possibly due to the password policy or an invalid oldPassword.`,
          );
        } else if (code === ResultCode.insufficientAccessRights) {
          logError(`Could not set the password of ${targetDN}, ${this.domain}\\${this.username} has insufficient rights`);
        } else {
          logError(`Could not change the password of ${targetDN}. ${e.getErrorString()}`);
        }
        return false;
      }
      throw e;
    }

    info(`Password was changed successfully for ${targetDN}`);
    return true;
  }

  protected async _changePassword(
    targetUsername: string,
    targetDomain: string,
    oldPassword: string,
    newPassword: string,
    _oldPwdHashLM: string,
    _oldPwdHashNT: string,
    _newPwdHashLM: string,
    _newPwdHashNT: string,
  ): Promise<boolean> {
    if (!oldPassword || !newPassword) {
      critical('LDAP requires the old and new passwords in plaintext');
      return false;
    }
    const oldPasswordEncoded = this.encodeLdapPassword(oldPassword);
    const newPasswordEncoded = this.encodeLdapPassword(newPassword);
    return this.modifyPassword(true, targetUsername, targetDomain, oldPasswordEncoded, newPasswordEncoded);
  }

  protected async _setPassword(
    targetUsername: string,
    targetDomain: string,
    newPassword: string,
    _newPwdHashLM: string,
    _newPwdHashNT: string,
  ): Promise<boolean> {
    if (!newPassword) {
      critical('LDAP requires the new password in plaintext');
      return false;
    }
    const newPasswordEncoded = this.encodeLdapPassword(newPassword);
    return this.modifyPassword(false, targetUsername, targetDomain, null, newPasswordEncoded);
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printUsage(): void {
  console.log(`Change or reset passwords over different protocols.

usage: changepasswd [-h] [-ts] [-debug]
                    [-newpass NEWPASS | -newhashes LMHASH:NTHASH]
                    [-hashes LMHASH:NTHASH] [-no-pass]
                    [-altuser ALTUSER] [-altpass ALTPASS | -althash ALTHASH]
                    [-protocol {smb-samr,rpc-samr,kpasswd,ldap}] [-reset]
                    [-k] [-aesKey hex key] [-dc-ip ip address]
                    target

positional arguments:
  target                [[domain/]username[:password]@]<hostname or address>

options:
  -h, --help            show this help message and exit
  -ts                   adds timestamp to every logging output
  -debug                turn DEBUG output ON

New credentials for target:
  -newpass NEWPASS      new password
  -newhashes LMHASH:NTHASH
                        new NTLM hashes, format is NTHASH or LMHASH:NTHASH

Authentication (target user whose password is changed):
  -hashes LMHASH:NTHASH NTLM hashes, format is NTHASH or LMHASH:NTHASH
  -no-pass              Don't ask for password (useful for Kerberos, -k)

Authentication (optional, privileged user performing the change):
  -altuser ALTUSER      Alternative username
  -altpass ALTPASS      Alternative password
  -althash ALTHASH      Alternative NT hash, format is NTHASH or LMHASH:NTHASH

Method of operations:
  -protocol, -p {smb-samr,rpc-samr,kpasswd,ldap}
                        Protocol to use for password change/reset (default: smb-samr)
  -reset, -admin        Try to reset the password with privileges

Kerberos authentication (applies to -altuser if defined, else target):
  -k                    Use Kerberos authentication (KRB5CCNAME ccache)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller, for Kerberos
`);
}

async function main(): Promise<void> {
  const rawArgs = normalizeArgs(process.argv.slice(2));
  if (rawArgs.length === 0) {
    printUsage();
    process.exit(1);
  }

  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: rawArgs,
      allowPositionals: true,
      options: {
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        newpass: { type: 'string' },
        newhashes: { type: 'string' },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        altuser: { type: 'string' },
        altpass: { type: 'string' },
        althash: { type: 'string' },
        althashes: { type: 'string' },
        protocol: { type: 'string', short: 'p', default: 'smb-samr' },
        reset: { type: 'boolean', default: false },
        admin: { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    printUsage();
    process.exit(1);
  }

  if (values.help || positionals.length < 1) {
    printUsage();
    process.exit(values.help ? 0 : 1);
  }

  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  const protocol = values.protocol ?? 'smb-samr';
  const validProtocols = ['smb-samr', 'rpc-samr', 'kpasswd', 'ldap'];
  if (!validProtocols.includes(protocol)) {
    critical(`Unsupported password protocol ${protocol}`);
    process.exit(1);
  }

  const reset = values.reset || values.admin;
  const althash = values.althash ?? values.althashes ?? null;

  // Parse account whose password is changed
  let [targetDomain, targetUsername, oldPassword, address] = parseTarget(positionals[0]!);

  if (!targetDomain) {
    targetDomain = protocol === 'rpc-samr' || protocol === 'smb-samr' ? 'Builtin' : address;
  }

  let oldPwdHashLM = '';
  let oldPwdHashNT = '';
  if (values.hashes != null) {
    if (values.hashes.includes(':')) {
      const parts = values.hashes.split(':');
      oldPwdHashLM = parts[0] ?? '';
      oldPwdHashNT = parts[1] ?? '';
    } else {
      oldPwdHashLM = EMPTY_LM_HASH;
      oldPwdHashNT = values.hashes;
    }
  }

  if (oldPassword === '' && oldPwdHashNT === '') {
    if (reset) {
      // no need for the old one when we reset
    } else if (values['no-pass']) {
      info('Current password not given: will use KRB5CCNAME');
    } else {
      oldPassword = await prompt('Current password: ');
    }
  }

  let newPassword = '';
  let newPwdHashLM = '';
  let newPwdHashNT = '';
  if (values.newhashes != null) {
    if (values.newhashes.includes(':')) {
      const parts = values.newhashes.split(':');
      newPwdHashLM = parts[0] || EMPTY_LM_HASH;
      newPwdHashNT = parts[1] ?? '';
    } else {
      newPwdHashLM = EMPTY_LM_HASH;
      newPwdHashNT = values.newhashes;
    }
  } else if (values.newpass == null) {
    newPassword = await prompt('New password: ');
    const retype = await prompt('Retype new password: ');
    if (newPassword !== retype) {
      critical('Passwords do not match, try again.');
      process.exit(1);
    }
  } else {
    newPassword = values.newpass;
  }

  // Parse account of the password changer
  let authDomain: string;
  let authUsername: string;
  let authPassword = '';
  let authPwdHashLM = '';
  let authPwdHashNT = '';

  if (values.altuser != null) {
    if (values.altuser.includes('/')) {
      const parts = values.altuser.split('/');
      authDomain = parts[0] ?? '';
      authUsername = parts[1] ?? '';
    } else {
      authDomain = targetDomain;
      authUsername = values.altuser;
    }

    if (althash != null) {
      if (althash.includes(':')) {
        const parts = althash.split(':');
        authPwdHashLM = parts[0] ?? '';
        authPwdHashNT = parts[1] ?? '';
      } else {
        authPwdHashLM = '';
        authPwdHashNT = althash;
      }
    }

    if (values.altpass != null) {
      authPassword = values.altpass;
    }

    if (values.altpass == null && althash == null && !values['no-pass']) {
      critical(
        'Please, provide either alternative password (-altpass) or NT hash (-althash) for authentication, ' +
          'or specify -no-pass if you rely on Kerberos only',
      );
      process.exit(1);
    }
  } else {
    authDomain = targetDomain;
    authUsername = targetUsername;
    authPassword = oldPassword;
    authPwdHashLM = oldPwdHashLM;
    authPwdHashNT = oldPwdHashNT;
  }

  let doKerberos = values.k ?? false;
  if (protocol === 'kpasswd' && !doKerberos) {
    logDebug('Using the KPassword protocol implies Kerberos authentication (-k)');
    doKerberos = true;
  }

  const opts: HandlerOpts = {
    address,
    domain: authDomain,
    authUsername,
    authPassword,
    authPwdHashLM,
    authPwdHashNT,
    doKerberos,
    aesKey: values.aesKey ?? '',
    kdcHost: values['dc-ip'] ?? null,
  };

  let handler: PasswordHandler;
  switch (protocol) {
    case 'kpasswd':
      handler = new KPassword(opts);
      break;
    case 'rpc-samr':
      handler = new RpcPassword(opts);
      break;
    case 'ldap':
      handler = new LdapPassword(opts);
      break;
    case 'smb-samr':
    default:
      handler = new SmbPassword(opts);
      break;
  }

  let ret: boolean;
  try {
    if (reset) {
      ret = await handler.setPassword(targetUsername, targetDomain, newPassword, newPwdHashLM, newPwdHashNT);
    } else {
      if (authDomain !== targetDomain || authUsername !== targetUsername) {
        warning(
          `Attempting to *change* the password of ${targetDomain}/${targetUsername} as ${authDomain}/${authUsername}. ` +
            "You may want to use '-reset' to *reset* the password of the target.",
        );
      }
      ret = await handler.changePassword(
        targetUsername,
        targetDomain,
        oldPassword,
        newPassword,
        oldPwdHashLM,
        oldPwdHashNT,
        newPwdHashLM,
        newPwdHashNT,
      );
    }
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) console.error(e);
    logError(String(e));
    ret = false;
  }

  process.exit(ret ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
