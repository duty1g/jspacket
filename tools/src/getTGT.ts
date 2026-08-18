#!/usr/bin/env node
/**
 * Impacket-js - getTGT
 *
 * Given a password, hash, or aesKey, requests a TGT and saves it as a ccache
 * file for later use.
 *
 * Python implementation by Alberto Solino (@agsolino).
 * TypeScript port.
 */

import { Buffer } from 'node:buffer';
import { parseArgs } from 'node:util';

import {
  parseIdentity,
  init as initLogger,
  initProxy,
  info,
  error as logError,
  debug as logDebug,
  warning,
  critical,
  getLevel,
  LogLevel,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';

import {
  KerberosV5,
  Types,
  Constants,
  Asn1,
  Crypto,
  CCache as KrbCCache,
  Keytab as KeytabModule,
} from '@impacket/krb5';

import type { AnyValue, Asn1Sequence } from '@impacket/asn1';

// ---------- helpers ----------

/**
 * Convert a JavaScript Date (or ASN.1 GeneralizedTime value) to a Unix
 * timestamp in seconds suitable for a ccache Times field.
 */
function toEpoch(value: unknown): number {
  if (value instanceof Date) return Math.floor(value.getTime() / 1000);
  if (typeof value === 'number') return value;
  if (typeof value === 'string') return Math.floor(new Date(value).getTime() / 1000);
  return 0;
}

// ---------- main class ----------

interface GetTGTOptions {
  aesKey: string;
  kdcHost: string | null;
  noPass: boolean;
  keytab: string | null;
  service: string | null;
  principalType: number;
}

class GETTGT {
  private username: string;
  private password: string;
  private domain: string;
  private lmhash: string;
  private nthash: string;
  private aesKey: string;
  private kdcHost: string | null;
  private keytab: string | null;
  private service: string | null;
  private principalType: number;

  constructor(
    username: string,
    password: string,
    domain: string,
    lmhash: string,
    nthash: string,
    opts: GetTGTOptions,
  ) {
    this.username = username;
    this.password = password;
    this.domain = domain;
    this.lmhash = lmhash;
    this.nthash = nthash;
    this.aesKey = opts.aesKey;
    this.kdcHost = opts.kdcHost;
    this.keytab = opts.keytab;
    this.service = opts.service;
    this.principalType = opts.principalType;
  }

  async run(): Promise<void> {
    const upperDomain = this.domain.toUpperCase();

    // Handle keytab authentication
    if (this.keytab !== null) {
      const keytab = KeytabModule.Keytab.loadFile(this.keytab);
      const spn = `${this.username}@${upperDomain}`;
      const key = keytab.getKey(spn);
      if (key !== null) {
        this.aesKey = key.keyvalue.data.toString('hex');
      } else {
        warning(`No key found in keytab for ${spn}, trying without keytab key`);
      }
    }

    const clientName = new Types.Principal(
      this.username,
      null,
      this.principalType,
    );

    // Build service principal if -service was specified
    let serverName: Types.Principal | null = null;
    if (this.service) {
      serverName = new Types.Principal(
        this.service,
        null,
        Constants.PrincipalNameType.NT_SRV_INST,
      );
      logDebug(`Requesting TGT for service ${this.service}`);
    }

    logDebug(`Requesting TGT for ${this.username}@${upperDomain}`);

    let tgtResult: KerberosV5.TGTResult;
    try {
      tgtResult = await KerberosV5.getKerberosTGT(
        clientName,
        this.password,
        this.domain,
        this.lmhash,
        this.nthash,
        this.aesKey,
        this.kdcHost,
        true,        // requestPAC
        serverName,  // serverName (custom service SPN)
      );
    } catch (e) {
      if (e instanceof KerberosV5.KerberosError) {
        logError(e.message);
        return;
      }
      throw e;
    }

    // Decode the AS-REP to extract ticket metadata for the ccache
    const asRep = Asn1.AS_REP();
    asRep.decode(tgtResult.tgt);
    const asRepValues = asRep.values;

    // Decrypt the enc-part to get times and flags
    const encPart = asRepValues['enc-part'] as Record<string, unknown>;
    const cipherText = encPart['cipher'] as Buffer;

    let encAsRepPart: Asn1Sequence | null = null;
    try {
      const plainText = tgtResult.cipher.decrypt(tgtResult.key, 3, cipherText);
      const decoded = Asn1.EncASRepPart();
      decoded.decode(plainText);
      encAsRepPart = decoded;
    } catch {
      // If the cipher from the TGT result doesn't match, try with the session cipher
      try {
        const sessionCipher = Crypto._get_enctype_profile(tgtResult.sessionKey.enctype);
        const plainText = sessionCipher.decrypt(tgtResult.key, 3, cipherText);
        const decoded = Asn1.EncASRepPart();
        decoded.decode(plainText);
        encAsRepPart = decoded;
      } catch {
        // Fall back: times will be zero but we still save the ticket
        warning('Could not decrypt enc-part for ticket metadata; saving with default times');
      }
    }

    // Build the CCache
    const ccache = new KrbCCache.CCache();
    ccache.setDefaultHeader();

    // Set the primary principal (client)
    const clientPrincipal = new KrbCCache.PrincipalCCache();
    clientPrincipal.fromPrincipal(
      new Types.Principal(this.username, upperDomain, Constants.PrincipalNameType.NT_PRINCIPAL),
    );
    ccache.principal = clientPrincipal;

    // Build the credential entry
    const cred = new KrbCCache.Credential();

    // Client principal
    cred.client = new KrbCCache.PrincipalCCache();
    cred.client.fromPrincipal(
      new Types.Principal(this.username, upperDomain, Constants.PrincipalNameType.NT_PRINCIPAL),
    );

    // Server principal: krbtgt/DOMAIN@DOMAIN
    cred.server = new KrbCCache.PrincipalCCache();
    cred.server.fromPrincipal(
      new Types.Principal(
        `krbtgt/${upperDomain}`,
        upperDomain,
        Constants.PrincipalNameType.NT_SRV_INST,
      ),
    );

    // Session key
    cred.key = new KrbCCache.KeyBlock();
    cred.key.keytype = tgtResult.sessionKey.enctype;
    cred.key.etype = 0;
    cred.key.keyvalue = tgtResult.sessionKey.contents;

    // Times from the decrypted enc-part
    cred.time = new KrbCCache.Times();
    if (encAsRepPart !== null) {
      cred.time.authtime = toEpoch(encAsRepPart.get('authtime'));
      cred.time.starttime = toEpoch(
        encAsRepPart.get('starttime') ?? encAsRepPart.get('authtime'),
      );
      cred.time.endtime = toEpoch(encAsRepPart.get('endtime'));
      cred.time.renew_till = toEpoch(encAsRepPart.get('renew-till') ?? 0);
    }

    // Ticket flags
    if (encAsRepPart !== null) {
      const flagsValue = encAsRepPart.get('flags');
      if (flagsValue !== null && flagsValue !== undefined) {
        if (Buffer.isBuffer(flagsValue)) {
          // BitString: first byte is unused-bits count, remaining bytes are the flags
          if (flagsValue.length >= 5) {
            cred.tktflags = flagsValue.readUInt32BE(1);
          } else if (flagsValue.length >= 4) {
            cred.tktflags = flagsValue.readUInt32BE(0);
          }
        } else if (typeof flagsValue === 'number') {
          cred.tktflags = flagsValue;
        }
      }
    }

    cred.is_skey = 0;

    // Encode the raw ticket for the ccache credential
    cred.ticket = new KrbCCache.CountedOctetString();
    const ticketNode = Asn1.Ticket();
    const ticketValues = asRepValues['ticket'] as Record<string, AnyValue>;
    ticketNode.values = ticketValues;
    cred.ticket.data = ticketNode.encode();

    ccache.credentials.push(cred);

    // Save to file
    const fileName = `${this.username}.ccache`;
    info(`Saving ticket in ${fileName}`);
    ccache.saveFile(fileName);
  }
}

// ---------- CLI ----------

function usage(): never {
  console.log(`Given a password, hash or aesKey, it will request a TGT and save it as ccache

usage: getTGT [-h] [-ts] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k]
              [-aesKey hex key] [-dc-ip ip address] [-keytab KEYTAB]
              [-service SPN] [-principalType PRINCIPALTYPE]
              identity

positional arguments:
  identity              [domain/]username[:password]

options:
  -h, --help            show this help message and exit
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
                        If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)
  -dc-ip ip address     IP Address of the domain controller. If ommited it use
                        the domain part (FQDN) specified in the target
                        parameter
  -keytab KEYTAB        Read keys for SPN from keytab file
  -service SPN          Request a Service Ticket directly through an AS-REQ
  -principalType PRINCIPALTYPE
                        PrincipalType of the token (default NT_PRINCIPAL).
                        Can be one of NT_UNKNOWN, NT_PRINCIPAL, NT_SRV_INST,
                        NT_SRV_HST, NT_SRV_XHST, NT_UID, NT_SMTP_NAME,
                        NT_ENTERPRISE, NT_WELLKNOWN, NT_SRV_HST_DOMAIN,
                        NT_MS_PRINCIPAL, NT_MS_PRINCIPAL_AND_ID,
                        NT_ENT_PRINCIPAL_AND_ID
`);
  process.exit(1);
}

async function main(): Promise<void> {
  const args = normalizeArgs(process.argv.slice(2));

  if (args.length === 0) {
    usage();
  }

  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        hashes: { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
        keytab: { type: 'string' },
        service: { type: 'string' },
        principalType: { type: 'string' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    usage();
  }

  if (values.help || positionals.length < 1) {
    usage();
  }

  const target = positionals[0]!;

  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  const identity = parseIdentity(target, {
    hashes: values.hashes,
    noPass: values['no-pass'],
    aesKey: values.aesKey,
  });

  if (identity.domain === '') {
    critical('Domain should be specified!');
    process.exit(1);
  }

  if (
    identity.password === '' &&
    identity.username !== '' &&
    identity.lmhash === '' &&
    identity.nthash === '' &&
    (values.aesKey === undefined || values.aesKey === '') &&
    (values.keytab === undefined || values.keytab === '') &&
    !values['no-pass']
  ) {
    critical(
      'No credentials supplied. Use -hashes, -aesKey, -keytab, or provide a password in the identity string.',
    );
    process.exit(1);
  }

  // Resolve principal type from string name to enum value
  let principalType = Constants.PrincipalNameType.NT_PRINCIPAL;
  if (values.principalType) {
    const ptKey = values.principalType as keyof typeof Constants.PrincipalNameType;
    if (ptKey in Constants.PrincipalNameType) {
      principalType = Constants.PrincipalNameType[ptKey];
      logDebug(`Using principal type: ${ptKey} (${principalType})`);
    } else {
      warning(`Unknown principal type '${values.principalType}', using default NT_PRINCIPAL`);
    }
  }

  const opts: GetTGTOptions = {
    aesKey: values.aesKey ?? '',
    kdcHost: values['dc-ip'] ?? null,
    noPass: values['no-pass'] ?? false,
    keytab: values.keytab ?? null,
    service: values.service ?? null,
    principalType,
  };

  try {
    const executer = new GETTGT(
      identity.username,
      identity.password,
      identity.domain,
      identity.lmhash,
      identity.nthash,
      opts,
    );
    await executer.run();
  } catch (e) {
    if (getLevel() === LogLevel.DEBUG) {
      console.error(e);
    }
    if (e instanceof KerberosV5.KerberosError) {
      logError(e.message);
    } else {
      logError(String(e));
    }
  }
}

main();
