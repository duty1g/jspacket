#!/usr/bin/env node
/**
 * Impacket-js - ticketConverter
 *
 * Converts kirbi files (KRB-CRED, commonly used by mimikatz) into ccache files
 * used by impacket, and vice versa.
 *
 * Examples:
 *   ticketConverter admin.ccache admin.kirbi
 *   ticketConverter admin.kirbi  admin.ccache
 *
 * Python implementation by Zer1t0 (https://github.com/Zer1t0).
 * TypeScript port.
 *
 * References:
 *   - https://tools.ietf.org/html/rfc4120
 *   - http://web.mit.edu/KERBEROS/krb5-devel/doc/formats/ccache_file_format.html
 */

import { Buffer } from 'node:buffer';
import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import { BANNER, initProxy } from '@impacket/examples';
import { Asn1, CCache as KrbCCache } from '@impacket/krb5';

import { Asn1SequenceOf, type Asn1Sequence, type AnyValue } from '@impacket/asn1';

// ---------- helpers ----------

/** Convert an ASN.1 GeneralizedTime (Date) into a Unix timestamp in seconds. */
function toTimeStamp(value: AnyValue | undefined): number {
  if (value instanceof Date) return Math.floor(value.getTime() / 1000);
  if (typeof value === 'number') return value;
  if (typeof value === 'string') return Math.floor(new Date(value).getTime() / 1000);
  return 0;
}

/**
 * Reverse a 32-bit ticket flags BitString into an integer. The decoded bits
 * are MSB-first; impacket right-pads to 32 bits and reads as a big-endian int.
 */
function reverseFlags(bits: Buffer): number {
  const b = Buffer.alloc(4);
  bits.copy(b, 0, 0, Math.min(4, bits.length));
  return b.readUInt32BE(0) >>> 0;
}

/** Build a ccache Principal directly from a name-type, realm and components. */
function buildPrincipal(
  nameType: number,
  realm: string,
  components: string[],
): KrbCCache.PrincipalCCache {
  const p = new KrbCCache.PrincipalCCache();
  p.name_type = nameType;
  p.num_components = components.length;
  const realmCos = new KrbCCache.CountedOctetString();
  realmCos.data = Buffer.from(realm, 'latin1');
  p.realm = realmCos;
  p.components = components.map((c) => {
    const cos = new KrbCCache.CountedOctetString();
    cos.data = Buffer.from(c, 'latin1');
    return cos;
  });
  return p;
}

/** Extract name-type + component strings from a decoded PrincipalName record. */
function principalNameParts(rec: Record<string, AnyValue>): {
  nameType: number;
  components: string[];
} {
  const nameType = Number(rec['name-type']);
  const arr = (rec['name-string'] ?? []) as unknown[];
  const components = arr.map((n) => {
    if (typeof n === 'string') return n;
    const node = n as { value?: unknown };
    return typeof node.value === 'string' ? node.value : String(n);
  });
  return { nameType, components };
}

// ---------- KRB-CRED <-> CCache conversion ----------

/** kirbi (KRB-CRED) bytes -> CCache. Mirrors impacket CCache.fromKRBCRED. */
function fromKRBCRED(encodedKrbCred: Buffer): KrbCCache.CCache {
  const krbCred = Asn1.KRB_CRED();
  krbCred.decode(encodedKrbCred);

  const encPart = krbCred.get('enc-part') as Record<string, AnyValue>;
  const cipher = encPart['cipher'] as Buffer;

  const encKrbCredPart = Asn1.EncKrbCredPart();
  encKrbCredPart.decode(cipher);

  const ticketInfos = (encKrbCredPart.get('ticket-info') ?? []) as Asn1Sequence[];
  const tickets = (krbCred.get('tickets') ?? []) as Asn1Sequence[];

  const ccache = new KrbCCache.CCache();
  ccache.setDefaultHeader();

  for (let i = 0; i < ticketInfos.length; i++) {
    const kci = ticketInfos[i]!;

    const prealm = (kci.get('prealm') as string) ?? '';
    const pnameRec = kci.get('pname') as Record<string, AnyValue>;
    const pname = principalNameParts(pnameRec);
    const clientPrincipal = buildPrincipal(pname.nameType, prealm, pname.components);

    if (i === 0) {
      ccache.principal = clientPrincipal;
    }

    const srealm = (kci.get('srealm') as string) ?? '';
    const snameRec = kci.get('sname') as Record<string, AnyValue>;
    const sname = principalNameParts(snameRec);
    const serverPrincipal = buildPrincipal(sname.nameType, srealm, sname.components);

    const credential = new KrbCCache.Credential();
    credential.client = clientPrincipal;
    credential.server = serverPrincipal;
    credential.is_skey = 0;

    const keyRec = kci.get('key') as Record<string, AnyValue>;
    const key = new KrbCCache.KeyBlock();
    key.version = 4;
    key.keytype = Number(keyRec['keytype']);
    key.etype = 0;
    key.keyvalue = keyRec['keyvalue'] as Buffer;
    credential.key = key;

    const times = new KrbCCache.Times();
    times.authtime = toTimeStamp(kci.get('starttime'));
    times.starttime = toTimeStamp(kci.get('starttime'));
    times.endtime = toTimeStamp(kci.get('endtime'));
    // After KB4586793 for CVE-2020-17049 this timestamp may be omitted.
    const renewTill = kci.get('renew-till');
    if (renewTill !== undefined && renewTill !== null) {
      times.renew_till = toTimeStamp(renewTill);
    }
    credential.time = times;

    credential.tktflags = reverseFlags((kci.get('flags') as Buffer) ?? Buffer.alloc(4));
    credential.num_address = 0;

    // Re-encode the matching Ticket (application [1]) into the credential.
    const ticketNode = tickets[i]!;
    const ticketCos = new KrbCCache.CountedOctetString();
    ticketCos.data = ticketNode.encode();
    credential.ticket = ticketCos;
    credential.secondTicket = new KrbCCache.CountedOctetString();

    ccache.credentials.push(credential);
  }

  return ccache;
}

/** CCache -> kirbi (KRB-CRED) bytes. Mirrors impacket CCache.toKRBCRED. */
function toKRBCRED(ccache: KrbCCache.CCache): Buffer {
  const ticketInfoSeq = new Asn1SequenceOf(Asn1.KrbCredInfo());
  const ticketsSeq = new Asn1SequenceOf(Asn1.Ticket());

  for (const credential of ccache.credentials) {
    const kci = Asn1.KrbCredInfo();

    kci.set('key', {
      keytype: credential.key.keytype,
      keyvalue: credential.key.keyvalue,
    } as unknown as AnyValue);

    const clientRealm = credential.client.realm.data.toString('latin1');
    const clientComponents = credential.client.components.map((c) => c.data.toString('latin1'));
    kci.set('prealm', clientRealm);
    kci.set(
      'pname',
      Asn1.principalToAsn1({
        type: credential.client.name_type,
        components: clientComponents,
      }) as unknown as AnyValue,
    );

    // 32-bit big-endian representation of the ticket flags.
    const flagsBuf = Buffer.alloc(4);
    flagsBuf.writeUInt32BE(credential.tktflags >>> 0, 0);
    kci.set('flags', flagsBuf);

    kci.set('starttime', new Date(credential.time.starttime * 1000));
    kci.set('endtime', new Date(credential.time.endtime * 1000));
    if (credential.time.renew_till !== 0) {
      kci.set('renew-till', new Date(credential.time.renew_till * 1000));
    }

    const serverRealm = credential.server.realm.data.toString('latin1');
    const serverComponents = credential.server.components.map((c) => c.data.toString('latin1'));
    kci.set('srealm', serverRealm);
    kci.set(
      'sname',
      Asn1.principalToAsn1({
        type: credential.server.name_type,
        components: serverComponents,
      }) as unknown as AnyValue,
    );

    ticketInfoSeq.add(kci);

    const ticket = Asn1.Ticket();
    ticket._rawData = credential.ticket.data;
    ticketsSeq.add(ticket);
  }

  const encKrbCredPart = Asn1.EncKrbCredPart();
  encKrbCredPart.set('ticket-info', ticketInfoSeq as unknown as AnyValue);

  const krbCred = Asn1.KRB_CRED();
  krbCred.set('pvno', 5);
  krbCred.set('msg-type', 22);
  krbCred.set('enc-part', {
    etype: 0,
    cipher: encKrbCredPart.encode(),
  } as unknown as AnyValue);
  krbCred.set('tickets', ticketsSeq as unknown as AnyValue);

  return krbCred.encode();
}

// ---------- file format detection ----------

function isKirbi(data: Buffer): boolean {
  return data.length > 0 && data[0] === 0x76;
}

function isCcache(data: Buffer): boolean {
  return data.length > 0 && data[0] === 0x05;
}

function base64DecodeWithUnwrap(fileName: string): Buffer {
  const text = readFileSync(fileName, 'latin1');
  const data = text
    .trim()
    .split(/\r?\n/)
    .map((l) => l.trim())
    .join('');
  return Buffer.from(data, 'base64');
}

// ---------- CLI ----------

function usage(): never {
  console.log(`usage: ticketConverter [-h] [-b] input_file output_file

positional arguments:
  input_file    File in kirbi (KRB-CRED) or ccache format
  output_file   Output file

options:
  -h, --help    show this help message and exit
  -b, --base64  Decode input ticket from base64 with unwrap support
`);
  process.exit(1);
}

function main(): void {
  const rawArgs = process.argv.slice(2);

  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: rawArgs,
      allowPositionals: true,
      options: {
        base64: { type: 'boolean', short: 'b', default: false },
        help: { type: 'boolean', short: 'h', default: false },
        proxy: { type: 'string' },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    usage();
  }

  if (values.help || positionals.length < 2) {
    usage();
  }

  initProxy(values.proxy);

  const inputFile = positionals[0]!;
  const outputFile = positionals[1]!;

  let inputData: Buffer;
  if (values.base64) {
    console.log('[*] base64 decoding ticket');
    inputData = base64DecodeWithUnwrap(inputFile);
  } else {
    inputData = readFileSync(inputFile);
  }

  if (isKirbi(inputData)) {
    console.log('[*] converting kirbi to ccache...');
    const ccache = fromKRBCRED(inputData);
    writeFileSync(outputFile, ccache.getData());
    console.log('[+] done');
  } else if (isCcache(inputData)) {
    console.log('[*] converting ccache to kirbi...');
    const ccache = new KrbCCache.CCache(inputData);
    writeFileSync(outputFile, toKRBCRED(ccache));
    console.log('[+] done');
  } else {
    console.log('[X] unknown file format');
  }
}

main();
