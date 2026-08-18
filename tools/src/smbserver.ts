#!/usr/bin/env node
// Impacket - Collection of TypeScript classes for working with network protocols.
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
//   Simple SMB Server example. Launches an SMB server and adds a share
//   specified on the command line. Usually you need to be root in order
//   to bind to port 445. For optional authentication it is possible to
//   specify a username and password or the NTLM hash.
//   Example: smbserver -comment 'My share' TMP /tmp
//
// Author:
//   Alberto Solino (@agsolino)
//   TypeScript port
//
// Reference for:
//   SMB Server (@impacket/smb-server)

import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import {
  init as initLogger,
  initProxy,
  info,
  warning,
  critical,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';
import { computeLmhash, computeNthash } from '@impacket/ntlm';
import { SimpleSMBServer } from '@impacket/smb-server';

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printBanner(): void {
  console.log(BANNER + '\n');
}

function printUsage(): void {
  console.log(`This script will launch a SMB Server and add a share specified as an
argument. Usually, you need to be root in order to bind to port 445. For
optional authentication, it is possible to specify username and password or
the NTLM hash. Example: smbserver -comment 'My share' TMP /tmp

usage: smbserver [-h] [-comment COMMENT] [-username USERNAME]
                 [-password PASSWORD] [-computeraccountname COMPUTERACCOUNTNAME]
                 [-computeraccounthash COMPUTERACCOUNTHASH]
                 [-computeraccountaes COMPUTERACCOUNTAES]
                 [-computeraccountpassword COMPUTERACCOUNTPASSWORD]
                 [-computeraccountdomain COMPUTERACCOUNTDOMAIN] [-dc-ip DC_IP]
                 [-hashes LMHASH:NTHASH] [-ts] [-debug]
                 [-ip INTERFACE_ADDRESS] [-readonly] [-disablekerberos]
                 [-disablentlm] [-port PORT] [-dropssp] [-6] [-smb2support]
                 [-outputfile OUTPUTFILE]
                 shareName sharePath

positional arguments:
  shareName             name of the share to add
  sharePath             path of the share to add

options:
  -h, --help            show this help message and exit
  -comment COMMENT      share's comment to display when asked for shares
  -username USERNAME    Username to authenticate clients
  -password PASSWORD    Password for the Username
  -computeraccountname COMPUTERACCOUNTNAME
                        computer account name to authenticate arbitrary clients
                        with signing via NetLogon/Kerberos
  -computeraccounthash COMPUTERACCOUNTHASH
                        computer account NT hash
  -computeraccountaes COMPUTERACCOUNTAES
                        computer account AES key
  -computeraccountpassword COMPUTERACCOUNTPASSWORD
                        computer account password
  -computeraccountdomain COMPUTERACCOUNTDOMAIN
                        computer account domain
  -dc-ip DC_IP          IP of domain controller
  -hashes LMHASH:NTHASH
                        NTLM hashes for the Username, format is LMHASH:NTHASH
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON
  -ip, --interface-address INTERFACE_ADDRESS
                        ip address of listening interface ("0.0.0.0" or "::")
  -readonly             Only allow reading of files
  -disablekerberos      Do not offer Kerberos authentication
  -disablentlm          Do not offer NTLM authentication
  -port PORT            TCP port for listening incoming connections (default 445)
  -dropssp              Disable NTLM ESS/SSP during negotiation
  -6, --ipv6            Listen on IPv6
  -smb2support          SMB2 Support (experimental!)
  -outputfile OUTPUTFILE
                        Output file to log smbserver output messages
`);
}

/**
 * Call an optional method on the server if it exists. Some advanced toggles
 * (Kerberos/NTLM support, computer-account signing) are not yet exposed by the
 * current @impacket/smb-server SimpleSMBServer. Returns whether the call ran.
 */
function callIfPresent(target: object, method: string, ...args: unknown[]): boolean {
  const fn = (target as Record<string, unknown>)[method];
  if (typeof fn === 'function') {
    (fn as (...a: unknown[]) => unknown).apply(target, args);
    return true;
  }
  return false;
}

async function main(): Promise<void> {
  printBanner();

  const args = normalizeArgs(process.argv.slice(2));

  if (args.length === 0) {
    printUsage();
    process.exit(1);
  }

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        comment: { type: 'string' },
        username: { type: 'string' },
        password: { type: 'string' },
        computeraccountname: { type: 'string' },
        computeraccounthash: { type: 'string' },
        computeraccountaes: { type: 'string' },
        computeraccountpassword: { type: 'string' },
        computeraccountdomain: { type: 'string' },
        'dc-ip': { type: 'string' },
        hashes: { type: 'string' },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        // -ip / --interface-address (two spellings, resolved below)
        ip: { type: 'string' },
        'interface-address': { type: 'string' },
        readonly: { type: 'boolean', default: false },
        disablekerberos: { type: 'boolean', default: false },
        disablentlm: { type: 'boolean', default: false },
        port: { type: 'string', default: '445' },
        dropssp: { type: 'boolean', default: false },
        // -6 / --ipv6
        ipv6: { type: 'boolean', short: '6', default: false },
        smb2support: { type: 'boolean', default: false },
        outputfile: { type: 'string' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    printUsage();
    process.exit(1);
  }

  if (values.help) {
    printUsage();
    process.exit(0);
  }

  if (positionals.length < 2) {
    printUsage();
    process.exit(1);
  }

  const shareName = positionals[0]!;
  const sharePath = positionals[1]!;

  initProxy(values.proxy);
  initLogger({ ts: values.ts, debug: values.debug });

  const comment = values.comment ?? '';

  const ipv6 = values.ipv6;
  let interfaceAddress = values['interface-address'] ?? values.ip;
  if (interfaceAddress === undefined) {
    interfaceAddress = ipv6 ? '::' : '0.0.0.0';
  }

  const port = parseInt(values.port ?? '445', 10);

  // SimpleSMBServer(listenAddress, listenPort, configFile). The current
  // library binding does not accept an explicit ipv6 flag; the address family
  // follows from the listen address ("::" vs "0.0.0.0").
  const server = new SimpleSMBServer(interfaceAddress, port);

  if (values.outputfile) {
    info(`Switching output to file ${values.outputfile}`);
    server.setLogFile(values.outputfile);
  }

  // addShare(shareName, sharePath, shareComment, shareType, readOnly)
  server.addShare(
    shareName.toUpperCase(),
    sharePath,
    comment,
    '0',
    values.readonly ? 'yes' : 'no',
  );
  server.setSMB2Support(values.smb2support);
  server.setDropSSP(values.dropssp);

  // Kerberos / NTLM negotiation toggles. These setters are not yet exposed by
  // the current SimpleSMBServer; warn only when the user asks to disable one.
  if (!callIfPresent(server, 'setKerberosSupport', !values.disablekerberos)) {
    if (values.disablekerberos) {
      warning('-disablekerberos is not supported by this build of @impacket/smb-server (setKerberosSupport missing); Kerberos negotiation left at default');
    }
  }
  if (!callIfPresent(server, 'setNTLMSupport', !values.disablentlm)) {
    if (values.disablentlm) {
      warning('-disablentlm is not supported by this build of @impacket/smb-server (setNTLMSupport missing); NTLM negotiation left at default');
    }
  }

  // If a user was specified, add it to the SMBServer credentials. If no user is
  // specified, anonymous connections will be allowed.
  if (values.username !== undefined) {
    let lmhash: string;
    let nthash: string;

    if (values.password === undefined && values.hashes === undefined) {
      const rl = createInterface({ input: process.stdin, output: process.stderr });
      const password = await new Promise<string>((resolve) => {
        rl.question('Password:', (answer) => {
          rl.close();
          resolve(answer);
        });
      });
      lmhash = computeLmhash(password).toString('hex');
      nthash = computeNthash(password).toString('hex');
    } else if (values.password !== undefined) {
      lmhash = computeLmhash(values.password).toString('hex');
      nthash = computeNthash(values.password).toString('hex');
    } else {
      const parts = (values.hashes ?? '').split(':');
      lmhash = parts[0] ?? '';
      nthash = parts[1] ?? '';
    }

    server.addCredential(values.username, 0, lmhash, nthash);
  }

  // If we want clients that enforce signing to connect, a computer account is
  // required to properly set up the connection (SMB2 only).
  const requiredSecureServerOptions = [
    values.computeraccountname,
    values.computeraccountdomain,
    values['dc-ip'],
  ];
  const atLeastOneSecureServerOptions = [
    values.computeraccounthash,
    values.computeraccountaes,
    values.computeraccountpassword,
  ];
  if (requiredSecureServerOptions.some((v) => v)) {
    if (values.username) {
      critical('You cannot use account credentials AND computer account credentials at the same time');
      process.exit(1);
    }
    if (!requiredSecureServerOptions.every((v) => v)) {
      critical('All of the following options need to be set for accepting signed connections from arbitrary users in the domain: -computeraccountname, -computeraccountdomain, -dc-ip');
      process.exit(1);
    }
    if (!atLeastOneSecureServerOptions.some((v) => v)) {
      critical('At least one of the following options need to be set for accepting signed connections from arbitrary users in the domain: -computeraccounthash, -computeraccountaes, -computeraccountpassword');
      process.exit(1);
    }
    const ran = callIfPresent(
      server,
      'setComputerAccount',
      values.computeraccountname,
      values.computeraccounthash,
      values.computeraccountaes,
      values.computeraccountpassword,
      values.computeraccountdomain,
      values['dc-ip'],
    );
    if (!ran) {
      critical('Computer-account (NetLogon/Kerberos signing) support is not yet available in @impacket/smb-server (setComputerAccount missing)');
      process.exit(1);
    }
  }

  // Here you can set a custom SMB challenge in hex format. If empty it defaults
  // to '4141414141414141' (must be 16 hex bytes long).
  server.setSMBChallenge('');

  // Rock and roll
  process.on('SIGINT', () => {
    console.log('\nInterrupted, exiting...');
    try {
      server.stop();
    } catch {
      // ignore
    }
    process.exit(130);
  });

  info(`Listening on ${interfaceAddress}:${port}`);
  server.start();
}

main().catch((e) => {
  critical(String(e instanceof Error ? e.message : e));
  process.exit(1);
});
