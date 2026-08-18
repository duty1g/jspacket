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
//   TDS/MSSQL interactive client. Supports SQL and Windows authentication,
//   xp_cmdshell execution, file upload/download via OLE automation,
//   linked server enumeration/execution, and user/database enumeration.
//
// Author:
//   beto (@agsolino)
//   Ported to TypeScript
//
// Reference for:
//   TDS (Tabular Data Stream)
//

import { Buffer } from 'node:buffer';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { createInterface, type Interface as ReadlineInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import {
  parseTarget,
  init as initLogger,
  initProxy,
  info,
  error,
  critical,
  debug,
  warning,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';
import {
  MSSQL,
  type Row,
  type RowDict,
} from '@impacket/tds';

// --------------------------------------------------------------------------
// SQLSHELL -- interactive MSSQL shell
// --------------------------------------------------------------------------

class SQLSHELL {
  private mssqlClient: MSSQL;
  private usingLinkedServer: string | null = null;
  private prompt = 'SQL> ';
  private showQueries: boolean;
  private lastQuery = '';

  constructor(mssqlClient: MSSQL, showQueries = false) {
    this.mssqlClient = mssqlClient;
    this.showQueries = showQueries;
  }

  private printHelp(): void {
    console.log(`
     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     enum_links                 - enumerate linked servers
     enum_users                 - enumerate current and available users
     enum_db                    - enumerate databases
     enum_owner                 - enumerate db owner
     enum_impersonate           - enumerate users that can be impersonated
     exec_as {user}             - impersonate user
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     xp_dirtree {path}          - executes xp_dirtree against the specified path
     sp_start_jobs {cmd}        - executes cmd using the sql server agent (blind)
     use_link {link}            - use a linked server
     ! {cmd}                    - executes a local shell cmd
     show_query                 - show the last SQL query issued
     put {localfile}            - upload a local file to the server via OLE Automation
     get {remotefile}           - download a remote file from the server via OLE Automation
`);
  }

  private async sqlQuery(query: string): Promise<Row[] | true> {
    let actual = query;
    if (this.usingLinkedServer !== null) {
      const escapedQuery = query.replace(/'/g, "''");
      actual = `EXEC ('${escapedQuery}') AT [${this.usingLinkedServer}]`;
    }
    this.lastQuery = actual;
    if (this.showQueries) {
      info(`Query: ${actual}`);
    }
    return this.mssqlClient.sqlQuery(actual);
  }

  async do_shell(command: string): Promise<void> {
    await this.do_xp_cmdshell(command);
  }

  async do_xp_cmdshell(command: string): Promise<void> {
    if (!command.trim()) {
      info('Usage: xp_cmdshell <command>');
      return;
    }
    try {
      await this.sqlQuery(`exec master..xp_cmdshell '${command}'`);
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      this.mssqlClient.printRows();
    } catch (e) {
      error(String(e));
    }
  }

  async do_xp_dirtree(treePath: string): Promise<void> {
    if (!treePath.trim()) {
      info('Usage: xp_dirtree <path>');
      return;
    }
    try {
      await this.sqlQuery(`exec master..xp_dirtree '${treePath}'`);
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      this.mssqlClient.printRows();
    } catch (e) {
      error(String(e));
    }
  }

  async do_sp_start_jobs(command: string): Promise<void> {
    if (!command.trim()) {
      info('Usage: sp_start_jobs <command>');
      return;
    }
    try {
      await this.sqlQuery(
        `EXEC msdb..sp_add_job @job_name='ImpacketJob'; ` +
        `EXEC msdb..sp_add_jobstep @job_name='ImpacketJob', @step_name='step1', ` +
        `@subsystem='CmdExec', @command='${command}'; ` +
        `EXEC msdb..sp_start_job @job_name='ImpacketJob'; ` +
        `EXEC msdb..sp_delete_job @job_name='ImpacketJob';`,
      );
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      info('Blind command executed successfully (no output)');
    } catch (e) {
      error(String(e));
    }
  }

  async do_enable_xp_cmdshell(): Promise<void> {
    try {
      await this.sqlQuery(
        "exec master.dbo.sp_configure 'show advanced options', 1; RECONFIGURE; " +
        "exec master.dbo.sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
      );
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      info('xp_cmdshell enabled');
    } catch (e) {
      error(String(e));
    }
  }

  async do_disable_xp_cmdshell(): Promise<void> {
    try {
      await this.sqlQuery(
        "exec master.dbo.sp_configure 'xp_cmdshell', 0; RECONFIGURE; " +
        "exec master.dbo.sp_configure 'show advanced options', 0; RECONFIGURE;",
      );
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      info('xp_cmdshell disabled');
    } catch (e) {
      error(String(e));
    }
  }

  async do_enum_links(): Promise<void> {
    try {
      await this.sqlQuery('EXEC sp_linkedservers');
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      this.mssqlClient.printRows();
    } catch (e) {
      error(String(e));
    }
  }

  async do_use_link(link: string): Promise<void> {
    if (!link.trim()) {
      if (this.usingLinkedServer !== null) {
        info(`Reverting to local server (was using linked server: ${this.usingLinkedServer})`);
        this.usingLinkedServer = null;
        this.prompt = 'SQL> ';
      } else {
        info('Usage: use_link <linked_server_name>');
      }
      return;
    }
    this.usingLinkedServer = link.trim();
    this.prompt = `SQL (${this.usingLinkedServer})> `;
    info(`Now executing queries at linked server: ${this.usingLinkedServer}`);
  }

  async do_enum_users(): Promise<void> {
    try {
      info('Current user:');
      await this.sqlQuery('SELECT SYSTEM_USER AS [Current Login], CURRENT_USER AS [Current User]');
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      this.mssqlClient.printRows();

      info('Available logins:');
      await this.sqlQuery(
        'SELECT sp.name AS Login, sp.type_desc AS LoginType, ' +
        'sp.is_disabled AS IsDisabled, sl.sysadmin AS IsSysadmin ' +
        'FROM sys.server_principals sp ' +
        'LEFT JOIN sys.syslogins sl ON sp.sid = sl.sid ' +
        "WHERE sp.type IN ('S','U','G')",
      );
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      this.mssqlClient.printRows();
    } catch (e) {
      error(String(e));
    }
  }

  async do_enum_db(): Promise<void> {
    try {
      await this.sqlQuery(
        'SELECT name, state_desc, is_read_only FROM sys.databases ORDER BY name',
      );
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      this.mssqlClient.printRows();
    } catch (e) {
      error(String(e));
    }
  }

  async do_enum_owner(): Promise<void> {
    try {
      await this.sqlQuery(
        'SELECT d.name AS [Database], sp.name AS [Owner] ' +
        'FROM sys.databases d ' +
        'JOIN sys.server_principals sp ON d.owner_sid = sp.sid ' +
        'ORDER BY d.name',
      );
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      this.mssqlClient.printRows();
    } catch (e) {
      error(String(e));
    }
  }

  async do_enum_impersonate(): Promise<void> {
    try {
      info('Users that can be impersonated (server-level):');
      await this.sqlQuery(
        'SELECT DISTINCT b.name ' +
        'FROM sys.server_permissions a ' +
        'INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id ' +
        "WHERE a.permission_name = 'IMPERSONATE'",
      );
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      this.mssqlClient.printRows();

      info('Users that can be impersonated (database-level):');
      await this.sqlQuery(
        'SELECT DISTINCT b.name ' +
        'FROM sys.database_permissions a ' +
        'INNER JOIN sys.database_principals b ON a.grantor_principal_id = b.principal_id ' +
        "WHERE a.permission_name = 'IMPERSONATE'",
      );
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      this.mssqlClient.printRows();
    } catch (e) {
      error(String(e));
    }
  }

  async do_exec_as(username: string): Promise<void> {
    if (!username.trim()) {
      info('Usage: exec_as <username>');
      return;
    }
    try {
      await this.sqlQuery(`EXECUTE AS LOGIN = '${username.trim()}'`);
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      info(`Now executing as: ${username.trim()}`);
    } catch (e) {
      error(String(e));
    }
  }

  do_lcd(dirPath: string): void {
    if (!dirPath.trim()) {
      info(`Current local directory: ${process.cwd()}`);
      return;
    }
    try {
      process.chdir(dirPath.trim());
      info(`Changed local directory to: ${process.cwd()}`);
    } catch (e) {
      error(`Failed to change directory: ${e}`);
    }
  }

  async do_put(localPath: string): Promise<void> {
    if (!localPath.trim()) {
      info('Usage: put <local_file_path>');
      return;
    }

    const filePath = localPath.trim();
    let fileData: Buffer;
    try {
      fileData = readFileSync(filePath);
    } catch (e) {
      error(`Could not read file ${filePath}: ${e}`);
      return;
    }

    const fileName = path.basename(filePath);
    const remotePath = `C:\\windows\\temp\\${fileName}`;
    const hexData = fileData.toString('hex');

    info(`Uploading ${filePath} to ${remotePath} via OLE Automation...`);

    try {
      // Enable OLE Automation Procedures
      await this.sqlQuery(
        "exec master.dbo.sp_configure 'show advanced options', 1; RECONFIGURE; " +
        "exec master.dbo.sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;",
      );
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => debug(String(msg)),
      );

      // Create the ADODB.Stream OLE object and write the file
      await this.sqlQuery(
        'DECLARE @ob INT; ' +
        "EXEC sp_OACreate 'ADODB.Stream', @ob OUTPUT; " +
        'EXEC sp_OASetProperty @ob, \'Type\', 1; ' +
        'EXEC sp_OAMethod @ob, \'Open\'; ' +
        `EXEC sp_OAMethod @ob, 'Write', NULL, 0x${hexData}; ` +
        `EXEC sp_OAMethod @ob, 'SaveToFile', NULL, '${remotePath}', 2; ` +
        'EXEC sp_OAMethod @ob, \'Close\'; ' +
        'EXEC sp_OADestroy @ob;',
      );
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      info(`File uploaded to ${remotePath}`);
    } catch (e) {
      error(`Upload failed: ${e}`);
    }
  }

  async do_get(remotePath: string): Promise<void> {
    if (!remotePath.trim()) {
      info('Usage: get <remote_file_path>');
      return;
    }

    const remoteFile = remotePath.trim();
    const localFile = path.basename(remoteFile);

    info(`Downloading ${remoteFile} via OLE Automation...`);

    try {
      // Enable OLE Automation Procedures
      await this.sqlQuery(
        "exec master.dbo.sp_configure 'show advanced options', 1; RECONFIGURE; " +
        "exec master.dbo.sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;",
      );
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => debug(String(msg)),
      );

      // Read the file via ADODB.Stream
      await this.sqlQuery(
        'DECLARE @ob INT, @data VARBINARY(MAX); ' +
        "EXEC sp_OACreate 'ADODB.Stream', @ob OUTPUT; " +
        'EXEC sp_OASetProperty @ob, \'Type\', 1; ' +
        'EXEC sp_OAMethod @ob, \'Open\'; ' +
        `EXEC sp_OAMethod @ob, 'LoadFromFile', NULL, '${remoteFile}'; ` +
        'EXEC sp_OAMethod @ob, \'Read\', @data OUTPUT; ' +
        'EXEC sp_OAMethod @ob, \'Close\'; ' +
        'EXEC sp_OADestroy @ob; ' +
        'SELECT @data AS FileContent;',
      );
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => debug(String(msg)),
      );

      // Extract binary data from query result
      const rows = this.mssqlClient.rows;
      if (rows.length > 0) {
        const row = rows[0] as RowDict | undefined;
        if (row) {
          const fileContent = row['FileContent'];
          if (fileContent && fileContent !== 'NULL') {
            let buf: Buffer;
            if (Buffer.isBuffer(fileContent)) {
              buf = fileContent;
            } else {
              buf = Buffer.from(String(fileContent), 'hex');
            }
            writeFileSync(localFile, buf);
            info(`File saved to ${localFile} (${buf.length} bytes)`);
          } else {
            error('No data returned from server. File may not exist or access denied.');
          }
        } else {
          error('No result returned from server.');
        }
      } else {
        error('No rows returned. File may not exist or OLE method failed.');
      }
    } catch (e) {
      error(`Download failed: ${e}`);
    }
  }

  private async doDefault(line: string): Promise<void> {
    try {
      await this.sqlQuery(line);
      this.mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      this.mssqlClient.printRows();
    } catch (e) {
      error(String(e));
    }
  }

  private async processLine(line: string): Promise<boolean> {
    const trimmed = line.trim();
    if (!trimmed) return true;

    if (trimmed === 'exit' || trimmed === 'quit') {
      return false;
    }

    if (trimmed === 'help' || trimmed === '?') {
      this.printHelp();
      return true;
    }

    if (trimmed.startsWith('!')) {
      const { execSync } = await import('node:child_process');
      try {
        const result = execSync(trimmed.slice(1), { encoding: 'utf-8' });
        process.stdout.write(result);
      } catch (e) {
        error(String(e));
      }
      return true;
    }

    // Parse command and argument
    const spaceIdx = trimmed.indexOf(' ');
    const command = spaceIdx === -1 ? trimmed : trimmed.substring(0, spaceIdx);
    const arg = spaceIdx === -1 ? '' : trimmed.substring(spaceIdx + 1);

    switch (command.toLowerCase()) {
      case 'lcd':
        this.do_lcd(arg);
        break;
      case 'enable_xp_cmdshell':
        await this.do_enable_xp_cmdshell();
        break;
      case 'disable_xp_cmdshell':
        await this.do_disable_xp_cmdshell();
        break;
      case 'xp_cmdshell':
        await this.do_xp_cmdshell(arg);
        break;
      case 'xp_dirtree':
        await this.do_xp_dirtree(arg);
        break;
      case 'sp_start_jobs':
        await this.do_sp_start_jobs(arg);
        break;
      case 'shell':
        await this.do_shell(arg);
        break;
      case 'enum_links':
        await this.do_enum_links();
        break;
      case 'use_link':
        await this.do_use_link(arg);
        break;
      case 'enum_users':
        await this.do_enum_users();
        break;
      case 'enum_db':
        await this.do_enum_db();
        break;
      case 'enum_owner':
        await this.do_enum_owner();
        break;
      case 'enum_impersonate':
        await this.do_enum_impersonate();
        break;
      case 'exec_as':
        await this.do_exec_as(arg);
        break;
      case 'show_query':
        info(`Last query: ${this.lastQuery || '(none)'}`);
        break;
      case 'put':
        await this.do_put(arg);
        break;
      case 'get':
        await this.do_get(arg);
        break;
      default:
        await this.doDefault(trimmed);
        break;
    }

    return true;
  }

  async cmdloop(): Promise<void> {
    const rl: ReadlineInterface = createInterface({
      input: process.stdin,
      output: process.stdout,
      prompt: this.prompt,
    });

    rl.prompt();

    let isClosed = false;
    rl.on('close', () => {
      isClosed = true;
    });

    for await (const line of rl) {
      const shouldContinue = await this.processLine(line);
      if (!shouldContinue || isClosed) {
        rl.close();
        break;
      }
      rl.setPrompt(this.prompt);
      rl.prompt();
    }
  }
}

// --------------------------------------------------------------------------
// CLI argument parsing and main
// --------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log(BANNER + '\n');

  let values: any;
  let positionals: string[];
  try {
    ({ values, positionals } = parseArgs({
      args: normalizeArgs(process.argv.slice(2)),
      allowPositionals: true,
      options: {
        port: { type: 'string', default: '1433' },
        db: { type: 'string' },
        'windows-auth': { type: 'boolean', default: false },
        'named-pipe': { type: 'string' },
        ts: { type: 'boolean', default: false },
        debug: { type: 'boolean', default: false },
        show: { type: 'boolean', default: false },
        command: { type: 'string', multiple: true },
        file: { type: 'string' },
        'host-name': { type: 'string', default: '' },
        'app-name': { type: 'string', default: '' },
        'client-interface-name': { type: 'string', default: '' },
        hashes: { type: 'string' },
        'auth-smb': { type: 'string' },
        'hashes-smb': { type: 'string' },
        'no-pass': { type: 'boolean', default: false },
        k: { type: 'boolean', default: false },
        aesKey: { type: 'string' },
        'dc-ip': { type: 'string' },
        'target-ip': { type: 'string' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    process.exit(1);
  }

  if (values.help || positionals.length === 0) {
    console.log(`TDS client implementation (SSL supported).

usage: mssqlclient [-h] [-db DB] [-windows-auth] [-named-pipe NAMED_PIPE]
                   [-debug] [-ts] [-show] [-command COMMAND] [-file FILE]
                   [--host-name HOST_NAME] [--app-name APP_NAME]
                   [--client-interface-name CLIENT_INTERFACE_NAME]
                   [-hashes LMHASH:NTHASH] [-auth-smb AUTH_SMB]
                   [-hashes-smb LMHASH:NTHASH] [-no-pass] [-k]
                   [-aesKey hex key] [-dc-ip ip address]
                   [-target-ip ip address] [-port PORT]
                   target

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -db DB                MSSQL database instance (default None)
  -windows-auth         whether or not to use Windows Authentication (default
                        False)
  -named-pipe NAMED_PIPE
                        Connect to the specified SMB named pipe
  -debug                Turn DEBUG output ON
  -ts                   Adds timestamp to every logging output
  -show                 show the queries
  -command COMMAND      Commands to execute in the SQL shell. Multiple commands
                        can be passed.
  -file FILE            input file with commands to execute in the SQL shell
  --host-name HOST_NAME
                        HostName property to use when connecting to the
                        MSSQLServer
  --app-name APP_NAME   AppName property to use when connecting to the
                        MSSQLServer
  --client-interface-name CLIENT_INTERFACE_NAME
                        CltIntName property to use when connecting to the
                        MSSQLServer

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -auth-smb [domain/]username[:password]
                        SMB NTLM credentials for named pipe transport when
                        different from SQL credentials
  -hashes-smb LMHASH:NTHASH
                        SMB NTLM hashes for named pipe transport
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)

connection:
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address
                        IP Address of the target machine. If omitted it will
                        use whatever was specified as target
  -port PORT            target MSSQL port (default 1433)
`);
    process.exit(positionals.length === 0 ? 1 : 0);
  }

  initLogger({ ts: values.ts, debug: values.debug });
  initProxy(values.proxy);

  const target = positionals[0]!;
  const [domain, username, password, remoteName] = parseTarget(target);

  // Parse auth credentials from -A config file if provided
  let effectiveUsername = username;
  let effectivePassword = password;
  let effectiveDomain = domain;
  let effectiveHashes = values.hashes ?? null;



  if (
    effectivePassword === '' &&
    effectiveUsername !== '' &&
    !effectiveHashes &&
    !values['no-pass'] &&
    !values.aesKey &&
    !values.k
  ) {
    critical('Password required. Use --hashes, --no-pass, -k, or provide password in the target string.');
    process.exit(1);
  }

  let lmhash = '';
  let nthash = '';
  if (effectiveHashes) {
    const parts = effectiveHashes.split(':');
    lmhash = parts[0] ?? '';
    nthash = parts[1] ?? '';
  }

  const port = parseInt(values.port ?? '1433', 10);
  const database = values.db ?? 'master';
  const useWindowsAuth = values['windows-auth'] ?? false;
  const doKerberos = values.k || !!values.aesKey;

  const targetIp = values['target-ip'] ?? remoteName;
  const hostName = values['host-name'] || '';
  const appName = values['app-name'] || '';
  const cltIntName = values['client-interface-name'] || '';

  if (values['named-pipe']) {
    warning('Named pipe transport is not yet implemented. Using TCP.');
  }
  if (values['auth-smb'] || values['hashes-smb']) {
    warning('SMB auth credentials for named pipe transport are not yet implemented.');
  }

  const mssqlClient = new MSSQL(targetIp, port, remoteName, hostName, appName, undefined, cltIntName);

  info(`Connecting to ${targetIp}:${port}...`);

  try {
    await mssqlClient.connect();
    info('Connected');
  } catch (e) {
    critical(`Connection failed: ${e}`);
    process.exit(1);
  }

  // Authenticate
  try {
    let loginResult = false;

    if (doKerberos) {
      warning('Kerberos login is not yet implemented in the TypeScript port');
      mssqlClient.disconnect();
      process.exit(1);
    } else {
      loginResult = await mssqlClient.login(
        database,
        effectiveUsername,
        effectivePassword,
        effectiveDomain,
        effectiveHashes,
        useWindowsAuth,
      );
    }

    if (loginResult) {
      info(`Authentication successful on database: ${database}`);
      mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
    } else {
      error('Authentication failed');
      mssqlClient.printReplies(
        (msg: unknown) => error(String(msg)),
        (msg: unknown) => info(String(msg)),
      );
      mssqlClient.disconnect();
      process.exit(1);
    }
  } catch (e) {
    critical(`Login failed: ${e}`);
    mssqlClient.disconnect();
    process.exit(1);
  }

  // If -command flags were provided, execute them and exit
  if (values.command && values.command.length > 0) {
    for (const cmd of values.command) {
      try {
        await mssqlClient.sqlQuery(cmd);
        mssqlClient.printReplies(
          (msg: unknown) => error(String(msg)),
          (msg: unknown) => info(String(msg)),
        );
        mssqlClient.printRows();
      } catch (e) {
        error(String(e));
      }
    }
    mssqlClient.disconnect();
    process.exit(0);
  }

  // If a file with commands was provided, execute them and exit
  if (values.file) {
    try {
      const fileContents = readFileSync(values.file, 'utf-8');
      const lines = fileContents.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('--')) {
          continue;
        }
        info(`Executing: ${trimmed}`);
        try {
          await mssqlClient.sqlQuery(trimmed);
          mssqlClient.printReplies(
            (msg: unknown) => error(String(msg)),
            (msg: unknown) => info(String(msg)),
          );
          mssqlClient.printRows();
        } catch (e) {
          error(String(e));
        }
      }
    } catch (e) {
      critical(`Could not read file ${values.file}: ${e}`);
    }
    mssqlClient.disconnect();
    process.exit(0);
  }

  // Launch interactive shell
  const shell = new SQLSHELL(mssqlClient, values.show);
  try {
    await shell.cmdloop();
  } catch (e) {
    error(String(e));
  } finally {
    mssqlClient.disconnect();
  }
  process.exit(0);
}

main().catch((e) => {
  critical(String(e));
  process.exit(1);
});
