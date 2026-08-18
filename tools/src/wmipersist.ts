#!/usr/bin/env node
/**
 * Creates/removes a WMI Event Consumer/Filter and link between both to
 * execute Visual Basic based on the WQL filter or timer specified.
 *
 * Original impacket author: Alberto Solino (@agsolino)
 * TypeScript port for jspacket.
 *
 * Reference for: DCOM / WMI
 */

import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import {
  parseTarget,
  init as initLogger,
  initProxy,
  info,
  error as logError,
  critical,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';

import {
  DCOMConnection,
  COMVERSION,
  INTERFACE,
  IWbemLevel1Login,
  type IWbemServices,
  type IWbemClassObject,
  CLSID_WbemLevel1Login,
  IID_IWbemLevel1Login,
  NULL,
  ENCODING_UNIT,
  OBJECT_BLOCK,
  INSTANCE_TYPE,
  ENCODED_STRING,
  HEAP,
  CIM_ARRAY_FLAG,
  CIM_TYPE_ENUM,
  CIM_TYPES_REF,
  CLSID_WbemClassObject,
  OBJREF_CUSTOM,
  WBEMSTATUS,
  type IWbemCallResult,
} from '@impacket/dcerpc';

const HEAPREF = '<L=0';
const Inherited = 0x4000;

function calcsize(fmt: string): number {
  const clean = fmt.replace(/[=<>!]/g, '');
  const sizes: Record<string, number> = {
    b: 1, B: 1, h: 2, H: 2, l: 4, L: 4, q: 8, Q: 8, f: 4, d: 8,
  };
  let total = 0;
  for (const ch of clean) {
    total += sizes[ch] ?? 0;
  }
  return total;
}

function structPack(fmt: string, value: number): Buffer {
  const size = calcsize(fmt);
  const buf = Buffer.alloc(size);
  const clean = fmt.replace(/[=<>!]/g, '');
  switch (clean[0]) {
    case 'B': buf.writeUInt8(value); break;
    case 'b': buf.writeInt8(value); break;
    case 'H': buf.writeUInt16LE(value); break;
    case 'h': buf.writeInt16LE(value); break;
    case 'L': buf.writeUInt32LE(value); break;
    case 'l': buf.writeInt32LE(value); break;
    default: buf.writeUInt32LE(value); break;
  }
  return buf;
}

function spawnInstance(classObj: IWbemClassObject): any {
  const ob = (classObj as any).encodingUnit?.fields?.['ObjectBlock'] ??
             (classObj as any).encodingUnit?.['ObjectBlock'];
  if (ob && typeof ob.isInstance === 'function' && ob.isInstance()) {
    return classObj;
  }

  const properties = (classObj as any).getProperties?.() ?? {};
  const propNames = Object.keys(properties);
  const className = (classObj as any).getClassName?.() ?? '__Unknown';

  const decoSrc = ob?.fields?.['Decoration'];
  let decoData: Buffer;
  if (decoSrc && typeof decoSrc.getData === 'function') {
    decoData = decoSrc.getData();
  } else if (Buffer.isBuffer(decoSrc)) {
    decoData = decoSrc;
  } else {
    decoData = Buffer.alloc(0);
  }

  const classPartSrc = ob?.fields?.['ClassType']?.fields?.['CurrentClass']?.fields?.['ClassPart'];
  let classPartData: Buffer;
  if (classPartSrc) {
    classPartData = typeof classPartSrc.getData === 'function' ? classPartSrc.getData() : classPartSrc;
  } else {
    classPartData = Buffer.alloc(0);
  }

  const iid: Buffer = (classObj as any)._iid ?? Buffer.alloc(16);

  const inst: any = {};
  for (const pn of propNames) {
    inst[pn] = properties[pn]!.value ?? null;
  }

  inst.getData = function (): Buffer {
    const instanceType = new INSTANCE_TYPE();
    instanceType.fields['CurrentClass'] = Buffer.alloc(0);
    instanceType.fields['InstanceQualifierSet'] = Buffer.from([0x04, 0x00, 0x00, 0x00, 0x01]);

    const classNameStr = new ENCODED_STRING();
    classNameStr.fields['Encoded_String_Flag'] = 0;
    classNameStr.structure = [...(ENCODED_STRING as any).tascii];
    classNameStr.fields['Character'] = Buffer.from(className + '\0');
    classNameStr.data = null;
    let instanceHeap = classNameStr.getData();
    let curHeapPtr = instanceHeap.length;

    let ndTable = 0;
    let valueTable = Buffer.alloc(0);

    for (let i = 0; i < propNames.length; i++) {
      const propRecord = properties[propNames[i]!]!;
      const rawType = propRecord.type ?? 0;
      const pType = rawType & (~(CIM_ARRAY_FLAG | Inherited));
      const isArray = !!(rawType & CIM_ARRAY_FLAG);
      const packStr = (isArray ? HEAPREF : (CIM_TYPES_REF[pType] ?? HEAPREF)).replace(/=.*$/, '');
      const value = this[propNames[i]!];

      if (isArray) {
        if (value != null && Array.isArray(value)) {
          const elemSize = calcsize(packStr);
          let arrBuf = structPack('<L', value.length);
          for (const elem of value) {
            if (elemSize === 1) {
              const b = Buffer.alloc(1);
              b.writeUInt8(Number(elem) & 0xff);
              arrBuf = Buffer.concat([arrBuf, b]);
            } else {
              arrBuf = Buffer.concat([arrBuf, structPack(packStr, Number(elem))]);
            }
          }
          valueTable = Buffer.concat([valueTable, structPack('<L', curHeapPtr)]);
          instanceHeap = Buffer.concat([instanceHeap, arrBuf]);
          curHeapPtr = instanceHeap.length;
        } else {
          valueTable = Buffer.concat([valueTable, structPack('<L', 0)]);
        }
      } else if (
        pType === CIM_TYPE_ENUM.CIM_TYPE_STRING ||
        pType === CIM_TYPE_ENUM.CIM_TYPE_DATETIME ||
        pType === CIM_TYPE_ENUM.CIM_TYPE_REFERENCE
      ) {
        const strIn = new ENCODED_STRING();
        strIn.fields['Encoded_String_Flag'] = 0;
        strIn.structure = [...(ENCODED_STRING as any).tascii];
        strIn.fields['Character'] = Buffer.from((value != null ? String(value) : '') + '\0');
        strIn.data = null;
        valueTable = Buffer.concat([valueTable, structPack('<L', curHeapPtr)]);
        instanceHeap = Buffer.concat([instanceHeap, strIn.getData()]);
        curHeapPtr = instanceHeap.length;
      } else if (pType === CIM_TYPE_ENUM.CIM_TYPE_OBJECT) {
        valueTable = Buffer.concat([valueTable, NULL.getData()]);
        ndTable |= ndEntry(i, true, true);
      } else {
        valueTable = Buffer.concat([valueTable, structPack(packStr, value != null ? Number(value) : 0)]);
      }
    }

    const ndTableLen = propNames.length > 0 ? Math.floor((propNames.length - 1) / 4) + 1 : 1;
    let packedNdTable = Buffer.alloc(0);
    let ndVal = ndTable;
    for (let i = 0; i < ndTableLen; i++) {
      const b = Buffer.alloc(1);
      b.writeUInt8(ndVal & 0xff);
      packedNdTable = Buffer.concat([packedNdTable, b]);
      ndVal >>= 8;
    }

    instanceType.fields['NdTable_ValueTable'] = Buffer.concat([packedNdTable, valueTable]);

    const heap = new HEAP();
    heap.fields['HeapItem'] = instanceHeap;
    heap.fields['HeapLength'] = instanceHeap.length | 0x80000000;
    instanceType.fields['InstanceHeap'] = heap;
    instanceType.fields['EncodingLength'] = instanceType.getData().length;
    instanceType.fields['CurrentClass'] = classPartData;

    const instanceDataBlock = new OBJECT_BLOCK();
    instanceDataBlock.structure = [...OBJECT_BLOCK.decoration, ...OBJECT_BLOCK.instanceType];
    instanceDataBlock.fields['ObjectFlags'] = 0x06;
    instanceDataBlock.fields['Decoration'] = decoData;
    instanceDataBlock.fields['InstanceType'] = instanceType.getData();

    const eu = new ENCODING_UNIT();
    eu.fields['ObjectBlock'] = instanceDataBlock;
    eu.fields['ObjectEncodingLength'] = instanceDataBlock.getData().length;

    const objRef = new OBJREF_CUSTOM();
    objRef.set('iid', iid);
    objRef.set('clsid', CLSID_WbemClassObject);
    objRef.set('cbExtension', 0);
    const euData = eu.getData();
    objRef.set('ObjectReferenceSize', euData.length);
    objRef.set('pObjectData', eu);
    return objRef.getData() as Buffer;
  };

  return inst;
}

function ndEntry(index: number, nullDefault: boolean, inheritedDefault: boolean): number {
  return ((nullDefault ? 1 : 0) << 1 | (inheritedDefault ? 1 : 0)) << (2 * index);
}

const CREATOR_SID = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];

async function checkError(banner: string, callResult: IWbemCallResult): Promise<void> {
  const status = ((await callResult.GetCallStatus(0)) as number) >>> 0;
  if (status !== 0) {
    let errorName = 'Unknown';
    try {
      const items = WBEMSTATUS.enumItems as Record<string, string>;
      errorName = items[status] ?? `0x${status.toString(16)}`;
    } catch { /* */ }
    logError(`${banner} - ERROR: ${errorName} (0x${status.toString(16).padStart(8, '0')})`);
  } else {
    info(`${banner} - OK`);
  }
}

async function run(
  addr: string,
  username: string,
  password: string,
  domain: string,
  lmhash: string,
  nthash: string,
  aesKey: string,
  doKerberos: boolean,
  dcIp: string | null,
  action: string,
  name: string,
  vbsFile: string | null,
  filter: string | null,
  timer: string | null,
): Promise<void> {
  const dcom = new DCOMConnection(
    addr, username, password, domain, lmhash, nthash,
    aesKey, undefined, undefined, undefined, false, doKerberos, dcIp ?? undefined,
  );

  await dcom.initConnection();
  const iInterface = await dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login);
  const iWbemLevel1Login = new IWbemLevel1Login(iInterface);
  const iWbemServices: IWbemServices = await iWbemLevel1Login.NTLMLogin('//./root/subscription', NULL as any, NULL);
  await iWbemLevel1Login.RemRelease();

  if (action === 'remove') {
    await checkError(
      `Removing ActiveScriptEventConsumer ${name}`,
      await iWbemServices.DeleteInstance(`ActiveScriptEventConsumer.Name="${name}"`),
    );
    await checkError(
      `Removing EventFilter EF_${name}`,
      await iWbemServices.DeleteInstance(`__EventFilter.Name="EF_${name}"`),
    );
    await checkError(
      `Removing IntervalTimerInstruction TI_${name}`,
      await iWbemServices.DeleteInstance(`__IntervalTimerInstruction.TimerId="TI_${name}"`),
    );
    await checkError(
      `Removing FilterToConsumerBinding ${name}`,
      await iWbemServices.DeleteInstance(
        `__FilterToConsumerBinding.Consumer="ActiveScriptEventConsumer.Name=\\"${name}\\"",` +
        `Filter="__EventFilter.Name=\\"EF_${name}\\""`,
      ),
    );
  } else {
    const [activeScriptClass] = await iWbemServices.GetObject('ActiveScriptEventConsumer');
    const activeScript = spawnInstance(activeScriptClass);
    activeScript.Name = name;
    activeScript.ScriptingEngine = 'VBScript';
    activeScript.CreatorSID = CREATOR_SID;
    activeScript.ScriptText = readFileSync(vbsFile!, 'utf-8');

    await checkError(
      `Adding ActiveScriptEventConsumer ${name}`,
      await iWbemServices.PutInstance(activeScript),
    );

    if (filter != null) {
      const [eventFilterClass] = await iWbemServices.GetObject('__EventFilter');
      const eventFilter = spawnInstance(eventFilterClass);
      eventFilter.Name = `EF_${name}`;
      eventFilter.CreatorSID = CREATOR_SID;
      eventFilter.Query = filter;
      eventFilter.QueryLanguage = 'WQL';
      eventFilter.EventNamespace = 'root\\cimv2';

      await checkError(
        `Adding EventFilter EF_${name}`,
        await iWbemServices.PutInstance(eventFilter),
      );
    } else {
      const [wmiTimerClass] = await iWbemServices.GetObject('__IntervalTimerInstruction');
      const wmiTimer = spawnInstance(wmiTimerClass);
      wmiTimer.TimerId = `TI_${name}`;
      wmiTimer.IntervalBetweenEvents = parseInt(timer!, 10);

      await checkError(
        'Adding IntervalTimerInstruction',
        await iWbemServices.PutInstance(wmiTimer),
      );

      const [eventFilterClass2] = await iWbemServices.GetObject('__EventFilter');
      const eventFilter2 = spawnInstance(eventFilterClass2);
      eventFilter2.Name = `EF_${name}`;
      eventFilter2.CreatorSID = CREATOR_SID;
      eventFilter2.Query = `select * from __TimerEvent where TimerID = "TI_${name}" `;
      eventFilter2.QueryLanguage = 'WQL';
      eventFilter2.EventNamespace = 'root\\subscription';
      eventFilter2.marshalMe?.();
      await checkError(
        `Adding EventFilter EF_${name}`,
        await iWbemServices.PutInstance(eventFilter2),
      );
    }

    const [filterBindingClass] = await iWbemServices.GetObject('__FilterToConsumerBinding');
    const filterBinding = spawnInstance(filterBindingClass);
    filterBinding.Filter = `__EventFilter.Name="EF_${name}"`;
    filterBinding.Consumer = `ActiveScriptEventConsumer.Name="${name}"`;
    filterBinding.CreatorSID = CREATOR_SID;

    await checkError(
      'Adding FilterToConsumerBinding',
      await iWbemServices.PutInstance(filterBinding),
    );
  }

  await dcom.disconnect();
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

console.log(BANNER);

const argv = normalizeArgs(process.argv.slice(2));
let opt: any;
let positionals: string[];
try {
  ({ values: opt, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      debug: { type: 'boolean', default: false },
      ts: { type: 'boolean', default: false },
      'com-version': { type: 'string' },
      name: { type: 'string' },
      vbs: { type: 'string' },
      filter: { type: 'string' },
      timer: { type: 'string' },
      hashes: { type: 'string' },
      'no-pass': { type: 'boolean', default: false },
      k: { type: 'boolean', default: false },
      aesKey: { type: 'string' },
      'dc-ip': { type: 'string' },
      proxy: { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  }));
} catch (e) {
  console.error(`[-] ${(e as Error).message}`);
  process.exit(1);
}

if (opt.help || positionals.length < 2) {
  console.log(`
Usage: wmipersist.py [domain/]username[:password]@<address> <install|remove> [options]

Creates/Removes a WMI Event Consumer/Filter and link between both to execute
Visual Basic based on the WQL filter or timer specified.

positional arguments:
  target                [domain/][username[:password]@]<address>
  action                install | remove

install options:
  -name NAME            Event name (required)
  -vbs FILE             VBS filename containing the script (required for install)
  -filter FILTER        WQL filter string that triggers the script
  -timer MS             Milliseconds between script triggers

remove options:
  -name NAME            Event name (required)

authentication:
  -hashes LMHASH:NTHASH   NTLM hashes
  -no-pass                 Don't ask for password
  -k                       Use Kerberos (from ccache / KRB5CCNAME)
  -aesKey HEX              AES key for Kerberos auth
  -dc-ip IP                Domain controller IP
  -com-version MAJ.MIN     DCOM version (e.g. 5.7)
  -ts                      Add timestamp to logging
  -debug                   Turn DEBUG output ON
`);
  process.exit(0);
}

initProxy(opt.proxy);
initLogger({ ts: opt.ts, debug: opt.debug });

if (opt['com-version']) {
  try {
    const [maj, min] = opt['com-version'].split('.').map(Number);
    COMVERSION.setDefaultVersion(maj!, min!);
  } catch {
    critical('Wrong COMVERSION format, use dot separated integers e.g. "5.7"');
    process.exit(1);
  }
}

const target = positionals[0]!;
const action = (positionals[1] ?? '').toLowerCase();

if (action !== 'install' && action !== 'remove') {
  critical('Action must be "install" or "remove"');
  process.exit(1);
}

if (!opt.name) {
  critical('-name is required');
  process.exit(1);
}

if (action === 'install') {
  if (!opt.vbs) {
    critical('-vbs is required for install');
    process.exit(1);
  }
  if ((opt.filter == null && opt.timer == null) || (opt.filter != null && opt.timer != null)) {
    critical('You have to either specify -filter or -timer (and not both)');
    process.exit(1);
  }
}

const [domain, username, password, address] = parseTarget(target);

let aesKey = opt.aesKey ?? '';
let doKerberos = opt.k ?? false;
if (aesKey) doKerberos = true;

let lmhash = '';
let nthash = '';
if (opt.hashes) {
  const parts = opt.hashes.split(':');
  lmhash = parts[0] ?? '';
  nthash = parts[1] ?? '';
}

let pwd = password;
if (!pwd && username && !opt.hashes && !opt['no-pass'] && !aesKey) {
  const readline = await import('node:readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  pwd = await new Promise<string>((resolve) => {
    rl.question('Password: ', (ans) => { rl.close(); resolve(ans); });
  });
}

try {
  await run(
    address, username, pwd, domain || '',
    lmhash, nthash, aesKey, doKerberos,
    opt['dc-ip'] ?? null, action, opt.name!,
    opt.vbs ?? null, opt.filter ?? null, opt.timer ?? null,
  );
  process.exit(0);
} catch (e: any) {
  if (opt.debug) console.error(e);
  critical(String(e.message ?? e));
  process.exit(1);
}
