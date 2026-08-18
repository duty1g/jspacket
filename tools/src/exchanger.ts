#!/usr/bin/env node
/**
 * jspacket - exchanger
 *
 * TypeScript port of impacket's examples/exchanger.py.
 *
 * Connects to MS Exchange via RPC over HTTP v2 (NSPI interface) to
 * enumerate address books, dump entries, resolve GUIDs, and lookup DNTs.
 *
 * Original impacket author: Arseniy Sharoglazov / Positive Technologies
 * TypeScript port for jspacket.
 */

import { parseArgs } from 'node:util';
import * as fs from 'node:fs';
import { Buffer } from 'node:buffer';
import {
  parseTarget,
  init as initLogger,
  initProxy,
  info,
  critical,
  debug,
  normalizeArgs,
  BANNER,
} from '@impacket/examples';
import {
  DCERPCTransportFactory,
  MSRPC_UUID_NSPI,
  CP_TELETEX,
  STAT,
  GUID_NSPI,
  MID_END_OF_TABLE,
  NspiUnicodeStrings,
  fSkipObjects,
  hNspiBind,
  hNspiUnbind,
  hNspiUpdateStat,
  hNspiQueryRows,
  hNspiGetSpecialTable,
  hNspiQueryColumns,
  hNspiResolveNamesW,
  ExchBinaryObject,
  getGuidFromDn,
  getDnFromGuid,
  PermanentEntryID,
  EphemeralEntryID,
  RPC_PROXY_REMOTE_NAME_NEEDED_ERR,
  RPC_PROXY_HTTP_IN_DATA_401_ERR,
  RPC_PROXY_CONN_A1_0X6BA_ERR,
  RPC_PROXY_CONN_A1_404_ERR,
  RPC_PROXY_RPC_OUT_DATA_404_ERR,
  RPC_PROXY_CONN_A1_401_ERR,
  PROP_VAL_UNION,
} from '@impacket/dcerpc';
import { AUTH_BASIC } from '@impacket/http';
import { binToString, stringToBin } from '@impacket/uuid';
import { parseBitmask } from '@impacket/structure';
import {
  PR_CONTAINER_FLAGS_VALUES,
  MAPI_PROPERTIES,
} from '@impacket/mapi-constants';


const PR_CONTAINER_FLAGS       = 0x36000003;
const PR_ENTRYID               = 0x0fff0102;
const PR_DEPTH                 = 0x30050003;
const PR_EMS_AB_IS_MASTER      = 0xfffb000B;
const PR_EMS_AB_CONTAINERID    = 0xfffd0003;
const PR_EMS_AB_PARENT_ENTRYID = 0xfffc0102;
const PR_DISPLAY_NAME          = 0x3001001F;
const PR_EMS_AB_OBJECT_GUID    = 0x8c6d0102;
const PR_INSTANCE_KEY          = 0x0ff60102;

const DELIMITER = '=======================';

type SimplifiedRow = Record<number, unknown>;

function simplifyPropertyRow(rowSetElem: any): SimplifiedRow {
  const row: SimplifiedRow = {};
  const props = rowSetElem.fields?.['lpProps'] ?? rowSetElem['lpProps'];
  if (!props) return row;

  const propList = Array.isArray(props) ? props : (props as any);

  for (const prop of propList) {
    const propTag = Number(prop.fields?.['ulPropTag']?.fields?.['Data'] ?? prop.get?.('ulPropTag') ?? 0);
    const propType = propTag & 0xffff;
    const valUnion: any = prop.fields?.['Value'] ?? prop['Value'];

    if (!valUnion || !valUnion.fields) continue;

    const cls = PROP_VAL_UNION as any;
    const armDef = cls.union?.[propType];
    if (!armDef) continue;

    const fieldName = armDef[0];
    const rawVal = valUnion.fields[fieldName];
    if (rawVal == null) continue;

    if (propType === 0x000a) continue; // error
    if (propType === 0x000d) continue; // PtypEmbeddedTable

    if (propType === 0x0002 || propType === 0x0003 || propType === 0x000b) {
      row[propTag] = Number(rawVal.fields?.['Data'] ?? rawVal);
    } else if (propType === 0x001f) {
      const s = String(rawVal.fields?.['Data'] ?? rawVal);
      row[propTag] = s.endsWith('\0') ? s.slice(0, -1) : s;
    } else if (propType === 0x001e) {
      const s = String(rawVal.fields?.['Data'] ?? rawVal);
      row[propTag] = s.endsWith('\0') ? s.slice(0, -1) : s;
    } else if (propType === 0x0102) {
      try {
        const lpb = rawVal.fields?.['lpb'];
        let value: Buffer;
        if (Buffer.isBuffer(lpb)) {
          value = lpb;
        } else if (Array.isArray(lpb)) {
          value = Buffer.concat(lpb.map((x: any) => Buffer.isBuffer(x) ? x : Buffer.from([x])));
        } else if (lpb?.fields?.['Data']) {
          const d = lpb.fields['Data'];
          value = Array.isArray(d) ? Buffer.concat(d.map((x: any) => Buffer.isBuffer(x) ? x : Buffer.from([x]))) : Buffer.from(d);
        } else {
          value = Buffer.alloc(0);
        }

        if (propTag === 0x8c6d0102 || propTag === 0x68c40102 || propTag === 0x8c730102 || propTag === 0x0ff80102) {
          row[propTag] = binToString(value).toLowerCase();
        } else if (propTag === 0x0ff60102) {
          row[propTag] = value.length >= 4 ? value.readInt32LE(0) : 0;
        } else if (value.length >= 20 && value.subarray(4, 20).equals(GUID_NSPI)) {
          row[propTag] = new PermanentEntryID(value);
        } else if (value.length === 32 && value.readUInt32LE(0) === 0x87) {
          row[propTag] = new EphemeralEntryID(value);
        } else {
          row[propTag] = new ExchBinaryObject(value);
        }
      } catch {
        row[propTag] = rawVal;
      }
    } else if (propType === 0x1102) {
      const arr: Buffer[] = [];
      const lpbin = rawVal.fields?.['lpbin']?.fields?.['Data'] ?? rawVal.fields?.['lpbin'] ?? [];
      for (const item of (Array.isArray(lpbin) ? lpbin : [])) {
        try {
          const lpb = item.fields?.['lpb'];
          if (Buffer.isBuffer(lpb)) arr.push(lpb);
          else if (lpb?.fields?.['Data']) {
            const d = lpb.fields['Data'];
            arr.push(Array.isArray(d) ? Buffer.concat(d) : Buffer.from(d));
          }
        } catch { /* skip */ }
      }
      row[propTag] = arr;
    } else if (propType === 0x101e || propType === 0x101f) {
      const arr: string[] = [];
      const fieldKey = propType === 0x101e ? 'lppszA' : 'lppszW';
      const items = rawVal.fields?.[fieldKey]?.fields?.['Data'] ?? rawVal.fields?.[fieldKey] ?? [];
      for (const item of (Array.isArray(items) ? items : [])) {
        let s = String(item.fields?.['Data'] ?? item);
        if (s.endsWith('\0')) s = s.slice(0, -1);
        arr.push(s);
      }
      row[propTag] = arr;
    } else if (propType === 0x0040) {
      row[propTag] = rawVal;
    } else {
      row[propTag] = rawVal;
    }
  }

  return row;
}

function simplifyPropertyRowSet(propertyRowSet: any): SimplifiedRow[] {
  const ret: SimplifiedRow[] = [];
  const aRow = propertyRowSet?.fields?.['aRow'] ?? propertyRowSet?.['aRow'];
  if (!aRow) return ret;
  for (const row of (Array.isArray(aRow) ? aRow : [])) {
    ret.push(simplifyPropertyRow(row));
  }
  return ret;
}

function intToDword(n: number): number {
  return n > 0 ? n : ((n + (1 << 32)) % (1 << 32)) >>> 0;
}

interface HTableEntry {
  flags: number;
  name: string;
  guid?: Buffer;
  parent_guid?: Buffer;
  depth: number;
  is_master: number;
  count?: number;
  start_mid?: number;
  printed?: boolean;
}

const PROPS_GUID = [PR_EMS_AB_OBJECT_GUID];

const PROPS_MINIMAL = [
  0x3a00001F, 0x39fe001F, 0x80270102, 0x30070040,
  0x30080040, 0x8c6d0102,
];

const PROPS_EXTENDED = [
  ...PROPS_MINIMAL,
  0x3a0f001f, 0x8202001f, 0x0fff0102, 0x3001001f,
  0x3a20001f, 0x39ff001f, 0x800f101f, 0x8171001f,
  0x8102101f, 0x804b001F, 0x806f101f, 0x3004001f,
  0x8069001f, 0x3a26001f, 0x3a2a001f, 0x3a28001f,
  0x3a29001f, 0x3a09001f, 0x3a1c001f, 0x3a1b101f,
  0x3a16001f, 0x3a18001f, 0x3a17001f, 0x3a11001f,
  0x3a0a001f, 0x3a06001f, 0x0ffe0003, 0x39000003,
  0x80bd0003, 0x802d001F, 0x802e001F, 0x802f001F,
  0x8030001F, 0x8031001F, 0x8032001F, 0x8033001F,
  0x8034001F, 0x8035001F, 0x8036001F, 0x8c57001F,
  0x8c58001F, 0x8c59001F, 0x8c60001F, 0x8c61001F,
  0x81b6101e, 0x8c9f001e, 0x8c730102, 0x8c96101e,
  0x8c750102, 0x8cb5000b, 0x8cb30003, 0x8ce20003,
  0x813b101e, 0x8170101e, 0x8011001e, 0x8175101e,
  0x8c6a1102, 0x0ff60102,
];

class NSPIAttacks {
  private dce: any;
  private handler: any;
  private stat: any;
  htable: Map<number, HTableEntry> = new Map();
  private anyExistingContainerID = -1;
  private props: number[] = [];
  private extendedOutput = false;
  private outputType = 'hex';
  private outputFd: fs.WriteStream | null = null;

  constructor() {
    this.stat = new STAT();
    (this.stat as any).set('CodePage', CP_TELETEX);
  }

  setExtendedOutput(val: boolean) { this.extendedOutput = val; }
  setOutputType(val: string) { this.outputType = val; }

  setOutputFile(filename: string) {
    this.outputFd = fs.createWriteStream(filename);
  }

  print(text: string) {
    if (this.outputFd) this.outputFd.write(text + '\n');
    console.log(text);
  }

  encodeBinary(buf: Buffer): string {
    if (this.outputType === 'hex') return '0x' + buf.toString('hex');
    return buf.toString('base64');
  }

  async connectRpc(
    username: string, password: string, domain: string,
    hashes: string | null, remoteName: string, rpcHostname: string,
    useBasic: boolean,
  ) {
    const stringbinding = `ncacn_http:${rpcHostname}[6004,RpcProxy=${remoteName}:443]`;
    debug(`StringBinding ${stringbinding}`);

    const rpctransport = DCERPCTransportFactory(stringbinding);
    let lmhash = '', nthash = '';
    if (hashes) [lmhash, nthash] = hashes.split(':') as [string, string];
    rpctransport.setCredentials(username, password, domain, lmhash, nthash);

    this.dce = rpctransport.getDceRpc();
    this.dce.setCredentials(username, password, domain, lmhash, nthash);

    if (useBasic) {
      (rpctransport as any).setAuthType?.(AUTH_BASIC);
    }

    this.dce.setAuthLevel(6);
    await this.dce.connect();
    await this.dce.bind(MSRPC_UUID_NSPI);

    const resp = await hNspiBind(this.dce, this.stat);
    this.handler = resp.fields?.['contextHandle'] ?? (resp as any)['contextHandle'];
  }

  async updateStat(tableMId: number) {
    const stat = new STAT();
    (stat as any).set('CodePage', CP_TELETEX);
    (stat as any).set('ContainerID', intToDword(tableMId));

    const resp = await hNspiUpdateStat(this.dce, this.handler, stat);
    this.stat = resp.fields?.['pStat'] ?? (resp as any)['pStat'];
  }

  async loadHtable() {
    const resp = await hNspiGetSpecialTable(this.dce, this.handler);
    const ppRows = resp.fields?.['ppRows'] ?? (resp as any)['ppRows'];
    const rows = simplifyPropertyRowSet(ppRows);
    this.parseAndSetHtable(rows);
  }

  private parseAndSetHtable(rows: SimplifiedRow[]) {
    this.htable.clear();
    for (const ab of rows) {
      const mId = ab[PR_EMS_AB_CONTAINERID] as number;
      const entry: HTableEntry = {
        flags: ab[PR_CONTAINER_FLAGS] as number,
        name: mId === 0 ? 'Default Global Address List' : (ab[PR_DISPLAY_NAME] as string ?? ''),
        depth: (ab[PR_DEPTH] as number) ?? 0,
        is_master: (ab[PR_EMS_AB_IS_MASTER] as number) ?? 0,
        printed: false,
      };

      if (mId !== 0 && ab[PR_ENTRYID]) {
        const entryId = ab[PR_ENTRYID];
        if (entryId instanceof PermanentEntryID) {
          entry.guid = getGuidFromDn((entryId as any).getData?.() ?? Buffer.alloc(0));
        } else if (Buffer.isBuffer(entryId)) {
          entry.guid = getGuidFromDn(entryId.toString());
        } else if (entryId instanceof ExchBinaryObject) {
          entry.guid = (entryId as any).data ?? Buffer.alloc(0);
        }
      }

      if (ab[PR_EMS_AB_PARENT_ENTRYID]) {
        const parentEntry = ab[PR_EMS_AB_PARENT_ENTRYID];
        if (parentEntry instanceof PermanentEntryID) {
          entry.parent_guid = getGuidFromDn((parentEntry as any).getData?.() ?? Buffer.alloc(0));
        } else if (Buffer.isBuffer(parentEntry)) {
          entry.parent_guid = getGuidFromDn(parentEntry.toString());
        } else if (parentEntry instanceof ExchBinaryObject) {
          entry.parent_guid = (parentEntry as any).data ?? Buffer.alloc(0);
        }
      }

      this.htable.set(mId, entry);
    }
  }

  async loadHtableStat() {
    for (const mId of Array.from(this.htable.keys())) {
      await this.updateStat(mId);
      const entry = this.htable.get(mId)!;
      entry.count = Number(this.stat.fields?.['TotalRecs']?.fields?.['Data'] ?? (this.stat as any).get?.('TotalRecs') ?? 0);
      entry.start_mid = Number(this.stat.fields?.['CurrentRec']?.fields?.['Data'] ?? (this.stat as any).get?.('CurrentRec') ?? 0);
    }
  }

  async loadHtableContainerId() {
    if (this.anyExistingContainerID !== -1) return;
    if (this.htable.size === 0) await this.loadHtable();

    for (const mId of Array.from(this.htable.keys())) {
      await this.updateStat(mId);
      const curRec = Number(this.stat.fields?.['CurrentRec']?.fields?.['Data'] ?? (this.stat as any).get?.('CurrentRec') ?? 0);
      if (curRec > 0) {
        this.anyExistingContainerID = intToDword(mId);
        return;
      }
    }
  }

  printHtable(parentGuid: Buffer | null = null) {
    const mIdsPrint: number[] = [];

    for (const [mId, entry] of Array.from(this.htable.entries())) {
      if (parentGuid === null && !entry.parent_guid) {
        mIdsPrint.push(mId);
      } else if (parentGuid && entry.parent_guid?.equals(parentGuid)) {
        mIdsPrint.push(mId);
      }
    }

    for (const mId of mIdsPrint) {
      const ab = this.htable.get(mId)!;
      ab.printed = true;
      const indent = '    '.repeat(ab.depth);

      console.log(`${indent}${ab.name}`);

      if (ab.count !== undefined) {
        console.log(`${indent}TotalRecs: ${ab.count}`);
      }

      if (mId !== 0 && ab.guid) {
        console.log(`${indent}Guid: ${binToString(ab.guid).toLowerCase()}`);
      } else {
        console.log(`${indent}Guid: None`);
      }

      if (ab.is_master !== 0) {
        console.log(`${indent}PR_EMS_AB_IS_MASTER attribute is set!`);
      }

      if (this.extendedOutput) {
        const dword = intToDword(mId);
        console.log(`${indent}Assigned MId: 0x${dword.toString(16).padStart(8, '0').toUpperCase()} (${mId})`);

        if (ab.start_mid !== undefined) {
          const smDword = intToDword(ab.start_mid);
          if (smDword === 2) {
            console.log(`${indent}Assigned first record MId: 0x00000002 (MID_END_OF_TABLE)`);
          } else {
            console.log(`${indent}Assigned first record MId: 0x${smDword.toString(16).padStart(8, '0').toUpperCase()} (${ab.start_mid})`);
          }
        }

        const flags = parseBitmask(PR_CONTAINER_FLAGS_VALUES, ab.flags);
        console.log(`${indent}Flags: ${flags}`);
      }

      console.log();

      if (mId !== 0 && ab.guid) {
        this.printHtable(ab.guid);
      }
    }

    if (parentGuid === null) {
      for (const [mId, entry] of Array.from(this.htable.entries())) {
        if (!entry.printed) {
          console.log('Found parentless object!');
          console.log(`Name: ${entry.name}`);
          if (entry.guid) console.log(`Guid: ${binToString(entry.guid).toLowerCase()}`);
          if (entry.parent_guid) console.log(`Parent guid: ${binToString(entry.parent_guid).toLowerCase()}`);
          const dword = intToDword(mId);
          console.log(`Assigned MId: 0x${dword.toString(16).padStart(8, '0').toUpperCase()} (${mId})`);
          const flags = parseBitmask(PR_CONTAINER_FLAGS_VALUES, entry.flags);
          console.log(`Flags: ${flags}`);
          console.log();
        }
      }
    }
  }

  printRow(rowSimpl: SimplifiedRow, delimiter?: string) {
    let empty = true;

    for (const aulPropTag of Object.keys(rowSimpl).map(Number)) {
      const propertyId = aulPropTag >> 16;
      const propertyType = aulPropTag & 0xffff;

      if (propertyType === 0x000a) continue; // error
      if (propertyType === 0x000d) continue; // PtypEmbeddedTable

      empty = false;
      let propertyName: string;
      const mapiEntry = MAPI_PROPERTIES[propertyId];
      if (mapiEntry) {
        propertyName = mapiEntry.ldapDisplayName ?? mapiEntry.alternateName ?? mapiEntry.exchangeName ?? `0x${aulPropTag.toString(16).padStart(8, '0')}`;
      } else {
        propertyName = `0x${aulPropTag.toString(16).padStart(8, '0')}`;
      }

      if (this.extendedOutput) {
        propertyName = `${propertyName}, 0x${aulPropTag.toString(16).padStart(8, '0')}`;
      }

      const val = rowSimpl[aulPropTag];
      if (val instanceof ExchBinaryObject) {
        this.print(`${propertyName}: ${this.encodeBinary((val as any).data ?? Buffer.alloc(0))}`);
      } else if (Buffer.isBuffer(val)) {
        this.print(`${propertyName}: ${this.encodeBinary(val)}`);
      } else {
        this.print(`${propertyName}: ${val}`);
      }
    }

    if (!empty && delimiter) {
      this.print(delimiter);
    }
  }

  async loadProps() {
    if (this.props.length > 0) return;
    const resp = await hNspiQueryColumns(this.dce, this.handler);
    const ppCols: any = resp.fields?.['ppColumns'] ?? (resp as any)['ppColumns'];
    const tags = ppCols?.fields?.['aulPropTag'] ?? ppCols?.['aulPropTag'] ?? [];

    for (const propObj of (Array.isArray(tags) ? tags : [])) {
      const propTag = Number(propObj.fields?.['Data'] ?? propObj);
      const propType = propTag & 0xffff;
      if (propType === 0x000d) continue; // skip PtypEmbeddedTable
      this.props.push(propTag);
    }
  }

  async reqPrintTableRows(opts: {
    tableMId?: number;
    attrs?: number[];
    count?: number;
    eTable?: number[];
    onlyCheck?: boolean;
  }): Promise<boolean> {
    const { tableMId, attrs = [], count = 50, eTable, onlyCheck = false } = opts;
    let printOnlyGUIDs = false;
    let useAsExplicitTable = false;

    if (this.anyExistingContainerID === -1) {
      await this.loadHtableContainerId();
    }

    if (tableMId === undefined && !eTable) throw new Error('Wrong arguments!');
    if (tableMId !== undefined && eTable) throw new Error('Wrong arguments!');

    if (tableMId !== undefined) {
      await this.updateStat(tableMId);
      const curRec = Number(this.stat.fields?.['CurrentRec']?.fields?.['Data'] ?? (this.stat as any).get?.('CurrentRec') ?? 0);
      if (curRec === MID_END_OF_TABLE) return false;
    }

    let firstReqProps: number[];
    let resolvedAttrs = attrs;

    if (JSON.stringify(attrs) === JSON.stringify(PROPS_GUID)) {
      firstReqProps = PROPS_GUID;
      printOnlyGUIDs = true;
    } else if (JSON.stringify(attrs) === JSON.stringify(PROPS_MINIMAL)) {
      firstReqProps = PROPS_MINIMAL;
    } else if (attrs.length === 0) {
      if (this.props.length === 0) await this.loadProps();
      resolvedAttrs = this.props;
      firstReqProps = [PR_INSTANCE_KEY];
      useAsExplicitTable = true;
    } else {
      firstReqProps = [PR_INSTANCE_KEY];
      useAsExplicitTable = true;
    }

    if (onlyCheck) {
      resolvedAttrs = PROPS_GUID;
      firstReqProps = PROPS_GUID;
      useAsExplicitTable = true;
    }

    let currentETable = eTable;

    while (true) {
      let respRows: SimplifiedRow[];

      if (!currentETable) {
        const resp = await hNspiQueryRows(this.dce, this.handler, {
          pStat: this.stat,
          Count: count,
          pPropTags: firstReqProps,
        });
        this.stat = resp.fields?.['pStat'] ?? (resp as any)['pStat'];

        try {
          const ppRows = resp.fields?.['ppRows'] ?? (resp as any)['ppRows'];
          respRows = simplifyPropertyRowSet(ppRows);
        } catch (e: any) {
          throw new Error(`NspiQueryRows returned wrong result: ${e.message}`);
        }

        if (onlyCheck) {
          if (respRows.length === 0) return false;
          for (const row of respRows) {
            if (!(0x8C6D000A in row)) return true;
          }
          return false;
        }
      } else {
        respRows = [];
      }

      if (useAsExplicitTable) {
        let eTableInt: number[];
        if (!currentETable) {
          eTableInt = respRows.map(row => row[PR_INSTANCE_KEY] as number).filter(x => x != null);
        } else {
          eTableInt = currentETable;
        }

        const resp = await hNspiQueryRows(this.dce, this.handler, {
          ContainerID: this.anyExistingContainerID,
          Count: count,
          pPropTags: resolvedAttrs,
          lpETable: eTableInt,
        });

        try {
          const ppRows = resp.fields?.['ppRows'] ?? (resp as any)['ppRows'];
          respRows = simplifyPropertyRowSet(ppRows);
        } catch (e: any) {
          throw new Error(`NspiQueryRows returned wrong result while processing explicit table: ${e.message}`);
        }

        if (onlyCheck) {
          if (respRows.length === 0) return false;
          for (const row of respRows) {
            if (!(0x8C6D000A in row)) return true;
          }
          return false;
        }
      }

      if (printOnlyGUIDs) {
        for (const row of respRows) {
          if (PR_EMS_AB_OBJECT_GUID in row) {
            this.print(String(row[PR_EMS_AB_OBJECT_GUID]));
          }
        }
      } else {
        for (const row of respRows) {
          this.printRow(row, DELIMITER);
        }
      }

      if (currentETable) break;

      const curRec = Number(this.stat.fields?.['CurrentRec']?.fields?.['Data'] ?? (this.stat as any).get?.('CurrentRec') ?? 0);
      if (curRec === MID_END_OF_TABLE) break;
      if (respRows.length === 0) break;
    }

    return true;
  }

  async reqPrintGuid(opts: {
    guid?: string;
    guidFile?: string;
    attrs?: number[];
    count?: number;
  }) {
    const { guid, guidFile, attrs = [], count = 50 } = opts;
    if (!guid && !guidFile) throw new Error('Wrong arguments!');

    let resolvedAttrs = attrs;
    if (resolvedAttrs.length === 0) {
      if (this.props.length === 0) await this.loadProps();
      resolvedAttrs = this.props;
    }

    if (guid) {
      const printed = await this.reqPrintGuidBatch([guid], resolvedAttrs);
      if (printed === 0) throw new Error('Object with specified GUID not found!');
      return;
    }

    const lines = fs.readFileSync(guidFile!, 'utf-8').split('\n');
    let i = 0;
    while (i < lines.length) {
      const guidList: string[] = [];
      for (let j = 0; j < count && i < lines.length; j++, i++) {
        const g = lines[i]!.trim();
        if (!g || g.startsWith('#')) continue;
        guidList.push(g);
      }
      if (guidList.length === 0) continue;
      await this.reqPrintGuidBatch(guidList, resolvedAttrs, DELIMITER);
    }
  }

  private async reqPrintGuidBatch(guidList: string[], attrs: number[], delimiter?: string): Promise<number> {
    const legacyDNList = guidList.map(g => getDnFromGuid(g, true));

    const resp = await hNspiResolveNamesW(this.dce, this.handler, {
      pPropTags: attrs,
      paStr: legacyDNList,
    });

    const ppRows: any = resp.fields?.['ppRows'] ?? (resp as any)['ppRows'];
    const cRows = Number(ppRows?.fields?.['cRows']?.fields?.['Data'] ?? ppRows?.['cRows'] ?? 0);
    if (cRows <= 0) return 0;

    const rows = simplifyPropertyRowSet(ppRows);
    for (const row of rows) {
      this.printRow(row, delimiter);
    }

    return cRows;
  }

  async reqPrintDnt(startDnt: number, stopDnt: number, opts: {
    attrs?: number[];
    count?: number;
    checkIfEmpty?: boolean;
  } = {}) {
    const { attrs = [], count = 50, checkIfEmpty = false } = opts;

    const step = stopDnt >= startDnt ? count : -count;
    const rstep = step > 0 ? 1 : -1;
    const endDnt = stopDnt + rstep;

    let dnt1 = startDnt;
    let dnt2 = startDnt + step;

    while (true) {
      if (step > 0 && dnt2 > endDnt) dnt2 = endDnt;
      else if (step < 0 && dnt2 < endDnt) dnt2 = endDnt;

      this.print(`# MIds ${dnt1}-${dnt2 - rstep}:`);

      const eTable: number[] = [];
      for (let d = dnt1; step > 0 ? d < dnt2 : d > dnt2; d += rstep) eTable.push(d);

      if (checkIfEmpty) {
        const exists = await this.reqPrintTableRows({ attrs, eTable, onlyCheck: true });
        if (exists) {
          await this.reqPrintTableRows({ attrs, eTable });
        }
      } else {
        await this.reqPrintTableRows({ attrs, eTable });
      }

      if (dnt2 === endDnt) break;
      dnt1 += step;
      dnt2 += step;
    }
  }

  async disconnect() {
    await hNspiUnbind(this.dce, this.handler);
    await this.dce.disconnect();
    if (this.outputFd) { this.outputFd.end(); this.outputFd = null; }
  }
}

async function main(): Promise<void> {
  console.log(BANNER);

  const argv = normalizeArgs(process.argv.slice(2));
  let opt: any;
  let positionals: string[];
  try {
    ({ values: opt, positionals } = parseArgs({
      args: argv,
      options: {
        debug: { type: 'boolean', short: 'd', default: false },
        ts: { type: 'boolean', default: false },
        'rpc-hostname': { type: 'string', default: '' },
        hashes: { type: 'string' },
        basic: { type: 'boolean', default: false },
        // submodule options
        count: { type: 'boolean', default: false },
        'lookup-type': { type: 'string' },
        'rows-per-request': { type: 'string', default: '50' },
        name: { type: 'string' },
        guid: { type: 'string' },
        'guid-file': { type: 'string' },
        'output-type': { type: 'string', default: 'hex' },
        'output-file': { type: 'string' },
        'start-dnt': { type: 'string', default: '500000' },
        'stop-dnt': { type: 'string', default: '0' },
        proxy: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
      allowPositionals: true,
      strict: false,
    }));
  } catch (e) {
    console.error(`[-] ${(e as Error).message}`);
    process.exit(1);
  }

  if (opt.help || positionals.length < 2) {
    console.log(`
usage: exchanger [[domain/]username[:password]@]<target> <module> <submodule> [options]

A tool to abuse Exchange services via RPC over HTTP v2

positional arguments:
  target                [[domain/]username[:password]@]<target>
  module                nspi
  submodule             list-tables | dump-tables | guid-known | dnt-lookup

options:
  -rpc-hostname NAME    RPC server name (GUID or NetBIOS)
  -hashes LMHASH:NTHASH
  -basic                Use Basic Auth instead of NTLM
  -debug                Turn DEBUG + extended output ON
  -ts                   Add timestamps to output

nspi list-tables:
  -count                Request total records per table

nspi dump-tables:
  -lookup-type TYPE     MINIMAL (default) | EXTENDED | FULL | GUIDS
  -rows-per-request N   Rows per request (default 50)
  -name NAME            Table name (inc. GAL)
  -guid GUID            Table GUID
  -output-type TYPE     hex (default) | base64
  -output-file PATH     Write output to file

nspi guid-known:
  -guid GUID            Object GUID
  -guid-file PATH       File with GUIDs
  -lookup-type TYPE     MINIMAL | EXTENDED | FULL
  -rows-per-request N   Rows per request (default 50)
  -output-type TYPE     hex | base64
  -output-file PATH     Output file

nspi dnt-lookup:
  -lookup-type TYPE     EXTENDED (default) | FULL | GUIDS
  -start-dnt N          Starting DNT (default 500000)
  -stop-dnt N           Ending DNT (default 0)
  -rows-per-request N   Rows per request (default 350)
  -output-type TYPE     hex | base64
  -output-file PATH     Output file

  -h, -help             Show this help message and exit
`);
    process.exit(0);
  }

  initProxy(opt.proxy);
  initLogger({ ts: opt.ts as boolean, debug: opt.debug as boolean });

  const [domain, username, password, remoteName] = parseTarget(positionals[0]!);
  const module = (positionals[1] ?? '').toLowerCase();
  const submodule = (positionals[2] ?? '').toLowerCase();

  if (module !== 'nspi') {
    critical(`${module} module not found`);
    process.exit(1);
  }

  if (!['list-tables', 'dump-tables', 'guid-known', 'dnt-lookup'].includes(submodule)) {
    critical(`Unknown submodule: ${submodule}`);
    process.exit(1);
  }

  let rpcHostname = opt['rpc-hostname'] as string;
  if (rpcHostname === '') rpcHostname = '';

  const rowsPerRequest = parseInt(opt['rows-per-request'] as string, 10);
  const lookupType = (opt['lookup-type'] as string)?.toUpperCase() ?? null;

  const exch = new NSPIAttacks();
  exch.setExtendedOutput(!!opt.debug);

  if (opt['output-file'] && ['dump-tables', 'guid-known', 'dnt-lookup'].includes(submodule)) {
    exch.setOutputFile(opt['output-file'] as string);
  }

  if (opt['output-type']) exch.setOutputType(opt['output-type'] as string);

  try {
    await exch.connectRpc(
      username, password, domain ?? '', opt.hashes as string | null,
      remoteName, rpcHostname, !!opt.basic,
    );

    if (submodule === 'list-tables') {
      await exch.loadHtable();
      if (opt.count) await exch.loadHtableStat();
      exch.printHtable();

    } else if (submodule === 'dump-tables') {
      if (!opt.name && !opt.guid) {
        critical('Specify -name or -guid');
        process.exit(1);
      }

      let propTags: number[];
      if (!lookupType || lookupType === 'MINIMAL') propTags = PROPS_MINIMAL;
      else if (lookupType === 'EXTENDED') propTags = PROPS_EXTENDED;
      else if (lookupType === 'GUIDS') propTags = PROPS_GUID;
      else propTags = []; // FULL

      const nameVal = opt.name as string | undefined;
      const guidVal = opt.guid as string | undefined;
      let tableMId = 0;

      if (nameVal?.toLowerCase() === 'gal' || nameVal?.toLowerCase() === 'default global address list' || nameVal?.toLowerCase() === 'global address list') {
        info('Lookuping Global Address List');
        tableMId = 0;
      } else {
        await exch.loadHtable();

        let found = false;
        for (const [mId, entry] of Array.from(exch.htable.entries())) {
          if (mId === 0) continue;

          if (guidVal) {
            const guidBuf = stringToBin(guidVal);
            if (entry.guid?.equals(guidBuf)) {
              debug(`MId ${mId} is assigned for ${guidVal} object`);
              info(`Lookuping ${entry.name}`);
              tableMId = mId;
              found = true;
              break;
            }
          } else if (nameVal && entry.name === nameVal) {
            const guid = entry.guid ? binToString(entry.guid).toLowerCase() : '?';
            debug(`MId ${mId} is assigned for ${guid} object`);
            info(`Lookuping address book with objectGUID = ${guid}`);
            tableMId = mId;
            found = true;
            break;
          }
        }

        if (!found && tableMId === 0 && !nameVal?.toLowerCase().includes('gal')) {
          critical('Specified address book not found!');
          process.exit(1);
        }
      }

      await exch.reqPrintTableRows({ tableMId, attrs: propTags, count: rowsPerRequest });

    } else if (submodule === 'guid-known') {
      if (!opt.guid && !opt['guid-file']) {
        critical('Specify -guid or -guid-file');
        process.exit(1);
      }

      let propTags: number[];
      if (!lookupType || lookupType === 'MINIMAL') propTags = PROPS_MINIMAL;
      else if (lookupType === 'EXTENDED') propTags = PROPS_EXTENDED;
      else propTags = []; // FULL

      await exch.reqPrintGuid({
        guid: opt.guid as string | undefined,
        guidFile: opt['guid-file'] as string | undefined,
        attrs: propTags,
        count: rowsPerRequest,
      });

    } else if (submodule === 'dnt-lookup') {
      let propTags: number[];
      if (!lookupType || lookupType === 'EXTENDED') propTags = PROPS_EXTENDED;
      else if (lookupType === 'GUIDS') propTags = PROPS_GUID;
      else propTags = []; // FULL

      await exch.reqPrintDnt(
        parseInt(opt['start-dnt'] as string, 10),
        parseInt(opt['stop-dnt'] as string, 10),
        { attrs: propTags, count: rowsPerRequest, checkIfEmpty: true },
      );
    }

    await exch.disconnect();

  } catch (e: any) {
    const errorText = `Protocol failed: ${e.message ?? e}`;
    critical(errorText);

    if (errorText.includes('NspiQueryRows returned wrong result') && submodule === 'dnt-lookup') {
      critical('Most likely ntdsai.dll in lsass.exe has crashed on a Domain Controller. The DC is probably rebooting. Try a different DNT range.');
    }
    if (errorText.includes(RPC_PROXY_CONN_A1_0X6BA_ERR)) {
      critical('This usually means the target has no ACL to connect to this endpoint using RPC Proxy');
      critical('Is the server a MS Exchange?');
      if (!rpcHostname) critical('Try to specify -rpc-hostname');
      else critical('Try a different -rpc-hostname, or enumerate endpoints via rpcmap / rpcdump');
    }
    if (errorText.includes(RPC_PROXY_RPC_OUT_DATA_404_ERR) || errorText.includes(RPC_PROXY_CONN_A1_404_ERR)) {
      if (!rpcHostname) critical('Cannot determine the right RPC Server name. Specify -rpc-hostname');
      else critical('The specified RPC Server is incorrect. Try a different -rpc-hostname');
    }
    if (errorText.includes(RPC_PROXY_REMOTE_NAME_NEEDED_ERR)) {
      critical('Specify -rpc-hostname');
    }
    if (errorText.includes(RPC_PROXY_HTTP_IN_DATA_401_ERR) || errorText.includes(RPC_PROXY_CONN_A1_401_ERR)) {
      critical('Wrong credentials!');
      if (domain === '') critical('The server requested authentication which may require you to specify the domain. Your domain is empty!');
    }

    process.exit(1);
  }
}

main().catch((err) => {
  console.error(`[-] ${err.message ?? err}`);
  process.exit(1);
});
