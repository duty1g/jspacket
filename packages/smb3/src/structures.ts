import { Buffer } from 'node:buffer';
import { type FieldDescriptor, Structure } from '@impacket/structure';

export class REQ_GET_DFS_REFERRAL extends Structure {
  static structure: FieldDescriptor[] = [
    ['MaxReferralLevel', '<H=0'],
    ['RequestFileName', ':'],
  ];
}

export class RESP_GET_DFS_REFERRAL extends Structure {
  static structure: FieldDescriptor[] = [
    ['PathConsumed', '<H=0'],
    ['NumberOfReferrals', '<H=0'],
    ['ReferralHeaderFlags', '<I=0'],
    ['ReferralEntries', ':'],
  ];
}

export class DFS_REFERRAL_V3 extends Structure {
  static structure: FieldDescriptor[] = [
    ['VersionNumber', '<H=0'],
    ['Size', '<H=0'],
    ['ServerType', '<H=0'],
    ['ReferralEntryFlags', '<H=0'],
    ['TimeToLive', '<I=0'],
    ['DFSPathOffset', '<H=0'],
    ['DFSAlternatePathOffset', '<H=0'],
    ['NetworkAddressOffset', '<H=0'],
    ['ServiceSiteGuid', '16s=b""'],
  ];
}

export function readUtf16String(data: Buffer, offset: number): string {
  let i = offset;
  while (i + 1 < data.length) {
    if (data[i] === 0 && data[i + 1] === 0) break;
    i += 2;
  }
  return data.subarray(offset, i).toString('utf-16le');
}

export function parseDfsReferral(data: Buffer): [Array<Record<string, unknown>>, number] {
  const resp = new RESP_GET_DFS_REFERRAL(data);
  const referrals: Array<Record<string, unknown>> = [];
  const entriesData = resp.get('ReferralEntries') as Buffer;
  let offset = 0;
  const count = resp.get('NumberOfReferrals') as number;

  for (let idx = 0; idx < count; idx++) {
    if (offset + 4 > entriesData.length) break;
    const version = entriesData.readUInt16LE(offset);
    const size = entriesData.readUInt16LE(offset + 2);
    if (size === 0) break;

    if (version === 3 || version === 4) {
      if (offset + 18 > entriesData.length) break;
      const serverType = entriesData.readUInt16LE(offset + 4);
      const flags = entriesData.readUInt16LE(offset + 6);
      const ttl = entriesData.readUInt32LE(offset + 8);
      const pathOff = entriesData.readUInt16LE(offset + 12);
      const altPathOff = entriesData.readUInt16LE(offset + 14);
      const netAddrOff = entriesData.readUInt16LE(offset + 16);

      let dfsPath = '';
      let dfsAltPath = '';
      let networkAddress = '';
      if (pathOff > 0) dfsPath = readUtf16String(entriesData, offset + pathOff);
      if (altPathOff > 0) dfsAltPath = readUtf16String(entriesData, offset + altPathOff);
      if (netAddrOff > 0) networkAddress = readUtf16String(entriesData, offset + netAddrOff);

      let targetServer = '';
      let targetShare = '';
      let targetPath = '';
      const cleaned = networkAddress.replace(/^\\+/, '');
      if (cleaned) {
        const parts = cleaned.split('\\');
        if (parts.length >= 1) targetServer = parts[0]!;
        if (parts.length >= 2) targetShare = parts[1]!;
        if (parts.length >= 3) targetPath = parts.slice(2).join('\\');
      }

      referrals.push({
        dfs_path: dfsPath,
        dfs_alt_path: dfsAltPath,
        network_address: networkAddress,
        server_type: serverType,
        flags,
        ttl,
        target_server: targetServer,
        target_share: targetShare,
        target_path: targetPath,
      });
    }
    offset += size;
  }
  return [referrals, resp.get('PathConsumed') as number];
}

export class SMBPacketBase extends Structure {
  static structure: FieldDescriptor[] = [];

  constructor(data?: Buffer) {
    super(data);
    if (data === undefined) {
      this.set('TreeID', 0);
    }
  }

  addCommand(_command: Structure): void {
    throw new Error('Implement This!');
  }

  isValidAnswer(status: number): boolean {
    if (this.get('Status') !== status) {
      const statusCode = this.get('Status') as number;
      const err = new Error(`SessionError: 0x${statusCode.toString(16)}`) as Error & { error: number; packet: unknown };
      err.error = statusCode;
      err.packet = this;
      throw err;
    }
    return true;
  }
}

export class SMB2PacketAsync extends SMBPacketBase {
  static structure: FieldDescriptor[] = [
    ['ProtocolID', '"\xfeSMB'],
    ['StructureSize', '<H=64'],
    ['CreditCharge', '<H=0'],
    ['Status', '<L=0'],
    ['Command', '<H=0'],
    ['CreditRequestResponse', '<H=0'],
    ['Flags', '<L=0'],
    ['NextCommand', '<L=0'],
    ['MessageID', '<Q=0'],
    ['AsyncID', '<Q=0'],
    ['SessionID', '<Q=0'],
    ['Signature', '16s=""'],
    ['Data', ':=""'],
  ];
}

export class SMB3PacketAsync extends SMBPacketBase {
  static structure: FieldDescriptor[] = [
    ['ProtocolID', '"\xfeSMB'],
    ['StructureSize', '<H=64'],
    ['CreditCharge', '<H=0'],
    ['ChannelSequence', '<H=0'],
    ['Reserved', '<H=0'],
    ['Command', '<H=0'],
    ['CreditRequestResponse', '<H=0'],
    ['Flags', '<L=0'],
    ['NextCommand', '<L=0'],
    ['MessageID', '<Q=0'],
    ['AsyncID', '<Q=0'],
    ['SessionID', '<Q=0'],
    ['Signature', '16s=""'],
    ['Data', ':=""'],
  ];
}

export class SMB2Packet extends SMBPacketBase {
  static structure: FieldDescriptor[] = [
    ['ProtocolID', '"\xfeSMB'],
    ['StructureSize', '<H=64'],
    ['CreditCharge', '<H=0'],
    ['Status', '<L=0'],
    ['Command', '<H=0'],
    ['CreditRequestResponse', '<H=0'],
    ['Flags', '<L=0'],
    ['NextCommand', '<L=0'],
    ['MessageID', '<Q=0'],
    ['Reserved', '<L=0'],
    ['TreeID', '<L=0'],
    ['SessionID', '<Q=0'],
    ['Signature', '16s=""'],
    ['Data', ':=""'],
  ];
}

export class SMB3Packet extends SMBPacketBase {
  static structure: FieldDescriptor[] = [
    ['ProtocolID', '"\xfeSMB'],
    ['StructureSize', '<H=64'],
    ['CreditCharge', '<H=0'],
    ['ChannelSequence', '<H=0'],
    ['Reserved', '<H=0'],
    ['Command', '<H=0'],
    ['CreditRequestResponse', '<H=0'],
    ['Flags', '<L=0'],
    ['NextCommand', '<L=0'],
    ['MessageID', '<Q=0'],
    ['Reserved', '<L=0'],
    ['TreeID', '<L=0'],
    ['SessionID', '<Q=0'],
    ['Signature', '16s=""'],
    ['Data', ':=""'],
  ];
}

export class Empty extends Structure {}

export class SMB2Error extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=9'],
    ['Reserved', '<H=0'],
    ['ByteCount', '<L=0'],
    ['_ErrorData', '_-ErrorData', 'self["ByteCount"]'],
    ['ErrorData', '"\xff'],
  ];
}

export class SMB2ErrorSymbolicLink extends Structure {
  static structure: FieldDescriptor[] = [
    ['SymLinkLength', '<L=0'],
    ['SymLinkErrorTag', '<L=0'],
    ['ReparseTag', '<L=0'],
    ['ReparseDataLenght', '<H=0'],
    ['UnparsedPathLength', '<H=0'],
    ['SubstituteNameOffset', '<H=0'],
    ['SubstituteNameLength', '<H=0'],
    ['PrintNameOffset', '<H=0'],
    ['PrintNameLength', '<H=0'],
    ['Flags', '<L=0'],
    ['PathBuffer', ':'],
  ];
}

export class SMB2Negotiate extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=36'],
    ['DialectCount', '<H=0'],
    ['SecurityMode', '<H=0'],
    ['Reserved', '<H=0'],
    ['Capabilities', '<L=0'],
    ['ClientGuid', '16s=""'],
    ['ClientStartTime', '8s=""'],
    ['Dialects', '*<H'],
    ['Padding', ':=""'],
    ['NegotiateContextList', ':=""'],
  ];
}

export class SMB311ContextData extends Structure {
  static structure: FieldDescriptor[] = [
    ['NegotiateContextOffset', '<L=0'],
    ['NegotiateContextCount', '<H=0'],
    ['Reserved2', '<H=0'],
  ];
}

export class SMB2Negotiate_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=65'],
    ['SecurityMode', '<H=0'],
    ['DialectRevision', '<H=0'],
    ['NegotiateContextCount', '<H=0'],
    ['ServerGuid', '16s=""'],
    ['Capabilities', '<L=0'],
    ['MaxTransactSize', '<L=0'],
    ['MaxReadSize', '<L=0'],
    ['MaxWriteSize', '<L=0'],
    ['SystemTime', '<Q=0'],
    ['ServerStartTime', '<Q=0'],
    ['SecurityBufferOffset', '<H=0'],
    ['SecurityBufferLength', '<H=0'],
    ['NegotiateContextOffset', '<L=0'],
    ['_AlignPad', '_-AlignPad', 'self["SecurityBufferOffset"] - (64 + self["StructureSize"] - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["SecurityBufferLength"]'],
    ['Buffer', ':'],
    [
      '_Padding',
      '_-Padding',
      '0 if self["NegotiateContextOffset"] == 0 else (self["NegotiateContextOffset"] - self["SecurityBufferOffset"] - self["SecurityBufferLength"])',
    ],
    ['Padding', ':=""'],
    [
      '_NegotiateContextList',
      '_-NegotiateContextList',
      '0 if self["NegotiateContextOffset"] == 0 else len(self.rawData)-self["NegotiateContextOffset"]+64',
    ],
    ['NegotiateContextList', ':=""'],
  ];
}

export class SMB2NegotiateContext extends Structure {
  static structure: FieldDescriptor[] = [
    ['ContextType', '<H=0'],
    ['DataLength', '<H=0'],
    ['Reserved', '<L=0'],
    ['_Data', '_-Data', 'self["DataLength"]'],
    ['Data', ':=""'],
  ];
}

export class SMB2PreAuthIntegrityCapabilities extends Structure {
  static structure: FieldDescriptor[] = [
    ['HashAlgorithmCount', '<H=0'],
    ['SaltLength', '<H=0'],
    ['_HashAlgorithms', '_-HashAlgorithms', 'self["HashAlgorithmCount"]*2'],
    ['HashAlgorithms', ':=""'],
    ['Salt', ':=""'],
  ];
}

export class SMB2EncryptionCapabilities extends Structure {
  static structure: FieldDescriptor[] = [
    ['CipherCount', '<H=0'],
    ['Ciphers', ':=""'],
  ];
}

export class SMB2CompressionCapabilities extends Structure {
  static structure: FieldDescriptor[] = [
    ['CompressionAlgorithmCount', '<H=0'],
    ['Padding', '<H=0'],
    ['Flags', '<L=0'],
    ['CompressionAlgorithms', ':=""'],
  ];
}

export class SMB2NetNameNegotiateContextID extends Structure {
  static structure: FieldDescriptor[] = [['NetName', ':=""']];
}

export class SMB2SessionSetup extends Structure {
  static SIZE = 24;
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=25'],
    ['Flags', '<B=0'],
    ['SecurityMode', '<B=0'],
    ['Capabilities', '<L=0'],
    ['Channel', '<L=0'],
    ['SecurityBufferOffset', '<H=(self.SIZE + 64 + len(self["AlignPad"]))'],
    ['SecurityBufferLength', '<H=0'],
    ['PreviousSessionId', '<Q=0'],
    ['_AlignPad', '_-AlignPad', 'self["SecurityBufferOffset"] - (64 + self["StructureSize"] - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["SecurityBufferLength"]'],
    ['Buffer', ':'],
  ];

  constructor(data?: Buffer) {
    super(data);
    if (data === undefined) {
      this.set('AlignPad', Buffer.alloc(0));
    }
  }
}

export class SMB2SessionSetup_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=9'],
    ['SessionFlags', '<H=0'],
    ['SecurityBufferOffset', '<H=0'],
    ['SecurityBufferLength', '<H=0'],
    ['_AlignPad', '_-AlignPad', 'self["SecurityBufferOffset"] - (64 + self["StructureSize"] - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["SecurityBufferLength"]'],
    ['Buffer', ':'],
  ];
}

export class SMB2Logoff extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=4'],
    ['Reserved', '<H=0'],
  ];
}

export class SMB2Logoff_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=4'],
    ['Reserved', '<H=0'],
  ];
}

export class SMB2TreeConnect extends Structure {
  static SIZE = 8;
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=9'],
    ['Reserved', '<H=0'],
    ['PathOffset', '<H=(self.SIZE + 64 + len(self["AlignPad"]))'],
    ['PathLength', '<H=0'],
    ['_AlignPad', '_-AlignPad', 'self["PathOffset"] - (64 + self.SIZE - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["PathLength"]'],
    ['Buffer', ':'],
  ];

  constructor(data?: Buffer) {
    super(data);
    if (data === undefined) {
      this.set('AlignPad', Buffer.alloc(0));
    }
  }
}

export class SMB2TreeConnect_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=16'],
    ['ShareType', '<B=0'],
    ['Reserved', '<B=0'],
    ['ShareFlags', '<L=0'],
    ['Capabilities', '<L=0'],
    ['MaximalAccess', '<L=0'],
  ];
}

export class SMB2TreeDisconnect extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=4'],
    ['Reserved', '<H=0'],
  ];
}

export class SMB2TreeDisconnect_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=4'],
    ['Reserved', '<H=0'],
  ];
}

export class SMB2_FILEID extends Structure {
  static structure: FieldDescriptor[] = [
    ['Persistent', '<Q=0'],
    ['Volatile', '<Q=0'],
  ];
}

export class SMB2Create extends Structure {
  static SIZE = 56;
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=57'],
    ['SecurityFlags', '<B=0'],
    ['RequestedOplockLevel', '<B=0'],
    ['ImpersonationLevel', '<L=0'],
    ['SmbCreateFlags', '<Q=0'],
    ['Reserved', '<Q=0'],
    ['DesiredAccess', '<L=0'],
    ['FileAttributes', '<L=0'],
    ['ShareAccess', '<L=0'],
    ['CreateDisposition', '<L=0'],
    ['CreateOptions', '<L=0'],
    ['NameOffset', '<H=(self.SIZE + 64 + len(self["AlignPad"]))'],
    ['NameLength', '<H=0'],
    ['CreateContextsOffset', '<L=0'],
    ['CreateContextsLength', '<L=0'],
    ['_AlignPad', '_-AlignPad', 'self["NameOffset"] - (64 + self["StructureSize"] - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["CreateContextsLength"]+self["NameLength"]'],
    ['Buffer', ':'],
  ];

  constructor(data?: Buffer) {
    super(data);
    if (data === undefined) {
      this.set('AlignPad', Buffer.alloc(0));
    }
  }
}

export class SMB2CreateContext extends Structure {
  static structure: FieldDescriptor[] = [
    ['Next', '<L=0'],
    ['NameOffset', '<H=0'],
    ['NameLength', '<H=0'],
    ['Reserved', '<H=0'],
    ['DataOffset', '<H=0'],
    ['DataLength', '<L=0'],
    ['_Buffer', '_-Buffer', 'self["DataLength"]+self["NameLength"]'],
    ['Buffer', ':'],
  ];
}

export class SMB2Create_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=89'],
    ['OplockLevel', '<B=0'],
    ['Flags', '<B=0'],
    ['CreateAction', '<L=0'],
    ['CreationTime', '<Q=0'],
    ['LastAccessTime', '<Q=0'],
    ['LastWriteTime', '<Q=0'],
    ['ChangeTime', '<Q=0'],
    ['AllocationSize', '<Q=0'],
    ['EndOfFile', '<Q=0'],
    ['FileAttributes', '<L=0'],
    ['Reserved2', '<L=0'],
    ['FileID', ':', SMB2_FILEID],
    ['CreateContextsOffset', '<L=0'],
    ['CreateContextsLength', '<L=0'],
    ['_AlignPad', '_-AlignPad', 'self["CreateContextsOffset"] - (64 + self["StructureSize"] - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["CreateContextsLength"]'],
    ['Buffer', ':'],
  ];
}

export class FILE_FULL_EA_INFORMATION extends Structure {
  static structure: FieldDescriptor[] = [
    ['NextEntryOffset', '<L=0'],
    ['Flags', '<B=0'],
    ['EaNameLength', '<B=0'],
    ['EaValueLength', '<H=0'],
    ['_EaName', '_-EaName', 'self["EaNameLength"]'],
    ['EaName', ':'],
    ['_EaValue', '_-EaValue', 'self["EaValue"]'],
    ['EaValue', ':'],
  ];
}

export class SMB2_CREATE_DURABLE_HANDLE_RECONNECT extends Structure {
  static structure: FieldDescriptor[] = [['Data', ':', SMB2_FILEID]];
}

export class SMB2_CREATE_DURABLE_HANDLE_REQUEST extends Structure {
  static structure: FieldDescriptor[] = [['DurableRequest', '16s=""']];
}

export class SMB2_CREATE_DURABLE_HANDLE_RESPONSE extends Structure {
  static structure: FieldDescriptor[] = [['Reserved', '<Q=0']];
}

export class SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST extends Structure {
  static structure: FieldDescriptor[] = [['Timestamp', '<Q=0']];
}

export class SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE extends Structure {
  static structure: FieldDescriptor[] = [
    ['QueryStatus', '<L=0'],
    ['MaximalAccess', '<L=0'],
  ];
}

export class SMB2_CREATE_ALLOCATION_SIZE extends Structure {
  static structure: FieldDescriptor[] = [['AllocationSize', '<Q=0']];
}

export class SMB2_CREATE_TIMEWARP_TOKEN extends Structure {
  static structure: FieldDescriptor[] = [['Timestamp', '<Q=0']];
}

export class SMB2_CREATE_REQUEST_LEASE extends Structure {
  static structure: FieldDescriptor[] = [
    ['LeaseKey', '16s=""'],
    ['LeaseState', '<L=0'],
    ['LeaseFlags', '<L=0'],
    ['LeaseDuration', '<Q=0'],
  ];
}

export const SMB2_CREATE_RESPONSE_LEASE = SMB2_CREATE_REQUEST_LEASE;

export class SMB2_CREATE_REQUEST_LEASE_V2 extends Structure {
  static structure: FieldDescriptor[] = [
    ['LeaseKey', '16s=""'],
    ['LeaseState', '<L=0'],
    ['Flags', '<L=0'],
    ['LeaseDuration', '<Q=0'],
    ['ParentLeaseKey', '16s=""'],
    ['Epoch', '<H=0'],
    ['Reserved', '<H=0'],
  ];
}

export const SMB2_CREATE_RESPONSE_LEASE_V2 = SMB2_CREATE_REQUEST_LEASE_V2;

export class SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 extends Structure {
  static structure: FieldDescriptor[] = [
    ['Timeout', '<L=0'],
    ['Flags', '<L=0'],
    ['Reserved', '8s=""'],
    ['CreateGuid', '16s=""'],
  ];
}

export class SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2 extends Structure {
  static structure: FieldDescriptor[] = [
    ['Timeout', '<L=0'],
    ['Flags', '<L=0'],
  ];
}

export class SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 extends Structure {
  static structure: FieldDescriptor[] = [
    ['FileID', ':', SMB2_FILEID],
    ['CreateGuid', '16s=""'],
    ['Flags', '<L=0'],
  ];
}

export class SMB2_CREATE_APP_INSTANCE_ID extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=0'],
    ['Reserved', '<H=0'],
    ['AppInstanceId', '16s=""'],
  ];
}

export class SMB2_CREATE_QUERY_ON_DISK_ID extends Structure {
  static structure: FieldDescriptor[] = [['DiskIDBuffer', '32s=""']];
}

export class SMB2Close extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=24'],
    ['Flags', '<H=0'],
    ['Reserved', '<L=0'],
    ['FileID', ':', SMB2_FILEID],
  ];
}

export class SMB2Close_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=60'],
    ['Flags', '<H=0'],
    ['Reserved', '<L=0'],
    ['CreationTime', '<Q=0'],
    ['LastAccessTime', '<Q=0'],
    ['LastWriteTime', '<Q=0'],
    ['ChangeTime', '<Q=0'],
    ['AllocationSize', '<Q=0'],
    ['EndofFile', '<Q=0'],
    ['FileAttributes', '<L=0'],
  ];
}

export class SMB2Flush extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=24'],
    ['Reserved1', '<H=0'],
    ['Reserved2', '<L=0'],
    ['FileID', ':', SMB2_FILEID],
  ];
}

export class SMB2Flush_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=4'],
    ['Reserved', '<H=0'],
  ];
}

export class SMB2Read extends Structure {
  static SIZE = 48;
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=49'],
    ['Padding', '<B=0'],
    ['Reserved', '<B=0'],
    ['Length', '<L=0'],
    ['Offset', '<Q=0'],
    ['FileID', ':', SMB2_FILEID],
    ['MinimumCount', '<L=0'],
    ['Channel', '<L=0'],
    ['RemainingBytes', '<L=0'],
    ['ReadChannelInfoOffset', '<H=0'],
    ['ReadChannelInfoLength', '<H=0'],
    ['_AlignPad', '_-AlignPad', 'self["ReadChannelInfoOffset"] - (64 + self["StructureSize"] - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["ReadChannelInfoLength"]'],
    ['Buffer', ':="0"'],
  ];

  constructor(data?: Buffer) {
    super(data);
    if (data === undefined) {
      this.set('AlignPad', Buffer.alloc(0));
    }
  }
}

export class SMB2Read_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=17'],
    ['DataOffset', '<B=0'],
    ['Reserved', '<B=0'],
    ['DataLength', '<L=0'],
    ['DataRemaining', '<L=0'],
    ['Reserved2', '<L=0'],
    ['_AlignPad', '_-AlignPad', 'self["DataOffset"] - (64 + self["StructureSize"] - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["DataLength"]'],
    ['Buffer', ':'],
  ];
}

export class SMB2Write extends Structure {
  static SIZE = 48;
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=49'],
    ['DataOffset', '<H=(self.SIZE + 64 + len(self["AlignPad"]))'],
    ['Length', '<L=0'],
    ['Offset', '<Q=0'],
    ['FileID', ':', SMB2_FILEID],
    ['Channel', '<L=0'],
    ['RemainingBytes', '<L=0'],
    ['WriteChannelInfoOffset', '<H=0'],
    ['WriteChannelInfoLength', '<H=0'],
    [
      '_AlignPad',
      '_-AlignPad',
      'self["DataOffset"] + self["WriteChannelInfoOffset"] - (64 + self["StructureSize"] - 1)',
    ],
    ['AlignPad', ':=""'],
    ['Flags', '<L=0'],
    ['_Buffer', '_-Buffer', 'self["Length"]+self["WriteChannelInfoLength"]'],
    ['Buffer', ':'],
  ];

  constructor(data?: Buffer) {
    super(data);
    if (data === undefined) {
      this.set('AlignPad', Buffer.alloc(0));
    }
  }
}

export class SMB2Write_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=17'],
    ['Reserved', '<H=0'],
    ['Count', '<L=0'],
    ['Remaining', '<L=0'],
    ['WriteChannelInfoOffset', '<H=0'],
    ['WriteChannelInfoLength', '<H=0'],
  ];
}

export class SMB2OplockBreakNotification extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=24'],
    ['OplockLevel', '<B=0'],
    ['Reserved', '<B=0'],
    ['Reserved2', '<L=0'],
    ['FileID', ':', SMB2_FILEID],
  ];
}

export const SMB2OplockBreakAcknowledgment = SMB2OplockBreakNotification;
export const SMB2OplockBreakResponse = SMB2OplockBreakNotification;

export class SMB2LeaseBreakNotification extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=44'],
    ['NewEpoch', '<H=0'],
    ['Flags', '<L=0'],
    ['LeaseKey', '16s=""'],
    ['CurrentLeaseState', '<L=0'],
    ['NewLeaseState', '<L=0'],
    ['BreakReason', '<L=0'],
    ['AccessMaskHint', '<L=0'],
    ['ShareMaskHint', '<L=0'],
  ];
}

export class SMB2LeaseBreakAcknowledgement extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=36'],
    ['Reserved', '<H=0'],
    ['Flags', '<L=0'],
    ['LeaseKey', '16s=""'],
    ['LeaseState', '<L=0'],
    ['LeaseDuration', '<Q=0'],
  ];
}

export const SMB2LeaseBreakResponse = SMB2LeaseBreakAcknowledgement;

export class SMB2_LOCK_ELEMENT extends Structure {
  static structure: FieldDescriptor[] = [
    ['Offset', '<Q=0'],
    ['Length', '<Q=0'],
    ['Flags', '<L=0'],
    ['Reserved', '<L=0'],
  ];
}

export class SMB2Lock extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=48'],
    ['LockCount', '<H=0'],
    ['LockSequence', '<L=0'],
    ['FileID', ':', SMB2_FILEID],
    ['_Locks', '_-Locks', 'self["LockCount"]*24'],
    ['Locks', ':'],
  ];
}

export class SMB2Lock_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=4'],
    ['Reserved', '<H=0'],
  ];
}

export class SMB2Echo extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=4'],
    ['Reserved', '<H=0'],
  ];
}

export const SMB2Echo_Response = SMB2Echo;

export class SMB2Cancel extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=4'],
    ['Reserved', '<H=0'],
  ];
}

export class SMB2Ioctl extends Structure {
  static SIZE = 56;
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=57'],
    ['Reserved', '<H=0'],
    ['CtlCode', '<L=0'],
    ['FileID', ':', SMB2_FILEID],
    ['InputOffset', '<L=(self.SIZE + 64 + len(self["AlignPad"]))'],
    ['InputCount', '<L=0'],
    ['MaxInputResponse', '<L=0'],
    ['OutputOffset', '<L=(self.SIZE + 64 + len(self["AlignPad"]) + self["InputCount"])'],
    ['OutputCount', '<L=0'],
    ['MaxOutputResponse', '<L=0'],
    ['Flags', '<L=0'],
    ['Reserved2', '<L=0'],
    ['_Buffer', '_-Buffer', 'self["InputCount"]+self["OutputCount"]'],
    ['Buffer', ':'],
  ];

  constructor(data?: Buffer) {
    super(data);
    if (data === undefined) {
      this.set('AlignPad', Buffer.alloc(0));
    }
  }
}

export class FSCTL_PIPE_WAIT_STRUCTURE extends Structure {
  static structure: FieldDescriptor[] = [
    ['Timeout', '<q=0'],
    ['NameLength', '<L=0'],
    ['TimeoutSpecified', '<B=0'],
    ['Padding', '<B=0'],
    ['_Name', '_-Name', 'self["NameLength"]'],
    ['Name', ':'],
  ];
}

export class SRV_COPYCHUNK extends Structure {
  static structure: FieldDescriptor[] = [
    ['SourceOffset', '<Q=0'],
    ['TargetOffset', '<Q=0'],
    ['Length', '<L=0'],
    ['Reserved', '<L=0'],
  ];
}

export class SRV_COPYCHUNK_COPY extends Structure {
  static structure: FieldDescriptor[] = [
    ['SourceKey', '24s=""'],
    ['ChunkCount', '<L=0'],
    ['Reserved', '<L=0'],
    ['_Chunks', '_-Chunks', 'self["ChunkCount"]*len(SRV_COPYCHUNK)'],
    ['Chunks', ':'],
  ];
}

export class SRV_COPYCHUNK_RESPONSE extends Structure {
  static structure: FieldDescriptor[] = [
    ['ChunksWritten', '<L=0'],
    ['ChunkBytesWritten', '<L=0'],
    ['TotalBytesWritten', '<L=0'],
  ];
}

export class SRV_READ_HASH extends Structure {
  static structure: FieldDescriptor[] = [
    ['HashType', '<L=0'],
    ['HashVersion', '<L=0'],
    ['HashRetrievalType', '<L=0'],
    ['Length', '<L=0'],
    ['Offset', '<Q=0'],
  ];
}

export class NETWORK_RESILIENCY_REQUEST extends Structure {
  static structure: FieldDescriptor[] = [
    ['Timeout', '<L=0'],
    ['Reserved', '<L=0'],
  ];
}

export class VALIDATE_NEGOTIATE_INFO extends Structure {
  static structure: FieldDescriptor[] = [
    ['Capabilities', '<L=0'],
    ['Guid', '16s=""'],
    ['SecurityMode', '<H=0'],
    ['Dialects', '<H*<H'],
  ];
}

export class VALIDATE_NEGOTIATE_INFO_RESPONSE extends Structure {
  static structure: FieldDescriptor[] = [
    ['Capabilities', '<L=0'],
    ['Guid', '16s=""'],
    ['SecurityMode', '<H=0'],
    ['Dialect', '<H=0'],
  ];
}

export class SRV_SNAPSHOT_ARRAY extends Structure {
  static structure: FieldDescriptor[] = [
    ['NumberOfSnapShots', '<L=0'],
    ['NumberOfSnapShotsReturned', '<L=0'],
    ['SnapShotArraySize', '<L=0'],
    ['_SnapShots', '_-SnapShots', 'self["SnapShotArraySize"]'],
    ['SnapShots', ':'],
  ];
}

export class SRV_REQUEST_RESUME_KEY extends Structure {
  static structure: FieldDescriptor[] = [
    ['ResumeKey', '24s=""'],
    ['ContextLength', '<L=0'],
    ['_Context', '_-Context', 'self["ContextLength"]'],
    ['Context', ':'],
  ];
}

export class HASH_HEADER extends Structure {
  static structure: FieldDescriptor[] = [
    ['HashType', '<L=0'],
    ['HashVersion', '<L=0'],
    ['SourceFileChangeTime', '<Q=0'],
    ['SourceFileSize', '<Q=0'],
    ['HashBlobLength', '<L=0'],
    ['HashBlobOffset', '<L=0'],
    ['Dirty', '<H=0'],
    ['SourceFileNameLength', '<L=0'],
    ['_SourceFileName', '_-SourceFileName', 'self["SourceFileNameLength"]'],
    ['SourceFileName', ':'],
  ];
}

export class SRV_HASH_RETRIEVE_HASH_BASED extends Structure {
  static structure: FieldDescriptor[] = [
    ['Offset', '<Q=0'],
    ['BufferLength', '<L=0'],
    ['Reserved', '<L=0'],
    ['_Buffer', '_-Buffer', 'self["BufferLength"]'],
    ['Buffer', ':'],
  ];
}

export class SRV_HASH_RETRIEVE_FILE_BASED extends Structure {
  static structure: FieldDescriptor[] = [
    ['FileDataOffset', '<Q=0'],
    ['FileDataLength', '<Q=0'],
    ['BufferLength', '<L=0'],
    ['Reserved', '<L=0'],
    ['_Buffer', '_-Buffer', 'self["BufferLength"]'],
    ['Buffer', ':'],
  ];
}

export class NETWORK_INTERFACE_INFO extends Structure {
  static structure: FieldDescriptor[] = [
    ['Next', '<L=0'],
    ['IfIndex', '<L=0'],
    ['Capability', '<L=0'],
    ['Reserved', '<L=0'],
    ['LinkSpeed', '<Q=0'],
    ['SockAddr_Storage', '128s=""'],
  ];
}

export class MOUNT_POINT_REPARSE_DATA_STRUCTURE extends Structure {
  static structure: FieldDescriptor[] = [
    ['ReparseTag', '<L=0xA0000003'],
    ['ReparseDataLen', '<H=len(self["PathBuffer"]) + 8'],
    ['Reserved', '<H=0'],
    ['SubstituteNameOffset', '<H=0'],
    ['SubstituteNameLength', '<H=0'],
    ['PrintNameOffset', '<H=0'],
    ['PrintNameLength', '<H=0'],
    ['PathBuffer', ':'],
  ];
}

export class MOUNT_POINT_REPARSE_GUID_DATA_STRUCTURE extends Structure {
  static structure: FieldDescriptor[] = [
    ['ReparseTag', '<L=0xA0000003'],
    ['ReparseDataLen', '<H=len(self["DataBuffer"])'],
    ['Reserved', '<H=0'],
    ['ReparseGuid', "16s=''"],
    ['DataBuffer', ':'],
  ];
}

export class SMB2Ioctl_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=49'],
    ['Reserved', '<H=0'],
    ['CtlCode', '<L=0'],
    ['FileID', ':', SMB2_FILEID],
    ['InputOffset', '<L=0'],
    ['InputCount', '<L=0'],
    ['OutputOffset', '<L=0'],
    ['OutputCount', '<L=0'],
    ['Flags', '<L=0'],
    ['Reserved2', '<L=0'],
    ['_AlignPad', '_-AlignPad', 'self["OutputOffset"] - (64 + self["StructureSize"] - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["InputCount"]+self["OutputCount"]'],
    ['Buffer', ':'],
  ];
}

export class SMB2QueryDirectory extends Structure {
  static SIZE = 32;
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=33'],
    ['FileInformationClass', '<B=0'],
    ['Flags', '<B=0'],
    ['FileIndex', '<L=0'],
    ['FileID', ':', SMB2_FILEID],
    ['FileNameOffset', '<H=(self.SIZE + 64 + len(self["AlignPad"]))'],
    ['FileNameLength', '<H=0'],
    ['OutputBufferLength', '<L=0'],
    ['_AlignPad', '_-AlignPad', 'self["FileNameOffset"] - (64 + self["StructureSize"] - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["FileNameLength"]'],
    ['Buffer', ':'],
  ];

  constructor(data?: Buffer) {
    super(data);
    if (data === undefined) {
      this.set('AlignPad', Buffer.alloc(0));
    }
  }
}

export class SMB2QueryDirectory_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=9'],
    ['OutputBufferOffset', '<H=0'],
    ['OutputBufferLength', '<L=0'],
    ['_AlignPad', '_-AlignPad', 'self["OutputBufferOffset"] - (64 + self["StructureSize"] - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["OutputBufferLength"]'],
    ['Buffer', ':'],
  ];
}

export class SMB2ChangeNotify extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=32'],
    ['Flags', '<H=0'],
    ['OutputBufferLength', '<L=0'],
    ['FileID', ':', SMB2_FILEID],
    ['CompletionFilter', '<L=0'],
    ['Reserved', '<L=0'],
  ];
}

export class SMB2ChangeNotify_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=9'],
    ['OutputBufferOffset', '<H=0'],
    ['OutputBufferLength', '<L=0'],
    ['_AlignPad', '_-AlignPad', 'self["OutputBufferOffset"] - (64 + self["StructureSize"] - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["OutputBufferLength"]'],
    ['Buffer', ':'],
  ];
}

export class FILE_NOTIFY_INFORMATION extends Structure {
  static structure: FieldDescriptor[] = [
    ['NextEntryOffset', '<L=0'],
    ['Action', '<L=0'],
    ['FileNameLength', '<L=0'],
    ['_FileName', '_-FileName', 'self["FileNameLength"]'],
    ['FileName', ':'],
  ];
}

export class SMB2QueryInfo extends Structure {
  static SIZE = 40;
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=41'],
    ['InfoType', '<B=0'],
    ['FileInfoClass', '<B=0'],
    ['OutputBufferLength', '<L=0'],
    ['InputBufferOffset', '<H=(self.SIZE + 64 + len(self["AlignPad"]))'],
    ['Reserved', '<H=0'],
    ['InputBufferLength', '<L=0'],
    ['AdditionalInformation', '<L=0'],
    ['Flags', '<L=0'],
    ['FileID', ':', SMB2_FILEID],
    ['_AlignPad', '_-AlignPad', 'self["InputBufferOffset"] - (64 + self["StructureSize"] - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["InputBufferLength"]'],
    ['Buffer', ':'],
  ];

  constructor(data?: Buffer) {
    super(data);
    if (data === undefined) {
      this.set('AlignPad', Buffer.alloc(0));
    }
  }
}

export class SMB2_QUERY_QUOTA_INFO extends Structure {
  static structure: FieldDescriptor[] = [
    ['ReturnSingle', '<B=0'],
    ['RestartScan', '<B=0'],
    ['Reserved', '<H=0'],
    ['SidListLength', '<L=0'],
    ['StartSidLength', '<L=0'],
    ['StartSidOffset', '<L=0'],
    ['SidBuffer', ':'],
  ];
}

export class SMB2QueryInfo_Response extends Structure {
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=9'],
    ['OutputBufferOffset', '<H=0'],
    ['OutputBufferLength', '<L=0'],
    ['_AlignPad', '_-AlignPad', 'self["OutputBufferOffset"] - (64 + self["StructureSize"] - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["OutputBufferLength"]'],
    ['Buffer', ':'],
  ];
}

export class FILE_BASIC_INFORMATION extends Structure {
  static structure: FieldDescriptor[] = [
    ['CreationTime', '<q=0'],
    ['LastAccessTime', '<q=0'],
    ['LastWriteTime', '<q=0'],
    ['ChangeTime', '<q=0'],
    ['FileAttributes', '<L=0'],
    ['Reserved', '<L=0'],
  ];
}

export class FILE_STANDARD_INFORMATION extends Structure {
  static structure: FieldDescriptor[] = [
    ['AllocationSize', '<q=0'],
    ['EndOfFile', '<q=0'],
    ['NumberOfLinks', '<L=0'],
    ['DeletePending', '<B=0'],
    ['Directory', '<B=0'],
    ['Reserved', '<H=0'],
  ];
}

export class FILE_INTERNAL_INFORMATION extends Structure {
  static structure: FieldDescriptor[] = [['IndexNumber', '<q=0']];
}

export class FILE_EA_INFORMATION extends Structure {
  static structure: FieldDescriptor[] = [['EaSize', '<L=0']];
}

export class FILE_ACCESS_INFORMATION extends Structure {
  static structure: FieldDescriptor[] = [['AccessFlags', '<L=0']];
}

export class FILE_POSITION_INFORMATION extends Structure {
  static structure: FieldDescriptor[] = [['CurrentByteOffset', '<Q=0']];
}

export class FILE_MODE_INFORMATION extends Structure {
  static structure: FieldDescriptor[] = [['Mode', '<L=0']];
}

export class FILE_ALIGNMENT_INFORMATION extends Structure {
  static structure: FieldDescriptor[] = [['AlignmentRequirement', '<L=0']];
}

export class FILE_NAME_INFORMATION extends Structure {
  static structure: FieldDescriptor[] = [
    ['FileNameLength', '<L=0'],
    ['_FileName', '_-FileName', 'self["FileNameLength"]'],
    ['FileName', ':'],
  ];
}

export class FILE_ALL_INFORMATION extends Structure {
  static structure: FieldDescriptor[] = [
    ['BasicInformation', ':', FILE_BASIC_INFORMATION],
    ['StandardInformation', ':', FILE_STANDARD_INFORMATION],
    ['InternalInformation', ':', FILE_INTERNAL_INFORMATION],
    ['EaInformation', ':', FILE_EA_INFORMATION],
    ['AccessInformation', ':', FILE_ACCESS_INFORMATION],
    ['PositionInformation', ':', FILE_POSITION_INFORMATION],
    ['ModeInformation', ':', FILE_MODE_INFORMATION],
    ['AlignmentInformation', ':', FILE_ALIGNMENT_INFORMATION],
    ['NameInformation', ':', FILE_NAME_INFORMATION],
  ];
}

export class FILE_ATTRIBUTE_TAG_INFORMATION extends Structure {
  static structure: FieldDescriptor[] = [
    ['FileAttributes', '<L=0'],
    ['ReparseTag', '<L=0'],
  ];
}

export class SMB2SetInfo extends Structure {
  static SIZE = 32;
  static structure: FieldDescriptor[] = [
    ['StructureSize', '<H=33'],
    ['InfoType', '<B=0'],
    ['FileInfoClass', '<B=0'],
    ['BufferLength', '<L=0'],
    ['BufferOffset', '<H=(self.SIZE + 64 + len(self["AlignPad"]))'],
    ['Reserved', '<H=0'],
    ['AdditionalInformation', '<L=0'],
    ['FileID', ':', SMB2_FILEID],
    ['_AlignPad', '_-AlignPad', 'self["BufferOffset"] - (64 + self["StructureSize"] - 1)'],
    ['AlignPad', ':=""'],
    ['_Buffer', '_-Buffer', 'self["BufferLength"]'],
    ['Buffer', ':'],
  ];

  constructor(data?: Buffer) {
    super(data);
    if (data === undefined) {
      this.set('AlignPad', Buffer.alloc(0));
    }
  }
}

export class SMB2SetInfo_Response extends Structure {
  static structure: FieldDescriptor[] = [['StructureSize', '<H=2']];
}

export class FILE_RENAME_INFORMATION_TYPE_2 extends Structure {
  static structure: FieldDescriptor[] = [
    ['ReplaceIfExists', '<B=0'],
    ['Reserved', '7s=""'],
    ['RootDirectory', '<Q=0'],
    ['FileNameLength', '<L=0'],
    ['_FileName', '_-FileName', 'self["FileNameLength"]'],
    ['FileName', ':'],
  ];
}

export class SMB2_TRANSFORM_HEADER extends Structure {
  static structure: FieldDescriptor[] = [
    ['ProtocolID', '"\xfdSMB'],
    ['Signature', '16s=""'],
    ['Nonce', '16s=""'],
    ['OriginalMessageSize', '<L=0'],
    ['Reserved', '<H=0'],
    ['EncryptionAlgorithm', '<H=0'],
    ['SessionID', '<Q=0'],
  ];
}

export class SMB2_COMPRESSION_TRANSFORM_HEADER extends Structure {
  static structure: FieldDescriptor[] = [
    ['ProtocolID', '<L=0'],
    ['OriginalCompressedSegmentSize', '<L=0'],
    ['CompressionAlgorithm', '<H=0'],
    ['Flags', '<H=0'],
    ['Offset_Length', '<L=0'],
  ];
}

export class SMB2_COMPRESSION_PAYLOAD_HEADER extends Structure {
  static structure: FieldDescriptor[] = [
    ['AlgorithmId', '<H=0'],
    ['Reserved', '<H=0'],
    ['Length', '<L=0'],
  ];
}

export class SMB2_COMPRESSION_PATTERN_PAYLOAD_V1 extends Structure {
  static structure: FieldDescriptor[] = [
    ['Pattern', 'B=0'],
    ['Reserved1', 'B=0'],
    ['Reserved2', 'B=0'],
    ['Repetitions', '<L=0'],
  ];
}

export class FileSecInformation extends Structure {
  static structure: FieldDescriptor[] = [
    ['Revision', '<h=1'],
    ['Type', '<h=0'],
    ['OffsetToOwner', '<I=0'],
    ['OffsetToGroup', '<I=0'],
    ['OffsetToSACL', '<I=0'],
    ['OffsetToDACL', '<I=0'],
  ];
}
