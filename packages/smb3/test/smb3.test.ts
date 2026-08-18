import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  FILE_ATTRIBUTE_NORMAL,
  FILE_OPEN,
  FILE_READ_DATA,
  FILE_SHARE_READ,
  FILE_WRITE_DATA,
  RESP_GET_DFS_REFERRAL,
  SMB2Close,
  SMB2Create,
  SMB2Create_Response,
  SMB2Echo,
  SMB2Ioctl,
  SMB2Negotiate,
  SMB2Negotiate_Response,
  SMB2Packet,
  SMB2QueryDirectory,
  SMB2QueryInfo,
  SMB2Read,
  SMB2Read_Response,
  SMB2SessionSetup,
  SMB2SessionSetup_Response,
  SMB2SetInfo,
  SMB2TreeConnect,
  SMB2TreeConnect_Response,
  SMB2Write,
  SMB2Write_Response,
  SMB2_CLOSE,
  SMB2_CREATE,
  SMB2_DIALECT_21,
  SMB2_DIALECT_30,
  SMB2_DIALECT_311,
  SMB2_DIALECT_WILDCARD,
  SMB2_ECHO,
  SMB2_FILEID,
  SMB2_GLOBAL_CAP_ENCRYPTION,
  SMB2_GLOBAL_CAP_LARGE_MTU,
  SMB2_IL_IMPERSONATION,
  SMB2_NEGOTIATE,
  SMB2_NEGOTIATE_SIGNING_REQUIRED,
  SMB2_OPLOCK_LEVEL_NONE,
  SMB2_QUERY_QUOTA_INFO,
  SMB2_READ,
  SMB2_SESSION_SETUP,
  SMB2_TRANSFORM_HEADER,
  SMB2_TREE_CONNECT,
  SMB2_WRITE,
  SMB3,
  STATUS_SUCCESS,
  SessionError,
  parseDfsReferral,
} from '../src/index.js';

describe('SMB2Packet', () => {
  it('builds a negotiate request packet', () => {
    const pkt = new SMB2Packet();
    pkt.set('Command', SMB2_NEGOTIATE);
    pkt.set('CreditCharge', 1);
    pkt.set('MessageID', 0n);

    const data = pkt.getData();
    expect(data.toString('latin1', 0, 4)).toBe('\xfeSMB');
    expect(data.readUInt16LE(4)).toBe(64);
    expect(data.readUInt16LE(10)).toBe(SMB2_NEGOTIATE);
  });

  it('round-trips a negotiate packet', () => {
    const pkt = new SMB2Packet();
    pkt.set('Command', SMB2_NEGOTIATE);
    pkt.set('CreditCharge', 1);
    pkt.set('MessageID', 1n);
    pkt.set('TreeID', 0x1234);
    pkt.set('SessionID', 0x5678n);
    pkt.set('Flags', 0x08);

    const data = pkt.getData();
    const parsed = new SMB2Packet(data);
    expect(parsed.get('Command')).toBe(SMB2_NEGOTIATE);
    expect(parsed.get('MessageID')).toBe(1n);
    expect(parsed.get('TreeID')).toBe(0x1234);
    expect(parsed.get('SessionID')).toBe(0x5678n);
    expect(parsed.get('Flags')).toBe(0x08);
  });
});

describe('SMB2Negotiate', () => {
  it('builds a negotiate request with dialects', () => {
    const neg = new SMB2Negotiate();
    neg.set('DialectCount', 3);
    neg.set('SecurityMode', SMB2_NEGOTIATE_SIGNING_REQUIRED);
    neg.set('Capabilities', SMB2_GLOBAL_CAP_ENCRYPTION | SMB2_GLOBAL_CAP_LARGE_MTU);
    neg.set('Dialects', [SMB2_DIALECT_311, SMB2_DIALECT_30, SMB2_DIALECT_21]);

    const data = neg.getData();
    const parsed = new SMB2Negotiate(data);
    expect(parsed.get('DialectCount')).toBe(3);
    expect(parsed.get('SecurityMode')).toBe(SMB2_NEGOTIATE_SIGNING_REQUIRED);
    expect(parsed.get('Capabilities')).toBe(SMB2_GLOBAL_CAP_ENCRYPTION | SMB2_GLOBAL_CAP_LARGE_MTU);
  });
});

describe('SMB2Negotiate_Response', () => {
  it('round-trips a negotiate response', () => {
    const resp = new SMB2Negotiate_Response();
    resp.set('StructureSize', 65);
    resp.set('DialectRevision', SMB2_DIALECT_30);
    resp.set('MaxTransactSize', 0x100000);
    resp.set('MaxReadSize', 0x100000);
    resp.set('MaxWriteSize', 0x100000);
    resp.set('SecurityBufferOffset', 0x44);
    resp.set('SecurityBufferLength', 0x40);
    resp.set('Buffer', Buffer.alloc(0x40, 0xaa));

    const data = resp.getData();
    const parsed = new SMB2Negotiate_Response(data);
    expect(parsed.get('DialectRevision')).toBe(SMB2_DIALECT_30);
    expect(parsed.get('MaxReadSize')).toBe(0x100000);
    expect(parsed.get('MaxWriteSize')).toBe(0x100000);
    expect(parsed.get('SecurityBufferLength')).toBe(0x40);
  });
});

describe('SMB2SessionSetup', () => {
  it('round-trips a session setup request', () => {
    const ss = new SMB2SessionSetup();
    ss.set('SecurityMode', SMB2_NEGOTIATE_SIGNING_REQUIRED);
    ss.set('SecurityBufferLength', 0x20);
    ss.set('Buffer', Buffer.alloc(0x20, 0xbb));

    const data = ss.getData();
    const parsed = new SMB2SessionSetup(data);
    expect(parsed.get('SecurityMode')).toBe(SMB2_NEGOTIATE_SIGNING_REQUIRED);
    expect(parsed.get('SecurityBufferLength')).toBe(0x20);
  });
});

describe('SMB2TreeConnect', () => {
  it('builds a tree connect request', () => {
    const tc = new SMB2TreeConnect();
    const path = Buffer.from('\\\\server\\share', 'utf-16le');
    tc.set('PathLength', path.length);
    tc.set('Buffer', path);

    const data = tc.getData();
    expect(data.readUInt16LE(0)).toBe(9); // StructureSize
    expect(data.readUInt16LE(4)).toBe(72); // PathOffset = SIZE + 64 = 72
    expect(data.readUInt16LE(6)).toBe(path.length); // PathLength
    // Buffer data follows immediately after the 8-byte fixed header
    expect(data.subarray(8, 8 + path.length).toString('utf-16le')).toBe('\\\\server\\share');
  });
});

describe('SMB2Create', () => {
  it('round-trips a create request', () => {
    const create = new SMB2Create();
    create.set('RequestedOplockLevel', SMB2_OPLOCK_LEVEL_NONE);
    create.set('ImpersonationLevel', SMB2_IL_IMPERSONATION);
    create.set('DesiredAccess', FILE_READ_DATA | FILE_WRITE_DATA);
    create.set('FileAttributes', FILE_ATTRIBUTE_NORMAL);
    create.set('ShareAccess', FILE_SHARE_READ);
    create.set('CreateDisposition', FILE_OPEN);
    create.set('NameLength', 0x10);
    create.set('Buffer', Buffer.alloc(0x10, 0x00));

    const data = create.getData();
    const parsed = new SMB2Create(data);
    expect(parsed.get('ImpersonationLevel')).toBe(SMB2_IL_IMPERSONATION);
    expect(parsed.get('DesiredAccess')).toBe(FILE_READ_DATA | FILE_WRITE_DATA);
    expect(parsed.get('CreateDisposition')).toBe(FILE_OPEN);
  });
});

describe('SMB2_FILEID', () => {
  it('round-trips a file ID', () => {
    const fid = new SMB2_FILEID();
    fid.set('Persistent', 0x1234567890abcdefn);
    fid.set('Volatile', 0xfedcba0987654321n);

    const data = fid.getData();
    const parsed = new SMB2_FILEID(data);
    expect(parsed.get('Persistent')).toBe(0x1234567890abcdefn);
    expect(parsed.get('Volatile')).toBe(0xfedcba0987654321n);
  });
});

describe('SMB2Create_Response', () => {
  it('round-trips a create response', () => {
    const resp = new SMB2Create_Response();
    const fid = new SMB2_FILEID();
    fid.set('Persistent', 1n);
    fid.set('Volatile', 2n);
    resp.set('FileID', fid.getData());
    resp.set('EndOfFile', 0x1000n);
    resp.set('FileAttributes', FILE_ATTRIBUTE_NORMAL);
    resp.set('Buffer', Buffer.alloc(0));

    const data = resp.getData();
    const parsed = new SMB2Create_Response(data);
    expect(parsed.get('EndOfFile')).toBe(0x1000n);
  });
});

describe('SMB2Close', () => {
  it('round-trips a close request', () => {
    const close = new SMB2Close();
    const fid = new SMB2_FILEID();
    fid.set('Persistent', 0x1122334455667788n);
    fid.set('Volatile', 0x99aabbccddeeff00n);
    close.set('FileID', fid.getData());

    const data = close.getData();
    const parsed = new SMB2Close(data);
    expect(parsed.get('StructureSize')).toBe(24);
  });
});

describe('SMB2Read', () => {
  it('round-trips a read request', () => {
    const read = new SMB2Read();
    read.set('Length', 0x10000);
    read.set('Offset', 0x200n);
    read.set('FileID', new SMB2_FILEID().getData());

    const data = read.getData();
    const parsed = new SMB2Read(data);
    expect(parsed.get('Length')).toBe(0x10000);
    expect(parsed.get('Offset')).toBe(0x200n);
  });
});

describe('SMB2Write', () => {
  it('round-trips a write request', () => {
    const write = new SMB2Write();
    write.set('Length', 0x1000);
    write.set('Offset', 0x0n);
    write.set('FileID', new SMB2_FILEID().getData());
    write.set('Buffer', Buffer.alloc(0x1000, 0xcc));

    const data = write.getData();
    const parsed = new SMB2Write(data);
    expect(parsed.get('Length')).toBe(0x1000);
  });
});

describe('SMB2Echo', () => {
  it('round-trips an echo request', () => {
    const echo = new SMB2Echo();
    const data = echo.getData();
    const parsed = new SMB2Echo(data);
    expect(parsed.get('StructureSize')).toBe(4);
  });
});

describe('SMB2QueryInfo', () => {
  it('round-trips a query info request', () => {
    const qi = new SMB2QueryInfo();
    qi.set('FileID', new SMB2_FILEID().getData());
    qi.set('InfoType', 0x01);
    qi.set('Buffer', Buffer.alloc(0));

    const data = qi.getData();
    const parsed = new SMB2QueryInfo(data);
    expect(parsed.get('InfoType')).toBe(0x01);
  });
});

describe('SMB2_TRANSFORM_HEADER', () => {
  it('round-trips a transform header', () => {
    const th = new SMB2_TRANSFORM_HEADER();
    th.set('OriginalMessageSize', 0x1000);
    th.set('EncryptionAlgorithm', 0x0001);
    th.set('SessionID', 0x1234n);

    const data = th.getData();
    const parsed = new SMB2_TRANSFORM_HEADER(data);
    expect(data.toString('latin1', 0, 4)).toBe('\xfdSMB');
    expect(parsed.get('OriginalMessageSize')).toBe(0x1000);
    expect(parsed.get('EncryptionAlgorithm')).toBe(0x0001);
  });
});

describe('DFS Referral parsing', () => {
  it('parses a simple DFS referral response', () => {
    const resp = new RESP_GET_DFS_REFERRAL();
    resp.set('PathConsumed', 10);
    resp.set('NumberOfReferrals', 0);
    resp.set('ReferralHeaderFlags', 0);
    resp.set('ReferralEntries', Buffer.alloc(0));

    const data = resp.getData();
    const [referrals, pathConsumed] = parseDfsReferral(data);
    expect(referrals.length).toBe(0);
    expect(pathConsumed).toBe(10);
  });
});

describe('SMB3 class', () => {
  it('SessionError can be constructed', () => {
    const err = new SessionError(0xc000006d);
    expect(err.getErrorCode()).toBe(0xc000006d);
    expect(err.message).toContain('c000006d');
  });

  it('HostnameValidationException exists', () => {
    expect(SMB3.HostnameValidationException).toBeDefined();
  });

  // Build a parseable SMB2 response packet for a given MessageID.
  const makeResp = (messageId: bigint, status = STATUS_SUCCESS): Buffer => {
    const pkt = new SMB2Packet();
    pkt.set('Command', SMB2_ECHO);
    pkt.set('CreditCharge', 1);
    pkt.set('MessageID', messageId);
    pkt.set('Status', status);
    pkt.set('Flags', 0x01); // SMB2_FLAGS_SERVER_TO_REDIR
    return pkt.getData();
  };

  // Minimal SMB3 instance with a scripted NetBIOS session (no network).
  const makeScriptedSMB3 = (frames: Buffer[]): SMB3 => {
    const queue = [...frames];
    const smb = Object.create(SMB3.prototype) as SMB3;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const anySmb = smb as any;
    anySmb._timeout = 5;
    anySmb._Connection = { SequenceWindow: 0, OutstandingResponses: new Map(), Dialect: SMB2_DIALECT_21 };
    anySmb._NetBIOSSession = {
      recvPacket: async () => {
        const next = queue.shift();
        if (!next) throw new Error('no more scripted packets');
        return { get_trailer: () => next };
      },
    };
    return smb;
  };

  it('recvSMB returns the packet whose MessageID matches, stashing others', async () => {
    // Server answers message 5 before message 4.
    const smb = makeScriptedSMB3([makeResp(5n), makeResp(4n)]);

    const first = await smb.recvSMB(4n);
    expect(first.get('MessageID')).toBe(4n); // got ours, not the 5 that arrived first

    // The out-of-order 5 was stashed and is delivered without another read.
    const second = await smb.recvSMB(5n);
    expect(second.get('MessageID')).toBe(5n);
  });

  it('recvSMB(null) returns the next packet regardless of MessageID', async () => {
    const smb = makeScriptedSMB3([makeResp(9n)]);
    const pkt = await smb.recvSMB(null);
    expect(pkt.get('MessageID')).toBe(9n);
  });

  it('recvSMB skips interim STATUS_PENDING frames', async () => {
    const STATUS_PENDING = 0x00000103;
    const smb = makeScriptedSMB3([makeResp(7n, STATUS_PENDING), makeResp(7n, STATUS_SUCCESS)]);
    const pkt = await smb.recvSMB(7n);
    expect(pkt.get('MessageID')).toBe(7n);
    expect(pkt.get('Status')).toBe(STATUS_SUCCESS);
  });
});
