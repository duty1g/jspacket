import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  AsciiOrUnicodeStructure,
  FLAGS2_UNICODE,
  FTtoPOSIX,
  NewSMBPacket,
  POSIXtoFT,
  SMB,
  SMBClose_Parameters,
  SMBCommand,
  SMBEcho_Parameters,
  SMBFindFileBothDirectoryInfo,
  SMBNTLMDialect_Data,
  SMBNTLMDialect_Parameters,
  SMBNtCreateAndXResponse_Parameters,
  SMBNtCreateAndX_Parameters,
  SMBQueryFileStandardInfo,
  SMBReadAndXResponse_Parameters,
  SMBReadAndX_Parameters,
  SMBSessionSetupAndX_Extended_Data,
  SMBSessionSetupAndX_Extended_Parameters,
  SMBSessionSetupAndX_Parameters,
  SMBTransaction2_Parameters,
  SMBTransaction_Parameters,
  SMBTreeConnectAndX_Data,
  SMBTreeConnectAndX_Parameters,
  SMBWriteAndXResponse_Parameters,
  SMBWriteAndX_Parameters,
  SMB_COMMAND_CLOSE,
  SMB_COMMAND_ECHO,
  SMB_COMMAND_NEGOTIATE,
  SMB_COMMAND_NO_ANDX_COMMAND,
  SMB_COMMAND_NT_CREATE_ANDX,
  SMB_COMMAND_READ_ANDX,
  SMB_COMMAND_SESSION_SETUP,
  SMB_COMMAND_TRANSACTION,
  SMB_COMMAND_TRANSACTION2,
  SMB_COMMAND_TREE_CONNECT_ANDX,
  SMB_COMMAND_WRITE_ANDX,
  strerror,
} from '../src/index.js';

describe('strerror', () => {
  it('translates ERRDOS codes', () => {
    expect(strerror(0x01, 0x05)).toBe('Access denied');
    expect(strerror(0x01, 0x02)).toBe('File not found');
  });

  it('returns generic for unknown', () => {
    const msg = strerror(0xff, 0x99);
    expect(msg).toContain('Unknown');
  });
});

describe('POSIXtoFT / FTtoPOSIX', () => {
  it('round-trips timestamps', () => {
    const ts = 1705312800;
    const ft = POSIXtoFT(ts);
    expect(FTtoPOSIX(ft)).toBe(ts);
  });

  it('produces correct Windows epoch offset', () => {
    const ft = POSIXtoFT(0);
    expect(ft.toString()).toBe('116444736000000000');
  });
});

describe('NewSMBPacket', () => {
  it('builds a negotiate request', () => {
    const pkt = new NewSMBPacket();
    pkt.set('Command', SMB_COMMAND_NEGOTIATE);
    pkt.set('Flags1', 0x18);
    pkt.set('Flags2', 0xc843);
    pkt.set('Pid', 0xfeff);
    pkt.set('Mid', 0xfeff);

    const data = pkt.getData();
    expect(data.toString('latin1', 0, 4)).toBe('\xffSMB');
    expect(data[4]).toBe(SMB_COMMAND_NEGOTIATE);
  });

  it('round-trips a negotiate packet', () => {
    const pkt = new NewSMBPacket();
    pkt.set('Command', SMB_COMMAND_NEGOTIATE);
    pkt.set('Flags1', 0x18);
    pkt.set('Flags2', 0xc843);
    pkt.set('Pid', 0x1000);
    pkt.set('Mid', 0x2000);

    const data = pkt.getData();
    const parsed = new NewSMBPacket(data);
    expect(parsed.get('Command')).toBe(SMB_COMMAND_NEGOTIATE);
    expect(parsed.get('Flags1')).toBe(0x18);
    expect(parsed.get('Flags2')).toBe(0xc843);
    expect(parsed.get('Pid')).toBe(0x1000);
    expect(parsed.get('Mid')).toBe(0x2000);
  });
});

describe('SMBCommand', () => {
  it('builds an empty command', () => {
    const cmd = new SMBCommand(SMB_COMMAND_NEGOTIATE);
    const data = cmd.getData();
    expect(data[0]).toBe(0);
  });

  it('round-trips with parameters', () => {
    const params = new SMBSessionSetupAndX_Parameters();
    params.set('MaxBufferSize', 0x1104);
    params.set('MaxMpxCount', 0x000a);
    params.set('VcNumber', 0);
    params.set('SessionKey', 0);
    params.set('UnicodePasswordLength', 0x18);
    params.set('PasswordLength', 0);

    const cmd = new SMBCommand(SMB_COMMAND_SESSION_SETUP);
    cmd.set('Parameters', params.getData());

    const data = cmd.getData();
    expect(data[0]).toBe(params.getData().length / 2);
  });
});

describe('SMB Negotiate structures', () => {
  it('round-trips SMBNTLMDialect_Parameters', () => {
    const params = new SMBNTLMDialect_Parameters();
    params.set('DialectIndex', 0x0c);
    params.set('SecurityMode', 0x03);
    params.set('MaxMpxCount', 0x000a);
    params.set('MaxBufferSize', 0x1104);
    params.set('SessionKey', 0x12345678);
    params.set('Capabilities', 0x8000f3fc);
    params.set('ChallengeLength', 8);

    const data = params.getData();
    const parsed = new SMBNTLMDialect_Parameters(data);
    expect(parsed.get('DialectIndex')).toBe(0x0c);
    expect(parsed.get('SecurityMode')).toBe(0x03);
    expect(parsed.get('MaxBufferSize')).toBe(0x1104);
    expect(parsed.get('Capabilities')).toBe(0x8000f3fc);
  });
});

describe('SMB Session Setup structures', () => {
  it('round-trips extended session setup parameters', () => {
    const params = new SMBSessionSetupAndX_Extended_Parameters();
    params.set('MaxBufferSize', 0x1104);
    params.set('MaxMpxCount', 0x000a);
    params.set('VcNumber', 0);
    params.set('SessionKey', 0);
    params.set('Capabilities', 0x8000f3fc);
    params.set('UnicodePasswordLength', 0x48);

    const data = params.getData();
    expect(data.length).toBeGreaterThan(0);

    const parsed = new SMBSessionSetupAndX_Extended_Parameters(data);
    expect(parsed.get('MaxBufferSize')).toBe(0x1104);
    expect(parsed.get('Capabilities')).toBe(0x8000f3fc);
  });
});

describe('SMB Tree Connect structures', () => {
  it('round-trips tree connect parameters', () => {
    const params = new SMBTreeConnectAndX_Parameters();
    params.set('Flags', 0x0008);
    params.set('PasswordLength', 0x01);

    const data = params.getData();
    const parsed = new SMBTreeConnectAndX_Parameters(data);
    expect(parsed.get('Flags')).toBe(0x0008);
    expect(parsed.get('PasswordLength')).toBe(0x01);
  });
});

describe('SMB NT Create structures', () => {
  it('round-trips SMBNtCreateAndX_Parameters', () => {
    const params = new SMBNtCreateAndX_Parameters();
    params.set('FileNameLength', 0x0e);
    params.set('AccessMask', 0x2019f);
    params.set('ShareAccess', 0x07);
    params.set('Disposition', 0x01);
    params.set('CreateOptions', 0x40);
    params.set('Impersonation', 0x02);

    const data = params.getData();
    const parsed = new SMBNtCreateAndX_Parameters(data);
    expect(parsed.get('FileNameLength')).toBe(0x0e);
    expect(parsed.get('AccessMask')).toBe(0x2019f);
    expect(parsed.get('ShareAccess')).toBe(0x07);
    expect(parsed.get('Disposition')).toBe(0x01);
    expect(parsed.get('CreateOptions')).toBe(0x40);
  });

  it('round-trips SMBNtCreateAndXResponse_Parameters', () => {
    const params = new SMBNtCreateAndXResponse_Parameters();
    params.set('Fid', 0x4000);
    params.set('CreateAction', 0x01);
    params.set('EndOfFile', 0x1000n);
    params.set('FileAttributes', 0x80);

    const data = params.getData();
    const parsed = new SMBNtCreateAndXResponse_Parameters(data);
    expect(parsed.get('Fid')).toBe(0x4000);
    expect(parsed.get('CreateAction')).toBe(0x01);
    expect(parsed.get('FileAttributes')).toBe(0x80);
  });
});

describe('SMB Read/Write structures', () => {
  it('round-trips SMBReadAndX_Parameters', () => {
    const params = new SMBReadAndX_Parameters();
    params.set('Fid', 0x4000);
    params.set('Offset', 0);
    params.set('MaxCount', 0x8000);

    const data = params.getData();
    const parsed = new SMBReadAndX_Parameters(data);
    expect(parsed.get('Fid')).toBe(0x4000);
    expect(parsed.get('MaxCount')).toBe(0x8000);
  });

  it('round-trips SMBReadAndXResponse_Parameters', () => {
    const params = new SMBReadAndXResponse_Parameters();
    params.set('DataCount', 0x1000);
    params.set('DataOffset', 64);
    params.set('Remaining', 0x7000);

    const data = params.getData();
    const parsed = new SMBReadAndXResponse_Parameters(data);
    expect(parsed.get('DataCount')).toBe(0x1000);
    expect(parsed.get('DataOffset')).toBe(64);
    expect(parsed.get('Remaining')).toBe(0x7000);
  });

  it('round-trips SMBWriteAndX_Parameters', () => {
    const params = new SMBWriteAndX_Parameters();
    params.set('Fid', 0x4000);
    params.set('Offset', 0x100);
    params.set('WriteMode', 8);
    params.set('Remaining', 0x1000);
    params.set('DataLength', 0x200);

    const data = params.getData();
    const parsed = new SMBWriteAndX_Parameters(data);
    expect(parsed.get('Fid')).toBe(0x4000);
    expect(parsed.get('Offset')).toBe(0x100);
    expect(parsed.get('WriteMode')).toBe(8);
    expect(parsed.get('DataLength')).toBe(0x200);
  });

  it('round-trips SMBWriteAndXResponse_Parameters', () => {
    const params = new SMBWriteAndXResponse_Parameters();
    params.set('Count', 0x200);
    params.set('Available', 0x1000);

    const data = params.getData();
    const parsed = new SMBWriteAndXResponse_Parameters(data);
    expect(parsed.get('Count')).toBe(0x200);
    expect(parsed.get('Available')).toBe(0x1000);
  });
});

describe('SMB Transaction structures', () => {
  it('round-trips SMBTransaction_Parameters', () => {
    const params = new SMBTransaction_Parameters();
    params.set('TotalParameterCount', 0x10);
    params.set('TotalDataCount', 0x100);
    params.set('ParameterCount', 0x10);
    params.set('DataCount', 0x100);
    params.set('Setup', Buffer.from([0x26, 0x00, 0x00, 0x00]));

    const data = params.getData();
    const parsed = new SMBTransaction_Parameters(data);
    expect(parsed.get('TotalParameterCount')).toBe(0x10);
    expect(parsed.get('TotalDataCount')).toBe(0x100);
    expect(parsed.get('Setup')).toEqual(Buffer.from([0x26, 0x00, 0x00, 0x00]));
  });

  it('round-trips SMBTransaction2_Parameters', () => {
    const params = new SMBTransaction2_Parameters();
    params.set('TotalParameterCount', 0x20);
    params.set('TotalDataCount', 0x200);
    params.set('Setup', Buffer.from([0x01, 0x00]));

    const data = params.getData();
    const parsed = new SMBTransaction2_Parameters(data);
    expect(parsed.get('TotalParameterCount')).toBe(0x20);
    expect(parsed.get('TotalDataCount')).toBe(0x200);
  });
});

describe('SMB misc structures', () => {
  it('round-trips SMBEcho_Parameters', () => {
    const params = new SMBEcho_Parameters();
    params.set('EchoCount', 1);
    const data = params.getData();
    const parsed = new SMBEcho_Parameters(data);
    expect(parsed.get('EchoCount')).toBe(1);
  });

  it('round-trips SMBClose_Parameters', () => {
    const params = new SMBClose_Parameters();
    params.set('FID', 0x4000);
    params.set('Time', 0);
    const data = params.getData();
    const parsed = new SMBClose_Parameters(data);
    expect(parsed.get('FID')).toBe(0x4000);
  });

  it('round-trips SMBQueryFileStandardInfo', () => {
    const info = new SMBQueryFileStandardInfo();
    info.set('AllocationSize', 0x1000n);
    info.set('EndOfFile', 0x200n);
    info.set('Directory', 0);
    const data = info.getData();
    const parsed = new SMBQueryFileStandardInfo(data);
    expect(parsed.get('EndOfFile')).toBe(0x200n);
    expect(parsed.get('Directory')).toBe(0);
  });

  it('round-trips SMBFindFileBothDirectoryInfo (unicode)', () => {
    const info = new SMBFindFileBothDirectoryInfo(FLAGS2_UNICODE);
    info.set('CreationTime', 0n);
    info.set('EndOfFile', 0x400n);
    info.set('FileName', Buffer.from('test.txt', 'utf-16le'));
    const data = info.getData();
    const parsed = new SMBFindFileBothDirectoryInfo(FLAGS2_UNICODE, data);
    expect(parsed.get('EndOfFile')).toBe(0x400n);
    expect((parsed.get('FileName') as Buffer).toString('utf-16le')).toBe('test.txt');
  });
});

describe('AsciiOrUnicodeStructure', () => {
  it('selects unicode structure when FLAGS2_UNICODE is set', () => {
    const data = new SMBSessionSetupAndX_Extended_Data(FLAGS2_UNICODE);
    expect(data.structure).toBe(SMBSessionSetupAndX_Extended_Data.UnicodeStructure);
  });

  it('selects ascii structure when FLAGS2_UNICODE is not set', () => {
    const data = new SMBSessionSetupAndX_Extended_Data(0);
    expect(data.structure).toBe(SMBSessionSetupAndX_Extended_Data.AsciiStructure);
  });
});

describe('SMB class', () => {
  it('getDialect returns NT LM 0.12', () => {
    expect(SMB.getDialect()).toBe('NT LM 0.12');
  });

  it('HostnameValidationException exists', () => {
    expect(SMB.HostnameValidationException).toBeDefined();
  });
});
