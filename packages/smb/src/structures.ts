import { Buffer } from 'node:buffer';
import { type FieldDescriptor, Structure } from '@impacket/structure';
import * as constants from './constants.js';

const F = constants.FLAGS2_UNICODE;

export class NewSMBPacket extends Structure {
  static structure: FieldDescriptor[] = [
    ['Signature', '"\xffSMB'],
    ['Command', 'B=0'],
    ['ErrorClass', 'B=0'],
    ['_reserved', 'B=0'],
    ['ErrorCode', '<H=0'],
    ['Flags1', 'B=0'],
    ['Flags2', '<H=0'],
    ['PIDHigh', '<H=0'],
    ['SecurityFeatures', '8s=""'],
    ['Reserved', '<H=0'],
    ['Tid', '<H=0xffff'],
    ['Pid', '<H=0'],
    ['Uid', '<H=0'],
    ['Mid', '<H=0'],
    ['Data', '*:'],
  ];

  constructor(data?: Buffer) {
    super(data);
    if (data === undefined) {
      if (!this.has('Flags2')) this.set('Flags2', 0);
      if (!this.has('Flags1')) this.set('Flags1', 0);
      if (!this.has('Data')) this.set('Data', []);
    }
  }

  addCommand(command: SMBCommand): void {
    const data = this.get('Data') as SMBCommand[];
    if (data.length === 0) {
      this.set('Command', command.command);
    } else {
      const lastParams = data[data.length - 1]!.get('Parameters') as Structure;
      lastParams.set('AndXCommand', command.command);
      lastParams.set('AndXOffset', this.getData().length);
    }
    data.push(command);
    this.set('Data', data);
  }

  isValidAnswer(cmd: number): boolean {
    if (this.get('Command') !== cmd) {
      throw new constants.UnsupportedFeature(
        `Unexpected answer from server: Got ${this.get('Command')}, Expected ${cmd}`,
      );
    }
    if (this.get('ErrorClass') === 0x00 && this.get('ErrorCode') === 0x00) return true;
    if (this.isMoreData()) return true;
    if (this.isMoreProcessingRequired()) return true;
    throw new constants.SessionError(
      constants.strerror(this.get('ErrorClass') as number, this.get('ErrorCode') as number),
      this.get('ErrorClass') as number,
      this.get('ErrorCode') as number,
    );
  }

  isMoreData(): boolean {
    return (
      (this.get('Command') === constants.SMB_COMMAND_TRANSACTION ||
        this.get('Command') === constants.SMB_COMMAND_READ_ANDX ||
        this.get('Command') === constants.SMB_COMMAND_READ_RAW) &&
      this.get('ErrorClass') === 1
    );
  }

  isMoreProcessingRequired(): boolean {
    return this.get('ErrorClass') === 0x16 && this.get('ErrorCode') === 0xc000;
  }
}

export class SMBCommand extends Structure {
  command = 0;
  static structure: FieldDescriptor[] = [
    ['WordCount', 'B=len(Parameters)//2'],
    ['_ParametersLength', '_-Parameters', 'WordCount*2'],
    ['Parameters', ':'],
    ['ByteCount', '<H-Data'],
    ['Data', ':'],
  ];

  constructor(commandOrData?: number | Buffer, data?: Buffer) {
    if (typeof commandOrData === 'number') {
      super();
      this.command = commandOrData;
    } else if (commandOrData !== undefined) {
      super(data ?? commandOrData);
    } else if (data !== undefined) {
      super(data);
    } else {
      super();
    }
    if (data === undefined) {
      this.set('Parameters', Buffer.alloc(0));
      this.set('Data', Buffer.alloc(0));
    }
  }
}

export class SMBAndXCommand_Parameters extends Structure {
  static structure: FieldDescriptor[] = [
    ['AndXCommand', 'B=0xff'],
    ['AndXReserved', 'B=0'],
    ['AndXOffset', '<H=0'],
  ];
}

export class SMBCommand_Parameters extends Structure {
  static commonHdr: FieldDescriptor[] = [['WordCount', 'B=0']];
}

export class AsciiOrUnicodeStructure extends Structure {
  static UnicodeStructure: FieldDescriptor[] = [];
  static AsciiStructure: FieldDescriptor[] = [];
  static ENCODING = 'utf-8';

  constructor(flags = 0, data?: Buffer | null) {
    super(null);
    const ctor = this.constructor as typeof AsciiOrUnicodeStructure;
    this.structure = flags & F ? ctor.UnicodeStructure : ctor.AsciiStructure;
    if (data) {
      this.rawData = Buffer.from(data);
      this.fromString(Buffer.from(data));
    }
  }
}

export class SMBNTLMDialect_Parameters extends Structure {
  static structure: FieldDescriptor[] = [
    ['DialectIndex', '<H=0x0c'],
    ['SecurityMode', 'B=0'],
    ['MaxMpxCount', '<H=0'],
    ['MaxNumberVcs', '<H=0'],
    ['MaxBufferSize', '<L=0'],
    ['MaxRawSize', '<L=0'],
    ['SessionKey', '<L=0'],
    ['Capabilities', '<L=0'],
    ['SystemTime', '<Q=0'],
    ['ServerTimeZone', '<H=0'],
    ['ChallengeLength', 'B=0'],
  ];
}

export class SMBNTLMDialect_Data extends Structure {
  static structure: FieldDescriptor[] = [
    ['ChallengeLength', '_-Challenge', 'self["ChallengeLength"]'],
    ['Challenge', ':'],
    ['Payload', ':'],
    ['DomainName', '_'],
    ['ServerName', '_'],
  ];

  constructor(data?: Buffer, alignment = 0) {
    super(data, alignment);
  }

  fromString(data: Buffer): this {
    super.fromString(data);
    this.set('DomainName', '');
    this.set('ServerName', '');
    return this;
  }
}

export class SMBNTLMDialect_Data_ExtSec extends Structure {
  static structure: FieldDescriptor[] = [
    ['ServerGuid', '16s=""'],
    [
      '_SecurityBlobLength',
      '_-SecurityBlob',
      'self["SecurityBlobLength"] if "SecurityBlobLength" in self.fields else 0',
    ],
    ['SecurityBlob', ':'],
  ];
}

export class SMBExtended_Security_Parameters extends Structure {
  static structure: FieldDescriptor[] = [
    ['DialectIndex', '<H=0x0c'],
    ['SecurityMode', 'B=0'],
    ['MaxMpxCount', '<H=0'],
    ['MaxNumberVcs', '<H=0'],
    ['MaxBufferSize', '<L=0'],
    ['MaxRawSize', '<L=0'],
    ['SessionKey', '<L=0'],
    ['Capabilities', '<L=0'],
    ['LowDateTime', '<L=0'],
    ['HighDateTime', '<L=0'],
    ['ServerTimeZone', '<H=0'],
    ['ChallengeLength', 'B=0'],
  ];
}

export class SMBExtended_Security_Data extends Structure {
  static structure: FieldDescriptor[] = [
    ['ServerGuid', '16s=""'],
    [
      '_SecurityBlobLength',
      '_-SecurityBlob',
      'self["SecurityBlobLength"] if "SecurityBlobLength" in self.fields else 0',
    ],
    ['SecurityBlob', ':'],
  ];
}

export class SMBSessionSetupAndX_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['MaxBuffer', '<H=0'],
    ['MaxMpxCount', '<H=0'],
    ['VCNumber', '<H=0'],
    ['SessionKey', '<L=0'],
    ['AnsiPwdLength', '<H=0'],
    ['UnicodePwdLength', '<H=0'],
    ['_reserved', '<L=0'],
    ['Capabilities', '<L=0'],
  ];
}

export class SMBSessionSetupAndX_Extended_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['MaxBufferSize', '<H=0'],
    ['MaxMpxCount', '<H=0'],
    ['VcNumber', '<H=0'],
    ['SessionKey', '<L=0'],
    ['SecurityBlobLength', '<H=0'],
    ['Reserved', '<L=0'],
    ['Capabilities', '<L=0'],
  ];
}

export class SMBSessionSetupAndX_Data extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [
    ['AnsiPwdLength', '_-AnsiPwd', 'self["AnsiPwdLength"]'],
    ['UnicodePwdLength', '_-UnicodePwd', 'self["UnicodePwdLength"]'],
    ['AnsiPwd', ':=""'],
    ['UnicodePwd', ':=""'],
    ['Account', 'z=""'],
    ['PrimaryDomain', 'z=""'],
    ['NativeOS', 'z=""'],
    ['NativeLanMan', 'z=""'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['AnsiPwdLength', '_-AnsiPwd', 'self["AnsiPwdLength"]'],
    ['UnicodePwdLength', '_-UnicodePwd', 'self["UnicodePwdLength"]'],
    ['AnsiPwd', ':=""'],
    ['UnicodePwd', ':=""'],
    ['Account', 'u=""'],
    ['PrimaryDomain', 'u=""'],
    ['NativeOS', 'u=""'],
    ['NativeLanMan', 'u=""'],
  ];
}

export class SMBSessionSetupAndX_Extended_Data extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [
    ['SecurityBlobLength', '_-SecurityBlob', 'self["SecurityBlobLength"]'],
    ['SecurityBlob', ':'],
    ['NativeOS', 'z=""'],
    ['NativeLanMan', 'z=""'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['SecurityBlobLength', '_-SecurityBlob', 'self["SecurityBlobLength"]'],
    ['SecurityBlob', ':'],
    ['NativeOS', 'u=""'],
    ['NativeLanMan', 'u=""'],
  ];
}

export class SMBSessionSetupAndXResponse_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['Action', '<H=0'],
  ];
}

export class SMBSessionSetupAndX_Extended_Response_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['Action', '<H=0'],
    ['SecurityBlobLength', '<H=0'],
  ];
}

export class SMBSessionSetupAndXResponse_Data extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [
    ['NativeOS', 'z=""'],
    ['NativeLanMan', 'z=""'],
    ['PrimaryDomain', 'z=""'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['NativeOS', 'u=""'],
    ['NativeLanMan', 'u=""'],
    ['PrimaryDomain', 'u=""'],
  ];
}

export class SMBSessionSetupAndX_Extended_Response_Data extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [
    ['SecurityBlobLength', '_-SecurityBlob', 'self["SecurityBlobLength"]'],
    ['SecurityBlob', ':'],
    ['NativeOS', 'z=""'],
    ['NativeLanMan', 'z=""'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['SecurityBlobLength', '_-SecurityBlob', 'self["SecurityBlobLength"]'],
    ['SecurityBlob', ':'],
    ['PadLen', '_-Pad', '1 if (len(self["SecurityBlob"]) % 2 == 0) else 0'],
    ['Pad', ':=""'],
    ['NativeOS', 'u=""'],
    ['NativeLanMan', 'u=""'],
  ];

  getData(): Buffer {
    if (this.structure === (this.constructor as typeof AsciiOrUnicodeStructure).UnicodeStructure) {
      const sb = this.get('SecurityBlob');
      if (sb && Buffer.isBuffer(sb) && sb.length % 2 === 0) {
        this.set('Pad', Buffer.from([0x00]));
      }
    }
    return super.getData();
  }
}

export class SMBTreeConnect_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [];
}

export class SMBTreeConnect_Data extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['PathFormat', '"\x04'],
    ['Path', 'z'],
    ['PasswordFormat', '"\x04'],
    ['Password', 'z'],
    ['ServiceFormat', '"\x04'],
    ['Service', 'z'],
  ];
}

export class SMBTreeConnectAndX_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['Flags', '<H=0'],
    ['PasswordLength', '<H=0'],
  ];
}

export class SMBTreeConnectAndXResponse_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['OptionalSupport', '<H=0'],
  ];
}

export class SMBTreeConnectAndXExtendedResponse_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['OptionalSupport', '<H=1'],
    ['MaximalShareAccessRights', '<L=0x1fffff'],
    ['GuestMaximalShareAccessRights', '<L=0x1fffff'],
  ];
}

export class SMBTreeConnectAndX_Data extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [
    ['_PasswordLength', '_-Password', 'self["_PasswordLength"]'],
    ['Password', ':'],
    ['Path', 'z'],
    ['Service', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    [
      '_PasswordLength',
      '_-Password',
      'self["_PasswordLength"] if self["_PasswordLength"] > 0 else 1',
    ],
    ['Password', ':'],
    ['Path', 'u'],
    ['Service', 'z'],
  ];
}

export class SMBTreeConnectAndXResponse_Data extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [
    ['Service', 'z'],
    ['PadLen', '_-Pad', 'self["PadLen"]'],
    ['Pad', ':=""'],
    ['NativeFileSystem', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['Service', 'z'],
    ['PadLen', '_-Pad', 'self["PadLen"]'],
    ['Pad', ':=""'],
    ['NativeFileSystem', 'u'],
  ];
}

export class SMBNtCreateAndX_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['_reserved', 'B=0'],
    ['FileNameLength', '<H=0'],
    ['CreateFlags', '<L=0'],
    ['RootFid', '<L=0'],
    ['AccessMask', '<L=0'],
    ['AllocationSizeLo', '<L=0'],
    ['AllocationSizeHi', '<L=0'],
    ['FileAttributes', '<L=0'],
    ['ShareAccess', '<L=3'],
    ['Disposition', '<L=1'],
    ['CreateOptions', '<L=0'],
    ['Impersonation', '<L=2'],
    ['SecurityFlags', 'B=3'],
  ];
}

export class SMBNtCreateAndXResponse_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['OplockLevel', 'B=0'],
    ['Fid', '<H=0'],
    ['CreateAction', '<L=0'],
    ['CreateTime', '<Q=0'],
    ['LastAccessTime', '<Q=0'],
    ['LastWriteTime', '<Q=0'],
    ['LastChangeTime', '<Q=0'],
    ['FileAttributes', '<L=0x80'],
    ['AllocationSize', '<Q=0'],
    ['EndOfFile', '<Q=0'],
    ['FileType', '<H=0'],
    ['IPCState', '<H=0'],
    ['IsDirectory', 'B=0'],
  ];
}

export class SMBNtCreateAndXExtendedResponse_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['OplockLevel', 'B=0'],
    ['Fid', '<H=0'],
    ['CreateAction', '<L=0'],
    ['CreateTime', '<Q=0'],
    ['LastAccessTime', '<Q=0'],
    ['LastWriteTime', '<Q=0'],
    ['LastChangeTime', '<Q=0'],
    ['FileAttributes', '<L=0x80'],
    ['AllocationSize', '<Q=0'],
    ['EndOfFile', '<Q=0'],
    ['FileType', '<H=0'],
    ['IPCState', '<H=0'],
    ['IsDirectory', 'B=0'],
    ['VolumeGUID', '16s=""'],
    ['FileIdLow', '<L=0'],
    ['FileIdHigh', '<L=0'],
    ['MaximalAccessRights', '<L=0x12019b'],
    ['GuestMaximalAccessRights', '<L=0x120089'],
  ];
}

export class SMBNtCreateAndX_Data extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [['FileName', 'z']];
  static UnicodeStructure: FieldDescriptor[] = [
    ['Pad', 'B=0'],
    ['FileName', 'u'],
  ];
}

export class SMBOpenAndX_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['Flags', '<H=0'],
    ['DesiredAccess', '<H=0'],
    ['SearchAttributes', '<H=0'],
    ['FileAttributes', '<H=0'],
    ['CreationTime', '<L=0'],
    ['OpenMode', '<H=1'],
    ['AllocationSize', '<L=0'],
    ['Reserved', '8s=""'],
  ];
}

export class SMBOpenAndX_Data extends SMBNtCreateAndX_Data {}

export class SMBOpenAndXResponse_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['Fid', '<H=0'],
    ['FileAttributes', '<H=0'],
    ['LastWriten', '<L=0'],
    ['FileSize', '<L=0'],
    ['GrantedAccess', '<H=0'],
    ['FileType', '<H=0'],
    ['IPCState', '<H=0'],
    ['Action', '<H=0'],
    ['ServerFid', '<L=0'],
    ['_reserved', '<H=0'],
  ];
}

export class SMBOpen_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['DesiredAccess', '<H=0'],
    ['SearchAttributes', '<H=0'],
  ];
}

export class SMBOpen_Data extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [
    ['FileNameFormat', '"\x04'],
    ['FileName', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['FileNameFormat', '"\x04'],
    ['FileName', 'u'],
  ];
}

export class SMBOpenResponse_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['Fid', '<H=0'],
    ['FileAttributes', '<H=0'],
    ['LastWriten', '<L=0'],
    ['FileSize', '<L=0'],
    ['GrantedAccess', '<H=0'],
  ];
}

export class SMBWriteAndX_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['Fid', '<H=0'],
    ['Offset', '<L=0'],
    ['_reserved', '<L=0xff'],
    ['WriteMode', '<H=8'],
    ['Remaining', '<H=0'],
    ['DataLength_Hi', '<H=0'],
    ['DataLength', '<H=0'],
    ['DataOffset', '<H=0'],
    ['HighOffset', '<L=0'],
  ];
}

export class SMBWriteAndX_Parameters_Short extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['Fid', '<H=0'],
    ['Offset', '<L=0'],
    ['_reserved', '<L=0xff'],
    ['WriteMode', '<H=8'],
    ['Remaining', '<H=0'],
    ['DataLength_Hi', '<H=0'],
    ['DataLength', '<H=0'],
    ['DataOffset', '<H=0'],
  ];
}

export class SMBWriteAndXResponse_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['Count', '<H=0'],
    ['Available', '<H=0'],
    ['Reserved', '<L=0'],
  ];
}

export class SMBWriteAndX_Data extends Structure {
  static structure: FieldDescriptor[] = [
    ['_PadLen', '_-Pad', 'self["DataOffset"] - 63'],
    ['Pad', ':'],
    ['DataLength', '_-Data', 'self["DataLength"]'],
    ['Data', ':'],
  ];
}

export class SMBWriteAndX_Data_Short extends Structure {
  static structure: FieldDescriptor[] = [
    ['_PadLen', '_-Pad', 'self["DataOffset"] - 59'],
    ['Pad', ':'],
    ['DataLength', '_-Data', 'self["DataLength"]'],
    ['Data', ':'],
  ];
}

export class SMBWrite_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['Fid', '<H=0'],
    ['Count', '<H=0'],
    ['Offset', '<L=0'],
    ['Remaining', '<H=0'],
  ];
}

export class SMBWriteResponse_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [['Count', '<H=0']];
}

export class SMBWrite_Data extends Structure {
  static structure: FieldDescriptor[] = [
    ['BufferFormat', '<B=1'],
    ['DataLength', '<H-Data'],
    ['Data', ':'],
  ];
}

export class SMBWriteRaw_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['Fid', '<H=0'],
    ['Count', '<H=0'],
    ['_reserved', '<H=0'],
    ['Offset', '<L=0'],
    ['Timeout', '<L=0'],
    ['WriteMode', '<H=0'],
    ['_reserved2', '<L=0'],
    ['DataLength', '<H=0'],
    ['DataOffset', '<H=0'],
  ];
}

export class SMBReadAndX_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['Fid', '<H=0'],
    ['Offset', '<L=0'],
    ['MaxCount', '<H=0'],
    ['MinCount', '<H=MaxCount'],
    ['_reserved', '<L=0x0'],
    ['Remaining', '<H=MaxCount'],
    ['HighOffset', '<L=0'],
  ];
}

export class SMBReadAndX_Parameters2 extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['Fid', '<H=0'],
    ['Offset', '<L=0'],
    ['MaxCount', '<H=0'],
    ['MinCount', '<H=MaxCount'],
    ['_reserved', '<L=0xffffffff'],
    ['Remaining', '<H=MaxCount'],
  ];
}

export class SMBReadAndXResponse_Parameters extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ...SMBAndXCommand_Parameters.structure,
    ['Remaining', '<H=0'],
    ['DataMode', '<H=0'],
    ['_reserved', '<H=0'],
    ['DataCount', '<H=0'],
    ['DataOffset', '<H=0'],
    ['DataCount_Hi', '<L=0'],
    ['_reserved2', '6s=""'],
  ];
}

export class SMBRead_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['Fid', '<H=0'],
    ['Count', '<H=0'],
    ['Offset', '<L=0'],
    ['Remaining', '<H=Count'],
  ];
}

export class SMBReadResponse_Parameters extends Structure {
  static structure: FieldDescriptor[] = [
    ['Count', '<H=0'],
    ['_reserved', '8s=""'],
  ];
}

export class SMBReadResponse_Data extends Structure {
  static structure: FieldDescriptor[] = [
    ['BufferFormat', '<B=0x1'],
    ['DataLength', '<H-Data'],
    ['Data', ':'],
  ];
}

export class SMBReadRaw_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['Fid', '<H=0'],
    ['Offset', '<L=0'],
    ['MaxCount', '<H=0'],
    ['MinCount', '<H=MaxCount'],
    ['Timeout', '<L=0'],
    ['_reserved', '<H=0'],
  ];
}

export class SMBClose_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['FID', '<H=0'],
    ['Time', '<L=0'],
  ];
}

export class SMBFlush_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [['FID', '<H=0']];
}

export class SMBDelete_Parameters extends Structure {
  static structure: FieldDescriptor[] = [['SearchAttributes', '<H=0']];
}

export class SMBTreeDisconnect_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [];
}

export class SMBLogOffAndX extends SMBAndXCommand_Parameters {
  static structure: FieldDescriptor[] = [];
}

export class SMBEcho_Parameters extends Structure {
  static structure: FieldDescriptor[] = [['EchoCount', '<H=0']];
}

export class SMBEcho_Data extends Structure {
  static structure: FieldDescriptor[] = [['Data', ':']];
}

export class SMBEchoResponse_Parameters extends Structure {
  static structure: FieldDescriptor[] = [['SequenceNumber', '<H=1']];
}

export class SMBEchoResponse_Data extends Structure {
  static structure: FieldDescriptor[] = [['Data', ':']];
}

export class SMBQueryInformationDiskResponse_Parameters extends Structure {
  static structure: FieldDescriptor[] = [
    ['TotalUnits', '<H=0'],
    ['BlocksPerUnit', '<H=0'],
    ['BlockSize', '<H=0'],
    ['FreeUnits', '<H=0'],
    ['Reserved', '<H=0'],
  ];
}

export class SMBQueryInformation2_Parameters extends Structure {
  static structure: FieldDescriptor[] = [['Fid', '<H=0']];
}

export class SMBQueryInformation2Response_Parameters extends Structure {
  static structure: FieldDescriptor[] = [
    ['CreateDate', '<H=0'],
    ['CreationTime', '<H=0'],
    ['LastAccessDate', '<H=0'],
    ['LastAccessTime', '<H=0'],
    ['LastWriteDate', '<H=0'],
    ['LastWriteTime', '<H=0'],
    ['FileDataSize', '<L=0'],
    ['FileAllocationSize', '<L=0'],
    ['FileAttributes', '<L=0'],
  ];
}

export class SMBQueryInformation_Data extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [
    ['BufferFormat', 'B=4'],
    ['FileName', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['BufferFormat', 'B=4'],
    ['FileName', 'u'],
  ];
}

export class SMBQueryInformationResponse_Parameters extends Structure {
  static structure: FieldDescriptor[] = [
    ['FileAttributes', '<H=0'],
    ['LastWriteTime', '<L=0'],
    ['FileSize', '<L=0'],
    ['Reserved', '"0123456789'],
  ];
}

export class SMBCreateDirectory_Data extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [
    ['BufferFormat', '<B=4'],
    ['DirectoryName', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['BufferFormat', '<B=4'],
    ['DirectoryName', 'u'],
  ];
}

export class SMBDelete_Data extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [
    ['BufferFormat', '<B=4'],
    ['FileName', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['BufferFormat', '<B=4'],
    ['FileName', 'u'],
  ];
}

export class SMBDeleteDirectory_Data extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [
    ['BufferFormat', '<B=4'],
    ['DirectoryName', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['BufferFormat', '<B=4'],
    ['DirectoryName', 'u'],
  ];
}

export class SMBCheckDirectory_Data extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [
    ['BufferFormat', '<B=4'],
    ['DirectoryName', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['BufferFormat', '<B=4'],
    ['DirectoryName', 'u'],
  ];
}

export class SMBRename_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [['SearchAttributes', '<H=0']];
}

export class SMBRename_Data extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [
    ['BufferFormat1', '<B=4'],
    ['OldFileName', 'z'],
    ['BufferFormat2', '<B=4'],
    ['NewFileName', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['BufferFormat1', '<B=4'],
    ['OldFileName', 'u'],
    ['BufferFormat2', '<B=4'],
    ['Pad', 'B=0'],
    ['NewFileName', 'u'],
  ];
}

export class SMBTransaction_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['TotalParameterCount', '<H=0'],
    ['TotalDataCount', '<H=0'],
    ['MaxParameterCount', '<H=1024'],
    ['MaxDataCount', '<H=65504'],
    ['MaxSetupCount', '<B=0'],
    ['Reserved1', '<B=0'],
    ['Flags', '<H=0'],
    ['Timeout', '<L=0'],
    ['Reserved2', '<H=0'],
    ['ParameterCount', '<H=0'],
    ['ParameterOffset', '<H=0'],
    ['DataCount', '<H=0'],
    ['DataOffset', '<H=0'],
    ['SetupCount', '<B=len(Setup)//2'],
    ['Reserved3', '<B=0'],
    ['SetupLength', '_-Setup', 'SetupCount*2'],
    ['Setup', ':'],
  ];
}

export class SMBTransactionResponse_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['TotalParameterCount', '<H=0'],
    ['TotalDataCount', '<H=0'],
    ['Reserved1', '<H=0'],
    ['ParameterCount', '<H=0'],
    ['ParameterOffset', '<H=0'],
    ['ParameterDisplacement', '<H=0'],
    ['DataCount', '<H=0'],
    ['DataOffset', '<H=0'],
    ['DataDisplacement', '<H=0'],
    ['SetupCount', '<B=0'],
    ['Reserved2', '<B=0'],
    ['SetupLength', '_-Setup', 'SetupCount*2'],
    ['Setup', ':'],
  ];
}

export class SMBTransaction_Data extends Structure {
  static structure: FieldDescriptor[] = [
    ['NameLength', '_-Name'],
    ['Name', ':'],
    ['Trans_ParametersLength', '_-Trans_Parameters'],
    ['Trans_Parameters', ':'],
    ['Trans_DataLength', '_-Trans_Data'],
    ['Trans_Data', ':'],
  ];
}

export class SMBTransactionResponse_Data extends Structure {
  static structure: FieldDescriptor[] = [
    ['Trans_ParametersLength', '_-Trans_Parameters'],
    ['Trans_Parameters', ':'],
    ['Trans_DataLength', '_-Trans_Data'],
    ['Trans_Data', ':'],
  ];
}

export class SMBTransaction_SData extends AsciiOrUnicodeStructure {
  static AsciiStructure: FieldDescriptor[] = [
    ['Name', 'z'],
    ['Trans_ParametersLength', '_-Trans_Parameters'],
    ['Trans_Parameters', ':'],
    ['Trans_DataLength', '_-Trans_Data'],
    ['Trans_Data', ':'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['Pad', 'B=0'],
    ['Name', 'u'],
    ['Trans_ParametersLength', '_-Trans_Parameters'],
    ['Trans_Parameters', ':'],
    ['Trans_DataLength', '_-Trans_Data'],
    ['Trans_Data', ':'],
  ];
}

export class SMBTransaction2_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['TotalParameterCount', '<H=0'],
    ['TotalDataCount', '<H=0'],
    ['MaxParameterCount', '<H=1024'],
    ['MaxDataCount', '<H=65504'],
    ['MaxSetupCount', '<B=0'],
    ['Reserved1', '<B=0'],
    ['Flags', '<H=0'],
    ['Timeout', '<L=0'],
    ['Reserved2', '<H=0'],
    ['ParameterCount', '<H=0'],
    ['ParameterOffset', '<H=0'],
    ['DataCount', '<H=0'],
    ['DataOffset', '<H=0'],
    ['SetupCount', '<B=len(Setup)//2'],
    ['Reserved3', '<B=0'],
    ['SetupLength', '_-Setup', 'SetupCount*2'],
    ['Setup', ':'],
  ];
}

export class SMBTransaction2Response_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['TotalParameterCount', '<H=0'],
    ['TotalDataCount', '<H=0'],
    ['Reserved1', '<H=0'],
    ['ParameterCount', '<H=0'],
    ['ParameterOffset', '<H=0'],
    ['ParameterDisplacement', '<H=0'],
    ['DataCount', '<H=0'],
    ['DataOffset', '<H=0'],
    ['DataDisplacement', '<H=0'],
    ['SetupCount', '<B=0'],
    ['Reserved2', '<B=0'],
    ['SetupLength', '_-Setup', 'SetupCount*2'],
    ['Setup', ':'],
  ];
}

export class SMBTransaction2_Data extends Structure {
  static structure: FieldDescriptor[] = [
    ['Pad1Length', '_-Pad1', 'self["Pad1Length"]'],
    ['Pad1', ':'],
    ['Trans_ParametersLength', '_-Trans_Parameters', 'self["Trans_ParametersLength"]'],
    ['Trans_Parameters', ':'],
    ['Pad2Length', '_-Pad2', 'self["Pad2Length"]'],
    ['Pad2', ':'],
    ['Trans_DataLength', '_-Trans_Data', 'self["Trans_DataLength"]'],
    ['Trans_Data', ':'],
  ];
}

export class SMBTransaction2Response_Data extends Structure {
  static structure: FieldDescriptor[] = [
    ['Pad1Length', '_-Pad1', 'self["Pad1Length"]'],
    ['Pad1', ':'],
    ['Trans_ParametersLength', '_-Trans_Parameters', 'self["Trans_ParametersLength"]'],
    ['Trans_Parameters', ':'],
    ['Pad2Length', '_-Pad2', 'self["Pad2Length"]'],
    ['Pad2', ':'],
    ['Trans_DataLength', '_-Trans_Data', 'self["Trans_DataLength"]'],
    ['Trans_Data', ':'],
  ];
}

export class SMBTransaction2Secondary_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['TotalParameterCount', '<H=0'],
    ['TotalDataCount', '<H=0'],
    ['ParameterCount', '<H=0'],
    ['ParameterOffset', '<H=0'],
    ['ParameterDisplacement', '<H=0'],
    ['DataCount', '<H=0'],
    ['DataOffset', '<H=0'],
    ['DataDisplacement', '<H=0'],
    ['FID', '<H=0'],
  ];
}

export class SMBTransaction2Secondary_Data extends Structure {
  static structure: FieldDescriptor[] = [
    ['Pad1Length', '_-Pad1', 'self["Pad1Length"]'],
    ['Pad1', ':'],
    ['Trans_ParametersLength', '_-Trans_Parameters', 'self["Trans_ParametersLength"]'],
    ['Trans_Parameters', ':'],
    ['Pad2Length', '_-Pad2', 'self["Pad2Length"]'],
    ['Pad2', ':'],
    ['Trans_DataLength', '_-Trans_Data', 'self["Trans_DataLength"]'],
    ['Trans_Data', ':'],
  ];
}

export class SMBNTTransaction_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['MaxSetupCount', '<B=0'],
    ['Reserved1', '<H=0'],
    ['TotalParameterCount', '<L=0'],
    ['TotalDataCount', '<L=0'],
    ['MaxParameterCount', '<L=1024'],
    ['MaxDataCount', '<L=65504'],
    ['ParameterCount', '<L=0'],
    ['ParameterOffset', '<L=0'],
    ['DataCount', '<L=0'],
    ['DataOffset', '<L=0'],
    ['SetupCount', '<B=len(Setup)//2'],
    ['Function', '<H=0'],
    ['SetupLength', '_-Setup', 'SetupCount*2'],
    ['Setup', ':'],
  ];
}

export class SMBNTTransactionResponse_Parameters extends SMBCommand_Parameters {
  static structure: FieldDescriptor[] = [
    ['Reserved1', '3s=""'],
    ['TotalParameterCount', '<L=0'],
    ['TotalDataCount', '<L=0'],
    ['ParameterCount', '<L=0'],
    ['ParameterOffset', '<L=0'],
    ['ParameterDisplacement', '<L=0'],
    ['DataCount', '<L=0'],
    ['DataOffset', '<L=0'],
    ['DataDisplacement', '<L=0'],
    ['SetupCount', '<B=0'],
    ['SetupLength', '_-Setup', 'SetupCount*2'],
    ['Setup', ':'],
  ];
}

export class SMBNTTransaction_Data extends Structure {
  static structure: FieldDescriptor[] = [
    ['Pad1Length', '_-Pad1', 'self["Pad1Length"]'],
    ['Pad1', ':'],
    ['NT_Trans_ParametersLength', '_-NT_Trans_Parameters', 'self["NT_Trans_ParametersLength"]'],
    ['NT_Trans_Parameters', ':'],
    ['Pad2Length', '_-Pad2', 'self["Pad2Length"]'],
    ['Pad2', ':'],
    ['NT_Trans_DataLength', '_-NT_Trans_Data', 'self["NT_Trans_DataLength"]'],
    ['NT_Trans_Data', ':'],
  ];
}

export class SMBNTTransactionResponse_Data extends Structure {
  static structure: FieldDescriptor[] = [
    ['Pad1Length', '_-Pad1', 'self["Pad1Length"]'],
    ['Pad1', ':'],
    ['Trans_ParametersLength', '_-Trans_Parameters', 'self["Trans_ParametersLength"]'],
    ['Trans_Parameters', ':'],
    ['Pad2Length', '_-Pad2', 'self["Pad2Length"]'],
    ['Pad2', ':'],
    ['Trans_DataLength', '_-Trans_Data', 'self["Trans_DataLength"]'],
    ['Trans_Data', ':'],
  ];
}

export class SMBQueryFsAttributeInfo extends Structure {
  static structure: FieldDescriptor[] = [
    ['FileSystemAttributes', '<L=0'],
    ['MaxFilenNameLengthInBytes', '<L=0'],
    ['LengthOfFileSystemName', '<L-FileSystemName'],
    ['FileSystemName', ':'],
  ];
}

export class SMBQueryFsInfoVolume extends AsciiOrUnicodeStructure {
  static commonHdr: FieldDescriptor[] = [
    ['ulVolSerialNbr', '<L=0xABCDEFAA'],
    ['cCharCount', '<B-VolumeLabel'],
  ];
  static AsciiStructure: FieldDescriptor[] = [['VolumeLabel', 'z']];
  static UnicodeStructure: FieldDescriptor[] = [['VolumeLabel', 'u']];
}

export class FileFsSizeInformation extends Structure {
  static structure: FieldDescriptor[] = [
    ['TotalAllocationUnits', '<q=0'],
    ['AvailableAllocationUnits', '<q=0'],
    ['SectorsPerAllocationUnit', '<L=2'],
    ['BytesPerSector', '<L=512'],
  ];
}

export class SMBQueryFsSizeInfo extends Structure {
  static structure: FieldDescriptor[] = [
    ['TotalAllocationUnits', '<q=0'],
    ['TotalFreeAllocationUnits', '<q=0'],
    ['SectorsPerAllocationUnit', '<L=2'],
    ['BytesPerSector', '<L=512'],
  ];
}

export class SMBFileFsFullSizeInformation extends Structure {
  static structure: FieldDescriptor[] = [
    ['TotalAllocationUnits', '<q=0'],
    ['CallerAvailableAllocationUnits', '<q=0'],
    ['ActualAvailableAllocationUnits', '<q=0'],
    ['SectorsPerAllocationUnit', '<L=15'],
    ['BytesPerSector', '<L=512'],
  ];
}

export class SMBQueryFsVolumeInfo extends Structure {
  static structure: FieldDescriptor[] = [
    ['VolumeCreationTime', '<q=0'],
    ['SerialNumber', '<L=0xABCDEFAA'],
    ['VolumeLabelSize', '<L=len(VolumeLabel)'],
    ['Reserved', '<H=0x10'],
    ['VolumeLabel', ':'],
  ];
}

export class SMBQueryFsDeviceInfo extends Structure {
  static structure: FieldDescriptor[] = [
    ['DeviceType', '<L=0'],
    ['DeviceCharacteristics', '<L=0'],
  ];
}

export class SMBFindFileBothDirectoryInfo extends AsciiOrUnicodeStructure {
  static commonHdr: FieldDescriptor[] = [
    ['NextEntryOffset', '<L=0'],
    ['FileIndex', '<L=0'],
    ['CreationTime', '<q=0'],
    ['LastAccessTime', '<q=0'],
    ['LastWriteTime', '<q=0'],
    ['LastChangeTime', '<q=0'],
    ['EndOfFile', '<q=0'],
    ['AllocationSize', '<q=0'],
    ['ExtFileAttributes', '<L=0'],
  ];
  static AsciiStructure: FieldDescriptor[] = [
    ['FileNameLength', '<L-FileName'],
    ['EaSize', '<L=0'],
    ['ShortNameLength', '<B=0'],
    ['Reserved', '<B=0'],
    ['ShortName', '24s=""'],
    ['FileName', ':'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['FileNameLength', '<L-FileName'],
    ['EaSize', '<L=0'],
    ['ShortNameLength', '<B=0'],
    ['Reserved', '<B=0'],
    ['ShortName', '24s=""'],
    ['FileName', ':'],
  ];
}

export class SMBFindFileIdFullDirectoryInfo extends AsciiOrUnicodeStructure {
  static commonHdr: FieldDescriptor[] = [
    ['NextEntryOffset', '<L=0'],
    ['FileIndex', '<L=0'],
    ['CreationTime', '<q=0'],
    ['LastAccessTime', '<q=0'],
    ['LastWriteTime', '<q=0'],
    ['LastChangeTime', '<q=0'],
    ['EndOfFile', '<q=0'],
    ['AllocationSize', '<q=0'],
    ['ExtFileAttributes', '<L=0'],
  ];
  static AsciiStructure: FieldDescriptor[] = [
    ['FileNameLength', '<L-FileName'],
    ['EaSize', '<L=0'],
    ['Reserved', '<L=0'],
    ['FileID', '<q=0'],
    ['FileName', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['FileNameLength', '<L-FileName'],
    ['EaSize', '<L=0'],
    ['Reserved', '<L=0'],
    ['FileID', '<q=0'],
    ['FileName', ':'],
  ];
}

export class SMBFindFileIdBothDirectoryInfo extends AsciiOrUnicodeStructure {
  static commonHdr: FieldDescriptor[] = [
    ['NextEntryOffset', '<L=0'],
    ['FileIndex', '<L=0'],
    ['CreationTime', '<q=0'],
    ['LastAccessTime', '<q=0'],
    ['LastWriteTime', '<q=0'],
    ['LastChangeTime', '<q=0'],
    ['EndOfFile', '<q=0'],
    ['AllocationSize', '<q=0'],
    ['ExtFileAttributes', '<L=0'],
  ];
  static AsciiStructure: FieldDescriptor[] = [
    ['FileNameLength', '<L-FileName'],
    ['EaSize', '<L=0'],
    ['ShortNameLength', '<B=0'],
    ['Reserved', '<B=0'],
    ['ShortName', '24s=""'],
    ['Reserved2', '<H=0'],
    ['FileID', '<q=0'],
    ['FileName', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['FileNameLength', '<L-FileName'],
    ['EaSize', '<L=0'],
    ['ShortNameLength', '<B=0'],
    ['Reserved', '<B=0'],
    ['ShortName', '24s=""'],
    ['Reserved2', '<H=0'],
    ['FileID', '<q=0'],
    ['FileName', ':'],
  ];
}

export class SMBFindFileDirectoryInfo extends AsciiOrUnicodeStructure {
  static commonHdr: FieldDescriptor[] = [
    ['NextEntryOffset', '<L=0'],
    ['FileIndex', '<L=0'],
    ['CreationTime', '<q=0'],
    ['LastAccessTime', '<q=0'],
    ['LastWriteTime', '<q=0'],
    ['LastChangeTime', '<q=0'],
    ['EndOfFile', '<q=0'],
    ['AllocationSize', '<q=1'],
    ['ExtFileAttributes', '<L=0'],
  ];
  static AsciiStructure: FieldDescriptor[] = [
    ['FileNameLength', '<L-FileName'],
    ['FileName', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['FileNameLength', '<L-FileName'],
    ['FileName', ':'],
  ];
}

export class SMBFindFileNamesInfo extends AsciiOrUnicodeStructure {
  static commonHdr: FieldDescriptor[] = [
    ['NextEntryOffset', '<L=0'],
    ['FileIndex', '<L=0'],
  ];
  static AsciiStructure: FieldDescriptor[] = [
    ['FileNameLength', '<L-FileName'],
    ['FileName', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['FileNameLength', '<L-FileName'],
    ['FileName', ':'],
  ];
}

export class SMBFindFileFullDirectoryInfo extends AsciiOrUnicodeStructure {
  static commonHdr: FieldDescriptor[] = [
    ['NextEntryOffset', '<L=0'],
    ['FileIndex', '<L=0'],
    ['CreationTime', '<q=0'],
    ['LastAccessTime', '<q=0'],
    ['LastWriteTime', '<q=0'],
    ['LastChangeTime', '<q=0'],
    ['EndOfFile', '<q=0'],
    ['AllocationSize', '<q=1'],
    ['ExtFileAttributes', '<L=0'],
  ];
  static AsciiStructure: FieldDescriptor[] = [
    ['FileNameLength', '<L-FileName'],
    ['EaSize', '<L=0'],
    ['FileName', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['FileNameLength', '<L-FileName'],
    ['EaSize', '<L=0'],
    ['FileName', ':'],
  ];
}

export class SMBFindInfoStandard extends AsciiOrUnicodeStructure {
  static commonHdr: FieldDescriptor[] = [
    ['ResumeKey', '<L=0xff'],
    ['CreationDate', '<H=0'],
    ['CreationTime', '<H=0'],
    ['LastAccessDate', '<H=0'],
    ['LastAccessTime', '<H=0'],
    ['LastWriteDate', '<H=0'],
    ['LastWriteTime', '<H=0'],
    ['EaSize', '<L=0'],
    ['AllocationSize', '<L=1'],
    ['ExtFileAttributes', '<H=0'],
  ];
  static AsciiStructure: FieldDescriptor[] = [
    ['FileNameLength', '<B-FileName'],
    ['FileName', 'z'],
  ];
  static UnicodeStructure: FieldDescriptor[] = [
    ['FileNameLength', '<B-FileName'],
    ['FileName', ':'],
  ];
}

export class SMBFindFirst2_Parameters extends AsciiOrUnicodeStructure {
  static commonHdr: FieldDescriptor[] = [
    ['SearchAttributes', '<H=0'],
    ['SearchCount', '<H=0'],
    ['Flags', '<H=0'],
    ['InformationLevel', '<H=0'],
    ['SearchStorageType', '<L=0'],
  ];
  static AsciiStructure: FieldDescriptor[] = [['FileName', 'z']];
  static UnicodeStructure: FieldDescriptor[] = [['FileName', 'u']];
}

export class SMBFindFirst2Response_Parameters extends Structure {
  static structure: FieldDescriptor[] = [
    ['SID', '<H=0'],
    ['SearchCount', '<H=0'],
    ['EndOfSearch', '<H=1'],
    ['EaErrorOffset', '<H=0'],
    ['LastNameOffset', '<H=0'],
  ];
}

export class SMBFindFirst2_Data extends Structure {
  static structure: FieldDescriptor[] = [
    [
      'GetExtendedAttributesListLength',
      '_-GetExtendedAttributesList',
      'self["GetExtendedAttributesListLength"]',
    ],
    ['GetExtendedAttributesList', ':'],
  ];
}

export class SMBFindNext2_Parameters extends AsciiOrUnicodeStructure {
  static commonHdr: FieldDescriptor[] = [
    ['SID', '<H=0'],
    ['SearchCount', '<H=0'],
    ['InformationLevel', '<H=0'],
    ['ResumeKey', '<L=0'],
    ['Flags', '<H=0'],
  ];
  static AsciiStructure: FieldDescriptor[] = [['FileName', 'z']];
  static UnicodeStructure: FieldDescriptor[] = [['FileName', 'u']];
}

export class SMBFindNext2Response_Parameters extends Structure {
  static structure: FieldDescriptor[] = [
    ['SearchCount', '<H=0'],
    ['EndOfSearch', '<H=1'],
    ['EaErrorOffset', '<H=0'],
    ['LastNameOffset', '<H=0'],
  ];
}

export class SMBFindNext2_Data extends Structure {
  static structure: FieldDescriptor[] = [
    [
      'GetExtendedAttributesListLength',
      '_-GetExtendedAttributesList',
      'self["GetExtendedAttributesListLength"]',
    ],
    ['GetExtendedAttributesList', ':'],
  ];
}

export class SMBSetPathInformation_Parameters extends AsciiOrUnicodeStructure {
  static commonHdr: FieldDescriptor[] = [
    ['InformationLevel', '<H=0'],
    ['Reserved', '<L=0'],
  ];
  static AsciiStructure: FieldDescriptor[] = [['FileName', 'z']];
  static UnicodeStructure: FieldDescriptor[] = [['FileName', 'u']];
}

export class SMBSetPathInformationResponse_Parameters extends Structure {
  static structure: FieldDescriptor[] = [['EaErrorOffset', '<H=0']];
}

export class SMBSetFileInformation_Parameters extends Structure {
  static structure: FieldDescriptor[] = [
    ['FID', '<H=0'],
    ['InformationLevel', '<H=0'],
    ['Reserved', '<H=0'],
  ];
}

export class SMBSetFileInformationResponse_Parameters extends Structure {
  static structure: FieldDescriptor[] = [['EaErrorOffset', '<H=0']];
}

export class SMBQueryFileInformation_Parameters extends Structure {
  static structure: FieldDescriptor[] = [
    ['FID', '<H=0'],
    ['InformationLevel', '<H=0'],
  ];
}

export class SMBQueryFileInformationResponse_Parameters extends Structure {
  static structure: FieldDescriptor[] = [['EaErrorOffset', '<H=0']];
}

export class SMBQueryFileInformation_Data extends Structure {
  static structure: FieldDescriptor[] = [['GetExtendedAttributeList', ':']];
}

export class SMBQueryPathInformationResponse_Parameters extends Structure {
  static structure: FieldDescriptor[] = [['EaErrorOffset', '<H=0']];
}

export class SMBQueryPathInformation_Parameters extends AsciiOrUnicodeStructure {
  static commonHdr: FieldDescriptor[] = [
    ['InformationLevel', '<H=0'],
    ['Reserved', '<L=0'],
  ];
  static AsciiStructure: FieldDescriptor[] = [['FileName', 'z']];
  static UnicodeStructure: FieldDescriptor[] = [['FileName', 'u']];
}

export class SMBQueryPathInformation_Data extends Structure {
  static structure: FieldDescriptor[] = [['GetExtendedAttributeList', ':']];
}

export class SMBQueryFileEaInfo extends Structure {
  static structure: FieldDescriptor[] = [['EaSize', '<L=0']];
}

export class SMBQueryFileBasicInfo extends Structure {
  static structure: FieldDescriptor[] = [
    ['CreationTime', '<q=0'],
    ['LastAccessTime', '<q=0'],
    ['LastWriteTime', '<q=0'],
    ['LastChangeTime', '<q=0'],
    ['ExtFileAttributes', '<L=0'],
  ];
}

export class SMBQueryFileStandardInfo extends Structure {
  static structure: FieldDescriptor[] = [
    ['AllocationSize', '<q=0'],
    ['EndOfFile', '<q=0'],
    ['NumberOfLinks', '<L=0'],
    ['DeletePending', '<B=0'],
    ['Directory', '<B=0'],
  ];
}

export class SMBQueryFileAllInfo extends Structure {
  static structure: FieldDescriptor[] = [
    ['CreationTime', '<q=0'],
    ['LastAccessTime', '<q=0'],
    ['LastWriteTime', '<q=0'],
    ['LastChangeTime', '<q=0'],
    ['ExtFileAttributes', '<L=0'],
    ['Reserved', '<L=0'],
    ['AllocationSize', '<q=0'],
    ['EndOfFile', '<q=0'],
    ['NumberOfLinks', '<L=0'],
    ['DeletePending', '<B=0'],
    ['Directory', '<B=0'],
    ['Reserved2', '<H=0'],
    ['EaSize', '<L=0'],
    ['FileNameLength', '<L-FileName'],
    ['FileName', ':'],
  ];
}

export class SMBSetStandardInfo extends Structure {
  static structure: FieldDescriptor[] = [
    ['CreateDate', '<H=0'],
    ['CreationTime', '<H=0'],
    ['LastAccessDate', '<H=0'],
    ['LastAccessTime', '<H=0'],
    ['LastWriteDate', '<H=0'],
    ['LastWriteTime', '<H=0'],
    ['Reserved', '<B=10'],
  ];
}

export class SMBSetFileDispositionInfo extends Structure {
  static structure: FieldDescriptor[] = [['DeletePending', '<B=0']];
}

export class SMBSetFileBasicInfo extends Structure {
  static structure: FieldDescriptor[] = [
    ['CreationTime', '<q=0'],
    ['LastAccessTime', '<q=0'],
    ['LastWriteTime', '<q=0'],
    ['ChangeTime', '<q=0'],
    ['ExtFileAttributes', '<L=0'],
    ['Reserved', '<L=0'],
  ];
}

export class SMBFileStreamInformation extends Structure {
  static commonHdr: FieldDescriptor[] = [
    ['NextEntryOffset', '<L=0'],
    ['StreamNameLength', '<L=0'],
    ['StreamSize', '<q=0'],
    ['StreamAllocationSize', '<q=0'],
    ['StreamName', ':=""'],
  ];
}

export class SMBFileNetworkOpenInfo extends Structure {
  static structure: FieldDescriptor[] = [
    ['CreationTime', '<q=0'],
    ['LastAccessTime', '<q=0'],
    ['LastWriteTime', '<q=0'],
    ['ChangeTime', '<q=0'],
    ['AllocationSize', '<q=0'],
    ['EndOfFile', '<q=0'],
    ['FileAttributes', '<L=0'],
    ['Reserved', '<L=0'],
  ];
}

export class SMBSetFileEndOfFileInfo extends Structure {
  static structure: FieldDescriptor[] = [['EndOfFile', '<q=0']];
}

export class SMBNetShareEnum extends Structure {
  static structure: FieldDescriptor[] = [
    ['RAPOpcode', '<H=0'],
    ['ParamDesc', 'z'],
    ['DataDesc', 'z'],
    ['InfoLevel', '<H=0'],
    ['ReceiveBufferSize', '<H=0'],
  ];
}

export class SMBNetShareEnumResponse extends Structure {
  static structure: FieldDescriptor[] = [
    ['Status', '<H=0'],
    ['Convert', '<H=0'],
    ['EntriesReturned', '<H=0'],
    ['EntriesAvailable', '<H=0'],
  ];
}

export class NetShareInfo1 extends Structure {
  static structure: FieldDescriptor[] = [
    ['NetworkName', '13s=""'],
    ['Pad', '<B=0'],
    ['Type', '<H=0'],
    ['RemarkOffsetLow', '<H=0'],
    ['RemarkOffsetHigh', '<H=0'],
  ];
}

export class SMBNetServerGetInfoResponse extends Structure {
  static structure: FieldDescriptor[] = [
    ['Status', '<H=0'],
    ['Convert', '<H=0'],
    ['TotalBytesAvailable', '<H=0'],
  ];
}

export class SMBNetServerInfo1 extends Structure {
  static structure: FieldDescriptor[] = [
    ['ServerName', '16s=""'],
    ['MajorVersion', 'B=5'],
    ['MinorVersion', 'B=0'],
    ['ServerType', '<L=3'],
    ['ServerCommentLow', '<H=0'],
    ['ServerCommentHigh', '<H=0'],
  ];
}

export class SMBNetShareGetInfo extends Structure {
  static structure: FieldDescriptor[] = [
    ['RAPOpcode', '<H=0'],
    ['ParamDesc', 'z'],
    ['DataDesc', 'z'],
    ['ShareName', 'z'],
    ['InfoLevel', '<H=0'],
    ['ReceiveBufferSize', '<H=0'],
  ];
}

export class SMBNetShareGetInfoResponse extends Structure {
  static structure: FieldDescriptor[] = [
    ['Status', '<H=0'],
    ['Convert', '<H=0'],
    ['TotalBytesAvailable', '<H=0'],
  ];
}

export class SecurityFeatures extends Structure {
  static structure: FieldDescriptor[] = [
    ['Key', '<L=0'],
    ['CID', '<H=0'],
    ['SequenceNumber', '<H=0'],
  ];
}

export class SMBMachine {
  name: string;
  type: number;
  comment: string;

  constructor(name: string, type: number, comment: string) {
    this.name = name;
    this.type = type;
    this.comment = comment;
  }
}

export class SMBDomain {
  name: string;
  type: number;
  masterBrowser: string;

  constructor(name: string, type: number, masterBrowser: string) {
    this.name = name;
    this.type = type;
    this.masterBrowser = masterBrowser;
  }
}
