import { Buffer } from 'node:buffer';
import { Structure, type FieldDescriptor } from '@impacket/structure';

export let RECALC_ACE_SIZE = true;

export class LDAP_SID_IDENTIFIER_AUTHORITY extends Structure {
  static structure: FieldDescriptor[] = [['Value', '6s']];
}

export class LDAP_SID extends Structure {
  static structure: FieldDescriptor[] = [
    ['Revision', '<B'],
    ['SubAuthorityCount', '<B'],
    ['IdentifierAuthority', ':', LDAP_SID_IDENTIFIER_AUTHORITY],
    ['SubLen', '_-SubAuthority', 'self["SubAuthorityCount"]*4'],
    ['SubAuthority', ':'],
  ];

  formatCanonical(): string {
    const idAuthByte = this.get('IdentifierAuthority') as LDAP_SID_IDENTIFIER_AUTHORITY;
    const idAuthVal = idAuthByte.get('Value') as Buffer;
    let ans = `S-${this.get('Revision')}-${idAuthVal[5]}`;
    const count = this.get('SubAuthorityCount') as number;
    const subAuth = this.get('SubAuthority') as Buffer;
    for (let i = 0; i < count; i++) {
      const val = subAuth.readUInt32LE(i * 4);
      ans += `-${val}`;
    }
    return ans;
  }

  fromCanonical(canonical: string): void {
    const items = canonical.split('-');
    this.set('Revision', Number.parseInt(items[1]!, 10));
    const idAuth = new LDAP_SID_IDENTIFIER_AUTHORITY();
    idAuth.set(
      'Value',
      Buffer.concat([Buffer.alloc(5, 0), Buffer.from([Number.parseInt(items[2]!, 10)])]),
    );
    this.set('IdentifierAuthority', idAuth);
    this.set('SubAuthorityCount', items.length - 3);
    let subAuth = Buffer.alloc(0);
    for (let i = 3; i < items.length; i++) {
      const buf = Buffer.alloc(4);
      buf.writeUInt32LE(Number.parseInt(items[i]!, 10));
      subAuth = Buffer.concat([subAuth, buf]);
    }
    this.set('SubAuthority', subAuth);
  }
}

export class SR_SECURITY_DESCRIPTOR extends Structure {
  static structure: FieldDescriptor[] = [
    ['Revision', 'c'],
    ['Sbz1', 'c'],
    ['Control', '<H'],
    ['OffsetOwner', '<L'],
    ['OffsetGroup', '<L'],
    ['OffsetSacl', '<L'],
    ['OffsetDacl', '<L'],
    ['Sacl', ':'],
    ['Dacl', ':'],
    ['OwnerSid', ':'],
    ['GroupSid', ':'],
  ];

  fromString(data: Buffer): this {
    super.fromString(data);
    if ((this.get('OffsetOwner') as number) !== 0) {
      this.set('OwnerSid', new LDAP_SID(data.subarray(this.get('OffsetOwner') as number)));
    } else {
      this.set('OwnerSid', Buffer.alloc(0));
    }
    if ((this.get('OffsetGroup') as number) !== 0) {
      this.set('GroupSid', new LDAP_SID(data.subarray(this.get('OffsetGroup') as number)));
    } else {
      this.set('GroupSid', Buffer.alloc(0));
    }
    if ((this.get('OffsetSacl') as number) !== 0) {
      this.set('Sacl', new ACL(data.subarray(this.get('OffsetSacl') as number)));
    } else {
      this.set('Sacl', Buffer.alloc(0));
    }
    if ((this.get('OffsetDacl') as number) !== 0) {
      this.set('Dacl', new ACL(data.subarray(this.get('OffsetDacl') as number)));
    } else {
      this.set('Dacl', Buffer.alloc(0));
    }
    return this;
  }

  getData(): Buffer {
    const headerlen = 20;
    let datalen = 0;
    const sacl = this.get('Sacl');
    if (sacl instanceof ACL) {
      this.set('OffsetSacl', headerlen + datalen);
      datalen += sacl.getData().length;
    } else if (Buffer.isBuffer(sacl) && sacl.length > 0) {
      this.set('OffsetSacl', headerlen + datalen);
      datalen += sacl.length;
    } else {
      this.set('OffsetSacl', 0);
    }
    const dacl = this.get('Dacl');
    if (dacl instanceof ACL) {
      this.set('OffsetDacl', headerlen + datalen);
      datalen += dacl.getData().length;
    } else if (Buffer.isBuffer(dacl) && dacl.length > 0) {
      this.set('OffsetDacl', headerlen + datalen);
      datalen += dacl.length;
    } else {
      this.set('OffsetDacl', 0);
    }
    const ownerSid = this.get('OwnerSid');
    if (ownerSid instanceof LDAP_SID) {
      this.set('OffsetOwner', headerlen + datalen);
      datalen += ownerSid.getData().length;
    } else if (Buffer.isBuffer(ownerSid) && ownerSid.length > 0) {
      this.set('OffsetOwner', headerlen + datalen);
      datalen += ownerSid.length;
    } else {
      this.set('OffsetOwner', 0);
    }
    const groupSid = this.get('GroupSid');
    if (groupSid instanceof LDAP_SID) {
      this.set('OffsetGroup', headerlen + datalen);
      datalen += groupSid.getData().length;
    } else if (Buffer.isBuffer(groupSid) && groupSid.length > 0) {
      this.set('OffsetGroup', headerlen + datalen);
      datalen += groupSid.length;
    } else {
      this.set('OffsetGroup', 0);
    }
    return super.getData();
  }
}

export class ACCESS_MASK extends Structure {
  static GENERIC_READ = 0x80000000;
  static GENERIC_WRITE = 0x40000000;
  static GENERIC_EXECUTE = 0x20000000;
  static GENERIC_ALL = 0x10000000;
  static MAXIMUM_ALLOWED = 0x02000000;
  static ACCESS_SYSTEM_SECURITY = 0x01000000;
  static SYNCHRONIZE = 0x00100000;
  static WRITE_OWNER = 0x00080000;
  static WRITE_DAC = 0x00040000;
  static READ_CONTROL = 0x00020000;
  static DELETE = 0x00010000;

  static structure: FieldDescriptor[] = [['Mask', '<L']];

  hasPriv(priv: number): boolean {
    return ((this.get('Mask') as number) & priv) >>> 0 === priv >>> 0;
  }
  setPriv(priv: number): void {
    this.set('Mask', ((this.get('Mask') as number) | priv) >>> 0);
  }
  removePriv(priv: number): void {
    this.set('Mask', ((this.get('Mask') as number) ^ priv) >>> 0);
  }
}

export class ACE extends Structure {
  static CONTAINER_INHERIT_ACE = 0x02;
  static FAILED_ACCESS_ACE_FLAG = 0x80;
  static INHERIT_ONLY_ACE = 0x08;
  static INHERITED_ACE = 0x10;
  static NO_PROPAGATE_INHERIT_ACE = 0x04;
  static OBJECT_INHERIT_ACE = 0x01;
  static SUCCESSFUL_ACCESS_ACE_FLAG = 0x40;

  static structure: FieldDescriptor[] = [
    ['AceType', 'B'],
    ['AceFlags', 'B'],
    ['AceSize', '<H'],
    ['AceLen', '_-Ace', 'self["AceSize"]-4'],
    ['Ace', ':'],
  ];

  typeName = '';
  aceData: Structure | Buffer = Buffer.alloc(0);

  constructor(data?: Buffer | null, alignment?: number) {
    super(null, alignment);
    this.typeName = '';
    this.aceData = Buffer.alloc(0);
    if (data) this.fromString(Buffer.from(data));
  }

  fromString(data: Buffer): this {
    super.fromString(data);
    const aceType = this.get('AceType') as number;
    const AceCls = ACE_TYPE_MAP[aceType];
    if (AceCls !== undefined) {
      this.typeName = AceCls.name;
      const aceBuf = this.get('Ace');
      const aceData = Buffer.isBuffer(aceBuf) ? aceBuf : Buffer.alloc(0);
      const ace = new AceCls(aceData);
      this.aceData = ace;
      this.set('Ace', ace);
    }
    return this;
  }

  getData(): Buffer {
    if (!this.fields['AceType']) this.set('AceType', 0);
    if (!this.fields['AceFlags']) this.set('AceFlags', 0);
    if (this.aceData instanceof Structure) {
      this.set('Ace', this.aceData.getData());
    } else if (Buffer.isBuffer(this.aceData)) {
      this.set('Ace', this.aceData);
    }
    if (RECALC_ACE_SIZE || !this.fields['AceSize']) {
      const ace = this.aceData;
      const aceLen = ace instanceof Structure ? ace.getData().length : (ace as Buffer).length;
      this.set('AceSize', aceLen + 4);
    }
    let aceSize = this.get('AceSize') as number;
    if (aceSize % 4 !== 0) {
      aceSize += aceSize % 4;
      this.set('AceSize', aceSize);
    }
    const data = super.getData();
    if (data.length < aceSize) {
      return Buffer.concat([data, Buffer.alloc(aceSize - data.length, 0)]);
    }
    return data;
  }

  hasFlag(flag: number): boolean {
    return ((this.get('AceFlags') as number) & flag) === flag;
  }
}

export class ACCESS_ALLOWED_ACE extends Structure {
  static ACE_TYPE = 0x00;
  static structure: FieldDescriptor[] = [
    ['Mask', ':', ACCESS_MASK],
    ['Sid', ':', LDAP_SID],
  ];
}

export class ACCESS_ALLOWED_OBJECT_ACE extends Structure {
  static ACE_TYPE = 0x05;
  static ACE_OBJECT_TYPE_PRESENT = 0x01;
  static ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02;
  static ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100;
  static ADS_RIGHT_DS_CREATE_CHILD = 0x00000001;
  static ADS_RIGHT_DS_DELETE_CHILD = 0x00000002;
  static ADS_RIGHT_DS_READ_PROP = 0x00000010;
  static ADS_RIGHT_DS_WRITE_PROP = 0x00000020;
  static ADS_RIGHT_DS_SELF = 0x00000008;

  static structure: FieldDescriptor[] = [
    ['Mask', ':', ACCESS_MASK],
    ['Flags', '<L'],
    ['ObjectTypeLen', '_-ObjectType', '(Flags & 0x01) ? 16 : 0'],
    ['ObjectType', ':=""'],
    [
      'InheritedObjectTypeLen',
      '_-InheritedObjectType',
      '(Flags & 0x02) ? 16 : 0',
    ],
    ['InheritedObjectType', ':=""'],
    ['Sid', ':', LDAP_SID],
  ];

  static checkObjectType(flags: number): number {
    if (flags & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT) return 16;
    return 0;
  }

  static checkInheritedObjectType(flags: number): number {
    if (flags & ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT) return 16;
    return 0;
  }

  getData(): Buffer {
    const objectType = this.get('ObjectType');
    if (Buffer.isBuffer(objectType) && objectType.length > 0) {
      this.set(
        'Flags',
        (this.get('Flags') as number) | ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT,
      );
    }
    const inheritedObjectType = this.get('InheritedObjectType');
    if (Buffer.isBuffer(inheritedObjectType) && inheritedObjectType.length > 0) {
      this.set(
        'Flags',
        (this.get('Flags') as number) | ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT,
      );
    }
    return super.getData();
  }

  hasFlag(flag: number): boolean {
    return ((this.get('Flags') as number) & flag) === flag;
  }
}

export class ACCESS_DENIED_ACE extends ACCESS_ALLOWED_ACE {
  static ACE_TYPE = 0x01;
}

export class ACCESS_DENIED_OBJECT_ACE extends ACCESS_ALLOWED_OBJECT_ACE {
  static ACE_TYPE = 0x06;
}

export class ACCESS_ALLOWED_CALLBACK_ACE extends Structure {
  static ACE_TYPE = 0x09;
  static structure: FieldDescriptor[] = [
    ['Mask', ':', ACCESS_MASK],
    ['Sid', ':', LDAP_SID],
    ['ApplicationData', ':'],
  ];
}

export class ACCESS_DENIED_CALLBACK_ACE extends ACCESS_ALLOWED_CALLBACK_ACE {
  static ACE_TYPE = 0x0a;
}

export class ACCESS_ALLOWED_CALLBACK_OBJECT_ACE extends ACCESS_ALLOWED_OBJECT_ACE {
  static ACE_TYPE = 0x0b;
  static structure: FieldDescriptor[] = [
    ['Mask', ':', ACCESS_MASK],
    ['Flags', '<L'],
    ['ObjectTypeLen', '_-ObjectType', '(Flags & 0x01) ? 16 : 0'],
    ['ObjectType', ':=""'],
    [
      'InheritedObjectTypeLen',
      '_-InheritedObjectType',
      '(Flags & 0x02) ? 16 : 0',
    ],
    ['InheritedObjectType', ':=""'],
    ['Sid', ':', LDAP_SID],
    ['ApplicationData', ':'],
  ];
}

export class ACCESS_DENIED_CALLBACK_OBJECT_ACE extends ACCESS_ALLOWED_CALLBACK_OBJECT_ACE {
  static ACE_TYPE = 0x0c;
}

export class SYSTEM_AUDIT_ACE extends ACCESS_ALLOWED_ACE {
  static ACE_TYPE = 0x02;
}

export class SYSTEM_AUDIT_OBJECT_ACE extends ACCESS_ALLOWED_CALLBACK_OBJECT_ACE {
  static ACE_TYPE = 0x07;
}

export class SYSTEM_AUDIT_CALLBACK_ACE extends ACCESS_ALLOWED_CALLBACK_ACE {
  static ACE_TYPE = 0x0d;
}

export class SYSTEM_MANDATORY_LABEL_ACE extends Structure {
  static ACE_TYPE = 0x11;
  static structure: FieldDescriptor[] = [
    ['Mask', ':', ACCESS_MASK],
    ['Sid', ':', LDAP_SID],
  ];
}

export class SYSTEM_AUDIT_CALLBACK_OBJECT_ACE extends ACCESS_ALLOWED_CALLBACK_OBJECT_ACE {
  static ACE_TYPE = 0x0f;
}

export class SYSTEM_RESOURCE_ATTRIBUTE_ACE extends ACCESS_ALLOWED_CALLBACK_ACE {
  static ACE_TYPE = 0x12;
}

export class SYSTEM_SCOPED_POLICY_ID_ACE extends ACCESS_ALLOWED_ACE {
  static ACE_TYPE = 0x13;
}

export const ACE_TYPES = [
  ACCESS_ALLOWED_ACE,
  ACCESS_ALLOWED_OBJECT_ACE,
  ACCESS_DENIED_ACE,
  ACCESS_DENIED_OBJECT_ACE,
  ACCESS_ALLOWED_CALLBACK_ACE,
  ACCESS_DENIED_CALLBACK_ACE,
  ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
  ACCESS_DENIED_CALLBACK_OBJECT_ACE,
  SYSTEM_AUDIT_ACE,
  SYSTEM_AUDIT_OBJECT_ACE,
  SYSTEM_AUDIT_CALLBACK_ACE,
  SYSTEM_MANDATORY_LABEL_ACE,
  SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
  SYSTEM_RESOURCE_ATTRIBUTE_ACE,
  SYSTEM_SCOPED_POLICY_ID_ACE,
];

export const ACE_TYPE_MAP: Record<number, typeof Structure> = Object.fromEntries(
  ACE_TYPES.map((cls) => [(cls as unknown as { ACE_TYPE: number }).ACE_TYPE, cls]),
);

export class ACL extends Structure {
  static structure: FieldDescriptor[] = [
    ['AclRevision', 'B'],
    ['Sbz1', 'B'],
    ['AclSize', '<H'],
    ['AceCount', '<H'],
    ['Sbz2', '<H'],
    ['DataLen', '_-Data', 'self["AclSize"]-8'],
    ['Data', ':'],
  ];

  aces: ACE[] = [];

  constructor(data?: Buffer | null, alignment?: number) {
    super(null, alignment);
    this.aces = [];
    if (data) this.fromString(Buffer.from(data));
  }

  fromString(data: Buffer): this {
    this.aces = [];
    super.fromString(data);
    const aceCount = this.get('AceCount') as number;
    let dataBuf = this.get('Data') as Buffer;
    for (let i = 0; i < aceCount; i++) {
      if (dataBuf.length === 0) {
        throw new Error(
          'ACL header indicated there are more ACLs to unpack, but there is no more data',
        );
      }
      const ace = new ACE(dataBuf);
      this.aces.push(ace);
      const aceSize = ace.get('AceSize') as number;
      dataBuf = dataBuf.subarray(aceSize);
    }
    this.set('Data', this.aces);
    return this;
  }

  getData(): Buffer {
    if (!this.fields['AclRevision']) this.set('AclRevision', 0x04);
    if (!this.fields['Sbz1']) this.set('Sbz1', 0);
    if (!this.fields['Sbz2']) this.set('Sbz2', 0);
    this.set('AceCount', this.aces.length);
    this.set('Data', Buffer.concat(this.aces.map((ace) => ace.getData())));
    this.set('AclSize', (this.get('Data') as Buffer).length + 8);
    const data = super.getData();
    this.set('Data', this.aces);
    return data;
  }
}

export const OBJECTTYPE_GUID_MAP: Record<string, string> = {
  group: 'bf967a9c-0de6-11d0-a285-00aa003049e2',
  domain: '19195a5a-6da0-11d0-afd3-00c04fd930c9',
  organizationalUnit: 'bf967aa5-0de6-11d0-a285-00aa003049e2',
  user: 'bf967aba-0de6-11d0-a285-00aa003049e2',
  groupPolicyContainer: 'f30e3bc2-9ff0-11d1-b603-0000f80367c1',
};

export enum LDAP_SERVER_SD_FLAGS {
  OWNER_SECURITY_INFORMATION = 0x1,
  GROUP_SECURITY_INFORMATION = 0x2,
  DACL_SECURITY_INFORMATION = 0x4,
  SACL_SECURITY_INFORMATION = 0x8,
}
