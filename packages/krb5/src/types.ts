import type { Buffer } from 'node:buffer';

export class KerberosException extends Error {}

export class Principal {
  type: number;
  components: string[];
  realm: string | null;

  constructor(
    value?: string | Principal | [string[], string] | string[],
    defaultRealm: string | null = null,
    type: number | null = null,
  ) {
    this.type = 0;
    this.components = [];
    this.realm = null;

    if (value === undefined || value === null) return;

    if (value instanceof Principal) {
      this.type = value.type;
      this.components = [...value.components];
      this.realm = value.realm;
    } else if (typeof value === 'string') {
      const m = value.match(/^((?:[^\\]|\\.)+?)(@((?:[^\\@]|\\.)+))?$/);
      if (!m) throw new KerberosException('invalid principal syntax');
      const unquote = (comp: string): string => comp.replace(/\\(.)/g, '$1');
      if (m[2] !== undefined) {
        this.realm = unquote(m[3]!);
      } else {
        this.realm = defaultRealm;
      }
      this.components = (m[1]!.match(/(?:[^\\/]|\\.)+/g) ?? []).map(unquote);
    } else if (Array.isArray(value)) {
      if (value.length === 2) {
        this.components = Array.isArray(value[0]) ? [...value[0]] : [value[0] as string];
        this.realm = value[value.length - 1] as string;
      } else if (value.length >= 2) {
        this.components = value.slice(0, -1) as string[];
        this.realm = value[value.length - 1] as string;
      } else {
        throw new KerberosException('invalid principal value');
      }
    }

    if (type !== null) this.type = type;
  }

  equals(other: Principal | string): boolean {
    if (typeof other === 'string') other = new Principal(other);
    return (
      (this.type === 0 || other.type === 0 || this.type === other.type) &&
      this.components.length === other.components.length &&
      this.components.every((c, i) => c === other!.components[i]) &&
      this.realm === other.realm
    );
  }

  toString(): string {
    const quote = (comp: string): string => comp.replace(/([\\/@])/g, '\\$1');
    let ret = this.components.map(quote).join('/');
    if (this.realm !== null) ret += `@${this.realm}`;
    return ret;
  }

  toRepr(): string {
    return `Principal(($JSON.stringify(this.components)}, ${JSON.stringify(this.realm)}), t=${this.type})`;
  }
}

export class Address {
  type: number | null = null;
  data: Buffer | null = null;

  toString(): string {
    return `(${this.type}, ${this.data})`;
  }
}

export class EncryptedData {
  etype: number | null = null;
  kvno: number | false = false;
  ciphertext: Buffer | null = null;
}

export class Ticket {
  tkt_vno: number | null = null;
  service_principal: Principal | null = null;
  encrypted_part: EncryptedData | null = null;

  toString(): string {
    return `<Ticket for ${this.service_principal} vno ${this.encrypted_part?.kvno}>`;
  }
}

export const KerberosTime = {
  INDEFINITE: new Date('1970-01-01T00:00:00Z'),
  toAsn1(dt: Date): string {
    const pad = (n: number, w: number): string => String(n).padStart(w, '0');
    return (
      pad(dt.getUTCFullYear(), 4) +
      pad(dt.getUTCMonth() + 1, 2) +
      pad(dt.getUTCDate(), 2) +
      pad(dt.getUTCHours(), 2) +
      pad(dt.getUTCMinutes(), 2) +
      pad(dt.getUTCSeconds(), 2) +
      'Z'
    );
  },
  fromAsn1(data: string): Date {
    const year = Number(data.slice(0, 4));
    const month = Number(data.slice(4, 6));
    const day = Number(data.slice(6, 8));
    const hour = Number(data.slice(8, 10));
    const minute = Number(data.slice(10, 12));
    const second = Number(data.slice(12, 14));
    if (data[14] !== 'Z') throw new KerberosException('timezone in KerberosTime is not Z');
    return new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  },
};
