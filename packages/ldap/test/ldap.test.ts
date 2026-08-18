import { describe, it, expect } from 'vitest';
import { LDAPConnection, LDAPFilterSyntaxError, LDAPFilterInvalidException } from '../src/ldap.js';
import { Scope, DerefAliases, encodeFilter, type Filter } from '../src/ldapasn1.js';

describe('ldap — filter parser', () => {
  const conn = new LDAPConnection({ url: 'ldap://localhost' });

  it('parses a simple equality filter', () => {
    const f = conn.parseFilter('(objectClass=user)');
    expect('equalityMatch' in f).toBe(true);
    if ('equalityMatch' in f) {
      expect(f.equalityMatch.attributeDesc).toBe('objectClass');
      expect(f.equalityMatch.assertionValue).toBe('user');
    }
  });

  it('parses a present filter', () => {
    const f = conn.parseFilter('(objectClass=*)');
    expect('present' in f).toBe(true);
    if ('present' in f) expect(f.present).toBe('objectClass');
  });

  it('parses a substring filter', () => {
    const f = conn.parseFilter('(cn=test*mid*end)');
    expect('substrings' in f).toBe(true);
    if ('substrings' in f) {
      expect(f.substrings.type).toBe('cn');
      expect(f.substrings.substrings.length).toBe(3);
      expect('initial' in f.substrings.substrings[0]!).toBe(true);
      expect('any' in f.substrings.substrings[1]!).toBe(true);
      expect('final' in f.substrings.substrings[2]!).toBe(true);
    }
  });

  it('parses a substring filter with only initial', () => {
    const f = conn.parseFilter('(cn=test*)');
    expect('substrings' in f).toBe(true);
    if ('substrings' in f) {
      expect(f.substrings.substrings.length).toBe(1);
      expect('initial' in f.substrings.substrings[0]!).toBe(true);
    }
  });

  it('parses a substring filter with only final', () => {
    const f = conn.parseFilter('(cn=*end)');
    expect('substrings' in f).toBe(true);
    if ('substrings' in f) {
      expect(f.substrings.substrings.length).toBe(1);
      expect('final' in f.substrings.substrings[0]!).toBe(true);
    }
  });

  it('parses a greaterOrEqual filter', () => {
    const f = conn.parseFilter('(uidNumber>=1000)');
    expect('greaterOrEqual' in f).toBe(true);
  });

  it('parses a lessOrEqual filter', () => {
    const f = conn.parseFilter('(uidNumber<=2000)');
    expect('lessOrEqual' in f).toBe(true);
  });

  it('parses an approxMatch filter', () => {
    const f = conn.parseFilter('(cn~=test)');
    expect('approxMatch' in f).toBe(true);
  });

  it('parses an AND filter', () => {
    const f = conn.parseFilter('(&(objectClass=user)(cn=test))');
    expect('and' in f).toBe(true);
    if ('and' in f) expect(f.and.length).toBe(2);
  });

  it('parses an OR filter', () => {
    const f = conn.parseFilter('(|(objectClass=user)(objectClass=group))');
    expect('or' in f).toBe(true);
    if ('or' in f) expect(f.or.length).toBe(2);
  });

  it('parses a NOT filter', () => {
    const f = conn.parseFilter('(!(objectClass=user))');
    expect('not' in f).toBe(true);
    if ('not' in f) expect(f.not.length).toBe(1);
  });

  it('parses nested composite filters', () => {
    const f = conn.parseFilter('(&(objectClass=user)(|(cn=test)(cn=admin)))');
    expect('and' in f).toBe(true);
    if ('and' in f) {
      expect(f.and.length).toBe(2);
      expect('or' in f.and[1]!).toBe(true);
    }
  });

  it('parses an extensibleMatch filter', () => {
    const f = conn.parseFilter('(member:1.2.840.113556.1.4.1941:=CN=test)');
    expect('extensibleMatch' in f).toBe(true);
    if ('extensibleMatch' in f) {
      expect(f.extensibleMatch.matchingRule).toBe('1.2.840.113556.1.4.1941');
      expect(f.extensibleMatch.type).toBe('member');
    }
  });

  it('parses escaped hex characters', () => {
    const f = conn.parseFilter('(cn=te\\73t)');
    if ('equalityMatch' in f) {
      expect(f.equalityMatch.assertionValue).toBe('test');
    }
  });

  it('throws on unbalanced parens', () => {
    expect(() => conn.parseFilter('(objectClass=user')).toThrow(LDAPFilterSyntaxError);
    expect(() => conn.parseFilter('objectClass=user)')).toThrow(LDAPFilterSyntaxError);
  });

  it('throws on empty AND', () => {
    expect(() => conn.parseFilter('(&)')).toThrow(LDAPFilterInvalidException);
  });

  it('throws on empty OR', () => {
    expect(() => conn.parseFilter('(|)')).toThrow(LDAPFilterInvalidException);
  });

  it('throws on NOT with multiple elements', () => {
    expect(() => conn.parseFilter('(!(a=b)(c=d))')).toThrow(LDAPFilterInvalidException);
  });
});

describe('ldap — filter encode/decode round-trip', () => {
  it('encodes a complex filter and checks tag bytes', () => {
    const filter: Filter = {
      and: [
        { equalityMatch: { attributeDesc: 'objectClass', assertionValue: 'user' } },
        {
          or: [
            { equalityMatch: { attributeDesc: 'cn', assertionValue: 'test' } },
            { present: 'description' },
          ],
        },
        { not: [{ equalityMatch: { attributeDesc: 'sn', assertionValue: 'bad' } }] },
      ],
    };
    const encoded = encodeFilter(filter);
    expect(encoded[0]).toBe(0xa0);
    expect(encoded.length).toBeGreaterThan(20);
  });
});
