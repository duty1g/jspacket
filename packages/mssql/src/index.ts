// MSSQL version detection
// Ported from impacket mssql/version.py
// Build data by @splouchy from https://sqlserverbuilds.blogspot.com/
// Added by @Deft_

/** Maps build number to a human-readable label (e.g. "RTM", "(SP1)", "(CU3)"). */
type BuildMap = Record<number, string>;

/** Maps minor version to a tuple of [suffix, BuildMap]. */
type MinorMap = Record<number, [suffix: string, builds: BuildMap]>;

/** Maps major version to a tuple of [name, MinorMap]. */
type MajorMap = Record<number, [name: string, minors: MinorMap]>;

/** Top-level version name structure: [base name, MajorMap]. */
type VersionName = [baseName: string, majors: MajorMap];

const VERSION_NAME: VersionName = ["Microsoft SQL Server", {
  6: ["6", {
    0: [".0", {
      121: "RTM (no SP)",
      124: "(SP1)",
      139: "(SP2)",
      151: "(SP3)",
    }],
    50: [".5", {
      201: "RTM (no SP)",
      213: "(SP1)",
      240: "(SP2)",
      258: "(SP3)",
      281: "(SP4)",
      416: "(SP5)",
    }],
  }],
  7: ["7", {
    0: ["", {
      623: "RTM (no SP)",
      699: "(SP1)",
      842: "(SP2)",
      961: "(SP3)",
      1063: "(SP4)",
    }],
  }],
  8: ["2000", {
    0: ["", {
      194: "RTM (no SP)",
      384: "(SP1)",
      532: "(SP2)",
      760: "(SP3)",
      2039: "(SP4)",
    }],
  }],
  9: ["2005", {
    0: ["", {
      1399: "RTM (no SP)",
      2047: "(SP1)",
      3042: "(SP2)",
      4035: "(SP3)",
      5000: "(SP4)",
    }],
  }],
  10: ["2008", {
    0: ["", {
      1600: "RTM (no SP)",
      2531: "(SP1)",
      4000: "(SP2)",
      5500: "(SP3)",
      6000: "(SP4)",
    }],
    50: [" R2", {
      1600: "RTM (no SP)",
      2500: "(SP1)",
      4000: "(SP2)",
      6000: "(SP3)",
    }],
  }],
  11: ["2012", {
    0: ["", {
      2100: "RTM (no SP)",
      3000: "(SP1)",
      5058: "(SP2)",
      6020: "(SP3)",
      7001: "(SP4)",
    }],
  }],
  12: ["2014", {
    0: ["", {
      2000: "RTM (no SP)",
      4100: "(SP1)",
      5000: "(SP2)",
      6024: "(SP3)",
    }],
  }],
  13: ["2016", {
    0: ["", {
      1601: "RTM (no SP)",
      4001: "(SP1)",
      5026: "(SP2)",
      6300: "(SP3)",
    }],
  }],
  14: ["2017", {
    0: ["", {
      1000: "RTM",
      3006: "(CU1)",
      3008: "(CU2)",
      3015: "(CU3)",
      3022: "(CU4)",
      3023: "(CU5)",
      3025: "(CU6)",
      3026: "(CU7)",
      3029: "(CU8)",
      3030: "(CU9)",
      3037: "(CU10)",
      3038: "(CU11)",
      3045: "(CU12)",
      3048: "(CU13)",
      3076: "(CU14)",
      3162: "(CU15)",
      3223: "(CU16)",
      3228: "(CU17)",
      3257: "(CU18)",
      3281: "(CU19)",
      3294: "(CU20)",
      3335: "(CU21)",
      3356: "(CU22)",
      3381: "(CU23)",
      3391: "(CU24)",
      3401: "(CU25)",
      3411: "(CU26)",
      3421: "(CU27)",
      3430: "(CU28)",
      3436: "(CU29)",
      3451: "(CU30)",
      3456: "(CU31)",
    }],
  }],
  15: ["2019", {
    0: ["", {
      2000: "RTM",
      4003: "(CU1)",
      4013: "(CU2)",
      4023: "(CU3)",
      4033: "(CU4)",
      4043: "(CU5)",
      4053: "(CU6)",
      4063: "(CU7)",
      4073: "(CU8)",
      4102: "(CU9)",
      4123: "(CU10)",
      4138: "(CU11)",
      4153: "(CU12)",
      4178: "(CU13)",
      4188: "(CU14)",
      4198: "(CU15)",
      4223: "(CU16)",
      4249: "(CU17)",
      4261: "(CU18)",
      4298: "(CU19)",
      4312: "(CU20)",
    }],
  }],
  16: ["2022", {
    0: ["", {
      1000: "RTM",
      4003: "(CU1)",
      4015: "(CU2)",
      4025: "(CU3)",
      4035: "(CU4)",
    }],
  }],
}];

/**
 * Parses a 4-byte version buffer from an MSSQL server and resolves it
 * to a human-readable product name (e.g. "Microsoft SQL Server 2019 (CU8)").
 *
 * The buffer layout matches Python struct format `>bbH`:
 *   byte 0: major (signed int8)
 *   byte 1: minor (signed int8)
 *   bytes 2-3: build (unsigned big-endian uint16)
 */
export class MSSQLVersion {
  readonly major: number;
  readonly minor: number;
  readonly build: number;

  constructor(version: Buffer) {
    this.major = version.readInt8(0);
    this.minor = version.readInt8(1);
    this.build = version.readUInt16BE(2);
  }

  /** Returns the numeric version string, e.g. "15.0.4073". */
  get versionNumber(): string {
    return `${this.major}.${this.minor}.${this.build}`;
  }

  /**
   * Returns the human-readable version name by looking up the nested
   * VERSION_NAME map. Falls back to a partial string if the exact
   * major/minor/build combination is not found.
   */
  get versionName(): string {
    let result = VERSION_NAME[0];
    try {
      const majors = VERSION_NAME[1];
      const majorEntry = majors[this.major];
      if (majorEntry === undefined) return result;
      result += " " + majorEntry[0];

      const minorEntry = majorEntry[1][this.minor];
      if (minorEntry === undefined) return result;
      result += minorEntry[0] + " ";

      const buildLabel = minorEntry[1][this.build];
      if (buildLabel === undefined) return result;
      result += buildLabel;
    } catch {
      // swallow lookup errors, return whatever we have so far
    }
    return result;
  }

  /** Returns "version_name (version_number)", matching Python __repr__. */
  toString(): string {
    return `${this.versionName} (${this.versionNumber})`;
  }
}
