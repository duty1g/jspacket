import { Buffer } from 'node:buffer';
import { uuidtupToBin } from '@impacket/uuid';
import {
  NDRCALL,
  NDRSTRUCT,
  NDRUNION,
  NDRPOINTER,
  NDRUniConformantArray,
  NDRUniConformantVaryingArray,
  NDRUniFixedArray,
  NDRBOOLEAN,
  NULL,
  type NDRField,
} from './ndr';
import {
  DWORD,
  ULONG,
  LPWSTR,
  WSTR,
  WCHAR,
  LPBYTE,
  LMSTR,
  GUID,
  LPLONG,
  SECURITY_INFORMATION,
} from './dtypes';
import { DCERPCException, type DCERPC_v5 } from './rpcrt';

export const MSRPC_UUID_SRVS = uuidtupToBin(['4B324FC8-1670-01D3-1278-5A47BF6EE188', '3.0'])!;

class DCERPCSessionError extends DCERPCException {
  constructor(errorString?: string | null, errorCode?: number | null, packet?: unknown) {
    super(errorString, errorCode, packet);
  }

  toString(): string {
    const key = this.error_code;
    if (key != null) {
      return `SRVS SessionError: code: 0x${key.toString(16)}`;
    }
    return `SRVS SessionError: unknown error code: 0x${(this.error_code ?? 0).toString(16)}`;
  }
}

export const SRVSVC_HANDLE = WCHAR;

export class PSRVSVC_HANDLE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SRVSVC_HANDLE]];
}

export class SHARE_DEL_HANDLE extends NDRSTRUCT {
  static align = 1;
  static structure: NDRField[] = [['Data', '20s=""']];
  getAlignment(): number {
    return 1;
  }
}

export class PSHARE_DEL_HANDLE extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_DEL_HANDLE]];
}

const MAX_PREFERRED_LENGTH = -1;

export const SESS_GUEST = 0x00000001;
export const SESS_NOENCRYPTION = 0x00000002;

export const STYPE_DISKTREE = 0x00000000;
export const STYPE_PRINTQ = 0x00000001;
export const STYPE_DEVICE = 0x00000002;
export const STYPE_IPC = 0x00000003;
export const STYPE_CLUSTER_FS = 0x02000000;
export const STYPE_CLUSTER_SOFS = 0x04000000;
export const STYPE_CLUSTER_DFS = 0x08000000;
export const STYPE_SPECIAL = 0x80000000;
export const STYPE_TEMPORARY = 0x40000000;
export const STYPE_MASK = 0x000000ff;

export const CSC_CACHE_MANUAL_REINT = 0x00;
export const CSC_CACHE_AUTO_REINT = 0x10;
export const CSC_CACHE_VDO = 0x20;
export const CSC_CACHE_NONE = 0x30;

export const PLATFORM_ID_DOS = 300;
export const PLATFORM_ID_OS2 = 400;
export const PLATFORM_ID_NT = 500;
export const PLATFORM_ID_OSF = 600;
export const PLATFORM_ID_VMS = 700;

export const SV_TYPE_WORKSTATION = 0x00000001;
export const SV_TYPE_SERVER = 0x00000002;
export const SV_TYPE_SQLSERVER = 0x00000004;
export const SV_TYPE_DOMAIN_CTRL = 0x00000008;
export const SV_TYPE_DOMAIN_BAKCTRL = 0x00000010;
export const SV_TYPE_TIME_SOURCE = 0x00000020;
export const SV_TYPE_AFP = 0x00000040;
export const SV_TYPE_NOVELL = 0x00000080;
export const SV_TYPE_DOMAIN_MEMBER = 0x00000100;
export const SV_TYPE_LOCAL_LIST_ONLY = 0x40000000;
export const SV_TYPE_PRINTQ_SERVER = 0x00000200;
export const SV_TYPE_DIALIN_SERVER = 0x00000400;
export const SV_TYPE_XENIX_SERVER = 0x00000800;
export const SV_TYPE_SERVER_MFPN = 0x00004000;
export const SV_TYPE_NT = 0x00001000;
export const SV_TYPE_WFW = 0x00002000;
export const SV_TYPE_SERVER_NT = 0x00008000;
export const SV_TYPE_POTENTIAL_BROWSER = 0x00010000;
export const SV_TYPE_BACKUP_BROWSER = 0x00020000;
export const SV_TYPE_MASTER_BROWSER = 0x00040000;
export const SV_TYPE_DOMAIN_MASTER = 0x00080000;
export const SV_TYPE_DOMAIN_ENUM = 0x80000000;
export const SV_TYPE_WINDOWS = 0x00400000;
export const SV_TYPE_ALL = 0xffffffff;
export const SV_TYPE_TERMINALSERVER = 0x02000000;
export const SV_TYPE_CLUSTER_NT = 0x10000000;
export const SV_TYPE_CLUSTER_VS_NT = 0x04000000;

export const NAMETYPE_USER = 1;
export const NAMETYPE_PASSWORD = 2;
export const NAMETYPE_GROUP = 3;
export const NAMETYPE_COMPUTER = 4;
export const NAMETYPE_EVENT = 5;
export const NAMETYPE_DOMAIN = 6;
export const NAMETYPE_SERVICE = 7;
export const NAMETYPE_NET = 8;
export const NAMETYPE_SHARE = 9;
export const NAMETYPE_MESSAGE = 10;
export const NAMETYPE_MESSAGEDEST = 11;
export const NAMETYPE_SHAREPASSWORD = 12;
export const NAMETYPE_WORKGROUP = 13;

export const ITYPE_UNC_COMPNAME = 4144;
export const ITYPE_UNC_WC = 4145;
export const ITYPE_UNC = 4096;
export const ITYPE_UNC_WC_PATH = 4097;
export const ITYPE_UNC_SYS_SEM = 6400;
export const ITYPE_UNC_SYS_SHMEM = 6656;
export const ITYPE_UNC_SYS_MSLOT = 6144;
export const ITYPE_UNC_SYS_PIPE = 6912;
export const ITYPE_UNC_SYS_QUEUE = 7680;
export const ITYPE_PATH_ABSND = 8194;
export const ITYPE_PATH_ABSD = 8198;
export const ITYPE_PATH_RELND = 8192;
export const ITYPE_PATH_RELD = 8196;
export const ITYPE_PATH_ABSND_WC = 8195;
export const ITYPE_PATH_ABSD_WC = 8199;
export const ITYPE_PATH_RELND_WC = 8193;
export const ITYPE_PATH_RELD_WC = 8197;
export const ITYPE_PATH_SYS_SEM = 10498;
export const ITYPE_PATH_SYS_SHMEM = 10754;
export const ITYPE_PATH_SYS_MSLOT = 10242;
export const ITYPE_PATH_SYS_PIPE = 11010;
export const ITYPE_PATH_SYS_COMM = 11266;
export const ITYPE_PATH_SYS_PRINT = 11522;
export const ITYPE_PATH_SYS_QUEUE = 11778;
export const ITYPE_PATH_SYS_SEM_M = 43266;
export const ITYPE_PATH_SYS_SHMEM_M = 43522;
export const ITYPE_PATH_SYS_MSLOT_M = 43010;
export const ITYPE_PATH_SYS_PIPE_M = 43778;
export const ITYPE_PATH_SYS_COMM_M = 44034;
export const ITYPE_PATH_SYS_PRINT_M = 44290;
export const ITYPE_PATH_SYS_QUEUE_M = 44546;
export const ITYPE_DEVICE_DISK = 16384;
export const ITYPE_DEVICE_LPT = 16400;
export const ITYPE_DEVICE_COM = 16416;
export const ITYPE_DEVICE_CON = 16448;
export const ITYPE_DEVICE_NUL = 16464;

export const SHARE_NETNAME_PARMNUM = 1;
export const SHARE_TYPE_PARMNUM = 3;
export const SHARE_REMARK_PARMNUM = 4;
export const SHARE_PERMISSIONS_PARMNUM = 5;
export const SHARE_MAX_USES_PARMNUM = 6;
export const SHARE_CURRENT_USES_PARMNUM = 7;
export const SHARE_PATH_PARMNUM = 8;
export const SHARE_PASSWD_PARMNUM = 9;
export const SHARE_FILE_SD_PARMNUM = 501;

export const SV_PLATFORM_ID_PARMNUM = 101;
export const SV_NAME_PARMNUM = 102;
export const SV_VERSION_MAJOR_PARMNUM = 103;
export const SV_VERSION_MINOR_PARMNUM = 104;
export const SV_TYPE_PARMNUM = 105;
export const SV_COMMENT_PARMNUM = 5;
export const SV_USERS_PARMNUM = 107;
export const SV_DISC_PARMNUM = 10;
export const SV_HIDDEN_PARMNUM = 16;
export const SV_ANNOUNCE_PARMNUM = 17;
export const SV_ANNDELTA_PARMNUM = 18;
export const SV_USERPATH_PARMNUM = 112;
export const SV_SESSOPENS_PARMNUM = 501;
export const SV_SESSVCS_PARMNUM = 502;
export const SV_OPENSEARCH_PARMNUM = 503;
export const SV_SIZREQBUF_PARMNUM = 504;
export const SV_INITWORKITEMS_PARMNUM = 505;
export const SV_MAXWORKITEMS_PARMNUM = 506;
export const SV_RAWWORKITEMS_PARMNUM = 507;
export const SV_IRPSTACKSIZE_PARMNUM = 508;
export const SV_MAXRAWBUFLEN_PARMNUM = 509;
export const SV_SESSUSERS_PARMNUM = 510;
export const SV_SESSCONNS_PARMNUM = 511;
export const SV_MAXNONPAGEDMEMORYUSAGE_PARMNUM = 512;
export const SV_MAXPAGEDMEMORYUSAGE_PARMNUM = 513;
export const SV_ENABLESOFTCOMPAT_PARMNUM = 514;
export const SV_ENABLEFORCEDLOGOFF_PARMNUM = 515;
export const SV_TIMESOURCE_PARMNUM = 516;
export const SV_ACCEPTDOWNLEVELAPIS_PARMNUM = 517;
export const SV_LMANNOUNCE_PARMNUM = 518;
export const SV_DOMAIN_PARMNUM = 519;
export const SV_MAXCOPYREADLEN_PARMNUM = 520;
export const SV_MAXCOPYWRITELEN_PARMNUM = 521;
export const SV_MINKEEPSEARCH_PARMNUM = 522;
export const SV_MAXKEEPSEARCH_PARMNUM = 523;
export const SV_MINKEEPCOMPLSEARCH_PARMNUM = 524;
export const SV_MAXKEEPCOMPLSEARCH_PARMNUM = 525;
export const SV_THREADCOUNTADD_PARMNUM = 526;
export const SV_NUMBLOCKTHREADS_PARMNUM = 527;
export const SV_SCAVTIMEOUT_PARMNUM = 528;
export const SV_MINRCVQUEUE_PARMNUM = 529;
export const SV_MINFREEWORKITEMS_PARMNUM = 530;
export const SV_XACTMEMSIZE_PARMNUM = 531;
export const SV_THREADPRIORITY_PARMNUM = 532;
export const SV_MAXMPXCT_PARMNUM = 533;
export const SV_OPLOCKBREAKWAIT_PARMNUM = 534;
export const SV_OPLOCKBREAKRESPONSEWAIT_PARMNUM = 535;
export const SV_ENABLEOPLOCKS_PARMNUM = 536;
export const SV_ENABLEOPLOCKFORCECLOSE_PARMNUM = 537;
export const SV_ENABLEFCBOPENS_PARMNUM = 538;
export const SV_ENABLERAW_PARMNUM = 539;
export const SV_ENABLESHAREDNETDRIVES_PARMNUM = 540;
export const SV_MINFREECONNECTIONS_PARMNUM = 541;
export const SV_MAXFREECONNECTIONS_PARMNUM = 542;
export const SV_INITSESSTABLE_PARMNUM = 543;
export const SV_INITCONNTABLE_PARMNUM = 544;
export const SV_INITFILETABLE_PARMNUM = 545;
export const SV_INITSEARCHTABLE_PARMNUM = 546;
export const SV_ALERTSCHEDULE_PARMNUM = 547;
export const SV_ERRORTHRESHOLD_PARMNUM = 548;
export const SV_NETWORKERRORTHRESHOLD_PARMNUM = 549;
export const SV_DISKSPACETHRESHOLD_PARMNUM = 550;
export const SV_MAXLINKDELAY_PARMNUM = 552;
export const SV_MINLINKTHROUGHPUT_PARMNUM = 553;
export const SV_LINKINFOVALIDTIME_PARMNUM = 554;
export const SV_SCAVQOSINFOUPDATETIME_PARMNUM = 555;
export const SV_MAXWORKITEMIDLETIME_PARMNUM = 556;

export const PKT_ENTRY_TYPE_CAIRO = 0x0001;
export const PKT_ENTRY_TYPE_MACHINE = 0x0002;
export const PKT_ENTRY_TYPE_NONCAIRO = 0x0004;
export const PKT_ENTRY_TYPE_LEAFONLY = 0x0008;
export const PKT_ENTRY_TYPE_OUTSIDE_MY_DOM = 0x0010;
export const PKT_ENTRY_TYPE_INSITE_ONLY = 0x0020;
export const PKT_ENTRY_TYPE_REFERRAL_SVC = 0x0080;
export const PKT_ENTRY_TYPE_PERMANENT = 0x0100;
export const PKT_ENTRY_TYPE_LOCAL = 0x0400;
export const PKT_ENTRY_TYPE_LOCAL_XPOINT = 0x0800;
export const PKT_ENTRY_TYPE_MACH_SHARE = 0x1000;
export const PKT_ENTRY_TYPE_OFFLINE = 0x2000;

export const PERM_FILE_READ = 0x00000001;
export const PERM_FILE_WRITE = 0x00000002;
export const PERM_FILE_CREATE = 0x00000004;
export const ACCESS_EXEC = 0x00000008;
export const ACCESS_DELETE = 0x00000010;
export const ACCESS_ATRIB = 0x00000020;
export const ACCESS_PERM = 0x00000040;

export const SHI1005_FLAGS_DFS = 0x00000001;
export const SHI1005_FLAGS_DFS_ROOT = 0x00000002;
export const CSC_MASK = 0x00000030;
export const SHI1005_FLAGS_RESTRICT_EXCLUSIVE_OPENS = 0x00000100;
export const SHI1005_FLAGS_FORCE_SHARED_DELETE = 0x00000200;
export const SHI1005_FLAGS_ALLOW_NAMESPACE_CACHING = 0x00000400;
export const SHI1005_FLAGS_ACCESS_BASED_DIRECTORY_ENUM = 0x00000800;
export const SHI1005_FLAGS_FORCE_LEVELII_OPLOCK = 0x00001000;
export const SHI1005_FLAGS_ENABLE_HASH = 0x00002000;
export const SHI1005_FLAGS_ENABLE_CA = 0x00004000;
export const SHI1005_FLAGS_ENCRYPT_DATA = 0x00008000;

export const SRV_SUPPORT_HASH_GENERATION = 0x0001;
export const SRV_HASH_GENERATION_ACTIVE = 0x0002;

export const SVTI2_REMAP_PIPE_NAMES = 0x00000002;
export const SVTI2_SCOPED_NAME = 0x00000004;

export const DFS_SITE_PRIMARY = 0x00000001;

export const DFS_SERVICE_TYPE_MASTER = 0x00000001;
export const DFS_SERVICE_TYPE_READONLY = 0x00000002;
export const DFS_SERVICE_TYPE_LOCAL = 0x00000004;
export const DFS_SERVICE_TYPE_REFERRAL = 0x00000008;
export const DFS_SERVICE_TYPE_ACTIVE = 0x00000010;
export const DFS_SERVICE_TYPE_DOWN_LEVEL = 0x00000020;
export const DFS_SERVICE_TYPE_COSTLIER = 0x00000040;
export const DFS_SERVICE_TYPE_OFFLINE = 0x00000080;

export const FILE_SUPERSEDE = 0x00000000;
export const FILE_OPEN = 0x00000001;
export const FILE_CREATE = 0x00000002;

export class CONNECTION_INFO_0 extends NDRSTRUCT {
  static structure: NDRField[] = [['coni0_id', DWORD]];
}

export class CONNECTION_INFO_0_ARRAY extends NDRUniConformantArray {
  static item = CONNECTION_INFO_0;
}

export class LPCONNECTION_INFO_0_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', CONNECTION_INFO_0_ARRAY]];
}

export class CONNECTION_INFO_1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['coni1_id', DWORD],
    ['coni1_type', DWORD],
    ['coni1_num_opens', DWORD],
    ['coni1_num_users', DWORD],
    ['coni1_time', DWORD],
    ['coni1_username', LPWSTR],
    ['coni1_netname', LPWSTR],
  ];
}

export class CONNECTION_INFO_1_ARRAY extends NDRUniConformantArray {
  static item = CONNECTION_INFO_1;
}

export class LPCONNECTION_INFO_1_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', CONNECTION_INFO_1_ARRAY]];
}

export class CONNECT_INFO_0_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPCONNECTION_INFO_0_ARRAY],
  ];
}

export class LPCONNECT_INFO_0_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', CONNECT_INFO_0_CONTAINER]];
}

export class CONNECT_INFO_1_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPCONNECTION_INFO_1_ARRAY],
  ];
}

export class LPCONNECT_INFO_1_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', CONNECT_INFO_1_CONTAINER]];
}

export class CONNECT_ENUM_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    0: ['Level0', LPCONNECT_INFO_0_CONTAINER],
    1: ['Level1', LPCONNECT_INFO_1_CONTAINER],
  };
}

export class CONNECT_ENUM_STRUCT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', DWORD],
    ['ConnectInfo', CONNECT_ENUM_UNION],
  ];
}

export class FILE_INFO_2 extends NDRSTRUCT {
  static structure: NDRField[] = [['fi2_id', DWORD]];
}

export class LPFILE_INFO_2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', FILE_INFO_2]];
}

export class FILE_INFO_2_ARRAY extends NDRUniConformantArray {
  static item = FILE_INFO_2;
}

export class LPFILE_INFO_2_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', FILE_INFO_2_ARRAY]];
}

export class FILE_INFO_3 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['fi3_id', DWORD],
    ['fi3_permissions', DWORD],
    ['fi3_num_locks', DWORD],
    ['fi3_path_name', LPWSTR],
    ['fi3_username', LPWSTR],
  ];
}

export class LPFILE_INFO_3 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', FILE_INFO_3]];
}

export class FILE_INFO_3_ARRAY extends NDRUniConformantArray {
  static item = FILE_INFO_3;
}

export class LPFILE_INFO_3_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', FILE_INFO_3_ARRAY]];
}

export class FILE_INFO_2_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPFILE_INFO_2_ARRAY],
  ];
}

export class LPFILE_INFO_2_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', FILE_INFO_2_CONTAINER]];
}

export class FILE_INFO_3_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPFILE_INFO_3_ARRAY],
  ];
}

export class LPFILE_INFO_3_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', FILE_INFO_3_CONTAINER]];
}

export class FILE_ENUM_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    2: ['Level2', LPFILE_INFO_2_CONTAINER],
    3: ['Level3', LPFILE_INFO_3_CONTAINER],
  };
}

export class FILE_ENUM_STRUCT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', DWORD],
    ['FileInfo', FILE_ENUM_UNION],
  ];
}

export class SESSION_INFO_0 extends NDRSTRUCT {
  static structure: NDRField[] = [['sesi0_cname', LPWSTR]];
}

export class LPSESSION_INFO_0 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_0]];
}

export class SESSION_INFO_0_ARRAY extends NDRUniConformantArray {
  static item = SESSION_INFO_0;
}

export class LPSESSION_INFO_0_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_0_ARRAY]];
}

export class SESSION_INFO_1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sesi1_cname', LPWSTR],
    ['sesi1_username', LPWSTR],
    ['sesi1_num_opens', DWORD],
    ['sesi1_time', DWORD],
    ['sesi1_idle_time', DWORD],
    ['sesi1_user_flags', DWORD],
  ];
}

export class LPSESSION_INFO_1 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_1]];
}

export class SESSION_INFO_1_ARRAY extends NDRUniConformantArray {
  static item = SESSION_INFO_1;
}

export class LPSESSION_INFO_1_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_1_ARRAY]];
}

export class SESSION_INFO_2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sesi2_cname', LPWSTR],
    ['sesi2_username', LPWSTR],
    ['sesi2_num_opens', DWORD],
    ['sesi2_time', DWORD],
    ['sesi2_idle_time', DWORD],
    ['sesi2_user_flags', DWORD],
    ['sesi2_cltype_name', LPWSTR],
  ];
}

export class LPSESSION_INFO_2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_2]];
}

export class SESSION_INFO_2_ARRAY extends NDRUniConformantArray {
  static item = SESSION_INFO_2;
}

export class LPSESSION_INFO_2_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_2_ARRAY]];
}

export class SESSION_INFO_10 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sesi10_cname', LPWSTR],
    ['sesi10_username', LPWSTR],
    ['sesi10_time', DWORD],
    ['sesi10_idle_time', DWORD],
  ];
}

export class LPSESSION_INFO_10 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_10]];
}

export class SESSION_INFO_10_ARRAY extends NDRUniConformantArray {
  static item = SESSION_INFO_10;
}

export class LPSESSION_INFO_10_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_10_ARRAY]];
}

export class SESSION_INFO_502 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sesi502_cname', LPWSTR],
    ['sesi502_username', LPWSTR],
    ['sesi502_num_opens', DWORD],
    ['sesi502_time', DWORD],
    ['sesi502_idle_time', DWORD],
    ['sesi502_user_flags', DWORD],
    ['sesi502_cltype_name', LPWSTR],
    ['sesi502_transport', LPWSTR],
  ];
}

export class LPSESSION_INFO_502 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_502]];
}

export class SESSION_INFO_502_ARRAY extends NDRUniConformantArray {
  static item = SESSION_INFO_502;
}

export class LPSESSION_INFO_502_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_502_ARRAY]];
}

export class SESSION_INFO_0_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSESSION_INFO_0_ARRAY],
  ];
}

export class LPSESSION_INFO_0_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_0_CONTAINER]];
}

export class SESSION_INFO_1_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSESSION_INFO_1_ARRAY],
  ];
}

export class LPSESSION_INFO_1_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_1_CONTAINER]];
}

export class SESSION_INFO_2_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSESSION_INFO_2_ARRAY],
  ];
}

export class LPSESSION_INFO_2_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_2_CONTAINER]];
}

export class SESSION_INFO_10_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSESSION_INFO_10_ARRAY],
  ];
}

export class LPSESSION_INFO_10_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_10_CONTAINER]];
}

export class SESSION_INFO_502_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSESSION_INFO_502_ARRAY],
  ];
}

export class LPSESSION_INFO_502_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SESSION_INFO_502_CONTAINER]];
}

export class SESSION_ENUM_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    0: ['Level0', LPSESSION_INFO_0_CONTAINER],
    1: ['Level1', LPSESSION_INFO_1_CONTAINER],
    2: ['Level2', LPSESSION_INFO_2_CONTAINER],
    10: ['Level10', LPSESSION_INFO_10_CONTAINER],
    502: ['Level502', LPSESSION_INFO_502_CONTAINER],
  };
}

export class SESSION_ENUM_STRUCT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', DWORD],
    ['SessionInfo', SESSION_ENUM_UNION],
  ];
}

export class SHARE_INFO_0 extends NDRSTRUCT {
  static structure: NDRField[] = [['shi0_netname', LPWSTR]];
}

export class LPSHARE_INFO_0 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_0]];
}

export class SHARE_INFO_0_ARRAY extends NDRUniConformantArray {
  static item = SHARE_INFO_0;
}

export class LPSHARE_INFO_0_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_0_ARRAY]];
}

export class SHARE_INFO_1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['shi1_netname', LPWSTR],
    ['shi1_type', DWORD],
    ['shi1_remark', LPWSTR],
  ];
}

export class LPSHARE_INFO_1 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_1]];
}

export class SHARE_INFO_1_ARRAY extends NDRUniConformantArray {
  static item = SHARE_INFO_1;
}

export class LPSHARE_INFO_1_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_1_ARRAY]];
}

export class SHARE_INFO_2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['shi2_netname', LPWSTR],
    ['shi2_type', DWORD],
    ['shi2_remark', LPWSTR],
    ['shi2_permissions', DWORD],
    ['shi2_max_uses', DWORD],
    ['shi2_current_uses', DWORD],
    ['shi2_path', LPWSTR],
    ['shi2_passwd', LPWSTR],
  ];
}

export class LPSHARE_INFO_2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_2]];
}

export class SHARE_INFO_2_ARRAY extends NDRUniConformantArray {
  static item = SHARE_INFO_2;
}

export class LPSHARE_INFO_2_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_2_ARRAY]];
}

export class SHARE_INFO_501 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['shi501_netname', LPWSTR],
    ['shi501_type', DWORD],
    ['shi501_remark', LPWSTR],
    ['shi501_flags', DWORD],
  ];
}

export class LPSHARE_INFO_501 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_501]];
}

export class SHARE_INFO_501_ARRAY extends NDRUniConformantArray {
  static item = SHARE_INFO_501;
}

export class LPSHARE_INFO_501_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_501_ARRAY]];
}

export class SHARE_INFO_502 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['shi502_netname', LPWSTR],
    ['shi502_type', DWORD],
    ['shi502_remark', LPWSTR],
    ['shi502_permissions', DWORD],
    ['shi502_max_uses', DWORD],
    ['shi502_current_uses', DWORD],
    ['shi502_path', LPWSTR],
    ['shi502_passwd', LPWSTR],
    ['shi502_reserved', DWORD],
    ['shi502_security_descriptor', LPBYTE],
  ];
}

export class LPSHARE_INFO_502 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_502]];
}

export class SHARE_INFO_502_ARRAY extends NDRUniConformantArray {
  static item = SHARE_INFO_502;
}

export class LPSHARE_INFO_502_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_502_ARRAY]];
}

export class SHARE_INFO_503 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['shi503_netname', LPWSTR],
    ['shi503_type', DWORD],
    ['shi503_remark', LPWSTR],
    ['shi503_permissions', DWORD],
    ['shi503_max_uses', DWORD],
    ['shi503_current_uses', DWORD],
    ['shi503_path', LPWSTR],
    ['shi503_passwd', LPWSTR],
    ['shi503_servername', LPWSTR],
    ['shi503_reserved', DWORD],
    ['shi503_security_descriptor', LPBYTE],
  ];
}

export class LPSHARE_INFO_503 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_503]];
}

export class SHARE_INFO_503_ARRAY extends NDRUniConformantArray {
  static item = SHARE_INFO_503;
}

export class LPSHARE_INFO_503_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_503_ARRAY]];
}

export class SHARE_INFO_1004 extends NDRSTRUCT {
  static structure: NDRField[] = [['shi1004_remark', LPWSTR]];
}

export class LPSHARE_INFO_1004 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_1004]];
}

export class SHARE_INFO_1004_ARRAY extends NDRUniConformantArray {
  static item = SHARE_INFO_1004;
}

export class LPSHARE_INFO_1004_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_1004_ARRAY]];
}

export class SHARE_INFO_1005 extends NDRSTRUCT {
  static structure: NDRField[] = [['shi1005_flags', DWORD]];
}

export class LPSHARE_INFO_1005 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_1005]];
}

export class SHARE_INFO_1005_ARRAY extends NDRUniConformantArray {
  static item = SHARE_INFO_1004;
}

export class LPSHARE_INFO_1005_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_1005_ARRAY]];
}

export class SHARE_INFO_1006 extends NDRSTRUCT {
  static structure: NDRField[] = [['shi1006_max_uses', DWORD]];
}

export class LPSHARE_INFO_1006 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_1006]];
}

export class SHARE_INFO_1006_ARRAY extends NDRUniConformantArray {
  static item = SHARE_INFO_1006;
}

export class LPSHARE_INFO_1006_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_1006_ARRAY]];
}

export class SHARE_INFO_1501 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['shi1501_reserved', DWORD],
    ['shi1501_security_descriptor', NDRUniConformantArray],
  ];
}

export class LPSHARE_INFO_1501 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_1501]];
}

export class SHARE_INFO_1501_ARRAY extends NDRUniConformantArray {
  static item = SHARE_INFO_1501;
}

export class LPSHARE_INFO_1501_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_1501_ARRAY]];
}

export class SHARE_INFO_0_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSHARE_INFO_0_ARRAY],
  ];
}

export class LPSHARE_INFO_0_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_0_CONTAINER]];
}

export class SHARE_INFO_1_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSHARE_INFO_1_ARRAY],
  ];
}

export class LPSHARE_INFO_1_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_1_CONTAINER]];
}

export class SHARE_INFO_2_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSHARE_INFO_2_ARRAY],
  ];
}

export class LPSHARE_INFO_2_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_2_CONTAINER]];
}

export class SHARE_INFO_501_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSHARE_INFO_501_ARRAY],
  ];
}

export class LPSHARE_INFO_501_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_501_CONTAINER]];
}

export class SHARE_INFO_502_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSHARE_INFO_502_ARRAY],
  ];
}

export class LPSHARE_INFO_502_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_502_CONTAINER]];
}

export class SHARE_INFO_503_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSHARE_INFO_503_ARRAY],
  ];
}

export class LPSHARE_INFO_503_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SHARE_INFO_503_CONTAINER]];
}

export class SHARE_ENUM_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    0: ['Level0', LPSHARE_INFO_0_CONTAINER],
    1: ['Level1', LPSHARE_INFO_1_CONTAINER],
    2: ['Level2', LPSHARE_INFO_2_CONTAINER],
    501: ['Level501', LPSHARE_INFO_501_CONTAINER],
    502: ['Level502', LPSHARE_INFO_502_CONTAINER],
    503: ['Level503', LPSHARE_INFO_503_CONTAINER],
  };
}

export class SHARE_ENUM_STRUCT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', DWORD],
    ['ShareInfo', SHARE_ENUM_UNION],
  ];
}

export class STAT_SERVER_0 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sts0_start', DWORD],
    ['sts0_fopens', DWORD],
    ['sts0_devopens', DWORD],
    ['sts0_jobsqueued', DWORD],
    ['sts0_sopens', DWORD],
    ['sts0_stimedout', DWORD],
    ['sts0_serrorout', DWORD],
    ['sts0_pwerrors', DWORD],
    ['sts0_permerrors', DWORD],
    ['sts0_syserrors', DWORD],
    ['sts0_bytessent_low', DWORD],
    ['sts0_bytessent_high', DWORD],
    ['sts0_bytesrcvd_low', DWORD],
    ['sts0_bytesrcvd_high', DWORD],
    ['sts0_avresponse', DWORD],
    ['sts0_reqbufneed', DWORD],
    ['sts0_bigbufneed', DWORD],
  ];
}

export class LPSTAT_SERVER_0 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', STAT_SERVER_0]];
}

export class SERVER_INFO_100 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sv100_platform_id', DWORD],
    ['sv100_name', LPWSTR],
  ];
}

export class LPSERVER_INFO_100 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_100]];
}

export class SERVER_INFO_101 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sv101_platform_id', DWORD],
    ['sv101_name', LPWSTR],
    ['sv101_version_major', DWORD],
    ['sv101_version_minor', DWORD],
    ['sv101_type', DWORD],
    ['sv101_comment', LPWSTR],
  ];
}

export class LPSERVER_INFO_101 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_101]];
}

export class SERVER_INFO_102 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sv102_platform_id', DWORD],
    ['sv102_name', LPWSTR],
    ['sv102_version_major', DWORD],
    ['sv102_version_minor', DWORD],
    ['sv102_type', DWORD],
    ['sv102_comment', LPWSTR],
    ['sv102_users', DWORD],
    ['sv102_disc', DWORD],
    ['sv102_hidden', DWORD],
    ['sv102_announce', DWORD],
    ['sv102_anndelta', DWORD],
    ['sv102_licenses', DWORD],
    ['sv102_userpath', LPWSTR],
  ];
}

export class LPSERVER_INFO_102 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_102]];
}

export class SERVER_INFO_103 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sv103_platform_id', DWORD],
    ['sv103_name', LPWSTR],
    ['sv103_version_major', DWORD],
    ['sv103_version_minor', DWORD],
    ['sv103_type', DWORD],
    ['sv103_comment', LPWSTR],
    ['sv103_users', DWORD],
    ['sv103_disc', DWORD],
    ['sv103_hidden', DWORD],
    ['sv103_announce', DWORD],
    ['sv103_anndelta', DWORD],
    ['sv103_licenses', DWORD],
    ['sv103_userpath', LPWSTR],
    ['sv103_capabilities', DWORD],
  ];
}

export class LPSERVER_INFO_103 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_103]];
}

export class SERVER_INFO_502 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sv502_sessopens', DWORD],
    ['sv502_sessvcs', DWORD],
    ['sv502_opensearch', DWORD],
    ['sv502_sizreqbuf', DWORD],
    ['sv502_initworkitems', DWORD],
    ['sv502_maxworkitems', DWORD],
    ['sv502_rawworkitems', DWORD],
    ['sv502_irpstacksize', DWORD],
    ['sv502_maxrawbuflen', DWORD],
    ['sv502_sessusers', DWORD],
    ['sv502_sessconns', DWORD],
    ['sv502_maxpagedmemoryusage', DWORD],
    ['sv502_maxnonpagedmemoryusage', DWORD],
    ['sv502_enablesoftcompat', DWORD],
    ['sv502_enableforcedlogoff', DWORD],
    ['sv502_timesource', DWORD],
    ['sv502_acceptdownlevelapis', DWORD],
    ['sv502_lmannounce', DWORD],
  ];
}

export class LPSERVER_INFO_502 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_502]];
}

export class SERVER_INFO_503 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sv503_sessopens', DWORD],
    ['sv503_sessvcs', DWORD],
    ['sv503_opensearch', DWORD],
    ['sv503_sizreqbuf', DWORD],
    ['sv503_initworkitems', DWORD],
    ['sv503_maxworkitems', DWORD],
    ['sv503_rawworkitems', DWORD],
    ['sv503_irpstacksize', DWORD],
    ['sv503_maxrawbuflen', DWORD],
    ['sv503_sessusers', DWORD],
    ['sv503_sessconns', DWORD],
    ['sv503_maxpagedmemoryusage', DWORD],
    ['sv503_maxnonpagedmemoryusage', DWORD],
    ['sv503_enablesoftcompat', DWORD],
    ['sv503_enableforcedlogoff', DWORD],
    ['sv503_timesource', DWORD],
    ['sv503_acceptdownlevelapis', DWORD],
    ['sv503_lmannounce', DWORD],
    ['sv503_domain', LPWSTR],
    ['sv503_maxcopyreadlen', DWORD],
    ['sv503_maxcopywritelen', DWORD],
    ['sv503_minkeepsearch', DWORD],
    ['sv503_maxkeepsearch', DWORD],
    ['sv503_minkeepcomplsearch', DWORD],
    ['sv503_maxkeepcomplsearch', DWORD],
    ['sv503_threadcountadd', DWORD],
    ['sv503_numblockthreads', DWORD],
    ['sv503_scavtimeout', DWORD],
    ['sv503_minrcvqueue', DWORD],
    ['sv503_minfreeworkitems', DWORD],
    ['sv503_xactmemsize', DWORD],
    ['sv503_threadpriority', DWORD],
    ['sv503_maxmpxct', DWORD],
    ['sv503_oplockbreakwait', DWORD],
    ['sv503_oplockbreakresponsewait', DWORD],
    ['sv503_enableoplocks', DWORD],
    ['sv503_enableoplockforceclose', DWORD],
    ['sv503_enablefcbopens', DWORD],
    ['sv503_enableraw', DWORD],
    ['sv503_enablesharednetdrives', DWORD],
    ['sv503_minfreeconnections', DWORD],
    ['sv503_maxfreeconnections', DWORD],
  ];
}

export class LPSERVER_INFO_503 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_503]];
}

export class SERVER_INFO_599 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['sv599_sessopens', DWORD],
    ['sv599_sessvcs', DWORD],
    ['sv599_opensearch', DWORD],
    ['sv599_sizreqbuf', DWORD],
    ['sv599_initworkitems', DWORD],
    ['sv599_maxworkitems', DWORD],
    ['sv599_rawworkitems', DWORD],
    ['sv599_irpstacksize', DWORD],
    ['sv599_maxrawbuflen', DWORD],
    ['sv599_sessusers', DWORD],
    ['sv599_sessconns', DWORD],
    ['sv599_maxpagedmemoryusage', DWORD],
    ['sv599_maxnonpagedmemoryusage', DWORD],
    ['sv599_enablesoftcompat', DWORD],
    ['sv599_enableforcedlogoff', DWORD],
    ['sv599_timesource', DWORD],
    ['sv599_acceptdownlevelapis', DWORD],
    ['sv599_lmannounce', DWORD],
    ['sv599_domain', LPWSTR],
    ['sv599_maxcopyreadlen', DWORD],
    ['sv599_maxcopywritelen', DWORD],
    ['sv599_minkeepsearch', DWORD],
    ['sv599_maxkeepsearch', DWORD],
    ['sv599_minkeepcomplsearch', DWORD],
    ['sv599_maxkeepcomplsearch', DWORD],
    ['sv599_threadcountadd', DWORD],
    ['sv599_numblockthreads', DWORD],
    ['sv599_scavtimeout', DWORD],
    ['sv599_minrcvqueue', DWORD],
    ['sv599_minfreeworkitems', DWORD],
    ['sv599_xactmemsize', DWORD],
    ['sv599_threadpriority', DWORD],
    ['sv599_maxmpxct', DWORD],
    ['sv599_oplockbreakwait', DWORD],
    ['sv599_oplockbreakresponsewait', DWORD],
    ['sv599_enableoplocks', DWORD],
    ['sv599_enableoplockforceclose', DWORD],
    ['sv599_enablefcbopens', DWORD],
    ['sv599_enableraw', DWORD],
    ['sv599_enablesharednetdrives', DWORD],
    ['sv599_minfreeconnections', DWORD],
    ['sv599_maxfreeconnections', DWORD],
    ['sv599_initsesstable', DWORD],
    ['sv599_initconntable', DWORD],
    ['sv599_initfiletable', DWORD],
    ['sv599_initsearchtable', DWORD],
    ['sv599_alertschedule', DWORD],
    ['sv599_errorthreshold', DWORD],
    ['sv599_networkerrorthreshold', DWORD],
    ['sv599_diskspacethreshold', DWORD],
    ['sv599_reserved', DWORD],
    ['sv599_maxlinkdelay', DWORD],
    ['sv599_minlinkthroughput', DWORD],
    ['sv599_linkinfovalidtime', DWORD],
    ['sv599_scavqosinfoupdatetime', DWORD],
    ['sv599_maxworkitemidletime', DWORD],
  ];
}

export class LPSERVER_INFO_599 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_599]];
}

export class SERVER_INFO_1005 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1005_comment', LPWSTR]];
}

export class LPSERVER_INFO_1005 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1005]];
}

export class SERVER_INFO_1107 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1107_users', DWORD]];
}

export class LPSERVER_INFO_1107 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1107]];
}

export class SERVER_INFO_1010 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1010_disc', DWORD]];
}

export class LPSERVER_INFO_1010 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1010]];
}

export class SERVER_INFO_1016 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1016_hidden', DWORD]];
}

export class LPSERVER_INFO_1016 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1016]];
}

export class SERVER_INFO_1017 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1017_announce', DWORD]];
}

export class LPSERVER_INFO_1017 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1017]];
}

export class SERVER_INFO_1018 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1018_anndelta', DWORD]];
}

export class LPSERVER_INFO_1018 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1018]];
}

export class SERVER_INFO_1501 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1501_sessopens', DWORD]];
}

export class LPSERVER_INFO_1501 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1501]];
}

export class SERVER_INFO_1502 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1502_sessvcs', DWORD]];
}

export class LPSERVER_INFO_1502 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1502]];
}

export class SERVER_INFO_1503 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1503_opensearch', DWORD]];
}

export class LPSERVER_INFO_1503 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1503]];
}

export class SERVER_INFO_1506 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1506_maxworkitems', DWORD]];
}

export class LPSERVER_INFO_1506 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1506]];
}

export class SERVER_INFO_1510 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1510_sessusers', DWORD]];
}

export class LPSERVER_INFO_1510 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1510]];
}

export class SERVER_INFO_1511 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1511_sessconns', DWORD]];
}

export class LPSERVER_INFO_1511 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1511]];
}

export class SERVER_INFO_1512 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1512_maxnonpagedmemoryusage', DWORD]];
}

export class LPSERVER_INFO_1512 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1512]];
}

export class SERVER_INFO_1513 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1513_maxpagedmemoryusage', DWORD]];
}

export class LPSERVER_INFO_1513 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1513]];
}

export class SERVER_INFO_1514 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1514_enablesoftcompat', DWORD]];
}

export class LPSERVER_INFO_1514 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1514]];
}

export class SERVER_INFO_1515 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1515_enableforcedlogoff', DWORD]];
}

export class LPSERVER_INFO_1515 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1515]];
}

export class SERVER_INFO_1516 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1516_timesource', DWORD]];
}

export class LPSERVER_INFO_1516 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1516]];
}

export class SERVER_INFO_1518 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1518_lmannounce', DWORD]];
}

export class LPSERVER_INFO_1518 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1518]];
}

export class SERVER_INFO_1523 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1523_maxkeepsearch', DWORD]];
}

export class LPSERVER_INFO_1523 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1523]];
}

export class SERVER_INFO_1528 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1528_scavtimeout', DWORD]];
}

export class LPSERVER_INFO_1528 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1528]];
}

export class SERVER_INFO_1529 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1529_minrcvqueue', DWORD]];
}

export class LPSERVER_INFO_1529 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1529]];
}

export class SERVER_INFO_1530 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1530_minfreeworkitems', DWORD]];
}

export class LPSERVER_INFO_1530 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1530]];
}

export class SERVER_INFO_1533 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1533_maxmpxct', DWORD]];
}

export class LPSERVER_INFO_1533 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1533]];
}

export class SERVER_INFO_1534 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1534_oplockbreakwait', DWORD]];
}

export class LPSERVER_INFO_1534 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1534]];
}

export class SERVER_INFO_1535 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1535_oplockbreakresponsewait', DWORD]];
}

export class LPSERVER_INFO_1535 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1535]];
}

export class SERVER_INFO_1536 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1536_enableoplocks', DWORD]];
}

export class LPSERVER_INFO_1536 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1536]];
}

export class SERVER_INFO_1538 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1538_enablefcbopens', DWORD]];
}

export class LPSERVER_INFO_1538 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1538]];
}

export class SERVER_INFO_1539 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1539_enableraw', DWORD]];
}

export class LPSERVER_INFO_1539 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1539]];
}

export class SERVER_INFO_1540 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1540_enablesharednetdrives', DWORD]];
}

export class LPSERVER_INFO_1540 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1540]];
}

export class SERVER_INFO_1541 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1541_minfreeconnections', DWORD]];
}

export class LPSERVER_INFO_1541 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1541]];
}

export class SERVER_INFO_1542 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1542_maxfreeconnections', DWORD]];
}

export class LPSERVER_INFO_1542 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1542]];
}

export class SERVER_INFO_1543 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1543_initsesstable', DWORD]];
}

export class LPSERVER_INFO_1543 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1543]];
}

export class SERVER_INFO_1544 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1544_initconntable', DWORD]];
}

export class LPSERVER_INFO_1544 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1544]];
}

export class SERVER_INFO_1545 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1545_initfiletable', DWORD]];
}

export class LPSERVER_INFO_1545 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1545]];
}

export class SERVER_INFO_1546 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1546_initsearchtable', DWORD]];
}

export class LPSERVER_INFO_1546 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1546]];
}

export class SERVER_INFO_1547 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1547_alertschedule', DWORD]];
}

export class LPSERVER_INFO_1547 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1547]];
}

export class SERVER_INFO_1548 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1548_errorthreshold', DWORD]];
}

export class LPSERVER_INFO_1548 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1548]];
}

export class SERVER_INFO_1549 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1549_networkerrorthreshold', DWORD]];
}

export class LPSERVER_INFO_1549 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1549]];
}

export class SERVER_INFO_1550 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1550_diskspacethreshold', DWORD]];
}

export class LPSERVER_INFO_1550 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1550]];
}

export class SERVER_INFO_1552 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1552_maxlinkdelay', DWORD]];
}

export class LPSERVER_INFO_1552 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1552]];
}

export class SERVER_INFO_1553 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1553_minlinkthroughput', DWORD]];
}

export class LPSERVER_INFO_1553 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1553]];
}

export class SERVER_INFO_1554 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1554_linkinfovalidtime', DWORD]];
}

export class LPSERVER_INFO_1554 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1554]];
}

export class SERVER_INFO_1555 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1555_scavqosinfoupdatetime', DWORD]];
}

export class LPSERVER_INFO_1555 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1555]];
}

export class SERVER_INFO_1556 extends NDRSTRUCT {
  static structure: NDRField[] = [['sv1556_maxworkitemidletime', DWORD]];
}

export class LPSERVER_INFO_1556 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_INFO_1556]];
}

class WCHAR_ARRAY extends NDRSTRUCT {
  static commonHdr: NDRField[] = [
    ['Offset', '<L=0'],
    ['ActualCount', '<L=len(Data)/2'],
  ];
  static commonHdr64: NDRField[] = [
    ['Offset', '<Q=0'],
    ['ActualCount', '<Q=len(Data)/2'],
  ];
  static structure: NDRField[] = [['Data', ':']];

  set(key: string, value: unknown): void {
    if (key === 'Data') {
      if (typeof value === 'string') {
        this.fields[key] = Buffer.from(value, 'utf-16le');
      } else {
        this.fields[key] = value;
      }
      this.fields['ActualCount'] = null;
    } else {
      super.set(key, value);
    }
  }

  get(key: string): unknown {
    if (key === 'Data') {
      const buf = this.fields[key] as Buffer;
      if (Buffer.isBuffer(buf)) {
        return buf.toString('utf-16le');
      }
      return buf;
    }
    return super.get(key);
  }

  getDataLen(data: Buffer, offset = 0): number {
    return (this.get('ActualCount') as number) * 2;
  }
}

export class DISK_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [['Disk', WCHAR_ARRAY]];
}

export class LPDISK_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DISK_INFO]];
}

export class DISK_INFO_ARRAY extends NDRUniConformantVaryingArray {
  static item = DISK_INFO;
}

export class LPDISK_INFO_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DISK_INFO_ARRAY]];
}

export class DISK_ENUM_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPDISK_INFO_ARRAY],
  ];
}

export class LPDISK_ENUM_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DISK_ENUM_CONTAINER]];
}

export class SERVER_TRANSPORT_INFO_0 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['svti0_numberofvcs', DWORD],
    ['svti0_transportname', LPWSTR],
    ['svti0_transportaddress', NDRUniConformantArray],
    ['svti0_transportaddresslength', DWORD],
    ['svti0_networkaddress', LPWSTR],
  ];
}

export class LPSERVER_TRANSPORT_INFO_0 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_TRANSPORT_INFO_0]];
}

export class SERVER_TRANSPORT_INFO_0_ARRAY extends NDRUniConformantArray {
  static item = SERVER_TRANSPORT_INFO_0;
}

export class LPSERVER_TRANSPORT_INFO_0_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_TRANSPORT_INFO_0_ARRAY]];
}

export class SERVER_TRANSPORT_INFO_1 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['svti1_numberofvcs', DWORD],
    ['svti1_transportname', LPWSTR],
    ['svti1_transportaddress', NDRUniConformantArray],
    ['svti1_transportaddresslength', DWORD],
    ['svti1_networkaddress', LPWSTR],
    ['svti1_domain', LPWSTR],
  ];
}

export class LPSERVER_TRANSPORT_INFO_1 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_TRANSPORT_INFO_1]];
}

export class SERVER_TRANSPORT_INFO_1_ARRAY extends NDRUniConformantArray {
  static item = SERVER_TRANSPORT_INFO_1;
}

export class LPSERVER_TRANSPORT_INFO_1_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_TRANSPORT_INFO_1_ARRAY]];
}

export class SERVER_TRANSPORT_INFO_2 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['svti2_numberofvcs', DWORD],
    ['svti2_transportname', LPWSTR],
    ['svti2_transportaddress', NDRUniConformantArray],
    ['svti2_transportaddresslength', DWORD],
    ['svti2_networkaddress', LPWSTR],
    ['svti2_domain', LPWSTR],
    ['svti2_flags', DWORD],
  ];
}

export class LPSERVER_TRANSPORT_INFO_2 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_TRANSPORT_INFO_2]];
}

export class SERVER_TRANSPORT_INFO_2_ARRAY extends NDRUniConformantArray {
  static item = SERVER_TRANSPORT_INFO_2;
}

export class LPSERVER_TRANSPORT_INFO_2_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_TRANSPORT_INFO_2_ARRAY]];
}

export class PASSWORD_ARRAY extends NDRUniFixedArray {
  getDataLen(data: Buffer, offset = 0): number {
    return 256;
  }
}

export class SERVER_TRANSPORT_INFO_3 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['svti3_numberofvcs', DWORD],
    ['svti3_transportname', LPWSTR],
    ['svti3_transportaddress', NDRUniConformantArray],
    ['svti3_transportaddresslength', DWORD],
    ['svti3_networkaddress', LPWSTR],
    ['svti3_domain', LPWSTR],
    ['svti3_flags', DWORD],
    ['svti3_passwordlength', DWORD],
    ['svti3_password', PASSWORD_ARRAY],
  ];
}

export class LPSERVER_TRANSPORT_INFO_3 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_TRANSPORT_INFO_3]];
}

export class SERVER_TRANSPORT_INFO_3_ARRAY extends NDRUniConformantArray {
  static item = SERVER_TRANSPORT_INFO_3;
}

export class LPSERVER_TRANSPORT_INFO_3_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_TRANSPORT_INFO_3_ARRAY]];
}

export class SERVER_XPORT_INFO_0_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSERVER_TRANSPORT_INFO_0_ARRAY],
  ];
}

export class LPSERVER_XPORT_INFO_0_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_XPORT_INFO_0_CONTAINER]];
}

export class SERVER_XPORT_INFO_1_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSERVER_TRANSPORT_INFO_1_ARRAY],
  ];
}

export class LPSERVER_XPORT_INFO_1_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_XPORT_INFO_1_CONTAINER]];
}

export class SERVER_XPORT_INFO_2_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSERVER_TRANSPORT_INFO_2_ARRAY],
  ];
}

export class LPSERVER_XPORT_INFO_2_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_XPORT_INFO_2_CONTAINER]];
}

export class SERVER_XPORT_INFO_3_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSERVER_TRANSPORT_INFO_3_ARRAY],
  ];
}

export class LPSERVER_XPORT_INFO_3_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_XPORT_INFO_3_CONTAINER]];
}

export class SERVER_XPORT_ENUM_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    0: ['Level0', LPSERVER_XPORT_INFO_0_CONTAINER],
    1: ['Level1', LPSERVER_XPORT_INFO_1_CONTAINER],
    2: ['Level2', LPSERVER_XPORT_INFO_2_CONTAINER],
    3: ['Level3', LPSERVER_XPORT_INFO_3_CONTAINER],
  };
}

export class SERVER_XPORT_ENUM_STRUCT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', DWORD],
    ['XportInfo', SERVER_XPORT_ENUM_UNION],
  ];
}

export class SERVER_ALIAS_INFO_0 extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['srvai0_alias', LMSTR],
    ['srvai0_target', LMSTR],
    ['srvai0_default', NDRBOOLEAN],
    ['srvai0_reserved', ULONG],
  ];
}

export class LPSERVER_ALIAS_INFO_0 extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_ALIAS_INFO_0]];
}

export class SERVER_ALIAS_INFO_0_ARRAY extends NDRUniConformantArray {
  static item = SERVER_ALIAS_INFO_0;
}

export class LPSERVER_ALIAS_INFO_0_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_ALIAS_INFO_0_ARRAY]];
}

export class SERVER_ALIAS_INFO_0_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['EntriesRead', DWORD],
    ['Buffer', LPSERVER_ALIAS_INFO_0_ARRAY],
  ];
}

export class LPSERVER_ALIAS_INFO_0_CONTAINER extends NDRPOINTER {
  static referent: NDRField[] = [['Data', SERVER_ALIAS_INFO_0_CONTAINER]];
}

export class SERVER_ALIAS_ENUM_UNION extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    0: ['Level0', LPSERVER_ALIAS_INFO_0_CONTAINER],
  };
}

export class SERVER_ALIAS_ENUM_STRUCT extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Level', DWORD],
    ['ServerAliasInfo', SERVER_ALIAS_ENUM_UNION],
  ];
}

export class TIME_OF_DAY_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['tod_elapsedt', DWORD],
    ['tod_msecs', DWORD],
    ['tod_hours', DWORD],
    ['tod_mins', DWORD],
    ['tod_secs', DWORD],
    ['tod_hunds', DWORD],
    ['tod_timezone', DWORD],
    ['tod_tinterval', DWORD],
    ['tod_day', DWORD],
    ['tod_month', DWORD],
    ['tod_year', DWORD],
    ['tod_weekday', DWORD],
  ];
}

export class LPTIME_OF_DAY_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', TIME_OF_DAY_INFO]];
}

export class ADT_SECURITY_DESCRIPTOR extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Length', DWORD],
    ['Buffer', NDRUniConformantArray],
  ];
}

export class PADT_SECURITY_DESCRIPTOR extends NDRPOINTER {
  static referent: NDRField[] = [['Data', ADT_SECURITY_DESCRIPTOR]];
}

export class NET_DFS_ENTRY_ID extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Uid', GUID],
    ['Prefix', LPWSTR],
  ];
}

export class NET_DFS_ENTRY_ID_ARRAY extends NDRUniConformantArray {
  static item = NET_DFS_ENTRY_ID;
}

export class LPNET_DFS_ENTRY_ID_ARRAY extends NDRPOINTER {
  static referent: NDRField[] = [['Data', NET_DFS_ENTRY_ID_ARRAY]];
}

export class NET_DFS_ENTRY_ID_CONTAINER extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['Count', DWORD],
    ['Buffer', LPNET_DFS_ENTRY_ID_ARRAY],
  ];
}

export class DFS_SITENAME_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['SiteFlags', DWORD],
    ['SiteName', LPWSTR],
  ];
}

export class DFS_SITENAME_INFO_ARRAY extends NDRUniConformantArray {
  static item = DFS_SITENAME_INFO;
}

export class DFS_SITELIST_INFO extends NDRSTRUCT {
  static structure: NDRField[] = [
    ['cSites', DWORD],
    ['Site', DFS_SITENAME_INFO_ARRAY],
  ];
}

export class LPDFS_SITELIST_INFO extends NDRPOINTER {
  static referent: NDRField[] = [['Data', DFS_SITELIST_INFO]];
}

export class FILE_INFO extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    2: ['FileInfo2', LPFILE_INFO_2],
    3: ['FileInfo3', LPFILE_INFO_3],
  };
}

export class SHARE_INFO extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    0: ['ShareInfo0', LPSHARE_INFO_0],
    1: ['ShareInfo1', LPSHARE_INFO_1],
    2: ['ShareInfo2', LPSHARE_INFO_2],
    502: ['ShareInfo502', LPSHARE_INFO_502],
    1004: ['ShareInfo1004', LPSHARE_INFO_1004],
    1006: ['ShareInfo1006', LPSHARE_INFO_1006],
    1501: ['ShareInfo1501', LPSHARE_INFO_1501],
    1005: ['ShareInfo1005', LPSHARE_INFO_1005],
    501: ['ShareInfo501', LPSHARE_INFO_501],
    503: ['ShareInfo503', LPSHARE_INFO_503],
  };
}

export class SERVER_INFO extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    100: ['ServerInfo100', LPSERVER_INFO_100],
    101: ['ServerInfo101', LPSERVER_INFO_101],
    102: ['ServerInfo102', LPSERVER_INFO_102],
    103: ['ServerInfo103', LPSERVER_INFO_103],
    502: ['ServerInfo502', LPSERVER_INFO_502],
    503: ['ServerInfo503', LPSERVER_INFO_503],
    599: ['ServerInfo599', LPSERVER_INFO_599],
    1005: ['ServerInfo1005', LPSERVER_INFO_1005],
    1107: ['ServerInfo1107', LPSERVER_INFO_1107],
    1010: ['ServerInfo1010', LPSERVER_INFO_1010],
    1016: ['ServerInfo1016', LPSERVER_INFO_1016],
    1017: ['ServerInfo1017', LPSERVER_INFO_1017],
    1018: ['ServerInfo1018', LPSERVER_INFO_1018],
    1501: ['ServerInfo1501', LPSERVER_INFO_1501],
    1502: ['ServerInfo1502', LPSERVER_INFO_1502],
    1503: ['ServerInfo1503', LPSERVER_INFO_1503],
    1506: ['ServerInfo1506', LPSERVER_INFO_1506],
    1510: ['ServerInfo1510', LPSERVER_INFO_1510],
    1511: ['ServerInfo1511', LPSERVER_INFO_1511],
    1512: ['ServerInfo1512', LPSERVER_INFO_1512],
    1513: ['ServerInfo1513', LPSERVER_INFO_1513],
    1514: ['ServerInfo1514', LPSERVER_INFO_1514],
    1515: ['ServerInfo1515', LPSERVER_INFO_1515],
    1516: ['ServerInfo1516', LPSERVER_INFO_1516],
    1518: ['ServerInfo1518', LPSERVER_INFO_1518],
    1523: ['ServerInfo1523', LPSERVER_INFO_1523],
    1528: ['ServerInfo1528', LPSERVER_INFO_1528],
    1529: ['ServerInfo1529', LPSERVER_INFO_1529],
    1530: ['ServerInfo1530', LPSERVER_INFO_1530],
    1533: ['ServerInfo1533', LPSERVER_INFO_1533],
    1534: ['ServerInfo1534', LPSERVER_INFO_1534],
    1535: ['ServerInfo1535', LPSERVER_INFO_1535],
    1536: ['ServerInfo1536', LPSERVER_INFO_1536],
    1538: ['ServerInfo1538', LPSERVER_INFO_1538],
    1539: ['ServerInfo1539', LPSERVER_INFO_1539],
    1540: ['ServerInfo1540', LPSERVER_INFO_1540],
    1541: ['ServerInfo1541', LPSERVER_INFO_1541],
    1542: ['ServerInfo1542', LPSERVER_INFO_1542],
    1543: ['ServerInfo1543', LPSERVER_INFO_1543],
    1544: ['ServerInfo1544', LPSERVER_INFO_1544],
    1545: ['ServerInfo1545', LPSERVER_INFO_1545],
    1546: ['ServerInfo1546', LPSERVER_INFO_1546],
    1547: ['ServerInfo1547', LPSERVER_INFO_1547],
    1548: ['ServerInfo1548', LPSERVER_INFO_1548],
    1549: ['ServerInfo1549', LPSERVER_INFO_1549],
    1550: ['ServerInfo1550', LPSERVER_INFO_1550],
    1552: ['ServerInfo1552', LPSERVER_INFO_1552],
    1553: ['ServerInfo1553', LPSERVER_INFO_1553],
    1554: ['ServerInfo1554', LPSERVER_INFO_1554],
    1555: ['ServerInfo1555', LPSERVER_INFO_1555],
    1556: ['ServerInfo1556', LPSERVER_INFO_1556],
  };
}

export class TRANSPORT_INFO extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    0: ['Transport0', SERVER_TRANSPORT_INFO_0],
    1: ['Transport1', SERVER_TRANSPORT_INFO_1],
    2: ['Transport2', SERVER_TRANSPORT_INFO_2],
    3: ['Transport3', SERVER_TRANSPORT_INFO_3],
  };
}

export class SERVER_ALIAS_INFO extends NDRUNION {
  static commonHdr: NDRField[] = [['tag', DWORD]];
  static union: Partial<Record<number | 'default', NDRField | null>> = {
    0: ['ServerAliasInfo0', LPSERVER_ALIAS_INFO_0],
  };
}

export class NetrConnectionEnumResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['InfoStruct', CONNECT_ENUM_STRUCT],
    ['TotalEntries', DWORD],
    ['ResumeHandle', LPLONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrConnectionEnum extends NDRCALL {
  static opnum = 8;
  static Response = NetrConnectionEnumResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Qualifier', LPWSTR],
    ['InfoStruct', CONNECT_ENUM_STRUCT],
    ['PreferedMaximumLength', DWORD],
    ['ResumeHandle', LPLONG],
  ];
}

export class NetrFileEnumResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['InfoStruct', FILE_ENUM_STRUCT],
    ['TotalEntries', DWORD],
    ['ResumeHandle', LPLONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrFileEnum extends NDRCALL {
  static opnum = 9;
  static Response = NetrFileEnumResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['BasePath', LPWSTR],
    ['UserName', LPWSTR],
    ['InfoStruct', FILE_ENUM_STRUCT],
    ['PreferedMaximumLength', DWORD],
    ['ResumeHandle', LPLONG],
  ];
}

export class NetrFileGetInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['InfoStruct', FILE_INFO],
    ['ErrorCode', ULONG],
  ];
}

export class NetrFileGetInfo extends NDRCALL {
  static opnum = 10;
  static Response = NetrFileGetInfoResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['FileId', DWORD],
    ['Level', DWORD],
  ];
}

export class NetrFileCloseResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrFileClose extends NDRCALL {
  static opnum = 11;
  static Response = NetrFileCloseResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['FileId', DWORD],
  ];
}

export class NetrSessionEnumResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['InfoStruct', SESSION_ENUM_STRUCT],
    ['TotalEntries', DWORD],
    ['ResumeHandle', LPLONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrSessionEnum extends NDRCALL {
  static opnum = 12;
  static Response = NetrSessionEnumResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['ClientName', LPWSTR],
    ['UserName', LPWSTR],
    ['InfoStruct', SESSION_ENUM_STRUCT],
    ['PreferedMaximumLength', DWORD],
    ['ResumeHandle', LPLONG],
  ];
}

export class NetrSessionDelResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrSessionDel extends NDRCALL {
  static opnum = 13;
  static Response = NetrSessionDelResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['ClientName', LPWSTR],
    ['UserName', LPWSTR],
  ];
}

export class NetrShareAddResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ParmErr', LPLONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrShareAdd extends NDRCALL {
  static opnum = 14;
  static Response = NetrShareAddResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Level', DWORD],
    ['InfoStruct', SHARE_INFO],
    ['ParmErr', LPLONG],
  ];
}

export class NetrShareEnumResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['InfoStruct', SHARE_ENUM_STRUCT],
    ['TotalEntries', DWORD],
    ['ResumeHandle', LPLONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrShareEnum extends NDRCALL {
  static opnum = 15;
  static Response = NetrShareEnumResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['InfoStruct', SHARE_ENUM_STRUCT],
    ['PreferedMaximumLength', DWORD],
    ['ResumeHandle', LPLONG],
  ];
}

export class NetrShareEnumStickyResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['InfoStruct', SHARE_ENUM_STRUCT],
    ['TotalEntries', DWORD],
    ['ResumeHandle', LPLONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrShareEnumSticky extends NDRCALL {
  static opnum = 36;
  static Response = NetrShareEnumStickyResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['InfoStruct', SHARE_ENUM_STRUCT],
    ['PreferedMaximumLength', DWORD],
    ['ResumeHandle', LPLONG],
  ];
}

export class NetrShareGetInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['InfoStruct', SHARE_INFO],
    ['ErrorCode', ULONG],
  ];
}

export class NetrShareGetInfo extends NDRCALL {
  static opnum = 16;
  static Response = NetrShareGetInfoResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['NetName', WSTR],
    ['Level', DWORD],
  ];
}

export class NetrShareSetInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ParmErr', LPLONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrShareSetInfo extends NDRCALL {
  static opnum = 17;
  static Response = NetrShareSetInfoResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['NetName', WSTR],
    ['Level', DWORD],
    ['ShareInfo', SHARE_INFO],
    ['ParmErr', LPLONG],
  ];
}

export class NetrShareDelResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrShareDel extends NDRCALL {
  static opnum = 18;
  static Response = NetrShareDelResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['NetName', WSTR],
    ['Reserved', DWORD],
  ];
}

export class NetrShareDelStickyResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrShareDelSticky extends NDRCALL {
  static opnum = 19;
  static Response = NetrShareDelStickyResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['NetName', WSTR],
    ['Reserved', DWORD],
  ];
}

export class NetrShareDelStartResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ContextHandle', SHARE_DEL_HANDLE],
    ['ErrorCode', ULONG],
  ];
}

export class NetrShareDelStart extends NDRCALL {
  static opnum = 37;
  static Response = NetrShareDelStartResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['NetName', WSTR],
    ['Reserved', DWORD],
  ];
}

export class NetrShareDelCommitResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrShareDelCommit extends NDRCALL {
  static opnum = 38;
  static Response = NetrShareDelCommitResponse;
  static structure: NDRField[] = [['ContextHandle', SHARE_DEL_HANDLE]];
}

export class NetrShareCheckResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Type', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class NetrShareCheck extends NDRCALL {
  static opnum = 20;
  static Response = NetrShareCheckResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Device', WSTR],
  ];
}

export class NetrServerGetInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['InfoStruct', SERVER_INFO],
    ['ErrorCode', ULONG],
  ];
}

export class NetrServerGetInfo extends NDRCALL {
  static opnum = 21;
  static Response = NetrServerGetInfoResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Level', DWORD],
  ];
}

export class NetrServerSetInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ParmErr', LPLONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrServerSetInfo extends NDRCALL {
  static opnum = 22;
  static Response = NetrServerSetInfoResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Level', DWORD],
    ['InfoStruct', SERVER_INFO],
  ];
}

export class NetrServerDiskEnumResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['DiskInfoStruct', DISK_ENUM_CONTAINER],
    ['TotalEntries', DWORD],
    ['ResumeHandle', LPLONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrServerDiskEnum extends NDRCALL {
  static opnum = 23;
  static Response = NetrServerDiskEnumResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Level', DWORD],
    ['DiskInfoStruct', DISK_ENUM_CONTAINER],
    ['PreferedMaximumLength', DWORD],
    ['ResumeHandle', LPLONG],
  ];
}

export class NetrServerStatisticsGetResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['InfoStruct', LPSTAT_SERVER_0],
    ['ErrorCode', ULONG],
  ];
}

export class NetrServerStatisticsGet extends NDRCALL {
  static opnum = 24;
  static Response = NetrServerStatisticsGetResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Service', LPWSTR],
    ['Level', DWORD],
    ['Options', DWORD],
  ];
}

export class NetrRemoteTODResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['BufferPtr', LPTIME_OF_DAY_INFO],
    ['ErrorCode', ULONG],
  ];
}

export class NetrRemoteTOD extends NDRCALL {
  static opnum = 28;
  static Response = NetrRemoteTODResponse;
  static structure: NDRField[] = [['ServerName', PSRVSVC_HANDLE]];
}

export class NetrServerTransportAddResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrServerTransportAdd extends NDRCALL {
  static opnum = 25;
  static Response = NetrServerTransportAddResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Level', DWORD],
    ['Buffer', SERVER_TRANSPORT_INFO_0],
  ];
}

export class NetrServerTransportAddExResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrServerTransportAddEx extends NDRCALL {
  static opnum = 41;
  static Response = NetrServerTransportAddExResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Level', DWORD],
    ['Buffer', TRANSPORT_INFO],
  ];
}

export class NetrServerTransportEnumResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['InfoStruct', SERVER_XPORT_ENUM_STRUCT],
    ['TotalEntries', DWORD],
    ['ResumeHandle', LPLONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrServerTransportEnum extends NDRCALL {
  static opnum = 26;
  static Response = NetrServerTransportEnumResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['InfoStruct', SERVER_XPORT_ENUM_STRUCT],
    ['PreferedMaximumLength', DWORD],
    ['ResumeHandle', LPLONG],
  ];
}

export class NetrServerTransportDelResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrServerTransportDel extends NDRCALL {
  static opnum = 27;
  static Response = NetrServerTransportDelResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Level', DWORD],
    ['Buffer', SERVER_TRANSPORT_INFO_0],
  ];
}

export class NetrServerTransportDelExResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrServerTransportDelEx extends NDRCALL {
  static opnum = 53;
  static Response = NetrServerTransportDelExResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Level', DWORD],
    ['Buffer', TRANSPORT_INFO],
  ];
}

export class NetrpGetFileSecurityResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['SecurityDescriptor', PADT_SECURITY_DESCRIPTOR],
    ['ErrorCode', ULONG],
  ];
}

export class NetrpGetFileSecurity extends NDRCALL {
  static opnum = 39;
  static Response = NetrpGetFileSecurityResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['ShareName', LPWSTR],
    ['lpFileName', WSTR],
    ['RequestedInformation', SECURITY_INFORMATION],
  ];
}

export class NetrpSetFileSecurityResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrpSetFileSecurity extends NDRCALL {
  static opnum = 40;
  static Response = NetrpSetFileSecurityResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['ShareName', LPWSTR],
    ['lpFileName', WSTR],
    ['SecurityInformation', SECURITY_INFORMATION],
    ['SecurityDescriptor', ADT_SECURITY_DESCRIPTOR],
  ];
}

export class NetprPathTypeResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['PathType', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class NetprPathType extends NDRCALL {
  static opnum = 30;
  static Response = NetprPathTypeResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['PathName', WSTR],
    ['Flags', DWORD],
  ];
}

export class NetprPathCanonicalizeResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Outbuf', NDRUniConformantArray],
    ['PathType', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class NetprPathCanonicalize extends NDRCALL {
  static opnum = 31;
  static Response = NetprPathCanonicalizeResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['PathName', WSTR],
    ['OutbufLen', DWORD],
    ['Prefix', WSTR],
    ['PathType', DWORD],
    ['Flags', DWORD],
  ];
}

export class NetprPathCompareResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetprPathCompare extends NDRCALL {
  static opnum = 32;
  static Response = NetprPathCompareResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['PathName1', WSTR],
    ['PathName2', WSTR],
    ['PathType', DWORD],
    ['Flags', DWORD],
  ];
}

export class NetprNameValidateResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetprNameValidate extends NDRCALL {
  static opnum = 33;
  static Response = NetprNameValidateResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Name', WSTR],
    ['NameType', DWORD],
    ['Flags', DWORD],
  ];
}

export class NetprNameCanonicalizeResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Outbuf', NDRUniConformantArray],
    ['NameType', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class NetprNameCanonicalize extends NDRCALL {
  static opnum = 34;
  static Response = NetprNameCanonicalizeResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Name', WSTR],
    ['OutbufLen', DWORD],
    ['NameType', DWORD],
    ['Flags', DWORD],
  ];
}

export class NetprNameCompareResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetprNameCompare extends NDRCALL {
  static opnum = 35;
  static Response = NetprNameCompareResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Name1', WSTR],
    ['Name2', WSTR],
    ['NameType', DWORD],
    ['Flags', DWORD],
  ];
}

export class NetrDfsGetVersionResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['Version', DWORD],
    ['ErrorCode', ULONG],
  ];
}

export class NetrDfsGetVersion extends NDRCALL {
  static opnum = 43;
  static Response = NetrDfsGetVersionResponse;
  static structure: NDRField[] = [['ServerName', PSRVSVC_HANDLE]];
}

export class NetrDfsCreateLocalPartitionResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrDfsCreateLocalPartition extends NDRCALL {
  static opnum = 44;
  static Response = NetrDfsCreateLocalPartitionResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['ShareName', WSTR],
    ['EntryUid', GUID],
    ['EntryPrefix', WSTR],
    ['ShortName', WSTR],
    ['RelationInfo', NET_DFS_ENTRY_ID_CONTAINER],
    ['Force', DWORD],
  ];
}

export class NetrDfsDeleteLocalPartitionResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrDfsDeleteLocalPartition extends NDRCALL {
  static opnum = 45;
  static Response = NetrDfsDeleteLocalPartitionResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Uid', GUID],
    ['Prefix', WSTR],
  ];
}

export class NetrDfsSetLocalVolumeStateResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrDfsSetLocalVolumeState extends NDRCALL {
  static opnum = 46;
  static Response = NetrDfsSetLocalVolumeStateResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Uid', GUID],
    ['Prefix', WSTR],
    ['State', DWORD],
  ];
}

export class NetrDfsCreateExitPointResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ShortPrefix', WCHAR_ARRAY],
    ['ErrorCode', ULONG],
  ];
}

export class NetrDfsCreateExitPoint extends NDRCALL {
  static opnum = 48;
  static Response = NetrDfsCreateExitPointResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Uid', GUID],
    ['Prefix', WSTR],
    ['Type', DWORD],
    ['ShortPrefixLen', DWORD],
  ];
}

export class NetrDfsModifyPrefixResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrDfsModifyPrefix extends NDRCALL {
  static opnum = 50;
  static Response = NetrDfsModifyPrefixResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Uid', GUID],
    ['Prefix', WSTR],
  ];
}

export class NetrDfsDeleteExitPointResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrDfsDeleteExitPoint extends NDRCALL {
  static opnum = 49;
  static Response = NetrDfsDeleteExitPointResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Uid', GUID],
    ['Prefix', WSTR],
    ['Type', DWORD],
  ];
}

export class NetrDfsFixLocalVolumeResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrDfsFixLocalVolume extends NDRCALL {
  static opnum = 51;
  static Response = NetrDfsFixLocalVolumeResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['VolumeName', WSTR],
    ['EntryType', DWORD],
    ['ServiceType', DWORD],
    ['StgId', WSTR],
    ['EntryUid', GUID],
    ['EntryPrefix', WSTR],
    ['RelationInfo', NET_DFS_ENTRY_ID_CONTAINER],
    ['CreateDisposition', DWORD],
  ];
}

export class NetrDfsManagerReportSiteInfoResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['ppSiteInfo', LPDFS_SITELIST_INFO],
    ['ErrorCode', ULONG],
  ];
}

export class NetrDfsManagerReportSiteInfo extends NDRCALL {
  static opnum = 52;
  static Response = NetrDfsManagerReportSiteInfoResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['ppSiteInfo', LPDFS_SITELIST_INFO],
  ];
}

export class NetrServerAliasAddResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrServerAliasAdd extends NDRCALL {
  static opnum = 54;
  static Response = NetrServerAliasAddResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Level', DWORD],
    ['InfoStruct', SERVER_ALIAS_INFO],
  ];
}

export class NetrServerAliasEnumResponse extends NDRCALL {
  static structure: NDRField[] = [
    ['InfoStruct', SERVER_ALIAS_ENUM_STRUCT],
    ['TotalEntries', DWORD],
    ['ResumeHandle', LPLONG],
    ['ErrorCode', ULONG],
  ];
}

export class NetrServerAliasEnum extends NDRCALL {
  static opnum = 55;
  static Response = NetrServerAliasEnumResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['InfoStruct', SERVER_ALIAS_ENUM_STRUCT],
    ['PreferedMaximumLength', DWORD],
    ['ResumeHandle', LPLONG],
  ];
}

export class NetrServerAliasDelResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrServerAliasDel extends NDRCALL {
  static opnum = 56;
  static Response = NetrServerAliasDelResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Level', DWORD],
    ['InfoStruct', SERVER_ALIAS_INFO],
  ];
}

export class NetrShareDelExResponse extends NDRCALL {
  static structure: NDRField[] = [['ErrorCode', ULONG]];
}

export class NetrShareDelEx extends NDRCALL {
  static opnum = 57;
  static Response = NetrShareDelExResponse;
  static structure: NDRField[] = [
    ['ServerName', PSRVSVC_HANDLE],
    ['Level', DWORD],
    ['ShareInfo', SHARE_INFO],
  ];
}

const OPNUMS = {
  8: [NetrConnectionEnum, NetrConnectionEnumResponse] as const,
  9: [NetrFileEnum, NetrFileEnumResponse] as const,
  10: [NetrFileGetInfo, NetrFileGetInfoResponse] as const,
  11: [NetrFileClose, NetrFileCloseResponse] as const,
  12: [NetrSessionEnum, NetrSessionEnumResponse] as const,
  13: [NetrSessionDel, NetrSessionDelResponse] as const,
  14: [NetrShareAdd, NetrShareAddResponse] as const,
  15: [NetrShareEnum, NetrShareEnumResponse] as const,
  16: [NetrShareGetInfo, NetrShareGetInfoResponse] as const,
  17: [NetrShareSetInfo, NetrShareSetInfoResponse] as const,
  18: [NetrShareDel, NetrShareDelResponse] as const,
  19: [NetrShareDelSticky, NetrShareDelStickyResponse] as const,
  20: [NetrShareCheck, NetrShareCheckResponse] as const,
  21: [NetrServerGetInfo, NetrServerGetInfoResponse] as const,
  22: [NetrServerSetInfo, NetrServerSetInfoResponse] as const,
  23: [NetrServerDiskEnum, NetrServerDiskEnumResponse] as const,
  24: [NetrServerStatisticsGet, NetrServerStatisticsGetResponse] as const,
  25: [NetrServerTransportAdd, NetrServerTransportAddResponse] as const,
  26: [NetrServerTransportEnum, NetrServerTransportEnumResponse] as const,
  27: [NetrServerTransportDel, NetrServerTransportDelResponse] as const,
  28: [NetrRemoteTOD, NetrRemoteTODResponse] as const,
  30: [NetprPathType, NetprPathTypeResponse] as const,
  31: [NetprPathCanonicalize, NetprPathCanonicalizeResponse] as const,
  32: [NetprPathCompare, NetprPathCompareResponse] as const,
  33: [NetprNameValidate, NetprNameValidateResponse] as const,
  34: [NetprNameCanonicalize, NetprNameCanonicalizeResponse] as const,
  35: [NetprNameCompare, NetprNameCompareResponse] as const,
  36: [NetrShareEnumSticky, NetrShareEnumStickyResponse] as const,
  37: [NetrShareDelStart, NetrShareDelStartResponse] as const,
  38: [NetrShareDelCommit, NetrShareDelCommitResponse] as const,
  39: [NetrpGetFileSecurity, NetrpGetFileSecurityResponse] as const,
  40: [NetrpSetFileSecurity, NetrpSetFileSecurityResponse] as const,
  41: [NetrServerTransportAddEx, NetrServerTransportAddExResponse] as const,
  43: [NetrDfsGetVersion, NetrDfsGetVersionResponse] as const,
  44: [NetrDfsCreateLocalPartition, NetrDfsCreateLocalPartitionResponse] as const,
  45: [NetrDfsDeleteLocalPartition, NetrDfsDeleteLocalPartitionResponse] as const,
  46: [NetrDfsSetLocalVolumeState, NetrDfsSetLocalVolumeStateResponse] as const,
  48: [NetrDfsCreateExitPoint, NetrDfsCreateExitPointResponse] as const,
  49: [NetrDfsDeleteExitPoint, NetrDfsDeleteExitPointResponse] as const,
  50: [NetrDfsModifyPrefix, NetrDfsModifyPrefixResponse] as const,
  51: [NetrDfsFixLocalVolume, NetrDfsFixLocalVolumeResponse] as const,
  52: [NetrDfsManagerReportSiteInfo, NetrDfsManagerReportSiteInfoResponse] as const,
  53: [NetrServerTransportDelEx, NetrServerTransportDelExResponse] as const,
  54: [NetrServerAliasAdd, NetrServerAliasAddResponse] as const,
  55: [NetrServerAliasEnum, NetrServerAliasEnumResponse] as const,
  56: [NetrServerAliasDel, NetrServerAliasDelResponse] as const,
  57: [NetrShareDelEx, NetrShareDelExResponse] as const,
};

type DceRequestFn = <T>(req: unknown, uuid?: unknown, checkError?: boolean) => Promise<T>;

function checkNullString(str: string | typeof NULL): string | typeof NULL {
  if (str === NULL) return str;
  if (typeof str !== 'string') return str;
  if (str.length === 0 || str[str.length - 1] !== '\x00') return str + '\x00';
  return str;
}

export async function hNetrConnectionEnum(
  dce: DCERPC_v5,
  qualifier: unknown,
  level: number,
  resumeHandle = 0,
  preferedMaximumLength = 0xffffffff,
) {
  const request = new NetrConnectionEnum();
  request.set('ServerName', NULL);
  request.set('Qualifier', qualifier);
  const infoStruct = request.fields['InfoStruct'] as CONNECT_ENUM_STRUCT;
  infoStruct.set('Level', level);
  const connectInfo = infoStruct.fields['ConnectInfo'] as CONNECT_ENUM_UNION;
  connectInfo.set('tag', level);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  request.set('ResumeHandle', resumeHandle);
  return (dce as unknown as { request: DceRequestFn }).request<NetrConnectionEnumResponse>(request);
}

export async function hNetrFileEnum(
  dce: DCERPC_v5,
  basePath: unknown,
  userName: unknown,
  level: number,
  resumeHandle = 0,
  preferedMaximumLength = 0xffffffff,
) {
  const request = new NetrFileEnum();
  request.set('ServerName', NULL);
  request.set('BasePath', basePath);
  request.set('UserName', userName);
  const infoStruct = request.fields['InfoStruct'] as FILE_ENUM_STRUCT;
  infoStruct.set('Level', level);
  const fileInfo = infoStruct.fields['FileInfo'] as FILE_ENUM_UNION;
  fileInfo.set('tag', level);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  request.set('ResumeHandle', resumeHandle);
  return (dce as unknown as { request: DceRequestFn }).request<NetrFileEnumResponse>(request);
}

export async function hNetrFileGetInfo(dce: DCERPC_v5, fileId: number, level: number) {
  const request = new NetrFileGetInfo();
  request.set('ServerName', NULL);
  request.set('FileId', fileId);
  request.set('Level', level);
  return (dce as unknown as { request: DceRequestFn }).request<NetrFileGetInfoResponse>(request);
}

export async function hNetrFileClose(dce: DCERPC_v5, fileId: number) {
  const request = new NetrFileClose();
  request.set('ServerName', NULL);
  request.set('FileId', fileId);
  return (dce as unknown as { request: DceRequestFn }).request<NetrFileCloseResponse>(request);
}

export async function hNetrSessionEnum(
  dce: DCERPC_v5,
  clientName: unknown,
  userName: unknown,
  level: number,
  resumeHandle = 0,
  preferedMaximumLength = 0xffffffff,
) {
  const request = new NetrSessionEnum();
  request.set('ServerName', NULL);
  request.set('ClientName', clientName);
  request.set('UserName', userName);
  const infoStruct = request.fields['InfoStruct'] as SESSION_ENUM_STRUCT;
  infoStruct.set('Level', level);
  const sessionInfo = infoStruct.fields['SessionInfo'] as SESSION_ENUM_UNION;
  sessionInfo.set('tag', level);
  const levelArmName = `Level${level}` as keyof SESSION_ENUM_UNION['fields'];
  const levelContainer = sessionInfo.fields[levelArmName] as
    | LPSESSION_INFO_0_CONTAINER
    | LPSESSION_INFO_1_CONTAINER
    | LPSESSION_INFO_2_CONTAINER
    | LPSESSION_INFO_10_CONTAINER
    | LPSESSION_INFO_502_CONTAINER;
  const containerData = levelContainer.fields['Data'] as
    | SESSION_INFO_0_CONTAINER
    | SESSION_INFO_1_CONTAINER
    | SESSION_INFO_2_CONTAINER
    | SESSION_INFO_10_CONTAINER
    | SESSION_INFO_502_CONTAINER;
  containerData.set('Buffer', NULL);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  request.set('ResumeHandle', resumeHandle);
  return (dce as unknown as { request: DceRequestFn }).request<NetrSessionEnumResponse>(request);
}

export async function hNetrSessionDel(
  dce: DCERPC_v5,
  clientName: unknown,
  userName: unknown,
) {
  const request = new NetrSessionDel();
  request.set('ServerName', NULL);
  request.set('ClientName', clientName);
  request.set('UserName', userName);
  return (dce as unknown as { request: DceRequestFn }).request<NetrSessionDelResponse>(request);
}

export async function hNetrShareAdd(
  dce: DCERPC_v5,
  level: number,
  infoStruct: unknown,
) {
  const request = new NetrShareAdd();
  request.set('ServerName', NULL);
  request.set('Level', level);
  const infoS = request.fields['InfoStruct'] as SHARE_INFO;
  infoS.set('tag', level);
  const armName = `ShareInfo${level}` as keyof SHARE_INFO['fields'];
  infoS.set(armName, infoStruct);
  return (dce as unknown as { request: DceRequestFn }).request<NetrShareAddResponse>(request);
}

export async function hNetrShareDel(dce: DCERPC_v5, netName: string) {
  const request = new NetrShareDel();
  request.set('ServerName', NULL);
  request.set('NetName', checkNullString(netName) as string);
  return (dce as unknown as { request: DceRequestFn }).request<NetrShareDelResponse>(request);
}

export async function hNetrShareEnum(
  dce: DCERPC_v5,
  level: number,
  resumeHandle = 0,
  preferedMaximumLength = 0xffffffff,
  serverName = '\x00',
) {
  let sn = serverName;
  if (sn.length === 0 || sn[sn.length - 1] !== '\x00') sn += '\x00';
  const request = new NetrShareEnum();
  request.set('ServerName', sn);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  request.set('ResumeHandle', resumeHandle);
  const infoStruct = request.fields['InfoStruct'] as SHARE_ENUM_STRUCT;
  infoStruct.set('Level', level);
  const shareInfo = infoStruct.fields['ShareInfo'] as SHARE_ENUM_UNION;
  shareInfo.set('tag', level);
  const levelArmName = `Level${level}` as keyof SHARE_ENUM_UNION['fields'];
  const levelContainer = shareInfo.fields[levelArmName] as
    | LPSHARE_INFO_0_CONTAINER
    | LPSHARE_INFO_1_CONTAINER
    | LPSHARE_INFO_2_CONTAINER
    | LPSHARE_INFO_501_CONTAINER
    | LPSHARE_INFO_502_CONTAINER
    | LPSHARE_INFO_503_CONTAINER;
  const containerData = levelContainer.fields['Data'] as
    | SHARE_INFO_0_CONTAINER
    | SHARE_INFO_1_CONTAINER
    | SHARE_INFO_2_CONTAINER
    | SHARE_INFO_501_CONTAINER
    | SHARE_INFO_502_CONTAINER
    | SHARE_INFO_503_CONTAINER;
  containerData.set('Buffer', NULL);
  return (dce as unknown as { request: DceRequestFn }).request<NetrShareEnumResponse>(request);
}

export async function hNetrShareEnumSticky(
  dce: DCERPC_v5,
  level: number,
  resumeHandle = 0,
  preferedMaximumLength = 0xffffffff,
) {
  const request = new NetrShareEnumSticky();
  request.set('ServerName', NULL);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  request.set('ResumeHandle', resumeHandle);
  const infoStruct = request.fields['InfoStruct'] as SHARE_ENUM_STRUCT;
  infoStruct.set('Level', level);
  const shareInfo = infoStruct.fields['ShareInfo'] as SHARE_ENUM_UNION;
  shareInfo.set('tag', level);
  const levelArmName = `Level${level}` as keyof SHARE_ENUM_UNION['fields'];
  const levelContainer = shareInfo.fields[levelArmName] as
    | LPSHARE_INFO_0_CONTAINER
    | LPSHARE_INFO_1_CONTAINER
    | LPSHARE_INFO_2_CONTAINER
    | LPSHARE_INFO_501_CONTAINER
    | LPSHARE_INFO_502_CONTAINER
    | LPSHARE_INFO_503_CONTAINER;
  const containerData = levelContainer.fields['Data'] as
    | SHARE_INFO_0_CONTAINER
    | SHARE_INFO_1_CONTAINER
    | SHARE_INFO_2_CONTAINER
    | SHARE_INFO_501_CONTAINER
    | SHARE_INFO_502_CONTAINER
    | SHARE_INFO_503_CONTAINER;
  containerData.set('Buffer', NULL);
  return (dce as unknown as { request: DceRequestFn }).request<NetrShareEnumStickyResponse>(
    request,
  );
}

export async function hNetrShareGetInfo(dce: DCERPC_v5, netName: string, level: number) {
  const request = new NetrShareGetInfo();
  request.set('ServerName', NULL);
  request.set('NetName', checkNullString(netName) as string);
  request.set('Level', level);
  return (dce as unknown as { request: DceRequestFn }).request<NetrShareGetInfoResponse>(request);
}

export async function hNetrShareSetInfo(
  dce: DCERPC_v5,
  netName: string,
  level: number,
  shareInfo: unknown,
) {
  const request = new NetrShareSetInfo();
  request.set('ServerName', NULL);
  request.set('NetName', checkNullString(netName) as string);
  request.set('Level', level);
  const infoS = request.fields['ShareInfo'] as SHARE_INFO;
  infoS.set('tag', level);
  const armName = `ShareInfo${level}` as keyof SHARE_INFO['fields'];
  infoS.set(armName, shareInfo);
  return (dce as unknown as { request: DceRequestFn }).request<NetrShareSetInfoResponse>(request);
}

export async function hNetrShareDelSticky(dce: DCERPC_v5, netName: string) {
  const request = new NetrShareDelSticky();
  request.set('ServerName', NULL);
  request.set('NetName', checkNullString(netName) as string);
  return (dce as unknown as { request: DceRequestFn }).request<NetrShareDelStickyResponse>(request);
}

export async function hNetrShareDelStart(dce: DCERPC_v5, netName: string) {
  const request = new NetrShareDelStart();
  request.set('ServerName', NULL);
  request.set('NetName', checkNullString(netName) as string);
  return (dce as unknown as { request: DceRequestFn }).request<NetrShareDelStartResponse>(request);
}

export async function hNetrShareDelCommit(
  dce: DCERPC_v5,
  contextHandle: SHARE_DEL_HANDLE,
) {
  const request = new NetrShareDelCommit();
  request.set('ContextHandle', contextHandle);
  return (dce as unknown as { request: DceRequestFn }).request<NetrShareDelCommitResponse>(request);
}

export async function hNetrShareCheck(dce: DCERPC_v5, device: string) {
  const request = new NetrShareCheck();
  request.set('ServerName', NULL);
  request.set('Device', checkNullString(device) as string);
  return (dce as unknown as { request: DceRequestFn }).request<NetrShareCheckResponse>(request);
}

export async function hNetrServerGetInfo(dce: DCERPC_v5, level: number) {
  const request = new NetrServerGetInfo();
  request.set('ServerName', NULL);
  request.set('Level', level);
  return (dce as unknown as { request: DceRequestFn }).request<NetrServerGetInfoResponse>(request);
}

export async function hNetrServerDiskEnum(
  dce: DCERPC_v5,
  level: number,
  resumeHandle = 0,
  preferedMaximumLength = 0xffffffff,
) {
  const request = new NetrServerDiskEnum();
  request.set('ServerName', NULL);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  request.set('ResumeHandle', resumeHandle);
  request.set('Level', level);
  const diskInfoStruct = request.fields['DiskInfoStruct'] as DISK_ENUM_CONTAINER;
  diskInfoStruct.set('Buffer', NULL);
  return (dce as unknown as { request: DceRequestFn }).request<NetrServerDiskEnumResponse>(request);
}

export async function hNetrServerStatisticsGet(
  dce: DCERPC_v5,
  service: unknown,
  level: number,
  options: number,
) {
  const request = new NetrServerStatisticsGet();
  request.set('ServerName', NULL);
  request.set('Service', service);
  request.set('Level', level);
  request.set('Options', options);
  return (dce as unknown as { request: DceRequestFn }).request<NetrServerStatisticsGetResponse>(
    request,
  );
}

export async function hNetrRemoteTOD(dce: DCERPC_v5) {
  const request = new NetrRemoteTOD();
  request.set('ServerName', NULL);
  return (dce as unknown as { request: DceRequestFn }).request<NetrRemoteTODResponse>(request);
}

export async function hNetrServerTransportEnum(
  dce: DCERPC_v5,
  level: number,
  resumeHandle = 0,
  preferedMaximumLength = 0xffffffff,
) {
  const request = new NetrServerTransportEnum();
  request.set('ServerName', NULL);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  request.set('ResumeHandle', resumeHandle);
  const infoStruct = request.fields['InfoStruct'] as SERVER_XPORT_ENUM_STRUCT;
  infoStruct.set('Level', level);
  const xportInfo = infoStruct.fields['XportInfo'] as SERVER_XPORT_ENUM_UNION;
  xportInfo.set('tag', level);
  const levelArmName = `Level${level}` as keyof SERVER_XPORT_ENUM_UNION['fields'];
  const levelContainer = xportInfo.fields[levelArmName] as
    | LPSERVER_XPORT_INFO_0_CONTAINER
    | LPSERVER_XPORT_INFO_1_CONTAINER
    | LPSERVER_XPORT_INFO_2_CONTAINER
    | LPSERVER_XPORT_INFO_3_CONTAINER;
  const containerData = levelContainer.fields['Data'] as
    | SERVER_XPORT_INFO_0_CONTAINER
    | SERVER_XPORT_INFO_1_CONTAINER
    | SERVER_XPORT_INFO_2_CONTAINER
    | SERVER_XPORT_INFO_3_CONTAINER;
  containerData.set('Buffer', NULL);
  return (dce as unknown as { request: DceRequestFn }).request<NetrServerTransportEnumResponse>(
    request,
  );
}

export async function hNetrpGetFileSecurity(
  dce: DCERPC_v5,
  shareName: unknown,
  lpFileName: string,
  requestedInformation: number,
) {
  const request = new NetrpGetFileSecurity();
  request.set('ServerName', NULL);
  request.set('ShareName', shareName);
  request.set('lpFileName', checkNullString(lpFileName) as string);
  request.set('RequestedInformation', requestedInformation);
  return (dce as unknown as { request: DceRequestFn }).request<NetrpGetFileSecurityResponse>(
    request,
  );
}

export async function hNetrpSetFileSecurity(
  dce: DCERPC_v5,
  shareName: unknown,
  lpFileName: string,
  securityInformation: number,
  securityDescriptor: Buffer,
) {
  const request = new NetrpSetFileSecurity();
  request.set('ServerName', NULL);
  request.set('ShareName', shareName);
  request.set('lpFileName', checkNullString(lpFileName) as string);
  request.set('SecurityInformation', securityInformation);
  const sd = request.fields['SecurityDescriptor'] as ADT_SECURITY_DESCRIPTOR;
  sd.set('Length', securityDescriptor.length);
  sd.set('Buffer', Array.from(securityDescriptor));
  return (dce as unknown as { request: DceRequestFn }).request<NetrpSetFileSecurityResponse>(
    request,
  );
}

export async function hNetprPathType(
  dce: DCERPC_v5,
  pathName: string,
  flags: number,
) {
  const request = new NetprPathType();
  request.set('ServerName', NULL);
  request.set('PathName', checkNullString(pathName) as string);
  request.set('Flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<NetprPathTypeResponse>(request);
}

export async function hNetprPathCanonicalize(
  dce: DCERPC_v5,
  pathName: string,
  prefix: string,
  outbufLen = 50,
  pathType = 0,
  flags = 0,
) {
  const request = new NetprPathCanonicalize();
  request.set('ServerName', NULL);
  request.set('PathName', checkNullString(pathName) as string);
  request.set('OutbufLen', outbufLen);
  request.set('Prefix', checkNullString(prefix) as string);
  request.set('PathType', pathType);
  request.set('Flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<NetprPathCanonicalizeResponse>(
    request,
  );
}

export async function hNetprPathCompare(
  dce: DCERPC_v5,
  pathName1: string,
  pathName2: string,
  pathType = 0,
  flags = 0,
) {
  const request = new NetprPathCompare();
  request.set('ServerName', NULL);
  request.set('PathName1', checkNullString(pathName1) as string);
  request.set('PathName2', checkNullString(pathName2) as string);
  request.set('PathType', pathType);
  request.set('Flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<NetprPathCompareResponse>(request);
}

export async function hNetprNameValidate(
  dce: DCERPC_v5,
  name: string,
  nameType: number,
  flags = 0,
) {
  const request = new NetprNameValidate();
  request.set('ServerName', NULL);
  request.set('Name', checkNullString(name) as string);
  request.set('NameType', nameType);
  request.set('Flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<NetprNameValidateResponse>(request);
}

export async function hNetprNameCanonicalize(
  dce: DCERPC_v5,
  name: string,
  outbufLen = 50,
  nameType = 0,
  flags = 0,
) {
  const request = new NetprNameCanonicalize();
  request.set('ServerName', NULL);
  request.set('Name', checkNullString(name) as string);
  request.set('OutbufLen', outbufLen);
  request.set('NameType', nameType);
  request.set('Flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<NetprNameCanonicalizeResponse>(
    request,
  );
}

export async function hNetprNameCompare(
  dce: DCERPC_v5,
  name1: string,
  name2: string,
  nameType = 0,
  flags = 0,
) {
  const request = new NetprNameCompare();
  request.set('ServerName', NULL);
  request.set('Name1', checkNullString(name1) as string);
  request.set('Name2', checkNullString(name2) as string);
  request.set('NameType', nameType);
  request.set('Flags', flags);
  return (dce as unknown as { request: DceRequestFn }).request<NetprNameCompareResponse>(request);
}

export async function hNetrDfsGetVersion(dce: DCERPC_v5) {
  const request = new NetrDfsGetVersion();
  request.set('ServerName', NULL);
  return (dce as unknown as { request: DceRequestFn }).request<NetrDfsGetVersionResponse>(request);
}

export async function hNetrServerAliasAdd(
  dce: DCERPC_v5,
  level: number,
  aliasInfo: unknown,
) {
  const request = new NetrServerAliasAdd();
  request.set('ServerName', NULL);
  request.set('Level', level);
  const infoS = request.fields['InfoStruct'] as SERVER_ALIAS_INFO;
  infoS.set('tag', level);
  const armName = `ServerAliasInfo${level}` as keyof SERVER_ALIAS_INFO['fields'];
  infoS.set(armName, aliasInfo);
  return (dce as unknown as { request: DceRequestFn }).request<NetrServerAliasAddResponse>(request);
}

export async function hNetrServerAliasDel(
  dce: DCERPC_v5,
  level: number,
  aliasInfo: unknown,
) {
  const request = new NetrServerAliasDel();
  request.set('ServerName', NULL);
  request.set('Level', level);
  const infoS = request.fields['InfoStruct'] as SERVER_ALIAS_INFO;
  infoS.set('tag', level);
  const armName = `ServerAliasInfo${level}` as keyof SERVER_ALIAS_INFO['fields'];
  infoS.set(armName, aliasInfo);
  return (dce as unknown as { request: DceRequestFn }).request<NetrServerAliasDelResponse>(request);
}

export async function hNetrServerAliasEnum(
  dce: DCERPC_v5,
  level: number,
  resumeHandle = 0,
  preferedMaximumLength = 0xffffffff,
) {
  const request = new NetrServerAliasEnum();
  request.set('ServerName', NULL);
  const infoStruct = request.fields['InfoStruct'] as SERVER_ALIAS_ENUM_STRUCT;
  infoStruct.set('Level', level);
  const serverAliasInfo = infoStruct.fields['ServerAliasInfo'] as SERVER_ALIAS_ENUM_UNION;
  serverAliasInfo.set('tag', level);
  const levelArmName = `Level${level}` as keyof SERVER_ALIAS_ENUM_UNION['fields'];
  const levelContainer = serverAliasInfo.fields[levelArmName] as LPSERVER_ALIAS_INFO_0_CONTAINER;
  const containerData = levelContainer.fields['Data'] as SERVER_ALIAS_INFO_0_CONTAINER;
  containerData.set('Buffer', NULL);
  request.set('PreferedMaximumLength', preferedMaximumLength);
  request.set('ResumeHandle', resumeHandle);
  return (dce as unknown as { request: DceRequestFn }).request<NetrServerAliasEnumResponse>(request);
}
