export const SMB_DIALECT = 'NT LM 0.12';

export const SHARED_DISK = 0x00;
export const SHARED_DISK_HIDDEN = 0x80000000;
export const SHARED_PRINT_QUEUE = 0x01;
export const SHARED_DEVICE = 0x02;
export const SHARED_IPC = 0x03;

export const ATTR_ARCHIVE = 0x020;
export const ATTR_COMPRESSED = 0x800;
export const ATTR_NORMAL = 0x080;
export const ATTR_HIDDEN = 0x002;
export const ATTR_READONLY = 0x001;
export const ATTR_TEMPORARY = 0x100;
export const ATTR_DIRECTORY = 0x010;
export const ATTR_SYSTEM = 0x004;
export const ATTR_REPARSE_POINT = 0x400;

export const SERVICE_DISK = 'A:';
export const SERVICE_PRINTER = 'LPT1:';
export const SERVICE_IPC = 'IPC';
export const SERVICE_COMM = 'COMM';
export const SERVICE_ANY = '?????';

export const SV_TYPE_WORKSTATION = 0x00000001;
export const SV_TYPE_SERVER = 0x00000002;
export const SV_TYPE_SQLSERVER = 0x00000004;
export const SV_TYPE_DOMAIN_CTRL = 0x00000008;
export const SV_TYPE_DOMAIN_BAKCTRL = 0x00000010;
export const SV_TYPE_TIME_SOURCE = 0x00000020;
export const SV_TYPE_AFP = 0x00000040;
export const SV_TYPE_NOVELL = 0x00000080;
export const SV_TYPE_DOMAIN_MEMBER = 0x00000100;
export const SV_TYPE_PRINTQ_SERVER = 0x00000200;
export const SV_TYPE_DIALIN_SERVER = 0x00000400;
export const SV_TYPE_XENIX_SERVER = 0x00000800;
export const SV_TYPE_NT = 0x00001000;
export const SV_TYPE_WFW = 0x00002000;
export const SV_TYPE_SERVER_NT = 0x00004000;
export const SV_TYPE_POTENTIAL_BROWSER = 0x00010000;
export const SV_TYPE_BACKUP_BROWSER = 0x00020000;
export const SV_TYPE_MASTER_BROWSER = 0x00040000;
export const SV_TYPE_DOMAIN_MASTER = 0x00080000;
export const SV_TYPE_LOCAL_LIST_ONLY = 0x40000000;
export const SV_TYPE_DOMAIN_ENUM = 0x80000000;

export const SMB_O_CREAT = 0x10;
export const SMB_O_EXCL = 0x00;
export const SMB_O_OPEN = 0x01;
export const SMB_O_TRUNC = 0x02;

export const SMB_SHARE_COMPAT = 0x00;
export const SMB_SHARE_DENY_EXCL = 0x10;
export const SMB_SHARE_DENY_WRITE = 0x20;
export const SMB_SHARE_DENY_READEXEC = 0x30;
export const SMB_SHARE_DENY_NONE = 0x40;
export const SMB_ACCESS_READ = 0x00;
export const SMB_ACCESS_WRITE = 0x01;
export const SMB_ACCESS_READWRITE = 0x02;
export const SMB_ACCESS_EXEC = 0x03;

export const TRANS_DISCONNECT_TID = 1;
export const TRANS_NO_RESPONSE = 2;

export const STATUS_SUCCESS = 0x00000000;
export const STATUS_LOGON_FAILURE = 0xc000006d;
export const STATUS_LOGON_TYPE_NOT_GRANTED = 0xc000015b;
export const MAX_TFRAG_SIZE = 5840;
export const EVASION_NONE = 0;
export const EVASION_LOW = 1;
export const EVASION_HIGH = 2;
export const EVASION_MAX = 3;
export const RPC_X_BAD_STUB_DATA = 0x6f7;

export const SMB_FILE_ATTRIBUTE_NORMAL = 0x0000;
export const SMB_FILE_ATTRIBUTE_READONLY = 0x0001;
export const SMB_FILE_ATTRIBUTE_HIDDEN = 0x0002;
export const SMB_FILE_ATTRIBUTE_SYSTEM = 0x0004;
export const SMB_FILE_ATTRIBUTE_VOLUME = 0x0008;
export const SMB_FILE_ATTRIBUTE_DIRECTORY = 0x0010;
export const SMB_FILE_ATTRIBUTE_ARCHIVE = 0x0020;
export const SMB_SEARCH_ATTRIBUTE_READONLY = 0x0100;
export const SMB_SEARCH_ATTRIBUTE_HIDDEN = 0x0200;
export const SMB_SEARCH_ATTRIBUTE_SYSTEM = 0x0400;
export const SMB_SEARCH_ATTRIBUTE_DIRECTORY = 0x1000;
export const SMB_SEARCH_ATTRIBUTE_ARCHIVE = 0x2000;

export const SMB_SETUP_GUEST = 0x01;
export const SMB_SETUP_USE_LANMAN_KEY = 0x02;

export const SMB_INFO_ALLOCATION = 0x0001;
export const SMB_INFO_VOLUME = 0x0002;
export const FILE_FS_SIZE_INFORMATION = 0x0003;
export const SMB_QUERY_FS_VOLUME_INFO = 0x0102;
export const SMB_QUERY_FS_SIZE_INFO = 0x0103;
export const SMB_QUERY_FILE_EA_INFO = 0x0103;
export const SMB_QUERY_FS_DEVICE_INFO = 0x0104;
export const SMB_QUERY_FS_ATTRIBUTE_INFO = 0x0105;
export const SMB_QUERY_FILE_BASIC_INFO = 0x0101;
export const SMB_QUERY_FILE_STANDARD_INFO = 0x0102;
export const SMB_QUERY_FILE_ALL_INFO = 0x0107;
export const SMB_QUERY_FILE_STREAM_INFO = 0x0109;
export const FILE_FS_FULL_SIZE_INFORMATION = 0x03ef;

export const SMB_INFO_STANDARD = 0x0001;
export const SMB_INFO_SET_EAS = 0x0002;
export const SMB_SET_FILE_BASIC_INFO = 0x0101;
export const SMB_SET_FILE_DISPOSITION_INFO = 0x0102;
export const SMB_SET_FILE_ALLOCATION_INFO = 0x0103;
export const SMB_SET_FILE_END_OF_FILE_INFO = 0x0104;

export const SMB_FIND_CLOSE_AFTER_REQUEST = 0x0001;
export const SMB_FIND_CLOSE_AT_EOS = 0x0002;
export const SMB_FIND_RETURN_RESUME_KEYS = 0x0004;
export const SMB_FIND_CONTINUE_FROM_LAST = 0x0008;
export const SMB_FIND_WITH_BACKUP_INTENT = 0x0010;

export const FILE_DIRECTORY_FILE = 0x00000001;
export const FILE_DELETE_ON_CLOSE = 0x00001000;
export const FILE_NON_DIRECTORY_FILE = 0x00000040;

export const SMB_FIND_INFO_STANDARD = 0x0001;
export const SMB_FIND_FILE_DIRECTORY_INFO = 0x0101;
export const SMB_FIND_FILE_FULL_DIRECTORY_INFO = 0x0102;
export const SMB_FIND_FILE_NAMES_INFO = 0x0103;
export const SMB_FIND_FILE_BOTH_DIRECTORY_INFO = 0x0104;
export const SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO = 0x105;
export const SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO = 0x106;

export const FILE_READ_DATA = 0x00000001;
export const FILE_WRITE_DATA = 0x00000002;
export const FILE_APPEND_DATA = 0x00000004;
export const FILE_READ_EA = 0x00000008;
export const FILE_WRITE_EA = 0x00000010;
export const FILE_EXECUTE = 0x00000020;
export const FILE_READ_ATTRIBUTES = 0x00000080;
export const FILE_WRITE_ATTRIBUTES = 0x00000100;
export const FILE_DELETE = 0x00010000;
export const READ_CONTROL = 0x00020000;
export const WRITE_DAC = 0x00040000;
export const WRITE_OWNER = 0x00080000;
export const SYNCHRONIZE = 0x00100000;
export const ACCESS_SYSTEM_SECURITY = 0x01000000;
export const MAXIMUM_ALLOWED = 0x02000000;
export const GENERIC_ALL = 0x10000000;
export const GENERIC_EXECUTE = 0x20000000;
export const GENERIC_WRITE = 0x40000000;
export const GENERIC_READ = 0x80000000;

export const FILE_SHARE_NONE = 0x00000000;
export const FILE_SHARE_READ = 0x00000001;
export const FILE_SHARE_WRITE = 0x00000002;
export const FILE_SHARE_DELETE = 0x00000004;

export const FILE_SUPERSEDE = 0x00000000;
export const FILE_OPEN = 0x00000001;
export const FILE_CREATE = 0x00000002;
export const FILE_OPEN_IF = 0x00000003;
export const FILE_OVERWRITE = 0x00000004;
export const FILE_OVERWRITE_IF = 0x00000005;

export const SMB_COMMAND_CREATE_DIRECTORY = 0x00;
export const SMB_COMMAND_DELETE_DIRECTORY = 0x01;
export const SMB_COMMAND_OPEN = 0x02;
export const SMB_COMMAND_CREATE = 0x03;
export const SMB_COMMAND_CLOSE = 0x04;
export const SMB_COMMAND_FLUSH = 0x05;
export const SMB_COMMAND_DELETE = 0x06;
export const SMB_COMMAND_RENAME = 0x07;
export const SMB_COMMAND_QUERY_INFORMATION = 0x08;
export const SMB_COMMAND_SET_INFORMATION = 0x09;
export const SMB_COMMAND_READ = 0x0a;
export const SMB_COMMAND_WRITE = 0x0b;
export const SMB_COMMAND_LOCK_BYTE_RANGE = 0x0c;
export const SMB_COMMAND_UNLOCK_BYTE_RANGE = 0x0d;
export const SMB_COMMAND_CREATE_TEMPORARY = 0x0e;
export const SMB_COMMAND_CREATE_NEW = 0x0f;
export const SMB_COMMAND_CHECK_DIRECTORY = 0x10;
export const SMB_COMMAND_PROCESS_EXIT = 0x11;
export const SMB_COMMAND_SEEK = 0x12;
export const SMB_COMMAND_LOCK_AND_READ = 0x13;
export const SMB_COMMAND_WRITE_AND_UNLOCK = 0x14;
export const SMB_COMMAND_READ_RAW = 0x1a;
export const SMB_COMMAND_READ_MPX = 0x1b;
export const SMB_COMMAND_READ_MPX_SECONDARY = 0x1c;
export const SMB_COMMAND_WRITE_RAW = 0x1d;
export const SMB_COMMAND_WRITE_MPX = 0x1e;
export const SMB_COMMAND_WRITE_MPX_SECONDARY = 0x1f;
export const SMB_COMMAND_WRITE_COMPLETE = 0x20;
export const SMB_COMMAND_QUERY_SERVER = 0x21;
export const SMB_COMMAND_SET_INFORMATION2 = 0x22;
export const SMB_COMMAND_QUERY_INFORMATION2 = 0x23;
export const SMB_COMMAND_LOCKING_ANDX = 0x24;
export const SMB_COMMAND_TRANSACTION = 0x25;
export const SMB_COMMAND_TRANSACTION_SECONDARY = 0x26;
export const SMB_COMMAND_IOCTL = 0x27;
export const SMB_COMMAND_IOCTL_SECONDARY = 0x28;
export const SMB_COMMAND_COPY = 0x29;
export const SMB_COMMAND_MOVE = 0x2a;
export const SMB_COMMAND_ECHO = 0x2b;
export const SMB_COMMAND_WRITE_AND_CLOSE = 0x2c;
export const SMB_COMMAND_OPEN_ANDX = 0x2d;
export const SMB_COMMAND_READ_ANDX = 0x2e;
export const SMB_COMMAND_WRITE_ANDX = 0x2f;
export const SMB_COMMAND_NEW_FILE_SIZE = 0x30;
export const SMB_COMMAND_CLOSE_AND_TREE_DISC = 0x31;
export const SMB_COMMAND_TRANSACTION2 = 0x32;
export const SMB_COMMAND_TRANSACTION2_SECONDARY = 0x33;
export const SMB_COMMAND_FIND_CLOSE2 = 0x34;
export const SMB_COMMAND_FIND_NOTIFY_CLOSE = 0x35;
export const SMB_COMMAND_TREE_CONNECT = 0x70;
export const SMB_COMMAND_TREE_DISCONNECT = 0x71;
export const SMB_COMMAND_NEGOTIATE = 0x72;
export const SMB_COMMAND_SESSION_SETUP = 0x73;
export const SMB_COMMAND_LOGOFF_ANDX = 0x74;
export const SMB_COMMAND_TREE_CONNECT_ANDX = 0x75;
export const SMB_COMMAND_QUERY_INFORMATION_DISK = 0x80;
export const SMB_COMMAND_SEARCH = 0x81;
export const SMB_COMMAND_FIND = 0x82;
export const SMB_COMMAND_FIND_UNIQUE = 0x83;
export const SMB_COMMAND_FIND_CLOSE = 0x84;
export const SMB_COMMAND_NT_TRANSACT = 0xa0;
export const SMB_COMMAND_NT_TRANSACT_SECONDARY = 0xa1;
export const SMB_COMMAND_NT_CREATE_ANDX = 0xa2;
export const SMB_COMMAND_NT_CANCEL = 0xa4;
export const SMB_COMMAND_NT_RENAME = 0xa5;
export const SMB_COMMAND_OPEN_PRINT_FILE = 0xc0;
export const SMB_COMMAND_WRITE_PRINT_FILE = 0xc1;
export const SMB_COMMAND_CLOSE_PRINT_FILE = 0xc2;
export const SMB_COMMAND_GET_PRINT_QUEUE = 0xc3;
export const SMB_COMMAND_READ_BULK = 0xd8;
export const SMB_COMMAND_WRITE_BULK = 0xd9;
export const SMB_COMMAND_WRITE_BULK_DATA = 0xda;
export const SMB_COMMAND_NO_ANDX_COMMAND = 0xff;

export const FLAGS1_PATHCASELESS = 0x08;
export const FLAGS1_CANONICALIZED_PATHS = 0x10;
export const FLAGS1_REPLY = 0x80;
export const FLAGS1_LOCK_AND_READ_OK = 0x01;

export const FLAGS2_LONG_NAMES = 0x0001;
export const FLAGS2_EAS = 0x0002;
export const FLAGS2_SMB_SECURITY_SIGNATURE = 0x0004;
export const FLAGS2_IS_LONG_NAME = 0x0040;
export const FLAGS2_EXTENDED_SECURITY = 0x0800;
export const FLAGS2_DFS_PATHNAME = 0x1000;
export const FLAGS2_PAGING_IO = 0x2000;
export const FLAGS2_NT_STATUS = 0x4000;
export const FLAGS2_UNICODE = 0x8000;

export const SECURITY_SHARE_MASK = 0x01;
export const SECURITY_SHARE_SHARE = 0x00;
export const SECURITY_SHARE_USER = 0x01;
export const SECURITY_SIGNATURES_ENABLED = 0x04;
export const SECURITY_SIGNATURES_REQUIRED = 0x08;
export const SECURITY_AUTH_MASK = 0x02;
export const SECURITY_AUTH_ENCRYPTED = 0x02;
export const SECURITY_AUTH_PLAINTEXT = 0x00;

export const RAW_READ_MASK = 0x01;
export const RAW_WRITE_MASK = 0x02;

export const NEGOTIATE_USER_SECURITY = 0x01;
export const NEGOTIATE_ENCRYPT_PASSWORDS = 0x02;
export const NEGOTIATE_SECURITY_SIGNATURE_ENABLE = 0x04;
export const NEGOTIATE_SECURITY_SIGNATURE_REQUIRED = 0x08;

export const SMB_SUPPORT_SEARCH_BITS = 0x01;
export const SMB_SHARE_IS_IN_DFS = 0x02;

export const TRANS_TRANSACT_NMPIPE = 0x26;

export const TRANS2_FIND_FIRST2 = 0x0001;
export const TRANS2_FIND_NEXT2 = 0x0002;
export const TRANS2_QUERY_FS_INFORMATION = 0x0003;
export const TRANS2_QUERY_PATH_INFORMATION = 0x0005;
export const TRANS2_QUERY_FILE_INFORMATION = 0x0007;
export const TRANS2_SET_FILE_INFORMATION = 0x0008;
export const TRANS2_SET_PATH_INFORMATION = 0x0006;

export const CAP_USE_NT_ERRORS = 0x0040;

export const CAP_RAW_MODE = 0x0001;
export const CAP_MPX_MODE = 0x0002;
export const CAP_UNICODE = 0x0004;
export const CAP_LARGE_FILES = 0x0008;
export const CAP_NT_SMBS = 0x0010;
export const CAP_RPC_REMOTE_APIS = 0x0020;
export const CAP_STATUS32 = 0x0040;
export const CAP_LEVEL_II_OPLOCKS = 0x0080;
export const CAP_LOCK_AND_READ = 0x0100;
export const CAP_NT_FIND = 0x0200;
export const CAP_DFS = 0x1000;
export const CAP_INFOLEVEL_PASSTHRU = 0x2000;
export const CAP_LARGE_READX = 0x4000;
export const CAP_LARGE_WRITEX = 0x8000;
export const CAP_EXTENDED_SECURITY = 0x80000000;

export const FID_EA_RETURNED = 0x4000;
export const FID_DELETE_ON_CLOSE = 0x2000;
export const FID_NO_EAS = 0x6000;

export const ERRDOS: Record<number, string> = {
  1: 'Invalid function',
  2: 'File not found',
  3: 'Invalid directory',
  4: 'Too many open files',
  5: 'Access denied',
  6: 'Invalid handle',
  7: 'Network name deleted',
  8: 'Device not sharing',
  9: 'Bad network path',
  10: 'Network busy',
  11: 'File exists',
  12: 'Cannot create',
  13: 'Invalid parameter',
  14: 'No more space',
  15: 'Device does not exist',
  16: 'Invalid access',
  17: 'Invalid device',
  18: 'No more files',
  19: 'Write protect',
  20: 'Bad unit',
  21: 'Not ready',
  22: 'Invalid command',
  23: 'CRC error',
  24: 'Bad length',
  25: 'Seek error',
  26: 'Not a DOS disk',
  27: 'Sector not found',
  28: 'Out of paper',
  29: 'Write fault',
  30: 'Read fault',
  31: 'General failure',
  32: 'Sharing violation',
  33: 'Lock violation',
  34: 'Wrong disk',
  35: 'FCB unavailable',
  36: 'Sharing buffer exceeded',
  37: 'Not supported',
  38: 'Remote not listening',
  39: 'Duplicate name',
  40: 'Bad password',
  41: 'Program limit exceeded',
  50: 'Cannot pipe',
  51: 'Pipe busy',
  52: 'Pipe closing',
  53: 'Pipeline not connected',
  54: 'Pipe data lost',
  55: 'No process',
  56: 'Too many semaphores',
  57: 'Exclusive semaphore',
  58: 'Semaphore owned',
  59: 'Semaphore limit',
  60: 'Drive locked',
  61: 'Not enough memory',
  62: 'Invalid name',
  63: 'Invalid drive',
  64: 'Current directory',
  65: 'Not same device',
  66: 'No more files',
  80: 'File already exists',
  82: 'Cannot make directory',
  83: 'Fail on INT 24',
  84: 'Too many redirects',
  85: 'Duplicate redirect',
  86: 'Bad redirect',
  87: 'Redirector paused',
  103: 'Incorrect netname',
  104: 'Network type',
  105: 'Server not sharing',
  106: 'Bad device type',
  107: 'Bad network name',
  108: 'Too many names',
  109: 'Too many sessions',
  110: 'Sharing paused',
  111: 'Request not accepted',
  112: 'Redirector paused',
  113: 'Bad password',
  114: 'Invalid verify',
  115: 'Bad device',
  116: 'Cannot share',
  122: 'Invalid level',
  123: 'Bad driver level',
  124: 'Bad password',
  125: 'Bad password',
  126: 'Bad password',
  127: 'Bad password',
  128: 'Bad password',
  129: 'Bad password',
  130: 'Bad password',
  131: 'Bad password',
  132: 'Bad password',
  133: 'Bad password',
  134: 'Bad password',
  135: 'Bad password',
  136: 'Bad password',
  137: 'Bad password',
  138: 'Bad password',
  139: 'Bad password',
  140: 'Bad password',
  141: 'Bad password',
  142: 'Bad password',
  143: 'Bad password',
  144: 'Bad password',
  145: 'Bad password',
  146: 'Bad password',
  147: 'Bad password',
  148: 'Bad password',
  149: 'Bad password',
  150: 'Bad password',
  151: 'Bad password',
  152: 'Bad password',
  153: 'Bad password',
  154: 'Bad password',
  155: 'Bad password',
  156: 'Bad password',
  157: 'Bad password',
  158: 'Bad password',
  159: 'Bad password',
  160: 'Bad password',
  161: 'Bad password',
  162: 'Bad password',
  163: 'Bad password',
  164: 'Bad password',
  165: 'Bad password',
  166: 'Bad password',
  167: 'Bad password',
  168: 'Bad password',
  169: 'Bad password',
  170: 'Bad password',
  171: 'Bad password',
  172: 'Bad password',
  173: 'Bad password',
  174: 'Bad password',
  175: 'Bad password',
  176: 'Bad password',
  177: 'Bad password',
  178: 'Bad password',
  179: 'Bad password',
  180: 'Bad password',
  181: 'Bad password',
  182: 'Bad password',
  183: 'Bad password',
  184: 'Bad password',
  185: 'Bad password',
  186: 'Bad password',
  187: 'Bad password',
  188: 'Bad password',
  189: 'Bad password',
  190: 'Bad password',
  191: 'Bad password',
  192: 'Bad password',
  193: 'Bad password',
  194: 'Bad password',
  195: 'Bad password',
  196: 'Bad password',
  197: 'Bad password',
  198: 'Bad password',
  199: 'Bad password',
  200: 'Bad password',
  201: 'Bad password',
  202: 'Bad password',
  203: 'Bad password',
  204: 'Bad password',
  205: 'Bad password',
  206: 'Bad password',
  207: 'Bad password',
  208: 'Bad password',
  209: 'Bad password',
  210: 'Bad password',
  211: 'Bad password',
  212: 'Bad password',
  213: 'Bad password',
  214: 'Bad password',
  215: 'Bad password',
  216: 'Bad password',
  217: 'Bad password',
  218: 'Bad password',
  219: 'Bad password',
  220: 'Bad password',
  221: 'Bad password',
  222: 'Bad password',
  223: 'Bad password',
  224: 'Bad password',
  225: 'Bad password',
  226: 'Bad password',
  227: 'Bad password',
  228: 'Bad password',
  229: 'Bad password',
  230: 'Bad password',
  231: 'Bad password',
  232: 'Bad password',
  233: 'Bad password',
  234: 'Bad password',
  235: 'Bad password',
  236: 'Bad password',
  237: 'Bad password',
  238: 'Bad password',
  239: 'Bad password',
  240: 'Bad password',
  241: 'Bad password',
  242: 'Bad password',
  243: 'Bad password',
  244: 'Bad password',
  245: 'Bad password',
  246: 'Bad password',
  247: 'Bad password',
  248: 'Bad password',
  249: 'Bad password',
  250: 'Bad password',
  251: 'Bad password',
  252: 'Bad password',
  253: 'Bad password',
  254: 'Bad password',
  255: 'Bad password',
};

export const ERRSRV: Record<number, string> = {
  1: 'Non-specific error',
  2: 'Bad password',
  3: 'Reserved',
  4: 'Access denied',
  5: 'Invalid handle',
  6: 'Network type',
  7: 'Server not sharing',
  8: 'Invalid device',
  9: 'Bad network name',
  10: 'Too many names',
  11: 'Too many sessions',
  12: 'Sharing paused',
  13: 'Request not accepted',
  14: 'Redirector paused',
  15: 'Bad password',
  16: 'Bad password',
  17: 'Bad password',
  18: 'Bad password',
  19: 'Bad password',
  20: 'Bad password',
  21: 'Bad password',
  22: 'Bad password',
  23: 'Bad password',
  24: 'Bad password',
  25: 'Bad password',
  26: 'Bad password',
  27: 'Bad password',
  28: 'Bad password',
  29: 'Bad password',
  30: 'Bad password',
  31: 'Bad password',
  32: 'Bad password',
  33: 'Bad password',
  34: 'Bad password',
  35: 'Account expired',
  36: 'Bad password',
  37: 'Bad password',
  38: 'Bad password',
  39: 'Bad password',
  40: 'Bad password',
  41: 'Bad password',
  42: 'Bad password',
  43: 'Bad password',
  44: 'Bad password',
  45: 'Bad password',
  46: 'Bad password',
  47: 'Bad password',
  48: 'Bad password',
  49: 'Bad password',
  50: 'Bad password',
  51: 'Bad password',
  52: 'Bad password',
  53: 'Bad password',
  54: 'Bad password',
  55: 'Bad password',
  56: 'Bad password',
  57: 'Bad password',
  58: 'Bad password',
  59: 'Bad password',
  60: 'Bad password',
  61: 'Bad password',
  62: 'Bad password',
  63: 'Bad password',
  64: 'Bad password',
  65: 'Bad password',
  66: 'Bad password',
  67: 'Bad password',
  68: 'Bad password',
  69: 'Bad password',
  70: 'Bad password',
  71: 'Bad password',
  72: 'Bad password',
  73: 'Bad password',
  74: 'Bad password',
  75: 'Bad password',
  76: 'Bad password',
  77: 'Bad password',
  78: 'Bad password',
  79: 'Bad password',
  80: 'Bad password',
  81: 'Bad password',
  82: 'Bad password',
  83: 'Bad password',
  84: 'Bad password',
  85: 'Bad password',
  86: 'Bad password',
  87: 'Bad password',
  88: 'Bad password',
  89: 'Bad password',
  90: 'Bad password',
  91: 'Bad password',
  92: 'Bad password',
  93: 'Bad password',
  94: 'Bad password',
  95: 'Bad password',
  96: 'Bad password',
  97: 'Bad password',
  98: 'Bad password',
  99: 'Bad password',
  100: 'Bad password',
  101: 'Bad password',
  102: 'Bad password',
  103: 'Bad password',
  104: 'Bad password',
  105: 'Bad password',
  106: 'Bad password',
  107: 'Bad password',
  108: 'Bad password',
  109: 'Bad password',
  110: 'Bad password',
  111: 'Bad password',
  112: 'Bad password',
  113: 'Bad password',
  114: 'Bad password',
  115: 'Bad password',
  116: 'Bad password',
  117: 'Bad password',
  118: 'Bad password',
  119: 'Bad password',
  120: 'Bad password',
  121: 'Bad password',
  122: 'Bad password',
  123: 'Bad password',
  124: 'Bad password',
  125: 'Bad password',
  126: 'Bad password',
  127: 'Bad password',
  128: 'Bad password',
  129: 'Bad password',
  130: 'Bad password',
  131: 'Bad password',
  132: 'Bad password',
  133: 'Bad password',
  134: 'Bad password',
  135: 'Bad password',
  136: 'Bad password',
  137: 'Bad password',
  138: 'Bad password',
  139: 'Bad password',
  140: 'Bad password',
  141: 'Bad password',
  142: 'Bad password',
  143: 'Bad password',
  144: 'Bad password',
  145: 'Bad password',
  146: 'Bad password',
  147: 'Bad password',
  148: 'Bad password',
  149: 'Bad password',
  150: 'Bad password',
  151: 'Bad password',
  152: 'Bad password',
  153: 'Bad password',
  154: 'Bad password',
  155: 'Bad password',
  156: 'Bad password',
  157: 'Bad password',
  158: 'Bad password',
  159: 'Bad password',
  160: 'Bad password',
  161: 'Bad password',
  162: 'Bad password',
  163: 'Bad password',
  164: 'Bad password',
  165: 'Bad password',
  166: 'Bad password',
  167: 'Bad password',
  168: 'Bad password',
  169: 'Bad password',
  170: 'Bad password',
  171: 'Bad password',
  172: 'Bad password',
  173: 'Bad password',
  174: 'Bad password',
  175: 'Bad password',
  176: 'Bad password',
  177: 'Bad password',
  178: 'Bad password',
  179: 'Bad password',
  180: 'Bad password',
  181: 'Bad password',
  182: 'Bad password',
  183: 'Bad password',
  184: 'Bad password',
  185: 'Bad password',
  186: 'Bad password',
  187: 'Bad password',
  188: 'Bad password',
  189: 'Bad password',
  190: 'Bad password',
  191: 'Bad password',
  192: 'Bad password',
  193: 'Bad password',
  194: 'Bad password',
  195: 'Bad password',
  196: 'Bad password',
  197: 'Bad password',
  198: 'Bad password',
  199: 'Bad password',
  200: 'Bad password',
  201: 'Bad password',
  202: 'Bad password',
  203: 'Bad password',
  204: 'Bad password',
  205: 'Bad password',
  206: 'Bad password',
  207: 'Bad password',
  208: 'Bad password',
  209: 'Bad password',
  210: 'Bad password',
  211: 'Bad password',
  212: 'Bad password',
  213: 'Bad password',
  214: 'Bad password',
  215: 'Bad password',
  216: 'Bad password',
  217: 'Bad password',
  218: 'Bad password',
  219: 'Bad password',
  220: 'Bad password',
  221: 'Bad password',
  222: 'Bad password',
  223: 'Bad password',
  224: 'Bad password',
  225: 'Bad password',
  226: 'Bad password',
  227: 'Bad password',
  228: 'Bad password',
  229: 'Bad password',
  230: 'Bad password',
  231: 'Bad password',
  232: 'Bad password',
  233: 'Bad password',
  234: 'Bad password',
  235: 'Bad password',
  236: 'Bad password',
  237: 'Bad password',
  238: 'Bad password',
  239: 'Bad password',
  240: 'Bad password',
  241: 'Bad password',
  242: 'Bad password',
  243: 'Bad password',
  244: 'Bad password',
  245: 'Bad password',
  246: 'Bad password',
  247: 'Bad password',
  248: 'Bad password',
  249: 'Bad password',
  250: 'Bad password',
  251: 'Bad password',
  252: 'Bad password',
  253: 'Bad password',
  254: 'Bad password',
  255: 'Bad password',
};

export const ERRHRD: Record<number, string> = {
  1: 'Invalid function',
  2: 'File not found',
  3: 'Path not found',
  4: 'Too many open files',
  5: 'Access denied',
  6: 'Invalid handle',
  7: 'Memory control block destroyed',
  8: 'Insufficient memory',
  9: 'Invalid memory block address',
  10: 'Invalid environment',
  11: 'Invalid format',
  12: 'Invalid access code',
  13: 'Invalid data',
  14: 'Reserved',
  15: 'Invalid drive',
  16: 'Current directory',
  17: 'Not same device',
  18: 'No more files',
  19: 'Write protect',
  20: 'Bad unit',
  21: 'Not ready',
  22: 'Invalid command',
  23: 'CRC error',
  24: 'Bad length',
  25: 'Seek error',
  26: 'Not a DOS disk',
  27: 'Sector not found',
  28: 'Out of paper',
  29: 'Write fault',
  30: 'Read fault',
  31: 'General failure',
  32: 'Sharing violation',
  33: 'Lock violation',
  34: 'Wrong disk',
  35: 'FCB unavailable',
  36: 'Sharing buffer exceeded',
  37: 'Not supported',
  38: 'Remote not listening',
  39: 'Duplicate name',
  40: 'Bad password',
  41: 'Program limit exceeded',
  42: 'Cannot pipe',
  43: 'Pipe busy',
  44: 'Pipe closing',
  45: 'Pipeline not connected',
  46: 'Pipe data lost',
  47: 'No process',
  48: 'Too many semaphores',
  49: 'Exclusive semaphore',
  50: 'Semaphore owned',
  51: 'Semaphore limit',
  52: 'Drive locked',
  53: 'Not enough memory',
  54: 'Invalid name',
  55: 'Invalid drive',
  56: 'Current directory',
  57: 'Not same device',
  58: 'No more files',
  59: 'Cannot share',
  60: 'Invalid parameter',
  61: 'Cannot make directory',
  62: 'Fail on INT 24',
  63: 'Too many redirects',
  64: 'Duplicate redirect',
  65: 'Bad redirect',
  66: 'Redirector paused',
  67: 'Incorrect netname',
  68: 'Network type',
  69: 'Server not sharing',
  70: 'Bad device type',
  71: 'Bad network name',
  72: 'Too many names',
  73: 'Too many sessions',
  74: 'Sharing paused',
  75: 'Request not accepted',
  76: 'Redirector paused',
  77: 'Bad password',
  78: 'Invalid verify',
  79: 'Bad device',
  80: 'Cannot share',
  81: 'Incorrect netname',
  82: 'Network type',
  83: 'Server not sharing',
  84: 'Bad device type',
  85: 'Bad network name',
  86: 'Too many names',
  87: 'Too many sessions',
  88: 'Sharing paused',
  89: 'Request not accepted',
  90: 'Redirector paused',
  91: 'Bad password',
  92: 'Invalid verify',
  93: 'Bad device',
  94: 'Cannot share',
  95: 'Incorrect netname',
  96: 'Network type',
  97: 'Server not sharing',
  98: 'Bad device type',
  99: 'Bad network name',
  100: 'Too many names',
  101: 'Too many sessions',
  102: 'Sharing paused',
  103: 'Request not accepted',
  104: 'Redirector paused',
  105: 'Bad password',
  106: 'Invalid verify',
  107: 'Bad device',
  108: 'Cannot share',
  109: 'Incorrect netname',
  110: 'Network type',
  111: 'Server not sharing',
  112: 'Bad device type',
  113: 'Bad network name',
  114: 'Too many names',
  115: 'Too many sessions',
  116: 'Sharing paused',
  117: 'Request not accepted',
  118: 'Redirector paused',
  119: 'Bad password',
  120: 'Invalid verify',
  121: 'Bad device',
  122: 'Cannot share',
  123: 'Incorrect netname',
  124: 'Network type',
  125: 'Server not sharing',
  126: 'Bad device type',
  127: 'Bad network name',
  128: 'Too many names',
  129: 'Too many sessions',
  130: 'Sharing paused',
  131: 'Request not accepted',
  132: 'Redirector paused',
  133: 'Bad password',
  134: 'Invalid verify',
  135: 'Bad device',
  136: 'Cannot share',
};

export function strerror(errclass: number, errcode: number): string {
  if (errcode in ERRDOS && errclass === 0x01) return ERRDOS[errcode]!;
  if (errcode in ERRSRV && errclass === 0x02) return ERRSRV[errcode]!;
  if (errcode in ERRHRD && errclass === 0x03) return ERRHRD[errcode]!;
  return `Unknown error (class=${errclass}, code=${errcode})`;
}

export function POSIXtoFT(t: number): bigint {
  return BigInt(t) * 10000000n + 116444736000000000n;
}

export function FTtoPOSIX(t: bigint): number {
  return Number((t - 116444736000000000n) / 10000000n);
}

export class SessionError extends Error {
  error: number;
  error_class: number;
  error_code: number;

  constructor(errorString = '', errorClass = 0, errorCode = 0) {
    super(errorString);
    this.error = 0;
    this.error_class = errorClass;
    this.error_code = errorCode;
  }

  toString(): string {
    const msg = strerror(this.error_class, this.error_code);
    return `SessionError: ${msg} (0x${this.error.toString(16)})`;
  }
}

export class UnsupportedFeature extends Error {}

export class SharedDevice {
  name: string;
  type: number;
  comment: string;

  constructor(name: string, type: number, comment: string) {
    this.name = name;
    this.type = type;
    this.comment = comment;
  }
}

export class SharedFile {
  name: string;
  shortname: string;
  filesize: number;
  attrib: number;
  mtime: Date;
  ctime: Date;
  atime: Date;

  constructor(
    name: string,
    shortname: string,
    filesize: number,
    attrib: number,
    mtime: Date,
    ctime: Date,
    atime: Date,
  ) {
    this.name = name;
    this.shortname = shortname;
    this.filesize = filesize;
    this.attrib = attrib;
    this.mtime = mtime;
    this.ctime = ctime;
    this.atime = atime;
  }
}

export const FILE_DEVICE_DISK = 0x0007;
export const FILE_DEVICE_DISK_FILE_SYSTEM = 0x0008;

export const FILE_CASE_SENSITIVE_SEARCH = 0x00000001;
export const FILE_CASE_PRESERVED_NAMES = 0x00000002;
