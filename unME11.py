#!/usr/bin/env python2
import os, sys, struct, hashlib, platform
import subprocess

try:
  import HuffDec11
  HuffDecoder11 = HuffDec11.HuffDecoder()
except:
  HuffDecoder11 = None

try:
  import HuffDec12
  HuffDecoder12 = HuffDec12.HuffDecoder()
except:
  HuffDecoder12 = None

class Globals(object):
  HuffDecoder = HuffDecoder11
  dumpManifest = True # Dump CPD manifest
  dumpMeta = True # Dump modules metadata
  dumpRaw = False # Dump raw modules data (compressed/encrypted)
  dumpChunks = False # Dump HUFF chunks
g = Globals()

class Error(Exception): pass

def BitFields(obj, val, bitDef):
 def bitf(val, lo, hi):  return (val & ((2<<hi)-1)) >> lo
 for name, lo, hi in bitDef: setattr(obj, name, bitf(val, lo, hi))

def ListTrueBools(obj, bitDef):
  return [v[0] for v in filter(lambda x: x[1] == x[2] and getattr(obj, x[0]), bitDef)]

class StructReader(object):
  def __init__(self, ab, base=0, isLE=True):
    self.ab = ab
    self.base = base
    self.o = self.base
    self.cE = "<" if isLE else ">"

  def sizeLeft(self):
    return len(self.ab) - self.o

  def getData(self, o, cb):
    o += self.base
    if o < len(self.ab) and cb >= 0 and o + cb <= len(self.ab):
      return self.ab[o:o+cb]

  def read(self, obj, stDef, o=None):
    if o is None: o = self.o
    self.o += self.base
    for fldDef in stDef: # Walk field definitions
      name = fldDef[0]
      fmt = self.cE + fldDef[1]
      val, = struct.unpack_from(fmt, self.ab, o)
      if 3 == len(fldDef):
        expected = fldDef[2]
        if isinstance(expected, (list, tuple)):
          if not val in expected:
            print >>sys.stderr, "- %s.%s: not %s in %s" % (obj.__class__.__name__, name, val, expected)
        else:
          if val != expected:
            print >>sys.stderr, "- %s.%s:" % (obj.__class__.__name__, name),
            if isinstance(val, str): print >>sys.stderr, "Got %s, expected %s" % (val.encode("hex"), expected.encode("hex"))
            else: print >>sys.stderr, "Got [%s], expected [%s]" % (repr(val), repr(expected))
          else: assert val == expected
      setattr(obj, name, val)
      o += struct.calcsize(fmt)
    self.o = o

  def done(self):
    assert len(self.ab) == self.o

aPubKeyHash = [v.decode("hex") for v in (
  "EA6FA86514FA887C9044218EDB4D70BB3BCC7C2D37587EA8F760BAFBE158C587",
  "A24E0682EDC8870DCA947C01603D19818AF714BEE9F39D2872D79B8C422F3890",
  "EA3E9C34C8FD6BDEA277F0A8C6AC5A37E8E39256469C89D279FA86A7317B21AE",
  "C8E7AA2C5F691F63A892BC044CD3935C5E77C6CB71C8E8627BE4987DFB730856",
  "3D512A6DB7C855E9F6328DB8B2C259A2C0F291BB6E3EC74A2FB811AD84C5D404",
  "04A6F35B14628879050AB0B3459326DDF946AE4E5EFD7BB1930883F57F68D084",
  "980F9572AC1B5BDC9A5F3E89F2503A624C9C5BDF97B72D9031DCCDAB11A9F7A8",
  "C468E6BA739856797BAF70910861BDE4C3BA95C956B1DCE24B738D614F1211BA",
)]

#***************************************************************************
#***************************************************************************
#***************************************************************************

args_lzma = {
  "Windows": ["lzma", "d", "-si", "-so"],
  "Linux":   ["lzma", "-d"],
  "Darwin":  ["lzma", "-d"], # "brew install xz" or "sudo port install xz"
}[platform.system()]

def LZMA_decompress(compdata):
  process = subprocess.Popen(args_lzma, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  output, errout = process.communicate(compdata)
  retcode = process.poll()
  if retcode: raise Error(errout)
  return output

def decompress(data, compType, length):
  if compType is None:
    return data
  elif "lzma" == compType:
    if not data.startswith("36004000".decode("hex")):
      print >>sys.stderr, "- Bad LZMA[0x%X] header %s" % (len(data), data[:17].encode("hex"))
      return None
    assert data.startswith("36004000".decode("hex"))
    assert '\0\0\0' == data[14:17]
    return LZMA_decompress(data[:14] + data[17:])
  elif "huff" == compType:
    return g.HuffDecoder.decompress(data, length) if g.HuffDecoder else None
  else:
    raise Error("Invalid compType %s" % compType)


RESTART_NOT_ALLOWED = 0
RESTART_IMMEDIATLY = 1
RESTART_ON_NEXT_BOOT = 2

# MODULE_TYPES
PROCESS_TYPE		= 0
SHARED_LIBRARY_TYPE	= 1
DATA_TYPE		= 2
IUNIT_TYPE		= 3 # v12

# PARTITION_TYPES
FPT_AREATYPE_GENERIC	= 1
FPT_AREATYPE_CODE	= 0
FPT_AREATYPE_ROM	= 1
FPT_AREATYPE_DATA	= 1

# COMPRESSION_TYPE
COMP_TYPE_NOT_COMPRESSED = 0
COMP_TYPE_HUFFMAN = 1
COMP_TYPE_LZMA = 2
dCompType = {
  COMP_TYPE_NOT_COMPRESSED : None,
  COMP_TYPE_HUFFMAN: "huff",
  COMP_TYPE_LZMA: "lzma",
}

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Extension(object):
  NAME = None
  TYPE = None
  LIST = None
  def Banner(self, noSize=False):
    nItems = "" if noSize or (self.LIST is None) else "[%d]" % len(getattr(self, self.LIST))
    return ". Ext#%d %s%s:" % (self.TYPE, self.NAME, nItems)

  def PrintItems(self, flog):
    for i,e in enumerate(getattr(self, self.LIST)): print >>flog, "%6d: %s" % (i+1, e)

  def LoadItems(self, stR, cls, cnt=None):
    if cnt is None:
      lst = []
      while stR.o < len(stR.ab): lst.append(cls(stR))
    else:
      lst = [cls(stR) for i in xrange(cnt)]
    stR.done()
    setattr(self, self.LIST, lst)

#***************************************************************************
#***************************************************************************
#***************************************************************************

#***************************************************************************
#***************************************************************************
#***************************************************************************

class System_Info_Ext(Extension): # 0 : used in Mainfist
  NAME = "SystemInfo"
  TYPE = 0 # for system info extension
  LIST = "indParts"
  SYSTEM_INFO_EXTENSION = (
    ("uma_size", 		"L",	),		# Minimum UMA size required for this SKU in bytes
    ("chipset_version",		"L",	),		# Chipset version
    ("img_default_hash",	"32s",	),		# SHA2 hash of a 'defaults' file added to the image. (/intel.cfg). The load manager is responsible for verifying the hash of this file and creating the default files at the first system boot.
    ("pageable_uma_size",	"L",	),		# Size of pageable space within UMA in bytes. Must be divisible by 4K.
    ("reserved_0",		"Q",	0),		#
    ("reserved_1",		"L",	0),		#
    # INDEPENDENT_PARTITION_ENTRY[]
  )
  def __init__(self, ab):
    stR = StructReader(ab)
    stR.read(self, self.SYSTEM_INFO_EXTENSION)
    self.img_default_hash = self.img_default_hash[::-1] # Reverse?
    self.LoadItems(stR, Independent_Partition_Entry)

  def dump(self, flog=sys.stdout):
    print >>flog, "%s uma_size:0x%X, chipset_version:0x%X, pageable_uma_size:0x%X defaults_h:%s" % (self.Banner(), self.uma_size, self.chipset_version, self.pageable_uma_size, self.img_default_hash.encode("hex"))
    self.PrintItems(flog)

#***************************************************************************

class Independent_Partition_Entry:
  INDEPENDENT_PARTITION_ENTRY = (
    ("name",	 		"4s",	),		#
    ("version",			"L",	),		#
    ("user_id",			"H",	),		#
    ("reserved",		"H",	),		#
  )
  def __init__(self, stR):
    stR.read(self, self.INDEPENDENT_PARTITION_ENTRY)
    self.name = self.name.rstrip('\0')

  def __str__(self):
    return "[%-4s] user_id:0x%04X ver:0x%08X %X" % (self.name, self.user_id, self.version, self.reserved)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Init_Script_Ext(Extension): # 1 : used in Mainfist
  NAME = "InitScript"
  TYPE = 1 # for initialization script extension
  LIST = "scripts"
  # length: In bytes; equals (16 + 52*n) for this version where n is the number of modules in the initialization script
  INIT_SCRIPT = (
    ("reserved",		"L",	0),		# Reserved for future use.
    ("number_of_modules",	"L",	),		# Number of modules in this initialization script. Cannot be more than MAX_MODULES (this is a configuration parameter defining the maximum number of modules supported by the system set at system build time).
    # INIT_SCRIPT_ENTRY[] # initialization script extension entries
  )
  def __init__(self, ab):
    stR = StructReader(ab)
    stR.read(self, self.INIT_SCRIPT)

    clsSize, remainder = divmod(stR.sizeLeft(), self.number_of_modules)
    if remainder: raise Error("Init_Script_Ext data size == %d is not miltiple of nItems == %d" % stR.sizeLeft(), self.number_of_modules)
    cls = {24: Init_Script_Entry, 28: Init_Script_Entry_v12}[clsSize]
    self.LoadItems(stR, cls, self.number_of_modules)

  def dump(self, flog=sys.stdout):
    print >>flog, self.Banner()
    self.PrintItems(flog)

#***************************************************************************

class Init_Script_Entry:
  INIT_SCRIPT_ENTRY = (
    ("partition_name",		"4s",	),		# Manifest Partition Name. This field identifies the manifest in which this module's hash will be found irregardles of manifest's physical location (i.e. FTP manifest may be physically located in NFTP flash partition during FW update).
    ("name",			"12s",	),		# Module Name
    ("bf_init_flags",		"L",	),		# Flags used govern initialization flow.
    ("bf_boot_type",		"L",	),		# Boot path flag bits to indicate which boot path(s) this module is applicable to. Bit 0 - Normal Bit 1 - HAP Bit 2 - HMRFPO Bit 3 - Temp Disable Bit 4 - Recovery Bit 5 - Safe Mode Bit 6 - FW Update Bits 7:31 - Reserved
  )
  def __init__(self, stR):
    self.unk = None
    stR.read(self, self.INIT_SCRIPT_ENTRY)
    self.partition_name = self.partition_name.rstrip('\0')
    self.name = self.name.rstrip('\0')
    self.init_flags = Init_Script_Flags(self.bf_init_flags)
    self.boot_type = Init_Script_Boot_Type(self.bf_boot_type)

  def __str__(self):
    return "%4s:%-12s Init: %08X (%s) Boot: %08X (%s)" % (self.partition_name, self.name, self.bf_init_flags, self.init_flags, self.bf_boot_type, self.boot_type)

#***************************************************************************

class Init_Script_Entry_v12:
  INIT_SCRIPT_ENTRY = (
    ("partition_name",		"4s",	),		# Manifest Partition Name. This field identifies the manifest in which this module's hash will be found irregardles of manifest's physical location (i.e. FTP manifest may be physically located in NFTP flash partition during FW update).
    ("name",			"12s",	),		# Module Name
    ("bf_init_flags",		"L",	),		# Flags used govern initialization flow.
    ("bf_boot_type",		"L",	),		# Boot path flag bits to indicate which boot path(s) this module is applicable to. Bit 0 - Normal Bit 1 - HAP Bit 2 - HMRFPO Bit 3 - Temp Disable Bit 4 - Recovery Bit 5 - Safe Mode Bit 6 - FW Update Bits 7:31 - Reserved
    ("unk",			"L",	),		#
  )
  def __init__(self, stR):
    stR.read(self, self.INIT_SCRIPT_ENTRY)
    self.partition_name = self.partition_name.rstrip('\0')
    self.name = self.name.rstrip('\0')
    self.init_flags = Init_Script_Flags(self.bf_init_flags)
    self.boot_type = Init_Script_Boot_Type(self.bf_boot_type)

  def __str__(self):
    return "%4s:%-12s Init: %08X (%s) Boot: %08X (%s) Unk: %X" % (self.partition_name, self.name, self.bf_init_flags, self.init_flags, self.bf_boot_type, self.boot_type, self.unk)

#***************************************************************************

class Init_Script_Flags: # !!! Not sure...
  dRestart = {
    RESTART_NOT_ALLOWED : "Not Allowed",	# 0
    RESTART_IMMEDIATLY  : "Immediatly",		# 1
    RESTART_ON_NEXT_BOOT: "On Next Boot",	# 2
  }
  INIT_SCRIPT_FLAGS = ( # BitFields
    ("Ibl",			0,	0),
    ("IsRemovable",		1,	1),
    ("InitImmediately",		2,	2),
    ("RestartPolicy",		3,	15),
    ("Cm0_u",			16,	16),
    ("Cm0_nu",			17,	17),
    ("Cm3",			18,	18),
#    ("reserved",		19,	31),
  )
  def __init__(self, dw):
    BitFields(self, dw, self.INIT_SCRIPT_FLAGS)

  def __str__(self):
    r = ListTrueBools(self, self.INIT_SCRIPT_FLAGS)
    if self.RestartPolicy: r.append("Restart %s" % self.dRestart[self.RestartPolicy])
    return ", ".join(r)

#***************************************************************************

class Init_Script_Boot_Type:
  INIT_SCRIPT_BOOT_TYPE = ( # BitFields
    ("Normal",			0,	0),
    ("HAP",			1,	1),
    ("HMRFPO",			2,	2),
    ("TmpDisable",		3,	3),
    ("Recovery",		4,	4),
    ("SafeMode",		5,	5),
    ("FWUpdate",		6,	6),
#    ("reserved",		7,	31),
  )
  def __init__(self, dw):
    BitFields(self, dw, self.INIT_SCRIPT_BOOT_TYPE)

  def __str__(self):
    return ", ".join(ListTrueBools(self, self.INIT_SCRIPT_BOOT_TYPE))

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Feature_Permissions_Ext(Extension): # 2 : used in Mainfist
  NAME = "FeaturePermissions"
  TYPE = 2 # for feature permission extension
  LIST = "permissions"
  # length: In bytes; equals (12 + 2*n) for this version where n is the number of features in this extension
  FEATURE_PERMISSIONS_EXTENSION = (
    ("num_of_features",		"L",	),		# Number of features feature numbering always starts from 0.
    # FEATURE_PERMISSION_ENTRY[] # feature permission extension entries
  )
  def __init__(self, ab):
    stR = StructReader(ab)
    stR.read(self, self.FEATURE_PERMISSIONS_EXTENSION)
    self.LoadItems(stR, Feature_Permission_Entry, self.num_of_features)

  def dump(self, flog=sys.stdout):
    print >>flog, "%s [%s]" % (self.Banner(), ", ".join("0x%04X" % e.user_id for e in self.permissions))

#***************************************************************************

class Feature_Permission_Entry:
  FEATURE_PERMISSION_ENTRY = (
    ("user_id",			"H",	),		# User ID that may change feature state for feature 0.
    ("reserved",		"H",	0),		#
  )
  def __init__(self, stR):
    stR.read(self, self.FEATURE_PERMISSION_ENTRY)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Partition_Info_Ext(Extension): # 3 : used in Mainfist
  NAME = "PartitionInfo"
  TYPE = 3 # for partition info extension
  LIST = "modules"
  # length: In bytes; equals (92 + 52*n) for this version where n is the number of modules in the manifest
  MANIFEST_PARTITION_INFO_EXT = (
    ("partition_name",		"4s",	),		# Name of the partition
    ("partition_length",	"L",	),		# Length of complete partition before any process have been removed by the OEM or the firmware update process
    ("partition_hash",		"32s",	),		# SHA256 hash of the original complete partition covering everything in the partition except for the manifest (directory binaries and LUT)
    ("version_control_number",	"L",	),		# The version control number (VCN) is incremented whenever a change is made to the FW that makes it incompatible from an update perspective with previously released versions of the FW.
    ("partition_version",	"L",	),		# minor number
    ("data_format_version",	"L",	),		#
    ("instance_id",		"L",	),		#
    ("flags",			"L",	),		# Support multiple instances Y/N. Used for independently updated partitions that may have multiple instances (such as WLAN uCode or Localization)
    ("reserved",		"16s",	('\0'*16, '\xFF'*16,)),	# set to 0xff
    ("unknown0",		"l",	(0, 1, 3, -1)),	# Was 0xffffffff
    # MANIFEST_MODULE_INFO_EXT[] # Module info extension entries
  )
  def __init__(self, ab):
    stR = StructReader(ab)
    stR.read(self, self.MANIFEST_PARTITION_INFO_EXT)
    self.partition_name = self.partition_name.rstrip('\0')
    self.partition_hash = self.partition_hash[::-1] # Reverse?
    self.LoadItems(stR, Module_Info)

  def dump(self, flog=sys.stdout):
    print >>flog, self.Banner(True)
    print >>flog, "  Name: [%s]" % self.partition_name
    print >>flog, "  Length: %08X" % self.partition_length
    print >>flog, "  Hash: %s" % self.partition_hash.encode("hex")
    print >>flog, "  VCN: %d" % self.version_control_number
    print >>flog, "  Ver: %X, %X" % (self.partition_version, self.data_format_version)
    print >>flog, "  Instance ID: %d" % self.instance_id
    print >>flog, "  Flags: %d" % self.flags
    print >>flog, "  Unknown: %d" % self.unknown0
    print >>flog, "  Modules[%d]:" % len(self.modules)
    self.PrintItems(flog)

#***************************************************************************

class Module_Info:
  dModType = {
    PROCESS_TYPE:        "Proc",	# 0
    SHARED_LIBRARY_TYPE: "Lib ",	# 1
    DATA_TYPE:           "Data",	# 2
    IUNIT_TYPE:          "iUnt",	# 3 v12
  }
  MANIFEST_MODULE_INFO_EXT = (
    ("name",			"12s",	),		# Character array. If name length is shorter than field size the name is padded with 0 bytes
    ("type",			"B",	(0,1,2,3)),	# 0 - Process; 1 - Shared Library; 2 - Data; 3 - iUnit
    ("reserved0",		"B",	),		#
    ("reserved1",		"H",	(0, 0xFFFF)),	# set to 0xffff
    ("metadata_size",		"L",	),		#
    ("metadata_hash",		"32s"	),		# For a process/shared library this is the SHA256 of the module metadata file; for a data module this is the SHA256 hash of the module binary itself
  )
  def __init__(self, stR):
    stR.read(self, self.MANIFEST_MODULE_INFO_EXT)
    self.name = self.name.rstrip('\0')
    self.metadata_hash = self.metadata_hash[::-1] # Reverse

  def __str__(self):
    return "%-4s, Meta cb:%4X h:%s %s" % (self.dModType[self.type], self.metadata_size, self.metadata_hash.encode("hex"), self.name)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Shared_Lib_Ext(Extension): # 4 : used in Metadata
  NAME = "SharedLib"
  TYPE = 4 # for shared library extension
  # length: In bytes equals 52 for this version
  SHARED_LIB_EXTENSION = (
    ("context_size",		"L",	),		# Size in bytes of the shared library context
    ("total_alloc_virtual_space", "L",	),		# Including padding pages for library growth. Currently set to a temporary value. This needs to be updated once the SHARED_CONTEXT_SIZE symbol is defined in the build process.
    ("code_base_address",	"L",	),		# Base address for the library private code in VAS. Must be 4KB aligned.
    ("tls_size",		"L",	),		# Size of Thread-Local-Storage used by the shared library.
    ("reserved",		"L",	),		# reserved bytes set to 0xffffffff
  )
  def __init__(self, ab):
    stR = StructReader(ab)
    stR.read(self, self.SHARED_LIB_EXTENSION)
    stR.done()

  def dump(self, flog=sys.stdout):
    print >>flog, "%s context_size:0x%X, total_alloc_virtual_space:0x%X, code_base_address:0x%X, tls_size:0x%x" % (self.Banner(), self.context_size, self.total_alloc_virtual_space, self.code_base_address, self.tls_size)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Man_Process_Ext(Extension): # 5 : used in Metadata
  NAME = "Process"
  TYPE = 5 # for process attribute extension
  # length: In bytes equals 160 + 2*n for this version where n is the number of group IDs entries in the extension
  MAN_PROCESS_EXTENSION = (
    ("bf_flags",		"L",	),		# Flags
    ("main_thread_id",		"L",	),		# TID for main thread. Optional for IBL processes only. Must be 0 for other processes.
    ("priv_code_base_address",	"L",	),		# Base address for code. Address is in LAS for Bringup/Kernel VAS for other processes. Must be 4KB aligned
    ("uncompressed_priv_code_size","L",	),		# Size of uncompressed process code. Does not include code for shared library.
    ("cm0_heap_size",		"L",	),		# Size of Thread-Local-Storage for the process
    ("bss_size",		"L",	),		#
    ("default_heap_size",	"L",	),		#
    ("main_thread_entry",	"L",	),		# VAS of entry point function for the process main thread
    ("allowed_sys_calls",	"12s",	),		# Bitmask of allowed system calls by the process
    ("user_id",			"H",	),		# Runtime User ID for process
    ("reserved_0",		"L",	),		# Temporary placeholder for thread base
    ("reserved_1",		"H",	0),		# Must be 0
    ("reserved_2",		"Q",	),		#
    # group_ids['H'] # Group ID for process
  )
  def __init__(self, ab):
    stR = StructReader(ab)
    stR.read(self, self.MAN_PROCESS_EXTENSION)
    abGIDs = stR.ab[stR.o:]
    self.group_ids = list(struct.unpack("<%dH" % (len(abGIDs) / 2), abGIDs))
    self.flags = Man_Process_Flags(self.bf_flags)

  def dump(self, flog=sys.stdout):
    print >>flog, self.Banner()
    print >>flog, "    flags: %s" % self.flags
    print >>flog, "    main_thread_id: 0x%X" % self.main_thread_id
    print >>flog, "    priv_code_base_address: 0x%08X" % self.priv_code_base_address
    print >>flog, "    uncompressed_priv_code_size: 0x%X" % self.uncompressed_priv_code_size
    print >>flog, "    cm0_heap_size: 0x%X" % self.cm0_heap_size
    print >>flog, "    bss_size: 0x%X" % self.bss_size
    print >>flog, "    default_heap_size: 0x%X" % self.default_heap_size
    print >>flog, "    main_thread_entry: 0x%08X" % self.main_thread_entry
    print >>flog, "    allowed_sys_calls: %s" % self.allowed_sys_calls.encode("hex")
    print >>flog, "    user_id: 0x%04X" % self.user_id
    print >>flog, "    group_ids[%d]: [%s]" % (len(self.group_ids), ", ".join("0x%04X" % gid for gid in self.group_ids))

#***************************************************************************

class Man_Process_Flags:
  MAN_PROCESS_FLAGS = ( # BitFields
    ("fault_tolerant",		0,	0),	# Kernel exception policy: 0 - Reset System, 1 - Terminate Process
    ("permanent_process",	1,	1),	# permanent process Y/N. A permanent process' code/rodata sections are not removed from RAM when it terminates normally in order to optimize its reload flow.
    ("single_instance",		2,	2),	# Single Instance Y/N. When the process is spawned if it is already running in the system the spawn will fail.
    ("trusted_snd_rev_sender",	3,	3),	# Trusted SendReceive Sender Y/N. If set this process is allowed to send IPC_SendReceive messages to any process (not only public).
    ("trusted_notify_sender",	4,	4),	# Trusted Notify Sender Y/N. If set this process is allowed to send IPC_Notify notifications to any process (not only public).
    ("public_snd_rev_receiver",	5,	5),	# Public SendReceive Receiver Y/N. If set any other process is allowed to send IPC_SendReceive messages to it (not only trusted).
    ("public_notify_receiver",	6,	6),	# Public Notify Receiver Y/N. If set any other process is allowed to IPC_Notify notifications messages to it (not only trusted).
    #("reserved",		7,	31),	# reserved. Set to 0
  )
  def __init__(self, dw):
    BitFields(self, dw, self.MAN_PROCESS_FLAGS)

  def __str__(self):
    return ", ".join(ListTrueBools(self, self.MAN_PROCESS_FLAGS))

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Threads_Ext(Extension): # 6 : used in Metadata
  NAME = "Threads"
  TYPE = 6 # for threads extension
  LIST = "threads"
  def __init__(self, ab):
    self.LoadItems(StructReader(ab), Thread_Entry)

  def dump(self, flog=sys.stdout):
    print >>flog, self.Banner()
    self.PrintItems(flog)

#***************************************************************************

class Thread_Entry:
  THREAD_ENTRY = (
    ("stack_size",	"L",	),		# Size of main thread stack in bytes (not including guard page including space reserved for TLS). Must be divisible by 4K with the following exception: if the default heap size is smaller than 4K the last thread's stack size may have any size.
    ("flags",		"L",	),		# Bit0 - set to 0 for live thread 1 for CM0-U-only thread; Bits 1-31 - reserved must be 0
    ("scheduling_policy", "L",	),		# Bits 0-7: Scheduling Policy, 0 -> fixed priority; Bits 8-31: Scheduling attributes. For a fixed priority policy this is the scheduling priority of the thread.
    ("reserved",	"L",	),		#
  )
  def __init__(self, stR):
    stR.read(self, self.THREAD_ENTRY)

  def __str__(self):
    return "stack_size:0x%08X, flags:%X, scheduling_policy:%08X" % (self.stack_size, self.flags, self.scheduling_policy)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Device_Ids_Ext(Extension): # 7 : used in Metadata
  NAME = "DeviceIds"
  TYPE = 7 # for device ids extension
  LIST = "device_id_group"
  def __init__(self, ab):
    self.LoadItems(StructReader(ab), Device_Entry)

  def dump(self, flog=sys.stdout):
    print >>flog, "%s [%s]" % (self.Banner(), ", ".join("%08X" % v.device_id for v in self.device_id_group))

#***************************************************************************

class Device_Entry:
  DEVICE_ENTRY = (
    ("device_id",	"L",	),		#
    ("reserved",	"L",	),		#
  )
  def __init__(self, stR):
    stR.read(self, self.DEVICE_ENTRY)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Mmio_Ranges_Ext(Extension): # 8 : used in Metadata
  NAME = "MmioRanges"
  TYPE = 8 # for mmio ranges extension
  LIST = "mmio_range_defs"
  def __init__(self, ab):
    self.LoadItems(StructReader(ab), Mmio_Range_Def)

  def dump(self, flog=sys.stdout):
    print >>flog, self.Banner()
#    self.PrintItems(flog)
    for i,e in enumerate(getattr(self, self.LIST)): print >>flog, "    %s" % (e)

#***************************************************************************

class Mmio_Range_Def:
  MMIO_RANGE_DEF = (
    ("base",		"L",	),		# Base address of the MMIO range
    ("size",		"L",	),		# Limit in bytes of the MMIO range
    ("flags",		"L",	),		# Read access Y/N
  )
  def __init__(self, stR):
    stR.read(self, self.MMIO_RANGE_DEF)

  def __str__(self):
    return "base:%08X, size:%08X, flags:%08X" % (self.base, self.size, self.flags)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Special_File_Producer_Ext(Extension): # 9 : used in Metadata
  NAME = "SpecialFileProducer"
  TYPE = 9 # for special file producer extension
  LIST = "files"
  SPECIAL_FILE_PRODUCER_EXTENSION = (
    ("major_number",		"H",	),		#
    ("flags",			"H",	),		#
    # SPECIAL_FILE_DEF[]
  )
  def __init__(self, ab):
    stR = StructReader(ab)
    stR.read(self, self.SPECIAL_FILE_PRODUCER_EXTENSION)
    self.LoadItems(stR, Special_File_Def)

  def dump(self, flog=sys.stdout):
    print >>flog, "%s major_number=0x%04X" % (self.Banner(), self.major_number)
    self.PrintItems(flog)

#***************************************************************************

class Special_File_Def:
  SPECIAL_FILE_DEF = (
    ("name",			"12s",	),		#
    ("access_mode",		"H",	),		#
    ("user_id",			"H",	),		#
    ("group_id",		"H",	),		#
    ("minor_number",		"B",	),		#
    ("reserved0",		"B",	),		#
    ("reserved1",		"L",	),		#
  )
  def __init__(self, stR):
    stR.read(self, self.SPECIAL_FILE_DEF)
    self.name = self.name.rstrip('\0')

  def __str__(self):
    return "%-12s access_mode:%04o, user_id:0x%04X group_id:0x%04X minor_number:%02X" % (self.name, self.access_mode, self.user_id, self.group_id, self.minor_number)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Mod_Attr_Ext(Extension): # 10 : used in Metadata
  NAME = "ModAttr"
  TYPE = 10 # for this module attribute extension
  # length: In bytes; equals 56 for this version
  dCompType = {
    COMP_TYPE_NOT_COMPRESSED:"    ",
    COMP_TYPE_HUFFMAN:"Huff",
    COMP_TYPE_LZMA:"LZMA",
  }
  MOD_ATTR_EXTENSION = (
    ("compression_type",	"B",	(0,1,2,)),	# 0 - Uncompressed; 1 - Huffman Compressed; 2 - LZMA Compressed
    ("encrypted",		"B",	(0,1)),		# Used as "encrypted" flag
    ("reserved1",		"B",	0), 		# Must be 0
    ("reserved2",		"B",	0), 		# Must be 0
    ("uncompressed_size",	"L",	),		# Uncompressed image size must be divisible by 4K
    ("compressed_size",		"L",	),		# Compressed image size. This is applicable for LZMA compressed modules only. For other modules should be the same as uncompressed_size field.
    ("module_number",		"H",	),		# Module number unique in the scope of the vendor.
    ("vendor_id",		"H",	0x8086),	# Vendor ID (PCI style). For Intel modules must be 0x8086.
    ("image_hash",		"32s",	),		# SHA2 Hash of uncompressed image
  )
  def __init__(self, ab):
    stR = StructReader(ab)
    stR.read(self, self.MOD_ATTR_EXTENSION)
    self.image_hash = self.image_hash[::-1] # Reverse
    stR.done()

  def dump(self, flog=sys.stdout):
    print >>flog, "%s %s enc=%d %08X->%08X id:%04X.%04X h:%s" % (self.Banner(), self.dCompType[self.compression_type], self.encrypted, self.compressed_size, self.uncompressed_size, self.module_number, self.vendor_id, self.image_hash.encode("hex"))

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Locked_Ranges_Ext(Extension): # 11 : used in Metadata
  NAME = "LockedRanges"
  TYPE = 11 # for unknown 11 extension
  LIST = "ranges"
  def __init__(self, ab):
    self.LoadItems(StructReader(ab), Locked_Range)

  def dump(self, flog=sys.stdout):
    print >>flog, self.Banner()
    self.PrintItems(flog)

#***************************************************************************

class Locked_Range:
  LOCKED_RANGE = (
    ("base",		"L",	),		# Base address in VAS of range to be locked. Must be divisible in 4KB.
    ("size",		"L",	),		# Size of range to be locked. Must be divisible in 4KB.
  )
  def __init__(self, stR):
    stR.read(self, self.LOCKED_RANGE)

  def __str__(self):
    return "base:0x%08X, size:%X" % (self.base, self.size)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Client_System_Info_Ext(Extension): # 12 : used in Manifest
  NAME = "ClientSystemInfo"
  TYPE = 12 # for client system info extension
  CLIENT_SYSTEM_INFO_EXTENSION = (
    ("fw_sku_caps",		"L",	),		#
    ("fw_sku_caps_reserved",	"28s",	'\xFF'*28),	#
    ("bf_fw_sku_attributes",	"Q",	),		# Bits 0:3 - CSE region size in multiples of 0.5 MB Bits 4:6 - firmware sku; 0 for 5.0MB 1 for 1.5MB 2 for slim sku. Bit 7 - Patsberg support Y/N Bit 8 - M3 support Y/N Bit 9 - M0 support Y/N Bits 10:11 - reserved Bits 12:15 - Si class (all H M L) Bits 16:63 - reserved
  )

  def __init__(self, ab):
    stR = StructReader(ab)
    stR.read(self, self.CLIENT_SYSTEM_INFO_EXTENSION)
    self.attr = Client_System_Sku_Attributes(self.bf_fw_sku_attributes)
    stR.done()

  def dump(self, flog=sys.stdout):
    print >>flog, self.Banner()
    print >>flog, "    fw_sku_caps: %x" % self.fw_sku_caps
    print >>flog, "    fw_sku_attributes: %s" % self.attr

#***************************************************************************

class Client_System_Sku_Attributes:
  dFirmwareSKU = {
    0: "5.0MB",
    1: "1.5MB",
    2: "Slim",
    3: "SPS",
  }
  CLIENT_SYSTEM_SKU_ATTRIBUTES = ( # BitFields
    ("CSE_region_size",		0,	3),		# Bits 0:3 - CSE region size in multiples of 0.5 MB
    ("firmware_sku",		4,	6),		# Bits 4:6 - firmware sku; 0 for 5.0MB 1 for 1.5MB 2 for slim sku.
    ("Patsberg",		7,	7),		# Bit 7 - Patsberg support Y/N
    ("M3",			8,	8),		# Bit 8 - M3 support Y/N
    ("M0",			9,	9),		# Bit 9 - M0 support Y/N
#    ("reserved0",		10,	11),		# Bits 10:11 - reserved
    ("Si_class",		12,	15),		# Bits 12:15 - Si class (all H M L)
#    ("reserved1",		16,	63),		# Bits 16:63 - reserved
  )
  def __init__(self, qw):
    BitFields(self, qw, self.CLIENT_SYSTEM_SKU_ATTRIBUTES)

  def __str__(self):
    return "CSE region size: %.2f, firmware sku: %s, Si class: %X, %s" % (0.5*self.CSE_region_size, self.dFirmwareSKU[self.firmware_sku], self.Si_class, ", ".join(ListTrueBools(self, self.CLIENT_SYSTEM_SKU_ATTRIBUTES)))

#***************************************************************************
#***************************************************************************
#***************************************************************************

class User_Info_Ext(Extension): # 13 : used in Manifest
  NAME = "UserInfo"
  TYPE = 13 # for user info extension
  LIST = "users"
  def __init__(self, ab):
    try:
      self.LoadItems(StructReader(ab), User_Info_Entry)
    except:
      self.LoadItems(StructReader(ab), User_Info_Entry_new)

  def dump(self, flog=sys.stdout):
    print >>flog, self.Banner()
    self.PrintItems(flog)

#***************************************************************************

class User_Info_Entry:
  USER_INFO_ENTRY = (
    ("user_id",			"H",	),		# User ID.
    ("reserved",		"H",	(0,1)),		# Must be 0.
    ("non_volatile_storage_quota","L",	),		# Maximum size of non-volatile storage area.
    ("ram_storage_quota",	"L",	),		# Maximum size of RAM storage area.
    ("wop_quota",		"L",	),		# Quota to use in wear-out prevention algorithm; in most cases this should match the non-volatile storage quota; however it is possible to virtually add quota to a user to allow it to perform more write operations on expense of another user. At build time the build system will check that the sum of all users WOP quota is not more than the sum of all users non-volatile storage quota.
    ("working_dir",		"36s",	),		# Starting directory for the user. Used when accessing files with a relative path. Character array; if name length is shorter than field size the name is padded with 0 bytes.
  )
  def __init__(self, stR):
    stR.read(self, self.USER_INFO_ENTRY)
    self.working_dir = self.working_dir.rstrip('\0')
    assert self.working_dir.find('\0') < 0

  def __str__(self):
    return "user id:0x%04X, NV quota:%8X, RAM quota:%8X, WOP quota:%8X, working dir: [%s]" % (self.user_id, self.non_volatile_storage_quota, self.ram_storage_quota, self.wop_quota, self.working_dir)

#***************************************************************************

class User_Info_Entry_new:
  USER_INFO_ENTRY = (
    ("user_id",			"H",	),		# User ID.
    ("reserved",		"H",	0),		# Must be 0.
    ("non_volatile_storage_quota","L",	),		# Maximum size of non-volatile storage area.
    ("ram_storage_quota",	"L",	),		# Maximum size of RAM storage area.
    ("wop_quota",		"L",	),		# Quota to use in wear-out prevention algorithm; in most cases this should match the non-volatile storage quota; however it is possible to virtually add quota to a user to allow it to perform more write operations on expense of another user. At build time the build system will check that the sum of all users WOP quota is not more than the sum of all users non-volatile storage quota.
  )
  def __init__(self, stR):
    stR.read(self, self.USER_INFO_ENTRY)

  def __str__(self):
    return "user id:0x%04X, NV quota:%8X, RAM quota:%8X, WOP quota:%8X" % (self.user_id, self.non_volatile_storage_quota, self.ram_storage_quota, self.wop_quota)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Package_Info_Ext(Extension): # 15 : used in TXE Mainfist
  NAME = "PackageInfo"
  TYPE = 15 # for partition info extension
  LIST = "modules"
  SIGNED_PACKAGE_INFO_EXT = (
    ("package_name",		"4s",	),		# Name of the partition
    ("version_control_number",	"L",	),		# The version control number (VCN) is incremented whenever a change is made to the FW that makes it incompatible from an update perspective with previously released versions of the FW.
    ("usage_bitmap",		"16s",	),		# Bitmap of usages depicted by this manifest, indicating which key is used to sign the manifest
    ("svn",			"L",	),		# Secure Version Number
    ("unknown",			"L",	),		#
    ("reserved",		"12s",	'\x00'*12),	# Must be 0
    # SIGNED_PACKAGE_INFO_EXT_ENTRY[] # Module info extension entries
  )
  def __init__(self, ab):
    stR = StructReader(ab)
    stR.read(self, self.SIGNED_PACKAGE_INFO_EXT)
    self.package_name = self.package_name.rstrip('\0')
    self.LoadItems(stR, Package_Info_Ext_Entry)

  def dump(self, flog=sys.stdout):
    print >>flog, self.Banner(True)
    print >>flog, "  Name: [%s]" % self.package_name
    print >>flog, "  VCN: %d" % self.version_control_number
    print >>flog, "  Usage Bitmap: %s" % self.usage_bitmap.encode("hex")
    print >>flog, "  svn: %d" % self.svn
    print >>flog, "  unknown: 0x%X" % self.unknown
    print >>flog, "  Modules[%d]:" % len(self.modules)
    self.PrintItems(flog)

#***************************************************************************

class Package_Info_Ext_Entry:
  dModType = {
    PROCESS_TYPE:        "Proc",	# 0
    SHARED_LIBRARY_TYPE: "Lib ",	# 1
    DATA_TYPE:           "Data",	# 2
    IUNIT_TYPE:		 "iUnt",	# 3 v12
  }
  dHashAlgorithm = {
    1: "SHA1",
    2: "SHA256",
  }
  SIGNED_PACKAGE_INFO_EXT_ENTRY = (
    ("name",			"12s",	),		# Character array. If name length is shorter than field size the name is padded with 0 bytes
    ("type",			"B",	(0,1,2,3)),	# 0 - Process; 1 - Shared Library; 2 - Data; 3 - iUnit
    ("hash_algorithm",		"B",	2),		# 0 - Reserved; 1 - SHA1; 2 - SHA256
    ("hash_size",		"H",	32),		# Size of Hash in bytes = N; BXT to support only SHA256. So N=32.
    ("metadata_size",		"L",	),		# Size of metadata file
    ("metadata_hash",		"32s"	),		# The SHA2 of the module metadata file
  )
  def __init__(self, stR):
    stR.read(self, self.SIGNED_PACKAGE_INFO_EXT_ENTRY)
    self.name = self.name.rstrip('\0')
    self.metadata_hash = self.metadata_hash[::-1] # Reverse

  def __str__(self):
    return "%-4s, Meta cb:%4X h=%s[%d]:%s %s" % (self.dModType[self.type], self.metadata_size, self.dHashAlgorithm[self.hash_algorithm], self.hash_size, self.metadata_hash.encode("hex"), self.name)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Unk_16_Ext(Extension): # 16 : used in Manifest (for iUnit)
  NAME = "Unk_iUnit_16"
  TYPE = 16 # for iUnit extension
  UNK_IUNIT_16_EXT = (
    ("v0_1",			"L",	1),		#
    ("unk16",			"16s",	'\0'*16),	#
    ("v2_3",			"L",	3),		#
    ("v3",			"L",	),		#
    ("v4_1",			"L",	1),		#
    ("h",			"32s",	),		#
    ("reserved",		"24s",	'\0'*24),	#
  )
  def __init__(self, ab):
    stR = StructReader(ab)
    stR.read(self, self.UNK_IUNIT_16_EXT)
#    self.h = self.h[::-1] # Reverse?
    stR.done()

  def dump(self, flog=sys.stdout):
    print >>flog, self.Banner()
    print >>flog, "  %X %X %X %X h=%s" % (self.v0_1, self.v2_3, self.v3, self.v4_1, self.h.encode("hex"))

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Unk_18_Ext(Extension): # 18 : used in Manifest
  NAME = "Unk_18"
  TYPE = 18 # for user info extension
  LIST = "records"
  UNK_18_EXT = (
    ("items",			"L",	),		#
    ("unk",			"16s",	),		#
  )
  def __init__(self, ab):
    stR = StructReader(ab)
    stR.read(self, self.UNK_18_EXT)
    self.LoadItems(stR, Unk_18_Ext_Entry)

  def dump(self, flog=sys.stdout):
    print >>flog, self.Banner()
    print >>flog, "  Records[%d] %s:" % (self.items, self.unk.encode("hex"))
    self.PrintItems(flog)

#***************************************************************************

class Unk_18_Ext_Entry:
  UNK_18_EXT_ENTRY = (
    ("ab",			"56s",	),		#
  )
  def __init__(self, stR):
    stR.read(self, self.UNK_18_EXT_ENTRY)

  def __str__(self):
    return self.ab.encode("hex")

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Unk_22_Ext(Extension): # 22 : used in Manifest (v12)
  NAME = "Unk_22"
  TYPE = 22 # for v12 extension
  UNK_22_EXT = (
    ("name",			"4s",	),		#
    ("unk24",			"24s",	),		#
    ("h",			"32s",	),		#
    ("reserved",		"20s",	'\0'*20),	#
  )
  def __init__(self, ab):
    stR = StructReader(ab)
    stR.read(self, self.UNK_22_EXT)
#    self.h = self.h[::-1] # Reverse?
    stR.done()

  def dump(self, flog=sys.stdout):
    print >>flog, "%s [%s] u=%s h=%s" % (self.Banner(), self.name, self.unk24.encode("hex"), self.h.encode("hex"))

#***************************************************************************
#***************************************************************************
#***************************************************************************

class Unk_50_Ext(Extension): # 50 : used in Manifest (HP)
  NAME = "Unk_50"
  TYPE = 50 # for iUnit extension
  UNK_50_EXT = (
    ("name",			"4s",	),		#
    ("dw0",			"L",	0),		#
  )
  def __init__(self, ab):
    stR = StructReader(ab)
    stR.read(self, self.UNK_50_EXT)
    stR.done()

  def dump(self, flog=sys.stdout):
    print >>flog, "%s [%s]" % (self.Banner(), self.name)

#***************************************************************************
#***************************************************************************
#***************************************************************************

aExtHandlers = (
  System_Info_Ext,		# 0
  Init_Script_Ext,		# 1
  Feature_Permissions_Ext,	# 2
  Partition_Info_Ext,		# 3
  Shared_Lib_Ext,		# 4
  Man_Process_Ext,		# 5
  Threads_Ext,			# 6
  Device_Ids_Ext,		# 7
  Mmio_Ranges_Ext,		# 8
  Special_File_Producer_Ext,	# 9
  Mod_Attr_Ext,			# 10
  Locked_Ranges_Ext,		# 11
  Client_System_Info_Ext,	# 12
  User_Info_Ext,		# 13
#  None,			# 14
  Package_Info_Ext,		# 15
  Unk_16_Ext,			# 16
  Unk_18_Ext,			# 18
  Unk_22_Ext,			# 22
  Unk_50_Ext,			# 50
)

dExtHandlers = {ext.TYPE: ext for ext in aExtHandlers}

def Ext_ParseAll(obj, ab, o=0):
  def EnumTags(ab, o=0):
    while o < len(ab):
      tag, cb = struct.unpack_from("<LL", ab, o)
      assert cb >= 8
      assert o+cb <= len(ab)
      yield tag, ab[o+8:o+cb]
      o += cb

  obj.extList = []
  for extType, extData in EnumTags(ab, o):
    ext = dExtHandlers.get(extType, None)
    if ext is not None:
      extObj = ext(extData)
      setattr(obj, ext.NAME, extObj)
      obj.extList.append(extObj)
#    else: raise Error("Extension #%d[%d] not supported" % (extType, len(extData)))
    else:
      parent = obj.name + (".met" if isinstance(obj, CPD_Entry) else "")
      print >>sys.stderr, "- %s: Unknown extType#%d[%d] %s" % (parent, extType, len(extData), extData.encode("hex"))

def Ext_DumpAll(obj, flog=sys.stdout):
  if hasattr(obj, "extList"):
    for extObj in obj.extList: extObj.dump(flog)
#  for ext in aExtHandlers:
#    if hasattr(obj, ext.NAME): getattr(obj, ext.NAME).dump(flog)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class CPD_Manifest:
  MARKER = "$MN2"
  MANIFEST_HEADER = (
    ("type",			"L",	4),		# Must be 0x4
    ("length",			"L",	161),		# in Dwords equals 161 for this version
    ("version",			"L",	0x10000),	# 0x1000 for this version
    ("flags",			"L",	),		# Debug intel owned
    ("vendor",			"L",	0x8086),	# 0x8086 for intel
    ("date",			"L",	),		# yyymmdd in BCD format
    ("size",			"L",	),		# in Dwords size of the entire manifest. Maximum size is 2K DWORDS (8KB)
    ("header_id",		"4s",	MARKER),	# Magic number. Equals $MN2 for this version
    ("reserved0",		"L",	),		# Must be 0x4 [not True: it is 0!]
    ("version_major",		"H",	),		# Major Version [== 11]
    ("version_minor",		"H",	),		# Minor Version
    ("version_hotfix",		"H",	),		# Hotfix
    ("version_build",		"H",	),		# Build number
    ("svn",			"L",	),		# Secure Version Number
    ("reserved1",		"Q",	0),		# must be 0
    ("reserved2",		"64s",	'\0'*64),	# will be set to 0
    ("modulus_size",		"L",	64),		# In DWORDs; 64 for pkcs 1.5-2048
    ("exponent_size",		"L",	1),		# In DWORDs; 1 for pkcs 1.5-2048
  )
  CRYPTO_BLOCK = (
    ("public_key",		"256s",	),		# Public Key
    ("exponent",		"L",	),		# Exponent [== 17]
    ("signature",		"256s"	),		# RSA signature of manifest
  )
  def __init__(self, ab, name):
    self.name = name
    self.stR = StructReader(ab)
    self.stR.read(self, self.MANIFEST_HEADER)
    self.stR.read(self, self.CRYPTO_BLOCK)
    assert 4*self.size == len(ab)
    Ext_ParseAll(self, ab, 4*self.length) # Parse all Extensions

    if 12 == self.version_major: g.HuffDecoder = HuffDecoder12

  def dump(self, flog=sys.stdout):
    print >>flog, "CPD Manifest"
    print >>flog, "  Date: %08X" % self.date
    print >>flog, "  Version: %d.%d.%d.%d" % (self.version_major, self.version_minor, self.version_hotfix, self.version_build)
    print >>flog, "  SVN: %08X" % self.svn

    # Validate RSA Public Key hash
    h = hashlib.sha256(self.public_key + struct.pack("<L", self.exponent)).digest()
    try:
      print >>flog, "  RSA Modulus: known[%d]," % aPubKeyHash.index(h),
    except:
      print >>flog, "- RSA Modulus is unknown,",

    # Validate RSA Signatire
    h = hashlib.sha256(self.stR.ab[:0x80] + self.stR.ab[4*self.length:]).digest()
    modulus = int(self.public_key[::-1].encode("hex"), 16)
    sign = int(self.signature[::-1].encode("hex"), 16)
    decoded = ("%0512X" % pow(sign, self.exponent, modulus)).decode("hex")
    expected = "\x00\x01" + "\xFF"*202 + "003031300D060960864801650304020105000420".decode("hex") + h
    print >>flog, "Exponent:%d, Verification:%s" % (self.exponent, "OK" if decoded == expected else "FAILED")
    Ext_DumpAll(self, flog) # Dump all extensions

#***************************************************************************
#***************************************************************************
#***************************************************************************

class CPD_Entry:
  CPD_ENTRY_OFFSET = ( # BitFields
    ("address",		        0,	24),
    ("compress_flag",		25,	25),
#    ("offset_reserved",		26,	31),
  )
  CPD_ENTRY = (
    ("name",			"12s",	),
    ("bf_offset",		"L",	),
    ("length",			"L",	),
    ("reserved",		"L",	),
  )
  def __init__(self, parent):
    self.cpd = parent
    self.cpd.stR.read(self, self.CPD_ENTRY)
    self.name = self.name.rstrip('\0')
    BitFields(self, self.bf_offset, self.CPD_ENTRY_OFFSET)
    self.mod = None
    self.metadata = None

  def __str__(self):
    return "%-12s %s %8X %-8X" % (self.name, "HUFF" if self.compress_flag else "    ", self.address, self.length)

  def getData(self):
    return self.cpd.stR.getData(self.address, self.ModAttr.compressed_size if self.compress_flag else self.length)

  def saveRaw(self, baseDir, name=None):
    if name is None: name = self.name
    with open (os.path.join(baseDir, name), "wb") as fo: fo.write(self.getData())

#***************************************************************************
#***************************************************************************
#***************************************************************************

class CPD: # Code Partition Directory
  MARKER = "$CPD"
  CPD_HEADER = (
    ("marker",			"4s",	MARKER),
    ("entries",			"L",	),
    ("header_version", 		"B",	0x01),
    ("entry_version", 		"B",	0x01),
    ("header_length", 		"B",	0x10),
    ("checksum", 		"B",	),
    ("partition_name",		"4s",	),
  )
  def __init__(self, ab, base):
    self.stR = StructReader(ab, base)
    self.stR.read(self, self.CPD_HEADER) # Read header
    self.partition_name = self.partition_name.rstrip('\0')
    self.files = [CPD_Entry(self) for i in xrange(self.entries)] # Read directory entries
    self.d = {e.name:e for e in self.files} # Dict maps name CPD_Entry

    e = self.files[0] # Access Manifest (very first entry in lookup table)
    self.Manifest = CPD_Manifest(e.getData(), e.name) if e.name.endswith(".man") else None
#    assert self.partition_name + ".man" == e.name

    self.modules = None
    if self.Manifest:
      if hasattr(self.Manifest, "PackageInfo"):
        self.modules = self.Manifest.PackageInfo.modules
      elif hasattr(self.Manifest, "PartitionInfo"):
        self.modules = self.Manifest.PartitionInfo.modules
        if len(self.files) != 1 + 2*len(self.modules): # Manfest + nFiles * (Data + Metadata)
          print >>sys.stderr, "- Partition holds %d files but only %d module[s] (%d expected)" % (len(self.files), len(self.modules), (len(self.files)-1)/2)

    if self.modules: # Try to attach Module Info and Metadata to Entry
      for i,mod in enumerate(self.modules): # Walk through modules listed in partion manifest
        e = self.d[mod.name] # Access CPD_Entry by module name
        e.mod = mod # Attach Module Info to entry
        metaName = e.name if e.name.endswith(".met") else e.name + ".met"
        e.metadata = self.d[metaName].getData() # Get Metadata content
        assert len(e.metadata) == e.mod.metadata_size # Check Metadata length
#        assert hashlib.sha256(e.metadata).digest() == mod.metadata_hash # Check Metadata hash
        if hashlib.sha256(e.metadata).digest() != e.mod.metadata_hash: # Check Metadata hash
          print >>sys.stderr, "MetaHash %s[%d]: %s != %s" % (e.name, e.mod.metadata_size, hashlib.sha256(e.metadata).hexdigest(), e.mod.metadata_hash.encode("hex"))
        Ext_ParseAll(e, e.metadata) # Parse all Metadata Extensions and store them in CPD_Entry

  def dump(self, flog=sys.stdout, baseDir=None):
    print >>flog, "%08X: CPD %-4s.%02X [%d]" % (self.stR.base, self.partition_name, self.checksum, self.entries)
    if baseDir is not None:
      baseDir = os.path.join(baseDir, "%08X.%s" % (self.stR.base, self.partition_name))
      if not os.path.exists(baseDir): os.makedirs(baseDir)
      if self.Manifest:
        with open(os.path.join(baseDir, "Manifest.txt"), "wt") as fo: self.Manifest.dump(fo)
    if self.Manifest: self.Manifest.dump(flog)

    print >>flog, "\nCPD Files[%d]:" % len(self.files)
    for i,e in enumerate(self.files):
      print >>flog, "=================================\n%4d: %s" % (i+1, e)
      Ext_DumpAll(e, flog) # Dump all Metadata Extensions
      if baseDir is None: continue

      fileName = e.name
      fileExt = os.path.splitext(fileName)[1]
      bSaveRaw = False
      if ".man" == fileExt: # CPD Manifest
        if g.dumpManifest: bSaveRaw = True
      elif ".met" == fileExt: # Module Metadata
        if g.dumpMeta: bSaveRaw = True
      else: # Module
        if e.metadata: # Module (with metadata)
          if g.dumpRaw:
            bSaveRaw = True
            fileName += ".raw"
        else: bSaveRaw = True # Not a module (without metadata) - always dump "as is"
      if bSaveRaw: e.saveRaw(baseDir, fileName) # Save raw file data (compressed/encrypted)

      if e.metadata: # Only for modules with metadata
        with open(os.path.join(baseDir, "%s.txt" % e.name), "wt") as fo: # Dump module info
          print >>fo, "%4d: %s" % (i+1, e)
          Ext_DumpAll(e, fo) # Dump all Metadata Extensions

        if not hasattr(e, "ModAttr"):
          e.saveRaw(baseDir)
          continue

        compType = dCompType[e.ModAttr.compression_type]
        data = e.getData()
        if e.ModAttr.encrypted:
          print >>sys.stderr, "- Module %s is encrypted" % e.name

        if "huff" == compType:
          assert e.length == e.ModAttr.uncompressed_size
          nChunks, left = divmod(e.length, 0x1000)
          assert 0 == left

        plain = decompress(data, compType, e.length)

        hashChecked = False
        if "huff" != compType and hashlib.sha256(data).digest() == e.ModAttr.image_hash:
#          print "%8s: data" % e.name
          hashChecked = True

        if plain:
          if not hashChecked:
#            assert hashlib.sha256(plain).digest() == e.ModAttr.image_hash
            if hashlib.sha256(plain).digest() == e.ModAttr.image_hash:
              hashChecked = True
#              print "%8s: plain" % e.name

          with open(os.path.join(baseDir, "%s.mod" % e.name), "wb") as fo: fo.write(plain)
        else:
          if "huff" == compType:
            chunks = HUFF_chunks(nChunks, data)
            chunks.save(os.path.join(baseDir, "%s.%s" % (e.name, compType)))
            if g.dumpChunks: chunks.dump(os.path.join(baseDir, "%s" % e.name))
          else:
            with open(os.path.join(baseDir, "%s.%s" % (e.name, compType)), "wb") as fo:
              fo.write(data)
        if not hashChecked: print >>sys.stderr, "- hash %s.%s[%s]: %s" % (self.partition_name, e.name, compType, e.ModAttr.image_hash.encode("hex"))
#    print

#***************************************************************************
#***************************************************************************
#***************************************************************************

class HUFF_chunks:
  def __init__(self, nChunks, data=None):
    if isinstance(nChunks, str):
      fn = nChunks
      with open(fn, "rb") as f:
        nChunks = struct.unpack("<L", f.read(4))
        data = f.read()

    self.nChunks = nChunks
    self.data = data

    self.a = []
    base = 4 * self.nChunks
    for v in struct.unpack_from("<%dL" % self.nChunks, self.data):
      opt, offs = divmod(v, 0x40000000)
      if len(self.a): self.a[-1].append(base + offs) # curr.offs is prev.end
      self.a.append([base + offs, opt])
    self.a[-1].append(len(data)) # Add End-Of-Data as last.end

    for iChunk in xrange(self.nChunks): # Verify chunks
      offs, opt, end = self.a[iChunk]
      assert opt in (1, 3)
      assert offs <= end

  def save(self, fn):
    with open(fn, "wb") as fo:
      fo.write(struct.pack("<L", self.nChunks))
      fo.write(self.data)

  def __len__(self): return self.nChunks
  def __getitem__(self, iChunk):
    offs, opt, end = self.a[iChunk]
    return opt, self.data[offs:end]

  def dump(self, baseName):
    chunksDir = baseName + ".chunks"
    if not os.path.exists(chunksDir): os.makedirs(chunksDir)
    for iChunk in xrange(self.nChunks): # Verify chunks
      opt, ab = self[iChunk]
      with open(os.path.join(chunksDir, "%d.%08X" % (opt, iChunk*0x1000)), "wb") as fo: fo.write(ab)


#***************************************************************************
#***************************************************************************
#***************************************************************************

class FPT_Entry_Attributes:
  dAreaType = {
    FPT_AREATYPE_CODE: "Code",
    FPT_AREATYPE_DATA: "Data",
  }

  FPT_ENTRY_ATTRIBUTES = ( # BitFields
    ("type", 			0,	6),
#    ("rsvd0",			7,	14),
    ("bwl0",			15,	15),
    ("bwl1", 			16,	16),
#    ("rsvd1",			17,	23),
    ("entry_invalid",		24,	31),
  )
  def __init__(self, dw): BitFields(self, dw, self.FPT_ENTRY_ATTRIBUTES)

  def __str__(self):
    r = [self.dAreaType[self.type]] + ListTrueBools(self, self.FPT_ENTRY_ATTRIBUTES)
    if self.entry_invalid: r.append("entry_invalid")
    return ", ".join(r)
#    return "%s bwl0=%d, bwl1=%d, entry_valid=%02X" % (, self.bwl0, self.bwl1, self.entry_valid)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class FPT_Entry:
  FPT_ENTRY = (
    ("name",			"4s",	),
    ("reserved",		"L",	),
    ("offset",			"L",	),
    ("length",			"L",	),
    ("reserved1",		"L",	),
    ("reserved2",		"L",	),
    ("reserved3",		"L",	),
    ("bf_attributes",		"L",	), # class:FPT_ENTRY_ATTRIBUTES
  )
  def __init__(self, parent):
    self.fpt = parent
    self.fpt.stR.read(self, self.FPT_ENTRY)
    self.name = self.name.rstrip('\0')
    self.attributes = FPT_Entry_Attributes(self.bf_attributes)

  def getData(self):
    return self.fpt.stR.getData(self.offset, self.length)

  def __str__(self):
    return "[%-4s] %8X:%-8X %s" % (self.name, self.offset, self.length, self.attributes)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class FPT: # Flash Partition Table
  MARKER = '$FPT'
  FPT_HEADER = (
    ("RomBypass",		"16s",	),
    ("HeaderMarker", 		"4s", 	MARKER),
    ("NumFptEntries",		"L",	),
    ("HeaderVersion", 		"B",	0x20),
    ("EntryVersion",		"B",	0x10),
    ("HeaderLength",		"B",	0x20),
    ("HeaderChecksum",		"B",	),
    ("TicksToAdd",		"H",	),
    ("TokensToAdd",		"H",	),
    ("reserved",		"L",	),
    ("FlashLayout",		"L",	),
    ("FitcMajor",		"H",	),
    ("FitcMinor",		"H",	),
    ("FitcHotfix",		"H",	),
    ("FitcBuild",		"H",	),
  )
  def __init__(self, ab, base=0):
    self.stR = StructReader(ab, base)
    self.stR.read(self, self.FPT_HEADER) # Read header
    self.partitions = [FPT_Entry(self) for i in xrange(self.NumFptEntries)] # Read entries

  def dump(self, flog=sys.stdout, baseDir=None):
    print >>flog, "NumFptEntries:  %d" % self.NumFptEntries
    print >>flog, "HeaderVersion:  %d.%d" % divmod(self.HeaderVersion, 16)
    print >>flog, "EntryVersion:   %d.%d" % divmod(self.EntryVersion, 16)
    print >>flog, "HeaderLength:   0x%02X" % self.HeaderLength
    print >>flog, "HeaderChecksum: 0x%02X" % self.HeaderChecksum
    print >>flog, "TicksToAdd:     0x%04X" % self.TicksToAdd
    print >>flog, "TokensToAdd:    0x%04X" % self.TokensToAdd
    print >>flog, "FlashLayout:    0x%X" % self.FlashLayout
    print >>flog, "Fitc:           %d.%d.%d.%d" % (self.FitcMajor, self.FitcMinor, self.FitcHotfix, self.FitcBuild)
    print >>flog, "ROM Bypass instruction: %s" % (self.RomBypass.encode("hex") if self.RomBypass.rstrip('\0') else "<None>")
    for i,e in enumerate(self.partitions):
      print >>flog, "%4d: %s" % (i+1, e)
      if baseDir is None: continue # Do not write files
      data = e.getData()
      if data:
        with open(os.path.join(baseDir, "%08X.%d.%s.part" % (e.offset, e.attributes.type, e.name)), "wb") as fo:
          fo.write(data)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class ME11:
  def __init__(self, fn):
    self.fn = fn
    with open (self.fn, "rb") as f: self.ab = f.read()

    for o in xrange(0, len(self.ab), 0x1000): # Search for FPT
      if not self.ab[o+16:o+16+4] == FPT.MARKER: continue
      self.fpt = FPT(self.ab, o)
      break
    else:
      print "FPT not found"
      self.fpt = None
#      raise Error("FPT not found")

    o = 0
    self.CPDs = []
    while True: # Search for CPDs
      o = self.ab.find(CPD.MARKER, o)
      if o < 0: break
      if "\x01\x01\x10" == self.ab[o+8:o+11]:
#        print "%s at %08X" % (CPD.MARKER, o)
        print ". Processing CPD at 0x%X" % o
        self.CPDs.append(CPD(self.ab, o))
#        try: except: pass
      o += 4

  def dump(self):
    baseDir = os.path.splitext(self.fn)[0]
#    baseDir = None
    if baseDir:
      if not os.path.exists(baseDir): os.makedirs(baseDir)
      flog = open(baseDir + ".txt", "wt")
    else: flog = sys.stdout

    if self.fpt: self.fpt.dump(flog, baseDir)

    for cpd in self.CPDs:
      print >>flog
      cpd.dump(flog, baseDir)

    if flog != sys.stdout: flog.close()

#***************************************************************************
#***************************************************************************
#***************************************************************************

def main(argv):
  for fn in argv[1:]:
    me = ME11(fn)
    me.dump()

if __name__=="__main__": main(sys.argv)
