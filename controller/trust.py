import ctypes
import os
import socket
import struct
import logging

logger = logging.getLogger("ADG-Trust")

# syscall numbers and constants
__NR_bpf = 321
BPF_OBJ_GET = 7
BPF_MAP_LOOKUP_ELEM = 1

HOST_TRUST_MAP_PATH = "/sys/fs/bpf/HOST_TRUST"

class BpfAttrObjGet(ctypes.Structure):
    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]

class BpfAttrMapLookupElem(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]

class TrustEntry(ctypes.Structure):
    _fields_ = [
        ("score", ctypes.c_uint8),
        ("level", ctypes.c_uint8),
        ("version", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
    ]

libc = ctypes.CDLL("libc.so.6", use_errno=True)

def bpf_syscall(cmd, attr_struct):
    # bpf_attr is exactly 144 bytes on modern linux
    buffer = ctypes.create_string_buffer(144)
    ctypes.memmove(buffer, ctypes.byref(attr_struct), ctypes.sizeof(attr_struct))
    
    ret = libc.syscall(__NR_bpf, cmd, ctypes.byref(buffer), 144)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return ret

class TrustStore:
    def __init__(self):
        self.map_fd = None
        self._open_map()

    def _open_map(self):
        try:
            path_bytes = HOST_TRUST_MAP_PATH.encode('utf-8')
            attr = BpfAttrObjGet()
            attr.pathname = ctypes.cast(ctypes.c_char_p(path_bytes), ctypes.c_void_p).value
            attr.bpf_fd = 0
            attr.file_flags = 0
            
            self.map_fd = bpf_syscall(BPF_OBJ_GET, attr)
            logger.info("Successfully opened HOST_TRUST map.")
        except OSError as e:
            # We don't crash if the map isn't there, we just fallback.
            logger.warning("Could not open HOST_TRUST map at %s: %s", HOST_TRUST_MAP_PATH, e)
            self.map_fd = None

    def get(self, ip: str) -> int:
        if self.map_fd is None:
            self._open_map()
            if self.map_fd is None:
                return 50 # Default trust score if map is unavailable

        try:
            ip_bytes = socket.inet_aton(ip)
            # Rust Ipv4Addr::into() for u32 produces (a<<24)|(b<<16)... (big-endian integer representation)
            ip_u32 = struct.unpack("!I", ip_bytes)[0]
            
            key = ctypes.c_uint32(ip_u32)
            value = TrustEntry()
            
            attr = BpfAttrMapLookupElem()
            attr.map_fd = self.map_fd
            attr.key = ctypes.cast(ctypes.byref(key), ctypes.c_void_p).value
            attr.value = ctypes.cast(ctypes.byref(value), ctypes.c_void_p).value
            attr.flags = 0

            bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr)
            
            return value.score
        except OSError as e:
            # Entry not found (ENOENT) or other error
            return 50
        except Exception as e:
            logger.error("Error looking up trust for %s: %s", ip, e)
            return 50