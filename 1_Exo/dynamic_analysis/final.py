from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC
from miasm.core.locationdb import LocationDB

# Parse arguments

parser = Sandbox_Win_x86_32.parser(description="PE sandboxer")
parser.add_argument("shellcode", help="Shellcode file")
parser.add_argument("filename", help="PE filename (can be dummy)")
options = parser.parse_args()

# Initialiser le sandbox
loc_db = LocationDB()
sb = Sandbox_Win_x86_32(loc_db, options.filename, options, globals())

data = open(options.shellcode, "rb").read()
run_addr = 0x40000000
sb.jitter.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE | PAGE_EXEC, data, "shellcode")
sb.jitter.cpu.EAX = run_addr

sb.jitter.vm.add_memory_page(0x7FFDF002, PAGE_READ | PAGE_WRITE, b"\x00" * 0x6, "dummy")

#0x7FFDF064
sb.jitter.vm.add_memory_page(0x7FFDF064, PAGE_READ | PAGE_WRITE, b"\x02" * 0x4, "dummy")
    
# hwnd=0x0, lptext=0x4000010a, lpcaption=0x40000115, utype=0x0) ret addr: 0x40000076
# Injecter et exécuter le shellcode
sb.run(run_addr)
