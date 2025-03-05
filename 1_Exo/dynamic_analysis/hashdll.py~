from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE, PAGE_EXEC

# Initialisation de la machine
machine = Machine("x86_32")
loc_db = LocationDB()
jitter = machine.jitter(loc_db)

# Adresse du shellcode
addr_shellcode = 0x10000
jitter.vm.add_memory_page(addr_shellcode, PAGE_READ | PAGE_WRITE | PAGE_EXEC, b"\x00" * 0x1000)

# Charger le shellcode
shellcode = open('output_015.bin', 'rb').read()
jitter.vm.set_mem(addr_shellcode, shellcode)

# Adresse et allocation de la pile (stack) étendue
addr_stack = 0x20000
jitter.vm.add_memory_page(addr_stack, PAGE_READ | PAGE_WRITE | PAGE_EXEC, b"\x00" * 0x3000)  # Étendre jusqu'à 0x23000
jitter.vm.set_mem(addr_stack + 0x3000 - 4, b"\xef\xbe\x37\x13")  
jitter.cpu.ESP = addr_stack + 0x3000 - 4  # Ajuster ESP

# Vérification mémoire avant exécution
print(f"[INFO] ESP initial: {hex(jitter.cpu.ESP)}")

# Allocation mémoire pour le nom de la DLL
addr_dllname = 0x40000
jitter.vm.add_memory_page(addr_dllname, PAGE_READ | PAGE_WRITE | PAGE_EXEC, b"\x00" * 0x1000, "dll name")
dllname = "kernel32.dll\x00"
jitter.vm.set_mem(addr_dllname, dllname.encode("utf-16le"))

# Initialisation des registres
jitter.cpu.EDI = 0
jitter.cpu.ESI = addr_dllname

# Fonction de debug pour afficher l'état avant crash
def dump(jitter):
    esp_value = jitter.cpu.ESP
    esp_24 = esp_value + 0x24
    try:
        mem_value = jitter.vm.get_mem(esp_24, 4)
        print(f"[DEBUG] ESP + 0x24 ({hex(esp_24)}): {mem_value.hex()}")
    except:
        print(f"[ERROR] Impossible de lire ESP + 0x24 ({hex(esp_24)}) !")
    
    print("HASH %x" % jitter.cpu.EDI)
    return False

jitter.add_breakpoint(addr_shellcode + 0xf7, dump)

# Activer le mode debug pour un suivi détaillé
jitter.set_trace_log(trace_instr=True, trace_regs=True, trace_new_blocks=True)

# Exécuter le shellcode
jitter.run(addr_shellcode + 0xdc)
