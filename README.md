# Reverse

J’ai utiliser un décompilateur miasm pour récupère un mapping complète de ce que fait le shellcode : 

```python
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container

with open("./rendu/output_012.bin", "rb") as f:
    buf = f.read()

loc_db = LocationDB()
container = Container.from_string(buf, loc_db)
machine = Machine('x86_32')

# dis_engine -> moteur de désassemblage
mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)

# désassemble récurssivement
mdis.follow_call = True
mdis.dondis_recall = True

# désassemble a l'offset 0
disasm = mdis.dis_multiblock(offset=0)

with open('bin_cfg.dot', 'w') as f:
    f.write(disasm.dot())
```

Ensuite je l’ai transformer en png pour pouvoir l’ouvrir : 

```bash
dot -Tpng bin_cfg.dot -o mapping.png
```

Maintenant j’analyse chaque block de ce que ma donné le mapping : 

![image.png](image.png)

[https://www.vergiliusproject.com/kernels/x86/windows-7/sp1/_PEB](https://www.vergiliusproject.com/kernels/x86/windows-7/sp1/_PEB)
loc_0 : 

```nasm
loc_0:
  MOV EDX, DWORD PTR FS:[0x30]  ; EDX = adresse du PEB (Process Environment Block)
  MOV AL,  BYTE PTR [EDX + 0x2] ; AL = champ BeingDebugged du PEB
  CMP AL, 0x0                   ; Compare AL avec 0
  JNZ     loc_76                ; Si BeingDebugged != 0, saute à loc_76 (anti-debug)

```

loc_3a : 

```nasm
loc_3a:
  MOV EAX, DWORD PTR [EDX + 0x64] ; EAX = champ à l’offset 0x64 dans le PEB (vérification env. système ?)
  CMP EAX, 0x2                    ; Compare EAX avec 2
  JBE loc_76                      ; Si EAX <= 2, saute à loc_76 (probable anti-sandbox/anti-VM)

```

loc_76 :

```nasm
loc_76:
	RET ; Exit 0 si c'est sous débug ou VM
```

loc_42 : 

```nasm
loc_42:
  CALL    loc_47               ; Appel vers loc_47 (adresse de retour stockée sur la pile)

```

loc_47 :

```nasm
loc_47:
  POP     ESI                  ; ESI = adresse de retour (ret) poussée par CALL
  LEA     EDI, [ESI + 0xC3]    ; EDI = ESI + 0xC3 (souvent pour accéder à des données encodées après l'appel)
  LEA     ESI, [ESI + 0xCE]    ; ESI = ESI + 0xCE (ajuste ESI pour pointer plus loin)
  NOP                          ; Instruction vide (possible alignement)
  PUSH    EDI                  ; Empile EDI comme argument
  CALL    loc_12a              ; Appel vers la routine loc_12a

```

loc_5b :

```nasm
loc_5b:
  PUSH    ESI               ; Sauvegarde ESI sur la pile
  CALL    loc_12a           ; Appel de la routine à loc_12a

```

loc_12a : 

```nasm
loc_12a:
  PUSHAD                  ; Sauvegarde tous les registres généraux (EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI)
  MOV     ESI, [ESP + 0x24] ; ESI = valeur précédemment stockée sur la pile
  MOV     EDI, ESI          ; EDI = ESI
  MOV     DL, 0x88          ; DL = 0x88 (constante)
```

loc_133 : 

```nasm
loc_133:
  LODSB                    ; AL = byte pointé par ESI, ESI++
  XOR     AL, DL           ; AL = AL ^ DL
  INC     DL               ; DL++
  STOSB                    ; [EDI] = AL, EDI++
  CMP     AL, 0x0          ; Compare AL à 0
  JNZ     loc_133          ; Boucle si AL != 0
```

loc_13d : 

```nasm
loc_13d:
  POPAD                    ; Restaure tous les registres
  RET     0x4              ; Retour en libérant 4 octets de la pile
```

loc_61 :

```nasm
loc_61:
  PUSH    0x0               ; Paramètre 1 = 0
  PUSH    ESI               ; Paramètre 2 = ESI
  PUSH    EDI               ; Paramètre 3 = EDI
  PUSH    0x1361678E        ; Paramètre 4 = constante (0x1361678E)
  PUSH    0x3E692A03        ; Paramètre 5 = constante (0x3E692A03)
  CALL    loc_11b           ; Appel de la routine à loc_11b
```

loc_11b : 

```nasm
loc_11b:
  POP     ECX            ; Dépile dans ECX la valeur au sommet de la pile
  CALL    loc_ca         ; Appel de la routine loc_ca
```

loc_ca :

[https://www.vergiliusproject.com/kernels/x86/windows-7/sp1/_PEB](https://www.vergiliusproject.com/kernels/x86/windows-7/sp1/_PEB)

```nasm
loc_ca:
  PUSHAD                        ; Sauvegarde tous les registres généraux
  XOR     EAX, EAX             ; EAX = 0
  MOV     EAX, DWORD PTR FS:[0x30]  
  ; EAX pointe sur le PEB (Process Environment Block)
  ; PEB +0xC = Ldr (struct _PEB_LDR_DATA*)
  MOV     EDX, [EAX + 0xC]    
  ; PEB_LDR_DATA +0x14 = InMemoryOrderModuleList (LIST_ENTRY)
  MOV     EDX, [EDX + 0x14]    
  ; À ce stade, EDX pointe sur la liste chaînée InMemoryOrderModuleList
```

loc_d7 : 

```nasm
loc_d7:
  ; Dans la structure associée (souvent un _LDR_DATA_TABLE_ENTRY),
  ; l’offset 0x28 peut correspondre par ex. à FullDllName.Buffer ou un champ similaire.
  MOV     ESI, [EDX + 0x28]    ; ESI = champ à l’offset 0x28 (pointeur vers une chaîne/un module ?)
  XOR     EDI, EDI             ; EDI = 0
```

Boucle de hashage : 

```nasm
; --- Début de la boucle de lecture/hachage ---
loc_dc:
	XOR     EAX, EAX             ; EAX = 0
	LODSB                       ; AL = [ESI], puis ESI++
	INC     ESI                  ; ESI++
	TEST    EAX, EAX             ; Vérifie si AL == 0
	JZ      loc_f7               ; Si AL == 0, saute à loc_f7 (fin de la boucle)

loc_e4:
  CMP     AL, 0x61           ; Compare AL avec 'a'
  JL      loc_ea             ; Si AL < 'a', saute à loc_e1

loc_e8:
  SUB     AL, 0x20           ; Convertit la lettre en majuscule (AL -= 0x20)

loc_ea:
  ROR     EDI, 0x12          ; Rotation à droite de EDI (18 bits)
  ADD     EDI, EAX           ; EDI += AL
  ADD     EDI, EAX           ; EDI += AL une deuxième fois
  JMP     loc_dc             ; Retour à la boucle (probable suite de hachage)

; --- Fin de la boucle / comparaison ---
loc_f7:
  CMP     EDI, [ESP + 0x1C]  ; Compare la valeur de hachage avec un attendu
  MOV     EAX, [EDI + 0x10]  ; EAX = [EDI + 0x10] (pointeur ou data associée)
	MOV     EDX, DWORD PTR [EDX]
  JNZ     loc_d7             ; Si différent, saute à loc_d7 (gestion d'erreur / autre cas)

; --- Sortie / restauration ---
loc_102:
  POPAD                      ; Restaure tous les registres sauvegardés
  RET                        ; Retour
```

loc_121 : 

```nasm
loc_121:
  PUSH    EAX            ; Empile EAX (passe EAX en paramètre ?)
  CALL    loc_77         ; Appel de la routine loc_77
```

loc_127 : 

```nasm
loc_127:
  PUSH    ECX   ; Empile ECX (sauvegarde ou paramètre supplémentaire ?)
  JMP     EAX   ; Saut inconditionnel vers l'adresse pointée par EAX

```

loc_77 :

```nasm
loc_77:
  PUSHAD                           ; Sauvegarde tous les registres (EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI)
  MOV     EBP, DWORD PTR [ESP + 0x24]      ; EBP = base du module (passé en paramètre)
  MOV     EAX, DWORD PTR [EBP + 0x3C]        ; EAX = offset vers l'en-tête PE (IMAGE_NT_HEADERS)
  MOV     EDX, DWORD PTR [EBP + EAX + 0x78]  ; EDX = RVA de l'Export Directory (dans la DataDirectory)
  ADD     EDX, EBP                         ; EDX = adresse absolue de l'Export Directory
  MOV     ECX, DWORD PTR [EDX + 0x18]        ; ECX = NumberOfNames (nombre de noms exportés) (offset 0x18 dans IMAGE_EXPORT_DIRECTORY)
  MOV     EDX, DWORD PTR [EDX + 0x20]        ; EDX = RVA d'AddressOfNames (offset 0x20 dans IMAGE_EXPORT_DIRECTORY)
  ADD     EDX, EBP                         ; EDX = adresse absolue d'AddressOfNames

```

loc_8d

```nasm
loc_8d:
  CMP     ECX, 0               ; Compare ECX à 0
  JZ      loc_c6               ; Si ECX == 0, saute à loc_c6
```

loc_92 : 

```nasm
loc_92:
  DEC     ECX                  ; ECX--
  MOV     ESI, DWORD PTR [EBX + ECX*0x4] ; ESI = *(EBX + ECX*4)
  ADD     ESI, EBP             ; ESI += EBP
  XOR     EDI, EDI             ; EDI = 0
  XOR     EAX, EAX             ; EAX = 0
  CLD                           ; Clear Direction Flag (avance auto de ESI/EDI)
```

loc_9d : 

```nasm
loc_9d:
  LODSB                           ; AL = [ESI], puis ESI++
  TEST    AL, AL                  ; Vérifie si AL == 0
  JZ      loc_a9                  ; Si AL == 0, saute vers loc_a9
```

loc_a2 : 

```nasm
loc_a2:
  ROR     EDI, 0xF                ; Rotation à droite de 15 bits sur EDI
  ADD     EDI, EAX                ; EDI += EAX
  JMP     loc_9d                  ; Retour à loc_9d (boucle)
```

loc_a9 : 

```nasm
loc_a9:
  CMP     EDI, DWORD PTR [ESP + 0x28] ; Compare EDI avec la valeur à [ESP + 0x28]
  JNZ     loc_8d                  ; Si EDI != [ESP + 0x28], saute vers loc_8d
```

loc_af

```nasm
loc_af:
  MOV     EBX, DWORD PTR [EDX + 0x24]   ; EBX = AddressOfNameOrdinals (RVA)
  ADD     EBX, EBP                     ; EBX = adresse absolue de la table d'ordinals
  MOV     CX,  WORD PTR [EBX + ECX*2]  ; CX = ordinal associé au nom indexé par ECX
  ADD     EDX, EBP                     ; EDX = EDX + EBP (EDX pointe déjà vers ExportDirectory + 0x1C ?)
  MOV     EAX, DWORD PTR [EDX + ECX*4] ; EAX = RVA de la fonction dans AddressOfFunctions[CX]
  ADD     EAX, EBP                     ; EAX = adresse absolue de la fonction (EAX += base)
  MOV     DWORD PTR [ESP + 0x1C], EAX  ; Stocke l’adresse résolue dans [ESP + 0x1C]

```

loc_c6 :

```nasm
loc_c6:
  POPAD                                ; Restaure tous les registres (EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI)
  RET     0x8                          ; Retour en libérant 8 octets sur la pil
```

Ensuite une fois tout les block analyser j’ai reproduit le hash en python vue qu’on à toutes les instructions : 

```python
def rotate_right(val, shift, bits=32):
    """
    Effectue une rotation à droite sur 'val' de 'shift' bits dans un entier de 'bits' bits.
    """
    mask = (1 << bits) - 1
    return ((val >> shift) | (val << (bits - shift))) & mask

def compute_dll_hash(dll_name):
    """
    Calcule le hash d'une DLL en appliquant :
      - Une conversion en minuscules,
      - Un XOR du code ASCII de chaque caractère avec un compteur (incrémenté),
      - Une rotation à droite de 0x12 (18 décimal) sur le hash courant,
      - L'addition du caractère transformé,
      - Enfin, une addition finale d'une constante (0x112212).
    """
    hash_val = 0        # Initialisation du hash
    incr = 0            # Compteur pour le XOR (équivalent à DL)
    
    for ch in dll_name.lower():
        # Transformation : XOR de la valeur ASCII du caractère avec le compteur
        char_val = ord(ch) ^ incr
        incr += 1
        # Rotation droite du hash courant de 0x12 bits
        hash_val = rotate_right(hash_val, 0x12, 32)
        # Addition de la valeur transformée au hash
        hash_val = (hash_val + char_val) & 0xFFFFFFFF

    # Addition finale d'une constante (correspond à l'ADD final dans le shellcode)
    hash_val = (hash_val + 0x112212) & 0xFFFFFFFF
    return hash_val

if __name__ == "__main__":
    dll = "kernel32.dll"
    computed_hash = compute_dll_hash(dll)
    print(f"[+] Computed Hash for {dll}: {hex(computed_hash)}")

```

output : 

```bash
reverse@reverse:~/Desktop$ python3 hash_groupe15.py 
[+] Computed Hash for kernel32.dll: 0xb82e8961
```

Code pour check un registre (marche pas)

```bash
from argparse import ArgumentParser
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB

parser = ArgumentParser(description="x86 32 basic Jitter modifié")
parser.add_argument("filename", help="x86 32 shellcode filename")
parser.add_argument("-j", "--jitter",
                    help="Jitter engine (default is 'gcc')",
                    default="gcc")
args = parser.parse_args()

loc_db = LocationDB()
# Créer la machine pour x86 32 bits et obtenir le jitter
myjit = Machine("x86_32").jitter(loc_db, args.jitter)
myjit.init_stack()

# Charger le shellcode depuis le fichier
with open(args.filename, 'rb') as f:
    data = f.read()
run_addr = 0x40000000
myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, data)

# Active la trace (optionnel)
myjit.set_trace_log()

# Boucle d'exécution pas à pas
while myjit.running:
    myjit.step()
    eax_val = myjit.cpu.Eax
    print("EAX:", hex(eax_val))
    if eax_val == 0xb82e8961:
        print("Adresse 0xb82e8961 trouvée!")
        myjit.running = False

```

A force de die and retry on à réussie à avoir le résultat du shellcode 

```bash
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
# Injecter et exÃ©cuter le shellcode
sb.run(run_addr)
```

![Screenshot_2025-03-01_19-01-20.png](Screenshot_2025-03-01_19-01-20.png)

![Screenshot_2025-03-01_19-00-45.png](Screenshot_2025-03-01_19-00-45.png)

![Screenshot_2025-03-01_19-00-16.png](Screenshot_2025-03-01_19-00-16.png)

![Screenshot_2025-03-01_18-57-00.png](Screenshot_2025-03-01_18-57-00.png)

![Screenshot_2025-03-01_19-02-15.png](Screenshot_2025-03-01_19-02-15.png)

# Unpacker

Je suis parti d’un code d’exemple déjà présent dans Miasm.

```bash
cd miasm/example/jitter/unpack_upx.py
```

Je l’ai copiée et simplifiée pour n’avoir que la base fonctionnelle, et je la complète à chaque itération.

```bash
from __future__ import print_function
import os
import logging
from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.jitter.loader.pe import vm2pe
from miasm.core.locationdb import LocationDB
from miasm.os_dep.common import get_win_str_a

parser = Sandbox_Win_x86_32.parser(description="Generic UPX unpacker")
parser.add_argument("filename", help="PE Filename")
parser.add_argument('-v', "--verbose",
                    help="verbose mode", action="store_true")
parser.add_argument("--graph",
                    help="Export the CFG graph in graph.dot",
                    action="store_true")
options = parser.parse_args()
options.load_hdr = True

loc_db = LocationDB()
sb = Sandbox_Win_x86_32(
    loc_db, options.filename, options, globals(),
    parse_reloc=False
)

if options.verbose is True:
    logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.WARNING)

if options.verbose is True:
    print(sb.jitter.vm)

if options.verbose is True:
    print(sb.jitter.vm)

def stop(jitter):
    logging.info('OEP reached')

    # Stop execution
    jitter.running = False
    return False

# Run
sb.run()

# Construct the output filename
bname, fname = os.path.split(options.filename)
fname = os.path.join(bname, fname.replace('.', '_'))
out_fname = fname + '_unupx.bin'

# Rebuild the PE thanks to `vm2pe`
vm2pe(sb.jitter, out_fname, libs=sb.libs, e_orig=sb.pe)
```

output : 

```bash
reverse@reverse:~/Desktop$ python3 unpack_upx.py output_015.exe --verbose
cannot find crypto, skipping
[WARNING ]: Create dummy entry for 'kernel32.dll'
[WARNING ]: Create dummy entry for 'user32.dll'
Addr               Size               Access Comment
0x130000           0x10000            RW_    Stack
0x6E0000           0x1000             RW_    'output_015.exe': PE Header
0x6E1000           0x1000             RW_    'output_015.exe': b'text\x00\x00\x00\x00'
0x6E2000           0x1000             RW_    'output_015.exe': b'iat\x00\x00\x00\x00\x00'
0x6E3000           0x1000             RW_    'output_015.exe': b'myimp\x00\x00\x00'
0x6E4000           0x2000             RW_    'output_015.exe': b'.aspack\x00'
0x6E6000           0x1000             RW_    'output_015.exe': b'.adata\x00\x00'

Addr               Size               Access Comment
0x130000           0x10000            RW_    Stack
0x6E0000           0x1000             RW_    'output_015.exe': PE Header
0x6E1000           0x1000             RW_    'output_015.exe': b'text\x00\x00\x00\x00'
0x6E2000           0x1000             RW_    'output_015.exe': b'iat\x00\x00\x00\x00\x00'
0x6E3000           0x1000             RW_    'output_015.exe': b'myimp\x00\x00\x00'
0x6E4000           0x2000             RW_    'output_015.exe': b'.aspack\x00'
0x6E6000           0x1000             RW_    'output_015.exe': b'.adata\x00\x00'

[INFO    ]: kernel32_GetModuleHandle(dllname=0x6e4441) ret addr: 0x6e4042
INFO:jit function call:kernel32_GetModuleHandle(dllname=0x6e4441) ret addr: 0x6e4042
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e4071) ret addr: 0x6e4055
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e4071) ret addr: 0x6e4055
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e407e) ret addr: 0x6e4066
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e407e) ret addr: 0x6e4066
[INFO    ]: kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x1800, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40c1
INFO:jit function call:kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x1800, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40c1
[INFO    ]: kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x110e, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
INFO:jit function call:kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x110e, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
[INFO    ]: kernel32_VirtualFree(lpvoid=0x20002000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
INFO:jit function call:kernel32_VirtualFree(lpvoid=0x20002000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
[INFO    ]: kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x110e, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
INFO:jit function call:kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x110e, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
[INFO    ]: kernel32_VirtualFree(lpvoid=0x20004000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
INFO:jit function call:kernel32_VirtualFree(lpvoid=0x20004000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
[INFO    ]: kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x1df, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
INFO:jit function call:kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x1df, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
[INFO    ]: kernel32_VirtualFree(lpvoid=0x20006000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
INFO:jit function call:kernel32_VirtualFree(lpvoid=0x20006000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
[INFO    ]: kernel32_VirtualFree(lpvoid=0x20000000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e41bc
INFO:jit function call:kernel32_VirtualFree(lpvoid=0x20000000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e41bc
[INFO    ]: kernel32_GetModuleHandle(dllname=0x6e303c) ret addr: 0x6e429b
INFO:jit function call:kernel32_GetModuleHandle(dllname=0x6e303c) ret addr: 0x6e429b
[INFO    ]: kernel32_GetProcAddress(libbase=0x71112000, fname=0x6e3049) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71112000, fname=0x6e3049) ret addr: 0x6e4302
[INFO    ]: kernel32_GetModuleHandle(dllname=0x6e3055) ret addr: 0x6e429b
INFO:jit function call:kernel32_GetModuleHandle(dllname=0x6e3055) ret addr: 0x6e429b
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3064) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3064) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e306b) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e306b) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3078) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3078) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3087) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3087) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3099) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3099) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e30a4) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e30a4) ret addr: 0x6e4302
[INFO    ]: kernel32_GetTickCount() ret addr: 0x6e100f
INFO:jit function call:kernel32_GetTickCount() ret addr: 0x6e100f
Traceback (most recent call last):
  File "/home/reverse/Desktop/unpack_upx.py", line 45, in <module>
    sb.run()
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/analysis/sandbox.py", line 529, in run
    super(Sandbox_Win_x86_32, self).run(addr)
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/analysis/sandbox.py", line 136, in run
    self.jitter.continue_run()
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/jitter/jitload.py", line 430, in continue_run
    return next(self.run_iterator)
           ^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/jitter/jitload.py", line 369, in runiter_once
    for res in self.breakpoints_handler.call_callbacks(self.pc, self):
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/jitter/jitload.py", line 129, in call_callbacks
    res = c(*args)
          ^^^^^^^^
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/jitter/jitload.py", line 517, in handle_lib
    raise ValueError('unknown api', hex(jitter.pc), repr(fname))
ValueError: ('unknown api', '0x71111054', "'kernel32_Beep'")
```

On constate que j’ai une erreur avec kernel32_Beep, du coup ce que je fais, c’est que j’ajoute une fonction qui vient ignorer l’appel à Beep, afin de voir si je peux continuer l’exécution.

```bash
def kernel32_Beep(jitter):
    """Ignore l'appel à Beep pour éviter un crash"""
    ret_ad, _ = jitter.func_args_stdcall(["dwFreq", "dwDuration"])
    jitter.func_ret_stdcall(ret_ad, 1)  # Retourne 1 (succès)

```

output : 

```bash
reverse@reverse:~/Desktop$ python3 unpack_upx.py output_015.exe --verbose
cannot find crypto, skipping
[WARNING ]: Create dummy entry for 'kernel32.dll'
[WARNING ]: Create dummy entry for 'user32.dll'
Addr               Size               Access Comment
0x130000           0x10000            RW_    Stack
0x6E0000           0x1000             RW_    'output_015.exe': PE Header
0x6E1000           0x1000             RW_    'output_015.exe': b'text\x00\x00\x00\x00'
0x6E2000           0x1000             RW_    'output_015.exe': b'iat\x00\x00\x00\x00\x00'
0x6E3000           0x1000             RW_    'output_015.exe': b'myimp\x00\x00\x00'
0x6E4000           0x2000             RW_    'output_015.exe': b'.aspack\x00'
0x6E6000           0x1000             RW_    'output_015.exe': b'.adata\x00\x00'

Addr               Size               Access Comment
0x130000           0x10000            RW_    Stack
0x6E0000           0x1000             RW_    'output_015.exe': PE Header
0x6E1000           0x1000             RW_    'output_015.exe': b'text\x00\x00\x00\x00'
0x6E2000           0x1000             RW_    'output_015.exe': b'iat\x00\x00\x00\x00\x00'
0x6E3000           0x1000             RW_    'output_015.exe': b'myimp\x00\x00\x00'
0x6E4000           0x2000             RW_    'output_015.exe': b'.aspack\x00'
0x6E6000           0x1000             RW_    'output_015.exe': b'.adata\x00\x00'

[INFO    ]: kernel32_GetModuleHandle(dllname=0x6e4441) ret addr: 0x6e4042
INFO:jit function call:kernel32_GetModuleHandle(dllname=0x6e4441) ret addr: 0x6e4042
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e4071) ret addr: 0x6e4055
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e4071) ret addr: 0x6e4055
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e407e) ret addr: 0x6e4066
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e407e) ret addr: 0x6e4066
[INFO    ]: kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x1800, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40c1
INFO:jit function call:kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x1800, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40c1
[INFO    ]: kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x110e, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
INFO:jit function call:kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x110e, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
[INFO    ]: kernel32_VirtualFree(lpvoid=0x20002000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
INFO:jit function call:kernel32_VirtualFree(lpvoid=0x20002000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
[INFO    ]: kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x110e, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
INFO:jit function call:kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x110e, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
[INFO    ]: kernel32_VirtualFree(lpvoid=0x20004000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
INFO:jit function call:kernel32_VirtualFree(lpvoid=0x20004000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
[INFO    ]: kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x1df, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
INFO:jit function call:kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x1df, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
[INFO    ]: kernel32_VirtualFree(lpvoid=0x20006000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
INFO:jit function call:kernel32_VirtualFree(lpvoid=0x20006000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
[INFO    ]: kernel32_VirtualFree(lpvoid=0x20000000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e41bc
INFO:jit function call:kernel32_VirtualFree(lpvoid=0x20000000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e41bc
[INFO    ]: kernel32_GetModuleHandle(dllname=0x6e303c) ret addr: 0x6e429b
INFO:jit function call:kernel32_GetModuleHandle(dllname=0x6e303c) ret addr: 0x6e429b
[INFO    ]: kernel32_GetProcAddress(libbase=0x71112000, fname=0x6e3049) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71112000, fname=0x6e3049) ret addr: 0x6e4302
[INFO    ]: kernel32_GetModuleHandle(dllname=0x6e3055) ret addr: 0x6e429b
INFO:jit function call:kernel32_GetModuleHandle(dllname=0x6e3055) ret addr: 0x6e429b
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3064) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3064) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e306b) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e306b) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3078) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3078) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3087) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3087) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3099) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3099) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e30a4) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e30a4) ret addr: 0x6e4302
[INFO    ]: kernel32_GetTickCount() ret addr: 0x6e100f
INFO:jit function call:kernel32_GetTickCount() ret addr: 0x6e100f
[INFO    ]: kernel32_Beep(dwFreq=0x190, dwDuration=0x64) ret addr: 0x6e101c
INFO:jit function call:kernel32_Beep(dwFreq=0x190, dwDuration=0x64) ret addr: 0x6e101c
[INFO    ]: kernel32_GetCommandLine() ret addr: 0x6e1022
INFO:jit function call:kernel32_GetCommandLine() ret addr: 0x6e1022
[INFO    ]: my_strlen(src=0x20007000) ret addr: 0x6e102b
INFO:jit function call:my_strlen(src=0x20007000) ret addr: 0x6e102b
[INFO    ]: my_lstrcmp(ptr_str1=0x2000700e, ptr_str2=0x6e106c) ret addr: 0x6e1041
INFO:jit function call:my_lstrcmp(ptr_str1=0x2000700e, ptr_str2=0x6e106c) ret addr: 0x6e1041
Traceback (most recent call last):
  File "/home/reverse/Desktop/unpack_upx.py", line 60, in <module>
    sb.run()
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/analysis/sandbox.py", line 529, in run
    super(Sandbox_Win_x86_32, self).run(addr)
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/analysis/sandbox.py", line 136, in run
    self.jitter.continue_run()
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/jitter/jitload.py", line 430, in continue_run
    return next(self.run_iterator)
           ^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/jitter/jitload.py", line 369, in runiter_once
    for res in self.breakpoints_handler.call_callbacks(self.pc, self):
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/jitter/jitload.py", line 129, in call_callbacks
    res = c(*args)
          ^^^^^^^^
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/jitter/jitload.py", line 518, in handle_lib
    ret = func(jitter)
          ^^^^^^^^^^^^
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/os_dep/win_api_x86_32.py", line 1526, in kernel32_lstrcmpA
    my_lstrcmp(jitter, whoami(), lambda addr:get_win_str_a(jitter, addr))
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/os_dep/win_api_x86_32.py", line 1494, in my_lstrcmp
    jitter.func_ret_stdcall(ret_ad, cmp(s1, s2))
  File "/usr/local/lib/python3.12/dist-packages/miasm-0.1.5-py3.12-linux-x86_64.egg/miasm/arch/x86/jit.py", line 123, in func_ret_stdcall
    self.cpu.EAX = ret_value1
    ^^^^^^^^^^^^
TypeError: Arg too big for uint32_t
```

Là, on voit que j’ai encore une erreur, mais on est allé bien plus loin et, en y regardant de près, on peut constater qu’il n’est pas nécessaire d’aller plus loin en réalité ; il suffit juste de placer un breakpoint au bon endroit.

Du coup, j’ai rajouté mes breakpoints et on peut voir que ça fonctionne nickel, et j’ai un bin en sortie.

```bash
from __future__ import print_function
import os
import logging
from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.jitter.loader.pe import vm2pe
from miasm.core.locationdb import LocationDB
from miasm.os_dep.common import get_win_str_a

def kernel32_Beep(jitter):
    """Ignore l'appel à Beep pour éviter un crash"""
    ret_ad, _ = jitter.func_args_stdcall(["dwFreq", "dwDuration"])
    jitter.func_ret_stdcall(ret_ad, 1)  # Retourne 1 (succès)

parser = Sandbox_Win_x86_32.parser(description="Generic UPX unpacker")
parser.add_argument("filename", help="PE Filename")
parser.add_argument('-v', "--verbose",
                    help="verbose mode", action="store_true")
parser.add_argument("--graph",
                    help="Export the CFG graph in graph.dot",
                    action="store_true")
options = parser.parse_args()
options.load_hdr = True

loc_db = LocationDB()
sb = Sandbox_Win_x86_32(
    loc_db, options.filename, options, globals(),
    parse_reloc=False
)

if options.verbose is True:
    logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.WARNING)

if options.verbose is True:
    print(sb.jitter.vm)

if options.verbose is True:
    print(sb.jitter.vm)

# Adresse du strcmp où on veut s'arrêter avant le crash
BREAKPOINT_ADDR = 0x6e102b # Tu peux ajuster cette adresse si nécessaire

def stop_before_crash(jitter):
    """Arrête l'exécution avant le crash et dumpe la mémoire"""
    logging.info(f'Breakpoint atteint à {hex(jitter.pc)}')

    # Afficher la chaîne utilisée dans strcmp
    ptr_str = src=0x20007000 # L'adresse observée dans les logs
    try:
        str_value = sb.jitter.get_c_str(ptr_str)
        logging.info(f"String en {hex(ptr_str)}: {str_value}")
    except:
        logging.warning(f"Impossible de récupérer la string en {hex(ptr_str)}")

    # Dumper le binaire à cet instant
    bname, fname = os.path.split(options.filename)
    fname = os.path.join(bname, fname.replace('.', '_'))
    out_fname = fname + '_unupx.bin'

    vm2pe(sb.jitter, out_fname, libs=sb.libs, e_orig=sb.pe)
    logging.info(f"Binaire unpacké sauvegardé sous : {out_fname}")

    # Stop execution proprement
    jitter.running = False
    return False

# Ajouter un breakpoint avant le crash
sb.jitter.add_breakpoint(BREAKPOINT_ADDR, stop_before_crash)

# Run (le breakpoint stoppera avant le crash)
sb.run()

```

output : 

```bash
reverse@reverse:~/Desktop$ python3 unpack_upx.py output_015.exe --verbose
cannot find crypto, skipping
[WARNING ]: Create dummy entry for 'kernel32.dll'
[WARNING ]: Create dummy entry for 'user32.dll'
Addr               Size               Access Comment
0x130000           0x10000            RW_    Stack
0x6E0000           0x1000             RW_    'output_015.exe': PE Header
0x6E1000           0x1000             RW_    'output_015.exe': b'text\x00\x00\x00\x00'
0x6E2000           0x1000             RW_    'output_015.exe': b'iat\x00\x00\x00\x00\x00'
0x6E3000           0x1000             RW_    'output_015.exe': b'myimp\x00\x00\x00'
0x6E4000           0x2000             RW_    'output_015.exe': b'.aspack\x00'
0x6E6000           0x1000             RW_    'output_015.exe': b'.adata\x00\x00'

Addr               Size               Access Comment
0x130000           0x10000            RW_    Stack
0x6E0000           0x1000             RW_    'output_015.exe': PE Header
0x6E1000           0x1000             RW_    'output_015.exe': b'text\x00\x00\x00\x00'
0x6E2000           0x1000             RW_    'output_015.exe': b'iat\x00\x00\x00\x00\x00'
0x6E3000           0x1000             RW_    'output_015.exe': b'myimp\x00\x00\x00'
0x6E4000           0x2000             RW_    'output_015.exe': b'.aspack\x00'
0x6E6000           0x1000             RW_    'output_015.exe': b'.adata\x00\x00'

[INFO    ]: kernel32_GetModuleHandle(dllname=0x6e4441) ret addr: 0x6e4042
INFO:jit function call:kernel32_GetModuleHandle(dllname=0x6e4441) ret addr: 0x6e4042
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e4071) ret addr: 0x6e4055
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e4071) ret addr: 0x6e4055
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e407e) ret addr: 0x6e4066
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e407e) ret addr: 0x6e4066
[INFO    ]: kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x1800, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40c1
INFO:jit function call:kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x1800, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40c1
[INFO    ]: kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x110e, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
INFO:jit function call:kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x110e, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
[INFO    ]: kernel32_VirtualFree(lpvoid=0x20002000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
INFO:jit function call:kernel32_VirtualFree(lpvoid=0x20002000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
[INFO    ]: kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x110e, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
INFO:jit function call:kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x110e, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
[INFO    ]: kernel32_VirtualFree(lpvoid=0x20004000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
INFO:jit function call:kernel32_VirtualFree(lpvoid=0x20004000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
[INFO    ]: kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x1df, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
INFO:jit function call:kernel32_VirtualAlloc(lpvoid=0x0, dwsize=0x1df, alloc_type=0x1000, flprotect=0x4) ret addr: 0x6e40df
[INFO    ]: kernel32_VirtualFree(lpvoid=0x20006000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
INFO:jit function call:kernel32_VirtualFree(lpvoid=0x20006000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e419d
[INFO    ]: kernel32_VirtualFree(lpvoid=0x20000000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e41bc
INFO:jit function call:kernel32_VirtualFree(lpvoid=0x20000000, dwsize=0x0, alloc_type=0x8000) ret addr: 0x6e41bc
[INFO    ]: kernel32_GetModuleHandle(dllname=0x6e303c) ret addr: 0x6e429b
INFO:jit function call:kernel32_GetModuleHandle(dllname=0x6e303c) ret addr: 0x6e429b
[INFO    ]: kernel32_GetProcAddress(libbase=0x71112000, fname=0x6e3049) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71112000, fname=0x6e3049) ret addr: 0x6e4302
[INFO    ]: kernel32_GetModuleHandle(dllname=0x6e3055) ret addr: 0x6e429b
INFO:jit function call:kernel32_GetModuleHandle(dllname=0x6e3055) ret addr: 0x6e429b
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3064) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3064) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e306b) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e306b) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3078) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3078) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3087) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3087) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3099) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e3099) ret addr: 0x6e4302
[INFO    ]: kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e30a4) ret addr: 0x6e4302
INFO:jit function call:kernel32_GetProcAddress(libbase=0x71111000, fname=0x6e30a4) ret addr: 0x6e4302
[INFO    ]: kernel32_GetTickCount() ret addr: 0x6e100f
INFO:jit function call:kernel32_GetTickCount() ret addr: 0x6e100f
[INFO    ]: kernel32_Beep(dwFreq=0x190, dwDuration=0x64) ret addr: 0x6e101c
INFO:jit function call:kernel32_Beep(dwFreq=0x190, dwDuration=0x64) ret addr: 0x6e101c
[INFO    ]: kernel32_GetCommandLine() ret addr: 0x6e1022
INFO:jit function call:kernel32_GetCommandLine() ret addr: 0x6e1022
[INFO    ]: my_strlen(src=0x20007000) ret addr: 0x6e102b
INFO:jit function call:my_strlen(src=0x20007000) ret addr: 0x6e102b
INFO:root:Breakpoint atteint à 0x6e102b
INFO:root:String en 0x20007000: "c:\mydir\test.exe"
INFO:root:Binaire unpacké sauvegardé sous : output_015_exe_unupx.bin
```

Maintenant qu’on a notre packer unpack, je l’ouvre avec strings :

```bash
strings output_015_exe_unupx.bin 
```

output :

```bash
006E1000
006E2000
006E3000
006E4000
006E6000
import
Bravo!
Code:
aqxbf
user32.dll
MessageBoxA
kernel32.dll
Beep
GetVersion
GetTickCount
GetCommandLineA
lstrlenA
lstrcmpA
]^SP
]kSW
VirtualAlloc
VirtualFree
PQVS
t.x,
[^YX
kernel32.dll
ExitProcess
user32.dll
MessageBoxA
wsprintfA
LOADER ERROR
The procedure entry point %s could not be located in the dynamic link library %s
The ordinal %u could not be located in the dynamic link library %s
 (08@P`p
|$,3
T$ v
(C@;
t$h3
D4l|M
_^]2
;;F,s
,;F0s
 ;F4s
;F8s
0>@D
_^][
T4$F
`u(j
L4#H
L4$F
_^][
_^][
_^][
D$$W3
0"@D
5>@D
D$ %
;|$(
8_^]
_^]2
kernel32.dll
GetProcAddress
GetModuleHandleA
LoadLibraryA
user32.dll
MessageBoxA
kernel32.dll
GetProcAddress
GetModuleHandleA
LoadLibraryA
user32.dll
MessageBoxA
```

Donc, on peut voir que j’ai bien mon "Bravo!" qui s’affiche, et les conditions permettant que "Bravo!" s’affiche sont essentiellement liées à GetCommandLineA. Il attend un code au moment où on exécute notre .exe, donc si on l’exécute comme ceci :

```bash
./output_015.exe aqxbf
```

On a le "Bravo!" qui s’affiche.

# Conclusion

Exercice 1: Il s'agit d'un shellcode. 
Quelles sont les conditions à remplir pour que le shellcode s'exécute complètement?

```
il faut que le shellcode soit pas dans un envirronement de débug et dans une vm et la résolution d'api via le hash

```

Quelles structures sont testées?

```
PEB,IMAGE_EXPORT_DIRECTORY,_LDR_DATA_TABLE_ENTRY
```

Trouver ce qu'affiche le shellcode

```
 fhabzvewlh
```

En se basant sur l'analyse du shellcode, quel est le hash de la dll "kernel32.dll" (sans les guillemets)

```
je me suis trompé faut refaire
```

Exercice 2: Le binaire est packé
Dépacker le binaire

```
C'est fait
```

Quelles sont les conditions à remplir pour que le shellcode affiche "Bravo"

```
Il faut que au moment d'exécuter le packer il faut mettre le code : aqxbf en argument
```