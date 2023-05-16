import struct
import time
import binascii
import psutil
import gdb

def mem_save_onto_disk(data, file_path):
    with open(file_path, "wb") as file:
        file.write(data)

def get_mapping_base(pid, name):
    base = 0
    maps_path = f"/proc/{pid}/maps"
    with open(maps_path, "r") as maps_file:
        for line in maps_file:
            if name in line:
                fields = line.split(" ")
                addr_range = fields[0]
                base_str = addr_range.split("-")[0]
                base = int(base_str, 16)
                break
    return base


def gdb_attach(pid):
    gdb.execute(f"attach {pid}")
    print(f"Attached to process with PID {pid}")


def gdb_bpadd_simple(addr):
    gdb.execute(f"break *{addr}")

def gdb_rdreg(register_name):
    value = gdb.parse_and_eval(register_name)
    return int(value)


def gdb_vmem_read(address, size):
    inferior = gdb.selected_inferior()
    mem_bytes = inferior.read_memory(address, size)
    return bytes(mem_bytes)


def get_named_proc_id(process_name):
    for process in psutil.process_iter(["pid", "name"]):
        if process.info["name"] == process_name:
            return process.info["pid"]
    return None


def eac_wait_for_helper(pid, module_name):
    while True:
        module_base = get_mapping_base(pid, module_name)
        if module_base != 0:
            return module_base
        else:
            time.sleep(1)


def handle_stop_event(event):
   if (isinstance(event, gdb.BreakpointEvent)):
       payload_base = gdb_rdreg("$rsi")
       payload_len = gdb_rdreg("$rdx")
       print(f"base: {payload_base:016X} | len: {payload_len:016X}")
       payload = gdb_vmem_read(payload_base, payload_len)
       if(len(payload) > 0):
             print("****** SUCCESS ******")
             payload_hash = binascii.crc32(payload)
             mem_save_onto_disk(payload, 
                                f"/home/drof/Documents/imod_{payload_hash:08X}.bin")
        
       gdb.execute("kill")
       gdb.execute("quit")

def run():
    gdb.events.stop.connect(handle_stop_event)

    gdb.execute("set pagination off")
    pid = None
    while pid is None:
        print("Waiting for process...")
        pid = get_named_proc_id("R5Apex.exe")
        if pid is not None:
            break
        time.sleep(1)

    print(f"found process at pid {pid}")
    eac_helper_base = eac_wait_for_helper(pid, "easyanticheat_x64.so")
    print(f"eac_helper has been found at 0x{eac_helper_base:016X}")
    gdb_attach(pid)
    patch_addr = eac_helper_base + 0x62A62
    patch_bytes_initial = gdb.selected_inferior().read_memory(patch_addr, 8)
    patch_bytes = struct.unpack("<Q", patch_bytes_initial)[0]
    print(f"initial patch bytes are 0x{patch_bytes:016X}")
    if patch_bytes == 0xE83948FFFF1359E8:
        print("offset correct, patch bytes are matching.")
        gdb_bpadd_simple(patch_addr)
        print("breakpoint has been set.")
        gdb.execute("c")
        print("waiting for our trap...")


run()
