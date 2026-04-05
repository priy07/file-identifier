# File Identifier

A command-line tool to detect the real file type using magic numbers (file signatures), instead of relying on file extensions.

Works even when extensions are incorrect or intentionally misleading (e.g., `.pdf.exe`).

---

## Installation

```bash
pip install file-identifier
```

---

## Usage

```bash
file-identifier <file_or_directory> [options]
```

### Examples

```bash
file-identifier file.pdf
file-identifier file.pdf --json
file-identifier suspicious.pdf.exe
file-identifier ./folder
file-identifier file.zip --verbose
```

---

## Features

* Detects file types using binary signatures (magic numbers)
* Works with incorrect or spoofed extensions
* JSON output for automation
* Directory scanning support
* Verbose mode for detailed inspection
* Fast and lightweight

---

## Output

* File type
* Likely extension
* File size
* Confidence level
* Hex header

---

## How it works

The tool reads the initial bytes of a file and compares them with known magic signatures to determine its actual type.

---

## License

MIT
