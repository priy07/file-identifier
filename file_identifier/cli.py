import sys
import os
import tempfile
import argparse
import json
from pathlib import Path
from .core import identify_file, print_report


def process_file(fp, json_mode=False, verbose=False):
    result = identify_file(fp)

    actual_ext = Path(fp).suffix
    expected_ext = result["extension"]

    mismatch = (
        actual_ext and expected_ext != "?" and actual_ext.lower() not in expected_ext
    )

    # JSON output
    if json_mode:
        output = {
            "file": result["path"],
            "type": result["file_type"],
            "extension": result["extension"],
            "confidence": result["confidence"],
        }

        if mismatch:
            output["warning"] = "Extension mismatch"

        print(json.dumps(output, indent=2))
        return

    # Normal output
    print_report(result)

    # Extension mismatch warning
    if mismatch:
        print("⚠️ Warning: File extension mismatch!")
        print(f"   Expected: {expected_ext}")
        print(f"   Actual  : {actual_ext}")

    # Verbose mode
    if verbose:
        print("\n[Verbose Info]")
        print(f"Matched Signature: {result['matched_sig']}")
        print(f"Hex Header      : {result['hex_header']}")


def main():
    parser = argparse.ArgumentParser(
        description="File Type Identifier using Magic Numbers."
    )
    parser.add_argument("files", nargs="*", help="Files or directories to identify")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--verbose", action="store_true", help="Show detailed info")

    args = parser.parse_args()

    # If files provided
    if args.files:
        for fp in args.files:
            path = Path(fp)

            # Directory scanning
            if path.is_dir():
                for file in path.iterdir():
                    if file.is_file():
                        process_file(str(file), args.json, args.verbose)
            else:
                process_file(str(path), args.json, args.verbose)

    else:
        # Demo mode
        print("\n🔍 File Type Identifier — Demo Mode")
        print("Creating sample files with known magic bytes...\n")

        samples = {
            "sample.jpg":  b'\xff\xd8\xff\xe0\x00\x10JFIF',
            "sample.png":  b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR',
            "sample.pdf":  b'%PDF-1.4\n%\xe2\xe3\xcf\xd3',
            "sample.gz":   b'\x1f\x8b\x08\x00\x00\x00\x00\x00',
            "sample.exe":  b'MZ\x90\x00\x03\x00\x00\x00',
            "sample.zip":  b'PK\x03\x04\x14\x00\x00\x00',
            "sample.mp3":  b'ID3\x03\x00\x00\x00\x00',
            "sample.txt":  b'Hello, world!\nThis is plain text.\n',
            "sample.bin":  bytes(range(16)),
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            for name, data in samples.items():
                fp = os.path.join(tmpdir, name)
                with open(fp, 'wb') as f:
                    f.write(data)
                process_file(fp, args.json, args.verbose)


if __name__ == "__main__":
    main()