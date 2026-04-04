import sys
import os
import tempfile
import argparse
from .core import identify_file, print_report

def main():
    parser = argparse.ArgumentParser(description="File Type Identifier using Magic Numbers.")
    parser.add_argument("files", nargs="*", help="List of files to identify")
    args = parser.parse_args()

    # If files are provided via CLI arguments
    if args.files:
        for fp in args.files:
            print_report(identify_file(fp))
    else:
        # Default behavior with no arguments: Self-demo
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
                print_report(identify_file(fp))

if __name__ == "__main__":
    main()
