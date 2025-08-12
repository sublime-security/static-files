import hashlib
import os

from typing import List, Optional


class Sorter:

    def get_file_hash(self, filepath: str) -> str:
        """Calculate SHA-256 hash of a file's contents"""
        hash_sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def sort(self, input_file: str, output_file: Optional[str] = None) -> None:
        """
        Read a file, get its hash, sort its lines, compare hashes, then write if different
        
        Args:
            input_file: Path to the input file
            output_file: Path for output file (defaults to input_file if None)
        """
        if output_file is None:
            output_file = input_file

        # Get hash of original file
        original_hash = self.get_file_hash(input_file)
        print(f"Original file hash: {original_hash}")

        # Read and sort the file contents
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Sort the lines
        sorted_lines = sorted(lines)

        # Write sorted content to a temporary file to get its hash
        temp_file = f"{input_file}.temp"
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.writelines(sorted_lines)

        # Get hash of sorted content
        sorted_hash = self.get_file_hash(temp_file)
        print(f"Sorted file hash: {sorted_hash}")

        # Compare hashes
        if original_hash == sorted_hash:
            print("File is already sorted - no changes needed")
            os.remove(temp_file)  # Clean up temp file
        else:
            print("File order changed - writing sorted version")
            # Move temp file to final location
            if temp_file != output_file:
                os.rename(temp_file, output_file)
            print(f"Sorted file written to: {output_file}")


if __name__ == "__main__":
    FILES: List[str] = [
        'bulk_mailer_url_root_domains.txt',
        'disposable_email_providers.txt',
        'email_forwarding_domains.txt',
        'file_extensions_common_archives.txt',
        'file_extensions_executables.txt',
        'file_extensions_macros.txt',
        'file_extensions_suspicious.txt',
        'file_types_images.txt',
        'free_email_providers.txt',
        'free_file_hosts.txt',
        'free_subdomain_hosts.txt',
        'high_trust_sender_root_domains.txt',
        'replyto_service_domains.txt',
        'self_service_creation_platform_domains.txt',
        'suspicious_content.txt',
        'suspicious_subjects.txt',
        'suspicious_tlds.txt',
        'url_shorteners.txt'
    ]
    for file in FILES:
        Sorter().sort(file)
