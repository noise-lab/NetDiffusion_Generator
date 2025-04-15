#!/usr/bin/env python3
import argparse
import os
import sys


def main():
    parser = argparse.ArgumentParser(description="Generate pcap files from .nprint using reconstruction.py.")
    parser.add_argument(
        "--input_dir",
        default="./generated_nprint",
        help="Directory containing generated .nprint files to process."
    )
    parser.add_argument(
        "--output_pcap_dir",
        default="./replayable_generated_pcaps",
        help="Directory to save the resulting .pcap files."
    )
    parser.add_argument(
        "--output_nprint_dir",
        default="./replayable_generated_nprints",
        help="Directory to save any newly generated .nprint files."
    )
    parser.add_argument(
        "--formatted_nprint_path",
        default="./correct_format.nprint",
        help="Path to the 'correct_format.nprint' reference file."
    )
    args = parser.parse_args()

    # Create the output directories if they don't exist
    os.makedirs(args.output_pcap_dir, exist_ok=True)
    os.makedirs(args.output_nprint_dir, exist_ok=True)

    # Loop through all .nprint files in args.input_dir
    input_files = os.listdir(args.input_dir)
    if not input_files:
        print(f"No files found in {args.input_dir}")
        sys.exit(0)

    for org_nprint in input_files:
        if not org_nprint.endswith(".nprint"):
            # skip non-nprint files
            continue

        org_nprint_path = os.path.join(args.input_dir, org_nprint)
        # Construct output file paths
        output_pcap_path = os.path.join(
            args.output_pcap_dir,
            org_nprint.replace(".nprint", ".pcap"),
        )
        output_nprint_path = os.path.join(
            args.output_nprint_dir,
            org_nprint,
        )

        print(f"\nProcessing: {org_nprint_path} -> {output_pcap_path}")

        # Verify the input file can be accessed (catch OS or IO errors)
        try:
            if not os.path.isfile(org_nprint_path):
                print(f"Skipping: {org_nprint_path} is not a valid file.")
                continue
        except Exception as e:
            print(f"Error accessing {org_nprint_path}: {e}")
            continue

        # Prepare the system command
        cmd = (
            f"python3 ./scripts/reconstruction.py "
            f"--generated_nprint_path '{org_nprint_path}' "
            f"--formatted_nprint_path '{args.formatted_nprint_path}' "
            f"--output '{output_pcap_path}' "
            f"--nprint '{output_nprint_path}'"
        )

        # Run reconstruction.py
        print(f"Running command:\n  {cmd}")
        try:
            return_code = os.system(cmd)
            if return_code != 0:
                # Non-zero exit code indicates an error
                print(f"ERROR: reconstruction.py failed with return code {return_code}")
                print("Skipping this file.")
                continue
        except Exception as e:
            # If os.system itself fails (rare)
            print(f"Exception while running reconstruction command: {e}")
            print("Skipping this file.")
            continue

        print(f"Success! Created {output_pcap_path} and possibly updated {output_nprint_path}.")


if __name__ == "__main__":
    main()
