#!/usr/bin/env python3
import argparse
import os
import pandas as pd
from PIL import Image

def ip_to_binary(ip_address):
    # Split the IP address into four octets
    octets = ip_address.split(".")
    # Convert each octet to binary form and pad with zeros
    binary_octets = [bin(int(octet))[2:].zfill(8) for octet in octets]
    return "".join(binary_octets)

def binary_to_ip(binary_ip_address):
    if len(binary_ip_address) != 32:
        raise ValueError("Input binary string must be 32 bits")
    octets = [binary_ip_address[i : i + 8] for i in range(0, 32, 8)]
    decimal_octets = [str(int(octet, 2)) for octet in octets]
    return ".".join(decimal_octets)

def rgba_to_ip(rgba):
    ip_parts = tuple(map(str, rgba))
    return ".".join(ip_parts)

def int_to_rgba(A):
    if A == 1:
        return (255, 0, 0, 255)
    elif A == 0:
        return (0, 255, 0, 255)
    elif A == -1:
        return (0, 0, 255, 255)
    elif A > 1:
        return (255, 0, 0, A)
    elif A < -1:
        return (0, 0, 255, abs(A))
    else:
        return None

def rgba_to_int(rgba):
    # Typical RGBA conversions
    if rgba == (255, 0, 0, 255):
        return 1
    elif rgba == (0, 255, 0, 255):
        return 0
    elif rgba == (0, 0, 255, 255):
        return -1
    elif rgba[0] == 255 and rgba[1] == 0 and rgba[2] == 0:
        return rgba[3]
    elif rgba[0] == 0 and rgba[1] == 0 and rgba[2] == 255:
        return -rgba[3]
    else:
        return None

def split_bits(s):
    return [int(b) for b in s]

def png_to_dataframe(input_file, columns):
    """
    Convert a PNG to a DataFrame, using columns that match the reference .nprint CSV.
    """
    img = Image.open(input_file).convert("RGBA")
    width, height = img.size
    print(f"Processing {input_file} with size {width} x {height}")

    data = []
    for y in range(height):
        row = []
        for x in range(width):
            rgba = img.getpixel((x, y))
            val = rgba_to_int(rgba)
            row.append(val)
        data.append(row)

    # Construct a DataFrame using the provided column names
    df = pd.DataFrame(data, columns=columns)
    return df

def main():
    parser = argparse.ArgumentParser(description="Convert .png files back into .nprint format.")
    parser.add_argument(
        "--org_nprint",
        required=True,
        help="Path to the original .nprint CSV file for column reference."
    )
    parser.add_argument(
        "--input_dir",
        required=True,
        help="Directory containing the .png images to convert."
    )
    parser.add_argument(
        "--output_dir",
        required=True,
        help="Directory to save the resulting .nprint files."
    )
    args = parser.parse_args()

    # 1) Load the reference .nprint CSV just to extract columns
    org_df = pd.read_csv(args.org_nprint)
    # If there's an unwanted "Unnamed: 0" column, remove it
    if "Unnamed: 0" in org_df.columns:
        org_df = org_df.drop("Unnamed: 0", axis=1)

    # Extract the columns to preserve the same structure
    columns = org_df.columns.tolist()

    # 2) Make sure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)

    # 3) Iterate over .png files in input_dir
    converted_count = 0
    for filename in os.listdir(args.input_dir):
        if filename.lower().endswith(".png"):
            input_file = os.path.join(args.input_dir, filename)
            df = png_to_dataframe(input_file, columns=columns)

            # 4) Save as .nprint in output_dir
            output_file = os.path.join(args.output_dir, filename.replace(".png", ".nprint"))
            df.to_csv(output_file, index=False)
            converted_count += 1
            print(f"Saved {output_file}")

    print(f"Done! Converted {converted_count} .png files into .nprint format.")

if __name__ == "__main__":
    main()
