import os
import argparse
import pandas as pd
import numpy as np
from PIL import Image

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
        return (0, 0, 0, 255)  # default fallback

def dataframe_to_png(df, output_file):
    width, height = df.shape[1], df.shape[0]
    padded_height = 1024

    np_img = np.full((padded_height, width, 4), (0, 0, 255, 255), dtype=np.uint8)
    np_df = np.array(df.applymap(np.array).to_numpy().tolist())
    np_img[:height, :, :] = np_df

    img = Image.fromarray(np_img, 'RGBA')

    file_exists = True
    counter = 1
    file_path, file_extension = os.path.splitext(output_file)
    while file_exists:
        if os.path.isfile(output_file):
            output_file = f"{file_path}_{counter}{file_extension}"
            counter += 1
        else:
            file_exists = False

    img.save(output_file)

def convert_nprint_to_png(nprint_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    for file in os.listdir(nprint_dir):
        if file.endswith(".nprint"):
            print(f"Processing {file}")
            file_path = os.path.join(nprint_dir, file)
            try:
                df = pd.read_csv(file_path)
                if df.empty:
                    continue

                substrings = ['ipv4_src', 'ipv4_dst', 'ipv6_src', 'ipv6_dst', 'src_ip']
                df = df.drop(columns=[col for col in df.columns if any(sub in col for sub in substrings)])

                for col in df.columns:
                    df[col] = df[col].apply(int_to_rgba)

                output_file = os.path.join(output_dir, file.replace('.nprint', '.png'))
                dataframe_to_png(df, output_file)

            except Exception as e:
                print(f"❌ Failed to process {file}: {e}")
                continue

def main():
    parser = argparse.ArgumentParser(description="Convert .nprint files to PNG images.")
    parser.add_argument(
        "--input_dir", "-i", required=True, help="Directory containing .nprint files"
    )
    parser.add_argument(
        "--output_dir", "-o", required=True, help="Directory to save PNG images"
    )
    args = parser.parse_args()

    convert_nprint_to_png(args.input_dir, args.output_dir)

if __name__ == "__main__":
    main()
