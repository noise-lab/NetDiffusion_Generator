#!/usr/bin/env python3
import os
import argparse
from PIL import Image

def process_image(input_file, output_file):
    image = Image.open(input_file).convert('RGBA')
    width, height = image.size

    # Red thresholds
    r_red = 0
    g_red = 160
    b_red = 100

    # Green thresholds
    r_green = 0
    g_green = 160
    b_green = 100

    # Blue thresholds
    r_blue = 0
    g_blue = 160
    b_blue = 100

    for x in range(width):
        for y in range(height):
            r, g, b, a = image.getpixel((x, y))

            if r > r_red and g < g_red and b < b_red:
                # Set the pixel to red
                image.putpixel((x, y), (255, 0, 0, 255))
            elif r < r_green and g > g_green and b < b_green:
                # Set the pixel to green
                image.putpixel((x, y), (0, 255, 0, 255))
            elif r < r_blue and g < g_blue and b > b_blue:
                # Set the pixel to blue
                image.putpixel((x, y), (0, 0, 255, 255))
            else:
                # Choose the max channel and set to that color
                max_color = max(r, g, b)
                if max_color == r:
                    image.putpixel((x, y), (255, 0, 0, 255))
                elif max_color == g:
                    image.putpixel((x, y), (0, 255, 0, 255))
                else:
                    image.putpixel((x, y), (0, 0, 255, 255))

    image.save(output_file)

def main():
    parser = argparse.ArgumentParser(
        description="Process all .png images in a directory and save them to another directory."
    )
    parser.add_argument("--input_dir", "-i", required=True, help="Path to input directory containing .png images.")
    parser.add_argument("--output_dir", "-o", required=True, help="Path to output directory for processed images.")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    count = 0
    for filename in os.listdir(args.input_dir):
        if filename.lower().endswith(".png"):
            input_path = os.path.join(args.input_dir, filename)
            output_path = os.path.join(args.output_dir, filename)
            process_image(input_path, output_path)
            count += 1

    print(f"Processed {count} images.")

if __name__ == "__main__":
    main()
