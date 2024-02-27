import pandas as pd
from PIL import Image
import os
def ip_to_binary(ip_address):
    # Split the IP address into four octets
    octets = ip_address.split(".")
    # Convert each octet to binary form and pad with zeros
    binary_octets = []
    for octet in octets:
        binary_octet = bin(int(octet))[2:].zfill(8)
        binary_octets.append(binary_octet)

    # Concatenate the four octets to get the 32-bit binary representation
    binary_ip_address = "".join(binary_octets)
    return binary_ip_address
def binary_to_ip(binary_ip_address):
    # Check that the input binary string is 32 bits
    if len(binary_ip_address) != 32:
        raise ValueError("Input binary string must be 32 bits")

    # Split the binary string into four octets
    octets = [binary_ip_address[i:i+8] for i in range(0, 32, 8)]
    # Convert each octet from binary to decimal form
    decimal_octets = [str(int(octet, 2)) for octet in octets]

    # Concatenate the four decimal octets to get the IP address string
    ip_address = ".".join(decimal_octets)
    return ip_address


def rgba_to_ip(rgba):
    ip_parts = tuple(map(str, rgba))
    ip = '.'.join(ip_parts)
    return ip

def int_to_rgba(A):
    if A == 1:
        rgba = (255, 0, 0, 255)
    elif A == 0:
        rgba = (0, 255, 0, 255)
    elif A == -1:
        rgba = (0, 0, 255, 255)
    elif A > 1:
        rgba = (255, 0, 0, A)
    elif A < -1:
        rgba = (0, 0, 255, abs(A))
    else:
        rgba = None
    return rgba

def rgba_to_int(rgba):
    if rgba == (255, 0, 0, 255):
        A = 1
    elif rgba == (0, 255, 0, 255):
        A = 0
    elif rgba == (0, 0, 255, 255):
        A = -1
    elif rgba[0] == 255 and rgba[1] == 0 and rgba[2] == 0:
        A = rgba[3]
    elif rgba[0] == 0 and rgba[1] == 0 and rgba[2] == 255:
        A = -rgba[3]
    else:
        A = None
    return A
# define function to split binary string into individual bits
def split_bits(s):
    return [int(b) for b in s]




org_nprint = 'column_example.nprint'
org_df = pd.read_csv(org_nprint)
org_df = org_df.drop('Unnamed: 0', axis=1)
# Define cols as the columns from the original df
cols = org_df.columns.tolist()

# Convert a PNG image back into a DataFrame
def png_to_dataframe(input_file):
    img = Image.open(input_file)
    width, height = img.size
    print(width)
    print(height)
    data = []

    for y in range(height):
        row = []
        for x in range(width):
            rgba = img.getpixel((x, y))
            #print(rgba)
            row.append(rgba_to_int(rgba))
        data.append(row)

    return pd.DataFrame(data, columns=cols)



org_dir = '../data/color_processed_generated_imgs/'
for i in os.listdir(org_dir):
    if 'png' in i:
        input_file = org_dir + i
        reverse_df = png_to_dataframe(input_file)
        output_file = '../data/generated_nprint/' + i.replace('png','nprint')
        reverse_df.to_csv(output_file)

