import os
import subprocess
from PIL import Image
import pandas as pd
import numpy as np
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

# Convert the DataFrame into a PNG image
def dataframe_to_png(df, output_file):
    width, height = df.shape[1], df.shape[0]
    padded_height = 1024
    print(output_file)
    # Convert DataFrame to numpy array and pad with blue pixels
    np_img = np.full((padded_height, width, 4), (0, 0, 255, 255), dtype=np.uint8)
    np_df = np.array(df.applymap(np.array).to_numpy().tolist())
    np_img[:height, :, :] = np_df

    # Create a new image with padded height filled with blue pixels
    img = Image.fromarray(np_img, 'RGBA')

    # Check if file exists and generate a new file name if necessary
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


def rgba_to_ip(rgba):
    ip_parts = tuple(map(str, rgba))
    ip = '.'.join(ip_parts)
    return ip
# The script defines a function int_to_rgba that takes an integer A as input and returns the corresponding RGBA color value based on the following conditions:
# If A is equal to 1, the RGBA value is (255, 0, 0, 255) (red color with full opacity)
# If A is equal to 0, the RGBA value is (0, 255, 0, 255) (green color with full opacity)
# If A is equal to -1, the RGBA value is (0, 0, 255, 255) (blue color with full opacity)
# If A is greater than 1, the RGBA value is (255, 0, 0, A) (red color with the alpha channel set to A)
# If A is less than -1, the RGBA value is (0, 0, 255, abs(A)) (blue color with the alpha channel set to the absolute value of A)
# If A is not equal to any of these values, the function returns None.
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
# In this function, the input RGBA color value rgba is checked against each of the same conditions as in the int_to_rgba function,
# and the corresponding integer value A is returned. The last two conditions check if the RGBA color value has a red or blue channel
# set to its maximum value (indicating a solid color of that channel), and extract the alpha channel value as the integer value A.
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

data_dir = '../data/fine_tune_pcaps'
for i in os.listdir(data_dir):
    if 'pcap' in i:
        pcap = data_dir+'/'+i
        nprint = '../data/preprocessed_fine_tune_nprints/'+i.split('.pcap')[0]+'.nprint'
        print(pcap)
        print('Creating nPrint for pcap')
        subprocess.run('nprint -F -1 -P {0} -4 -i -6 -t -u -p 0 -c 1024 -W {1}'.format(pcap, nprint), shell=True)
            

nprint_dir = '../data/preprocessed_fine_tune_nprints'
for i in os.listdir(nprint_dir):
    if 'nprint' in i:
        service_name = i.split('.nprint')[0]
        print(i)
        nprint_path = nprint_dir+'/'+i
        df = pd.read_csv(nprint_path)
        num_packet = df.shape[0]
        if num_packet != 0:
            try:
            #conversion to NOT include ip
                #df = pd.read_csv(nprint)
                #df = df.drop('src_ip', axis=1)
                # apply function to src_ip column and expand into 32 columns
                #df_bits = df['src_ip'].apply(split_bits).apply(pd.Series)
                # rename columns to bit position
                #df_bits = df_bits.rename(columns={i: f'src_ip_bit_{i+1}' for i in range(32)})
                # combine original dataframe and bit columns
                #df_combined = pd.concat([df, df_bits], axis=1)
                #new_columns = df_bits.columns.tolist() + df.columns.tolist()
                #df_combined = df_combined[new_columns]
                #df_combined = df_combined.drop('src_ip', axis=1)
                #df=df_combined
                # Define the list of substrings to look for
                substrings = ['ipv4_src', 'ipv4_dst', 'ipv6_src', 'ipv6_dst','src_ip']

                # Get the list of columns that contain any of the specified substrings
                cols_to_drop = [col for col in df.columns if any(substring in col for substring in substrings)]

                # Drop the selected columns and assign the resulting DataFrame back to 'df'
                df = df.drop(columns=cols_to_drop)
                cols = df.columns.tolist()
                print(df.shape)
                for col in cols:
                    df[col] = df[col].apply(int_to_rgba)
                #print(1)
                #print(df.head(10))
                output_file = "../data/preprocessed_fine_tune_imgs/"+service_name+".png"
                dataframe_to_png(df, output_file)
            except:
                continue
