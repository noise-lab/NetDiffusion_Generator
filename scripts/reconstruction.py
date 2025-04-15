import pandas as pd
import subprocess
import numpy as np
import sys
import argparse
import random
import math
from collections import Counter
from scapy.all import *
from scapy.utils import PcapWriter
from scapy.all import rdpcap, wrpcap
from scapy.layers.inet import IP, TCP

def update_ipv4_checksum(pcap_file, output_file):
    # Read the packets from the pcap file
    packets = rdpcap(pcap_file)
    
    # Create a PcapWriter instance with the desired DLT value (DLT_RAW)
    writer = PcapWriter(output_file, linktype=101, sync=True)
    
    # Iterate over each packet
    for packet in packets:
        # Check if the packet is an IPv4 packet
        if packet.haslayer(IP):
            # Delete the checksum field
            del packet[IP].chksum
            
            # Scapy will automatically calculate the checksum when the packet is serialized/sent
            
        # Write packet to the output file with desired DLT
        writer.write(packet)

    # Close the writer
    writer.close()

def binary_to_decimal(binary_list):
    """Convert a binary list representation to its decimal equivalent."""
    binary_str = ''.join(map(str, binary_list))
    return int(binary_str, 2)

def random_ip():
    return '.'.join(str(random.randint(0, 255)) for _ in range(4))

def read_syn_nprint(generated_nprint_path):
    syn_nprint_df = pd.read_csv(generated_nprint_path)
    substrings = ['Unnamed: 0']
    # Get the list of columns that contain any of the specified substrings
    cols_to_drop = [col for col in syn_nprint_df.columns if any(substring in col for substring in substrings)]
    # Drop the selected columns and assign the resulting DataFrame back to 'df'
    syn_nprint_df = syn_nprint_df.drop(columns=cols_to_drop)
    return syn_nprint_df

def encode_ip(ip):
    return ''.join([f'{int(x):08b}' for x in ip.split('.')])

def reconstruction_to_pcap(formatted_generated_nprint_path, rebuilt_pcap_path):
    subprocess.run('nprint -N {0} -W {1}'.format(formatted_generated_nprint_path, rebuilt_pcap_path), shell=True)

def ip_address_formatting(generated_nprint, synthetic_sequence):
    # ################IP address population for non binary encoded ips
    if args.src_ip == '0.0.0.0':
        implementing_src_ip = random_ip()
    else:
        implementing_src_ip = args.src_ip

    if args.dst_ip == '0.0.0.0':     
        implementing_dst_ip = random_ip()
    else:
        implementing_dst_ip = args.dst_ip

    # Iterate through the dataframe and list together
    for idx, value in enumerate(synthetic_sequence):
        if value == 0:
            generated_nprint.at[idx, 'src_ip'] = implementing_src_ip
            generated_nprint.at[idx, 'dst_ip'] = implementing_dst_ip
        else:
            generated_nprint.at[idx, 'src_ip'] = implementing_dst_ip
            generated_nprint.at[idx, 'dst_ip'] = implementing_src_ip
    
    
    ################Derive binary encoded ips according
    # Apply the function to the 'src_ip' column
    generated_nprint['src_binary_ip'] = generated_nprint['src_ip'].apply(encode_ip)
    # Apply the function to the 'dst_ip' column
    generated_nprint['dst_binary_ip'] = generated_nprint['dst_ip'].apply(encode_ip)
    # Split the binary IP addresses into separate columns
    for i in range(32):
        generated_nprint[f'ipv4_src_{i}'] = generated_nprint['src_binary_ip'].apply(lambda x: x[i]).astype(np.int8)
    for i in range(32):
        generated_nprint[f'ipv4_dst_{i}'] = generated_nprint['dst_binary_ip'].apply(lambda x: x[i]).astype(np.int8)
    # Drop the 'binary_ip' column as it's no longer needed
    generated_nprint = generated_nprint.drop(columns=['src_binary_ip'])
    generated_nprint = generated_nprint.drop(columns=['dst_binary_ip'])
    generated_nprint = generated_nprint.drop(columns=['dst_ip'])
    #print(generated_nprint['src_ip'])
    return generated_nprint

def ipv4_hl_formatting(generated_nprint,formatted_nprint):
    # Get the subset of columns containing 'ipv4'
    ipv4_columns = generated_nprint.filter(like='ipv4')
    # For each row in the DataFrame
    for idx, row in ipv4_columns.iterrows():
        # Count the 1s and 0s in this row
        count = (row == 1).sum() + (row == 0).sum()
        #print(count)
        # Convert to 32-bit/4-byte words
        header_size_words = math.ceil(count / 32)

        # Convert to binary and pad with zeroes to get a 4-bit representation
        binary_count = format(header_size_words, '04b')
        # Update the 'ipv4_hl' columns in the original DataFrame based on this binary representation
        for i in range(4):
            generated_nprint.at[idx, f'ipv4_hl_{i}'] = int(binary_count[i])
    return generated_nprint

def ipv4_tl_formatting_tcp(generated_nprint, formatted_nprint):

    counter = 0
    for idx, row in generated_nprint.iterrows():
        # Extracting binary values for ipv4_tl, ipv4_hl, and tcp_doff
        ipv4_tl_binary = [row[f'ipv4_tl_{i}'] for i in range(16)]
        ipv4_hl_binary = [row[f'ipv4_hl_{i}'] for i in range(4)]
        tcp_doff_binary = [row[f'tcp_doff_{i}'] for i in range(4)]

        # Convert the binary representation to integer
        ipv4_tl_value = binary_to_decimal(ipv4_tl_binary)
        ipv4_hl_value = binary_to_decimal(ipv4_hl_binary) * 4  # Convert from 4-byte words to bytes
        tcp_doff_value = binary_to_decimal(tcp_doff_binary) * 4  # Convert from 4-byte words to bytes
        # Checking and setting the new value if condition is met
        if ipv4_tl_value < ipv4_hl_value + tcp_doff_value:
            new_ipv4_tl_value = ipv4_hl_value + tcp_doff_value
            # Convert new value back to binary and update the fields
            new_ipv4_tl_binary = format(new_ipv4_tl_value, '016b')
            for i, bit in enumerate(new_ipv4_tl_binary):
                generated_nprint.at[idx, f'ipv4_tl_{i}'] = int(bit)
        elif ipv4_tl_value>1500:
            new_ipv4_tl_binary = format(1500, '016b')
            for i, bit in enumerate(new_ipv4_tl_binary):
                generated_nprint.at[idx, f'ipv4_tl_{i}'] = int(bit)
        else:
            new_ipv4_tl_binary = format(ipv4_tl_value, '016b')
            for i, bit in enumerate(new_ipv4_tl_binary):
                generated_nprint.at[idx, f'ipv4_tl_{i}'] = int(bit)
    # for i in range(16):
    #     generated_nprint[f'ipv4_tl_{i}'] = formatted_nprint[f'ipv4_tl_{i}']
    for idx, row in generated_nprint.iterrows():
        # Extracting binary values for ipv4_tl, ipv4_hl, and tcp_doff
        ipv4_tl_binary = [row[f'ipv4_tl_{i}'] for i in range(16)]
        ipv4_hl_binary = [row[f'ipv4_hl_{i}'] for i in range(4)]
        tcp_doff_binary = [row[f'tcp_doff_{i}'] for i in range(4)]

        # Convert the binary representation to integer
        ipv4_tl_value = binary_to_decimal(ipv4_tl_binary)
        ipv4_hl_value = binary_to_decimal(ipv4_hl_binary) * 4  # Convert from 4-byte words to bytes
        tcp_doff_value = binary_to_decimal(tcp_doff_binary) * 4  # Convert from 4-byte words to bytes
        # print(f'Packet {counter}:')
        # print('ipv4 total length in bytes:')
        # print(ipv4_tl_value)
        # print('ipv4 header length in bytes:')
        # print(ipv4_hl_value)
        # print('tcp doff in bytes:')
        # print(tcp_doff_value)
        # print()
        counter +=1


    return generated_nprint

def ipv4_ver_formatting(generated_nprint,formatted_nprint):
    #following is placeholder, how do we get payload size?:
    # Define the substrings that have static values, e.g., ip version = 4
    fields = ["ipv4_ver"]
    # Iterate over the columns of the source DataFrame
    for column in formatted_nprint.columns:
        # Check if the substring exists in the column name
        for field in fields:
            if field in column:
                # Copy the column values to the destination DataFrame
                #generated_nprint[column] = formatted_nprint[column]
                # limit to ipv4
                if '0' in column:
                    generated_nprint[column] = 0
                elif '1' in column:
                    generated_nprint[column] = 1
                elif '2' in column:
                    generated_nprint[column] = 0
                else:
                    generated_nprint[column] = 0

    return generated_nprint

def protocol_determination(generated_nprint):
    protocols = ["tcp", "udp", "icmp"]
    percentages = {}

    # Iterate over the protocols
    for protocol in protocols:
        columns = [col for col in generated_nprint.columns if protocol in col and 'opt' not in col]

        # Count non-negatives in each column and calculate the total percentage for each protocol
        total_count = 0
        non_negative_count = 0
        for column in columns:
            total_count += len(generated_nprint[column])
            non_negative_count += (generated_nprint[column] >= 0).sum()

        # Calculate percentage and store in the dictionary
        if total_count > 0:
            percentages[protocol] = (non_negative_count / total_count) * 100
        else:
            percentages[protocol] = 0

    # Find protocol with the highest percentage of non-negative values
    max_protocol = max(percentages, key=percentages.get)
    return max_protocol

def ipv4_pro_formatting(generated_nprint,formatted_nprint):
    #following is placeholder, how do we get payload size?:
    # Define the substrings that have static values, e.g., ip version = 4

    # Call the function to determine the protocol
    dominating_protocol = protocol_determination(generated_nprint)
    print(dominating_protocol)
    # tcp = 0,0,0,0,0,1,1,0
    # udp = 0,0,0,1,0,0,0,1
    # icmp = 0,0,0,0,0,0,0,1
    fields = ["ipv4_pro"]
    # Iterate over the columns of the source DataFrame
    for column in formatted_nprint.columns:
        # Check if the substring exists in the column name
        for field in fields:
            if field in column:
                if dominating_protocol == 'tcp':
                    if '_0' in column:
                        generated_nprint[column] = 0
                    elif '_1' in column:
                        generated_nprint[column] = 0
                    elif '_2' in column:
                        generated_nprint[column] = 0
                    elif '_3' in column:
                        generated_nprint[column] = 0
                    elif '_4' in column:
                        generated_nprint[column] = 0
                    elif '_5' in column:
                        generated_nprint[column] = 1
                    elif '_6' in column:
                        generated_nprint[column] = 1
                    elif '_7' in column:
                        generated_nprint[column] = 0
                elif dominating_protocol == 'udp':
                    if '_0' in column:
                        generated_nprint[column] = 0
                    elif '_1' in column:
                        generated_nprint[column] = 0
                    elif '_2' in column:
                        generated_nprint[column] = 0
                    elif '_3' in column:
                        generated_nprint[column] = 1
                    elif '_4' in column:
                        generated_nprint[column] = 0
                    elif '_5' in column:
                        generated_nprint[column] = 0
                    elif '_6' in column:
                        generated_nprint[column] = 0
                    elif '_7' in column:
                        generated_nprint[column] = 1
                elif dominating_protocol == 'icmp':
                    if '_0' in column:
                        generated_nprint[column] = 0
                    elif '_1' in column:
                        generated_nprint[column] = 0
                    elif '_2' in column:
                        generated_nprint[column] = 0
                    elif '_3' in column:
                        generated_nprint[column] = 0
                    elif '_4' in column:
                        generated_nprint[column] = 0
                    elif '_5' in column:
                        generated_nprint[column] = 0
                    elif '_6' in column:
                        generated_nprint[column] = 0
                    elif '_7' in column:
                        generated_nprint[column] = 1

                # Copy the column values to the destination DataFrame
                #generated_nprint[column] = formatted_nprint[column]
    # make sure non-dominant-protocol values are -1s
    protocols = ["tcp", "udp", "icmp"]
    for column in formatted_nprint.columns:
        # Check if the substring exists in the column name
        for protocol in protocols:
            if protocol in column:
                if protocol != dominating_protocol:
                    generated_nprint[column] = -1


    return generated_nprint

def ipv4_header_negative_removal(generated_nprint, formatted_nprint):
    fields = ["ipv4"]

    # Function to apply to each cell
    def replace_negative_one(val):
        if val == -1:
            return np.random.randint(0, 2)  # Generates either 0 or 1
        else:
            return val

    # Iterate over the columns of the source DataFrame
    for column in formatted_nprint.columns:
        # Check if the substring exists in the column name
        for field in fields:
            #if field in column:
            if field in column and 'opt' not in column:
                generated_nprint[column] = generated_nprint[column].apply(replace_negative_one)
            # ######## no opt for debugging
            # elif field in column:
            #     generated_nprint[column] = -1

    return generated_nprint

def ipv4_option_removal(generated_nprint, formatted_nprint):
    fields = ["ipv4_opt"]

    # Iterate over the columns of the source DataFrame
    for column in formatted_nprint.columns:
        # Check if the substring exists in the column name
        for field in fields:
            #if field in column:
            if field in column:
                generated_nprint[column] = -1
            # ######## no opt for debugging
            # elif field in column:
            #     generated_nprint[column] = -1

    return generated_nprint

def ipv4_ttl_ensure(generated_nprint,formatted_nprint):

    for index in range(0, len(generated_nprint)):
        ttl_0 = True
        for j in range(8):
            if generated_nprint.at[index, f'ipv4_ttl_{j}'] != 0:
                ttl_0 = False
        if ttl_0 == True:
            generated_nprint.at[index, 'ipv4_ttl_7'] = 1
    return generated_nprint

def tcp_header_negative_removal(generated_nprint, formatted_nprint):
    fields = ["tcp"]

    # Function to apply to each cell
    def replace_negative_one(val):
        if val == -1:
            return np.random.randint(0, 2)  # Generates either 0 or 1
        else:
            return val

    # Iterate over the columns of the source DataFrame
    for column in formatted_nprint.columns:
        # Check if the substring exists in the column name
        for field in fields:
            #if field in column:
            if field in column and 'opt' not in column:
                generated_nprint[column] = generated_nprint[column].apply(replace_negative_one)
            # ######## no opt for debugging
            # elif field in column:
            #     generated_nprint[column] = -1

    return generated_nprint

def modify_tcp_option(packet):
    # This function processes each packet of the dataframe and modifies the TCP option fields to align with the actual structure of the TCP options.
    option_data = packet.loc['tcp_opt_0':'tcp_opt_319'].to_numpy()
    idx = 0
    options_lengths = [0, 8, 32, 24, 16, 40, 80]  # NOP/EOL, MSS, Window Scale, SACK Permitted, SACK, Timestamp

    while idx < 320:
        start_idx = idx
        end_idx = idx
        while end_idx < 320 and option_data[end_idx] != -1:
            end_idx += 1
        length = end_idx - start_idx
        closest_option = min(options_lengths, key=lambda x: abs(x - length))

        if closest_option == 32:  # MSS
            #print('mss')
            idx += 32
            mss_data = np.concatenate(([0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0], option_data[start_idx+16:idx]))
            mss_data = [np.random.choice([0, 1]) if bit == -1 else bit for bit in mss_data]
            option_data[start_idx:idx] = mss_data
            options_lengths.remove(closest_option)
        elif closest_option == 24:  # Window Scale
            #print('ws')
            idx += 24
            ws_data =  np.concatenate(([0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1], option_data[start_idx+16:idx]))
            ws_data = [np.random.choice([0, 1]) if bit == -1 else bit for bit in ws_data]
            option_data[start_idx:idx] = ws_data
            options_lengths.remove(closest_option)
        elif closest_option == 16:  # SACK Permitted
            #print('sack permitted')
            idx += 16
            option_data[start_idx:idx] = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]
            options_lengths.remove(closest_option)

        elif closest_option == 40:  # SACK (Assuming one block for simplicity)
            # Assuming the length would be for one SACK block: kind (1 byte), length (1 byte, value 10 for one block), and 8 bytes of data.
            idx+=40
            sack_data = np.concatenate(([0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0], option_data[start_idx+16:idx]))
            sack_data = [np.random.choice([0, 1]) if bit == -1 else bit for bit in sack_data]
            option_data[start_idx:idx] = sack_data
            options_lengths.remove(closest_option)

        elif closest_option == 80:  # Timestamp
            #print('time stamp')
            idx += 80
            ts_data = np.concatenate(([0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0], option_data[start_idx+16:idx]))
            ts_data = [np.random.choice([0, 1]) if bit == -1 else bit for bit in ts_data]
            option_data[start_idx:idx] = ts_data
            options_lengths.remove(closest_option)

        elif closest_option == 8:  # 
            #print('eol/nop')
            if option_data[start_idx] == 0:  # EOL
                if start_idx == 0:
                    idx += 8
                    option_data[start_idx:idx] = [-1,-1,-1,-1,-1,-1,-1,-1]
                    options_lengths.remove(closest_option)
                    continue
                else:
                    idx += 8
                    option_data[start_idx:idx] = [0,0,0,0,0,0,0,0]
                    option_data[idx:] = [-1] * (320 - idx)
                    options_lengths.remove(closest_option) 
                    break
            elif option_data[start_idx] == 1:  # NOP
                idx += 8
                option_data[start_idx:idx] = [0,0,0,0,0,0,0,1]
        elif closest_option == 0:
            idx += 8
            option_data[start_idx:idx] = [-1,-1,-1,-1,-1,-1,-1,-1]


    # Assign back the modified options to the DataFrame's row
    packet.loc['tcp_opt_0':'tcp_opt_319'] = option_data
    return packet

def tcp_opt_formatting(generated_nprint, formatted_nprint):
    generated_nprint = generated_nprint.apply(modify_tcp_option, axis=1)
    return generated_nprint

def tcp_data_offset_calculation(generated_nprint, formatted_nprint):
    # Get the subset of columns containing 'tcp'
    tcp_columns = generated_nprint.filter(like='tcp')
    # For each row in the DataFrame
    for idx, row in tcp_columns.iterrows():
        # Count the 1s and 0s in this row
        count = (row == 1).sum() + (row == 0).sum()
        # Convert to 32-bit/4-byte words
        header_size_words = math.ceil(count / 32)
        # Convert to binary and pad with zeroes to get a 4-bit representation
        binary_count = format(header_size_words, '04b')
        # Update the 'ipv4_hl' columns in the original DataFrame based on this binary representation
        for i in range(4):
            generated_nprint.at[idx, f'tcp_doff_{i}'] = int(binary_count[i])

    return generated_nprint

def src_ip_distribution(formatted_nprint_path):
    # Assuming formatted_nprint_path is a DataFrame
    formatted_nprint = pd.read_csv(formatted_nprint_path)
    # Get the value counts for the 'src_ip' column and convert to a dictionary
    ip_counts = formatted_nprint['src_ip'].value_counts()

    # Convert the counts to percentages and store in a dictionary
    ip_distribution = (ip_counts / ip_counts.sum()).to_dict()

    return ip_distribution

def direction_sampleing(formatted_nprint_path):
    # example distribution sampling
    # Let's say this is your analyzed distribution
    ip_distribution = src_ip_distribution(formatted_nprint_path)
    sorted_ips = sorted(ip_distribution.items(), key=lambda x: x[1], reverse=True)
    # Get the first two items (IPs with the highest proportions)
    top_two_ips = dict(sorted_ips[:2])
    ips = []
    for key in top_two_ips:
        ips.append(key)

    # Read the dataframe
    formatted_nprint_df = pd.read_csv(formatted_nprint_path)
    
    # Get the distinct IP addresses in order, but only if they belong to the top two IPs
    unique_ips = formatted_nprint_df['src_ip'].drop_duplicates()
    ordered_ips = [ip for ip in unique_ips if ip in top_two_ips]
    # Get the first two distinct IP addresses in order
    first_ip = ordered_ips[0]
    second_ip = ordered_ips[1]
    # Initialize the transition counts
    transition_counts = {
        (first_ip, first_ip): 0,
        (first_ip, second_ip): 0,
        (second_ip, first_ip): 0,
        (second_ip, second_ip): 0
    }
    # Iterate over the source IP addresses in order
    for i in range(1, len(formatted_nprint_df['src_ip'])):
        # Check if current and previous IP belong to top_two_ips
        if formatted_nprint_df['src_ip'][i] in top_two_ips and formatted_nprint_df['src_ip'][i-1] in top_two_ips:
            # Increment the count for the transition from the previous IP to the current IP
            transition_counts[(formatted_nprint_df['src_ip'][i-1], formatted_nprint_df['src_ip'][i])] += 1

    # Calculate the total counts from each state
    total_from_first_ip = transition_counts[(first_ip, first_ip)] + transition_counts[(first_ip, second_ip)]
    total_from_second_ip = transition_counts[(second_ip, first_ip)] + transition_counts[(second_ip, second_ip)]
    
    # Calculate the transition probabilities
    transition_matrix = np.array([
        [transition_counts[(first_ip, first_ip)] / total_from_first_ip if total_from_first_ip > 0 else 0,
         transition_counts[(first_ip, second_ip)] / total_from_first_ip if total_from_first_ip > 0 else 0],
        [transition_counts[(second_ip, first_ip)] / total_from_second_ip if total_from_second_ip > 0 else 0,
         transition_counts[(second_ip, second_ip)] / total_from_second_ip if total_from_second_ip > 0 else 0]
    ])
    # Map the indices to the IPs
    index_to_ip = {0: first_ip, 1: second_ip}

    # Starting state, for example 'src_to_dst'
    current_state = 0

    # Generate synthetic sequence
    synthetic_sequence = []
    # start with the first IP as source
    synthetic_sequence.append(current_state)
    for _ in range(1023):
        # Choose the next state
        current_state = np.random.choice([0, 1], p=transition_matrix[current_state])
        # Add the corresponding IP to the sequence
        # synthetic_sequence.append(index_to_ip[current_state])
        synthetic_sequence.append(current_state)
    return synthetic_sequence

def id_num_initialization_src_dst(generated_nprint):
    random_id_num = random_bits_generation(16)
    for i in range(16):
        generated_nprint.at[0, f'ipv4_id_{i}'] = int(random_id_num[i])
    first_row_src_ip = generated_nprint.at[0, 'src_ip']
    current_bin_str = random_id_num
    # Go through all other rows
    for index in range(1, len(generated_nprint)):
        # If src_ip of the current row matches that of the first row
        if generated_nprint.at[index, 'src_ip'] == first_row_src_ip:
            current_bin_str = increment_binary(current_bin_str)
            # Update the fields with the incremented value
            for i in range(16):
                generated_nprint.at[index, f'ipv4_id_{i}'] = int(current_bin_str[i])
    
    return generated_nprint

def id_num_initialization_dst_src(generated_nprint):
    random_id_num = random_bits_generation(16)
    first_row_src_ip = generated_nprint.at[0, 'src_ip']
    current_bin_str = random_id_num
    # Go through all other rows
    for index in range(1, len(generated_nprint)):
        # If src_ip of the current row matches that of the first row
        if generated_nprint.at[index, 'src_ip'] != first_row_src_ip:
            current_bin_str = increment_binary(current_bin_str)
            # Update the fields with the incremented value
            for i in range(16):
                generated_nprint.at[index, f'ipv4_id_{i}'] = int(current_bin_str[i])
    
    return generated_nprint

def increment_binary(bin_str):
    '''Increment a binary string by one.'''
    bin_int = int(bin_str, 2) + 1
    return format(bin_int, f'0{len(bin_str)}b')

def ip_fragementation_bits(generated_nprint):
    generated_nprint['ipv4_rbit_0'] = 0
    generated_nprint['ipv4_dfbit_0'] = 1
    generated_nprint['ipv4_mfbit_0'] = 0
    for i in range(13):
        generated_nprint[f'ipv4_foff_{i}'] = 0
    return generated_nprint

def random_bits_generation(required_num_bits):
    return ''.join(str(random.randint(0, 1)) for _ in range(required_num_bits))

def port_initialization(generated_nprint):
    random_src_port = random_bits_generation(16)
    random_dst_port = random_bits_generation(16)
    dominating_protocol = protocol_determination(generated_nprint)
    if dominating_protocol == 'tcp':
        for i in range(16):
            generated_nprint.at[0, f'tcp_sprt_{i}'] = int(random_src_port[i])
            generated_nprint.at[0, f'tcp_dprt_{i}'] = int(random_dst_port[i])
        first_row_src_ip = generated_nprint.at[0, 'src_ip']
        # Go through all other rows
        for index in range(1, len(generated_nprint)):
            # If src_ip of the current row matches that of the first row
            if generated_nprint.at[index, 'src_ip'] == first_row_src_ip:
                for i in range(16):
                    generated_nprint.at[index, f'tcp_sprt_{i}'] = int(random_src_port[i])
                    generated_nprint.at[index, f'tcp_dprt_{i}'] = int(random_dst_port[i])
            else:
                for i in range(16):
                    generated_nprint.at[index, f'tcp_sprt_{i}'] = int(random_dst_port[i])
                    generated_nprint.at[index, f'tcp_dprt_{i}'] = int(random_src_port[i])
    elif dominating_protocol == 'udp':
        for i in range(16):
            generated_nprint.at[0, f'udp_sport_{i}'] = int(random_src_port[i])
            generated_nprint.at[0, f'udp_dport_{i}'] = int(random_dst_port[i])
        first_row_src_ip = generated_nprint.at[0, 'src_ip']
        # Go through all other rows
        for index in range(1, len(generated_nprint)):
            # If src_ip of the current row matches that of the first row
            if generated_nprint.at[index, 'src_ip'] == first_row_src_ip:
                for i in range(16):
                    generated_nprint.at[index, f'udp_sport_{i}'] = int(random_src_port[i])
                    generated_nprint.at[index, f'udp_dport_{i}'] = int(random_dst_port[i])
            else:
                for i in range(16):
                    generated_nprint.at[index, f'udp_sport_{i}'] = int(random_dst_port[i])
                    generated_nprint.at[index, f'udp_dport_{i}'] = int(random_src_port[i])
    return generated_nprint

def compute_tcp_segment_length(row):
    total_length = int(''.join(str(row[f'ipv4_tl_{i}']) for i in range(16)), 2)
    ipv4_header_length = int(''.join(str(row[f'ipv4_hl_{i}']) for i in range(4)), 2) * 4  # in bytes
    tcp_header_length = int(''.join(str(row[f'tcp_doff_{i}']) for i in range(4)), 2) * 4  # in bytes
    
    return total_length - ipv4_header_length - tcp_header_length

def increment_binary_non_fixed(bin_str, increment_value):
    decimal_value = int(bin_str, 2)
    decimal_value += increment_value
    new_bin_str = bin(decimal_value)[2:].zfill(len(bin_str))
    return new_bin_str

def seq_initialization_src_dst(generated_nprint):
    random_id_num = random_bits_generation(32)
    for i in range(32):
        generated_nprint.at[0, f'tcp_seq_{i}'] = int(random_id_num[i])
    first_row_src_ip = generated_nprint.at[0, 'src_ip']
    current_bin_str = random_id_num
    
    # To keep track of the last packet for each src_ip
    last_packet_for_ip = {first_row_src_ip: 0}

    # Go through all other rows
    for index in range(1, len(generated_nprint)):
        current_src_ip = generated_nprint.at[index, 'src_ip']
        # If src_ip of the current row matches that of the first row
        if current_src_ip == first_row_src_ip:
            # If this IP has been seen before
            if current_src_ip in last_packet_for_ip:
                previous_index = last_packet_for_ip[current_src_ip]
                previous_row = generated_nprint.iloc[previous_index]
                segment_length = compute_tcp_segment_length(previous_row)
                current_bin_str = increment_binary_non_fixed(current_bin_str, segment_length)
            else:
                # If this IP has not been seen before
                current_bin_str = random_bits_generation(32)
            # Update the fields with the incremented value
            for i in range(32):
                generated_nprint.at[index, f'tcp_seq_{i}'] = int(current_bin_str[i])
            
            # Update the last packet for this IP
            last_packet_for_ip[current_src_ip] = index

    return generated_nprint

def seq_initialization_dst_src(generated_nprint):
    random_id_num = random_bits_generation(32)
    first_row_src_ip = generated_nprint.at[0, 'src_ip']
    current_bin_str = random_id_num
    
    # To keep track of the last packet for each src_ip
    last_packet_for_ip = {first_row_src_ip: 0}

    # Go through all other rows
    for index in range(1, len(generated_nprint)):
        current_src_ip = generated_nprint.at[index, 'src_ip']
        # If src_ip of the current row does not match that of the first row
        if current_src_ip != first_row_src_ip:
            # If this IP has been seen before
            if current_src_ip in last_packet_for_ip:
                previous_index = last_packet_for_ip[current_src_ip]
                previous_row = generated_nprint.iloc[previous_index]
                segment_length = compute_tcp_segment_length(previous_row)
                current_bin_str = increment_binary_non_fixed(current_bin_str, segment_length)
            else:
                # If this IP has not been seen before
                current_bin_str = random_bits_generation(32)
            # Update the fields with the incremented value
            for i in range(32):
                generated_nprint.at[index, f'tcp_seq_{i}'] = int(current_bin_str[i])
            
            # Update the last packet for this IP
            last_packet_for_ip[current_src_ip] = index

    return generated_nprint

def three_way_handshake(generated_nprint):
    #tcp_ackf_0,tcp_psh_0,tcp_rst_0,tcp_syn_0,tcp_fin_0,
    # Modify the dataframe for a 3-way handshake
    response_received = False
    handshake_complete = False
    for index in range(0, len(generated_nprint)):
        # If src_ip of the current row matches that of the first row
        if index == 0:
                generated_nprint.at[index, 'tcp_syn_0'] = 1
                generated_nprint.loc[index, ['tcp_ackf_0', 'tcp_psh_0', 'tcp_rst_0', 'tcp_fin_0']] = 0
                first_row_src_ip = generated_nprint.at[index, 'src_ip']
        elif handshake_complete == False:
            if generated_nprint.at[index, 'src_ip'] == first_row_src_ip and response_received == False:
                generated_nprint.at[index, 'tcp_syn_0'] = 1
                generated_nprint.loc[index, ['tcp_ackf_0', 'tcp_psh_0', 'tcp_rst_0', 'tcp_fin_0']] = 0
            elif generated_nprint.at[index, 'src_ip'] != first_row_src_ip:
                generated_nprint.loc[index, ['tcp_syn_0', 'tcp_ackf_0']] = 1
                generated_nprint.loc[index, ['tcp_psh_0', 'tcp_rst_0', 'tcp_fin_0']] = 0
                response_received = True
            elif generated_nprint.at[index, 'src_ip'] == first_row_src_ip and response_received == True:
                generated_nprint.at[index, 'tcp_ackf_0'] = 1
                generated_nprint.loc[index, ['tcp_syn_0', 'tcp_psh_0', 'tcp_rst_0', 'tcp_fin_0']] = 0       
                handshake_complete = True   
        elif handshake_complete == True:
            generated_nprint.at[index, 'tcp_ackf_0'] = 1
    return generated_nprint

def ackn_initialization_src_dst(generated_nprint):
    last_src_to_dst_seq = []
    last_dst_to_src_seq = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    src_ip = generated_nprint.at[0, 'src_ip']
    for i in range(32):
        generated_nprint.at[0, f'tcp_ackn_{i}'] = 0
    for i in range(32):
        last_src_to_dst_seq.append(generated_nprint.at[0, f'tcp_seq_{i}'])
    
    first_switch_done = False
    for index in range(1, len(generated_nprint)):
        current_src_ip = generated_nprint.at[index, 'src_ip']
        # if current src is identical as src and first switch is not done
        if current_src_ip == src_ip and not first_switch_done:
            # keep assign ack to be 0s
            for i in range(32):
                generated_nprint.at[index, f'tcp_ackn_{i}'] = 0
            # update the last sequence numbe from src to dst
            last_src_to_dst_seq = []
            for i in range(32):
                last_src_to_dst_seq.append(generated_nprint.at[index, f'tcp_seq_{i}'])
        # if current src is non-identical now: we have switched direction
        if current_src_ip != src_ip:
            # assign first switch to be true.
            first_switch_done = True
            # update the ack to be the last_src_to_dst_seq
            for i in range(32):
                generated_nprint.at[index, f'tcp_ackn_{i}'] = last_src_to_dst_seq[i]
            # update the seq of last_dst_to_src_seq
            last_dst_to_src_seq = []
            for i in range(32):
                last_dst_to_src_seq.append(generated_nprint.at[index, f'tcp_seq_{i}'])
        # if the src is identical as src and we have switch direction
        if current_src_ip == src_ip and first_switch_done:
            # update the ack to be the last_dst_to_src_seq
            for i in range(32):
                generated_nprint.at[index, f'tcp_ackn_{i}'] = last_dst_to_src_seq[i]
            # update the seq of last_src_to_dst_seq
            last_src_to_dst_seq = []
            for i in range(32):
                last_src_to_dst_seq.append(generated_nprint.at[index, f'tcp_seq_{i}'])




    return generated_nprint

def udp_len_calculation(generated_nprint, formatted_nprint):
    # For each row in the DataFrame
    for idx, row in generated_nprint.iterrows():
        ipv4_hl_binary = [row[f'ipv4_hl_{i}'] for i in range(4)]
        ipv4_hl_value = binary_to_decimal(ipv4_hl_binary) * 4  # Convert from 4-byte words to bytes
        upper_limit = 1500 - ipv4_hl_value - 8
        udp_len_binary = [row[f'udp_len_{i}'] for i in range(16)]
        udp_len_value = binary_to_decimal(udp_len_binary)  # Convert from 4-byte words to bytes
        if udp_len_value >= 8 and udp_len_value <= upper_limit:
            continue
        elif udp_len_value < 8:
            for i in range(16):
                generated_nprint.at[idx, f'udp_len_{i}'] = 0
            generated_nprint.at[idx, f'udp_len_12'] = 1
        else:
            new_udp_len_binary = format(upper_limit, '016b')
            for i in range(16):
                generated_nprint.at[idx, f'udp_len_{i}'] = int(new_udp_len_binary[i])

    return generated_nprint

def udp_header_negative_removal(generated_nprint, formatted_nprint):
    fields = ["udp"]

    # Function to apply to each cell
    def replace_negative_one(val):
        if val == -1:
            return np.random.randint(0, 2)  # Generates either 0 or 1
        else:
            return val

    # Iterate over the columns of the source DataFrame
    for column in formatted_nprint.columns:
        # Check if the substring exists in the column name
        for field in fields:
            #if field in column:
            if field in column and 'opt' not in column:
                generated_nprint[column] = generated_nprint[column].apply(replace_negative_one)
            # ######## no opt for debugging
            # elif field in column:
            #     generated_nprint[column] = -1

    return generated_nprint

def ipv4_tl_formatting_udp(generated_nprint, formatted_nprint):

    counter = 0
    for idx, row in generated_nprint.iterrows():
        # Extracting binary values for ipv4_tl, ipv4_hl, and tcp_doff
        ipv4_tl_binary = [row[f'ipv4_tl_{i}'] for i in range(16)]
        ipv4_hl_binary = [row[f'ipv4_hl_{i}'] for i in range(4)]
        udp_len_binary = [row[f'udp_len_{i}'] for i in range(16)]

        # Convert the binary representation to integer
        ipv4_tl_value = binary_to_decimal(ipv4_tl_binary)
        ipv4_hl_value = binary_to_decimal(ipv4_hl_binary) * 4  # Convert from 4-byte words to bytes
        udp_len_value = binary_to_decimal(udp_len_binary)  # Convert from 4-byte words to bytes
        # Checking and setting the new value if condition is met
        if ipv4_tl_value < ipv4_hl_value + udp_len_value:
            new_ipv4_tl_value = ipv4_hl_value + udp_len_value
            # Convert new value back to binary and update the fields
            new_ipv4_tl_binary = format(new_ipv4_tl_value, '016b')
            for i, bit in enumerate(new_ipv4_tl_binary):
                generated_nprint.at[idx, f'ipv4_tl_{i}'] = int(bit)
        elif ipv4_tl_value>1500:
            new_ipv4_tl_binary = format(1500, '016b')
            for i, bit in enumerate(new_ipv4_tl_binary):
                generated_nprint.at[idx, f'ipv4_tl_{i}'] = int(bit)
        else:
            new_ipv4_tl_binary = format(ipv4_tl_value, '016b')
            for i, bit in enumerate(new_ipv4_tl_binary):
                generated_nprint.at[idx, f'ipv4_tl_{i}'] = int(bit)
    # for i in range(16):
    #     generated_nprint[f'ipv4_tl_{i}'] = formatted_nprint[f'ipv4_tl_{i}']
    for idx, row in generated_nprint.iterrows():
        # Extracting binary values for ipv4_tl, ipv4_hl, and tcp_doff
        ipv4_tl_binary = [row[f'ipv4_tl_{i}'] for i in range(16)]
        ipv4_hl_binary = [row[f'ipv4_hl_{i}'] for i in range(4)]
        udp_len_binary = [row[f'udp_len_{i}'] for i in range(16)]

        # Convert the binary representation to integer
        ipv4_tl_value = binary_to_decimal(ipv4_tl_binary)
        ipv4_hl_value = binary_to_decimal(ipv4_hl_binary) * 4  # Convert from 4-byte words to bytes
        udp_len_value = binary_to_decimal(udp_len_binary) # Convert from 4-byte words to bytes

        counter +=1


    return generated_nprint

def main(generated_nprint_path, formatted_nprint_path, output, nprint):
    rebuilt_pcap_path = output
    generated_nprint = read_syn_nprint(generated_nprint_path)
    formatted_nprint = pd.read_csv(formatted_nprint_path)
    # Get the list of column names in both CSVs
    generated_columns = set(generated_nprint.columns)
    formatted_columns = set(formatted_nprint.columns)
    # Find missing columns in the generated nprint
    missing_columns = formatted_columns - generated_columns
    # Add the missing columns to the generated nprint with value 0
    missing_data = pd.DataFrame(0, index=generated_nprint.index, columns=list(missing_columns))
    generated_nprint = pd.concat([generated_nprint, missing_data], axis=1)
    # Reindex the columns of generated_nprint to match the order of columns in formatted_nprint
    generated_nprint = generated_nprint.reindex(columns=formatted_nprint.columns)




    ##############################################################################Intra packet dependency adjustments#########################################################################
    ########### ip address formatting (we have flexibility here)
    synthetic_sequence = direction_sampleing(formatted_nprint_path)
    generated_nprint = ip_address_formatting(generated_nprint, synthetic_sequence)

    ########### IPV4
    generated_nprint = ipv4_ver_formatting(generated_nprint,formatted_nprint) # we are using ipv4 only
    generated_nprint = ipv4_header_negative_removal(generated_nprint,formatted_nprint) # here we make sure minimum ipv4 header size is achieved - no missing ipv4 header fields, random int is assigned as the fields largely are correct due to diffusion    
    generated_nprint = ipv4_pro_formatting(generated_nprint,formatted_nprint) # this is less flexible -> choose protocol with most percentage of non negatives excluding option, and change all non-determined-protocol fields to -1
    generated_nprint = ipv4_option_removal(generated_nprint,formatted_nprint) # mordern Internet rarely uses ipv4 options is used at all, from the data we observe ipv4 options are never present due to it being obsolete
    generated_nprint = ipv4_ttl_ensure(generated_nprint,formatted_nprint) # ensure ttl > 0
    generated_nprint = ipv4_hl_formatting(generated_nprint,formatted_nprint) # ipv4 header length formatting (this is computation based so we do not have flexibility here), need to be done after all other ipv4 fields are formatted
    # CHECKSUM UPDATED AT THE END


    ########### TCP
    dominating_protocol = protocol_determination(generated_nprint)
    if dominating_protocol == 'tcp':
        generated_nprint = tcp_header_negative_removal(generated_nprint, formatted_nprint)
        generated_nprint = tcp_opt_formatting(generated_nprint,formatted_nprint) # option must be continuous and has fixed length, we use closest approximation here
        generated_nprint = tcp_data_offset_calculation(generated_nprint, formatted_nprint) # count the total number of bytes in the tcp header fields including options and store the sume as the offset

    ########### IPV4
        generated_nprint = ipv4_tl_formatting_tcp(generated_nprint,formatted_nprint) # payload need to be considered
    elif dominating_protocol == 'udp':
        generated_nprint = udp_header_negative_removal(generated_nprint, formatted_nprint)
        generated_nprint = udp_len_calculation(generated_nprint, formatted_nprint) 
        ########### IPV4
        generated_nprint = ipv4_tl_formatting_udp(generated_nprint,formatted_nprint) # payload need to be considered

    ##############################################################################End of Intra packet dependency adjustments#########################################################################




    ############################################################################## Inter packet dependency adjustments#########################################################################
    # random initial identification number initial for first source to destination packet, use synthetic_sequence to keep track for the rest for increments
    generated_nprint = id_num_initialization_src_dst(generated_nprint)
    # random initial identification number initial for first dst to src packet, use synthetic_sequence to keep track
    generated_nprint = id_num_initialization_dst_src(generated_nprint)
    #generated_nprint = seq_num_initialization_dst_src(generated_nprint)

    # Set fragmentation related bits, do not fragment to 1, OR NOT? reseved bit to 0 for all packets, more fragments bit to 0 for all packets, 0 for fragmentation offset
    generated_nprint = ip_fragementation_bits(generated_nprint)
    dominating_protocol = protocol_determination(generated_nprint)
    if dominating_protocol == 'tcp':
        # ports needs to be consistent but can be randomly generated
        generated_nprint = port_initialization(generated_nprint)
        # seq number must be computed based on tcp segment length
        generated_nprint = seq_initialization_src_dst(generated_nprint)
        generated_nprint = seq_initialization_dst_src(generated_nprint)
        # three way handshake initial flags must be set correctly
        generated_nprint = three_way_handshake(generated_nprint)

        # ack num formatting
        generated_nprint = ackn_initialization_src_dst(generated_nprint)
    elif dominating_protocol == 'udp':
        # ports needs to be consistent but can be randomly generated
        generated_nprint = port_initialization(generated_nprint)


    ##############################################################################End of Inter packet dependency adjustments#########################################################################


    ## ipv6 removal
    fields = ["ipv6"]
    # Iterate over the columns of the source DataFrame
    for column in formatted_nprint.columns:
        # Check if the substring exists in the column name
        for field in fields:
            #if field in column:
            if field in column :
                generated_nprint[column] = -1

    # saved the formatted_generated_nprint and attempt reconstruction
    formatted_generated_nprint_path = nprint
    generated_nprint.to_csv(formatted_generated_nprint_path, index=False)
    reconstruction_to_pcap(formatted_generated_nprint_path, rebuilt_pcap_path)
    update_ipv4_checksum(rebuilt_pcap_path, rebuilt_pcap_path)    
    subprocess.run('nprint -F -1 -P {0} -4 -i -6 -t -u -p 0 -c 1024 -W {1}'.format(rebuilt_pcap_path, formatted_generated_nprint_path), shell=True)
    #reconstruction_to_pcap('/Users/chasejiang/Desktop/netdiffussion/replayability/meet_real.nprint', rebuilt_pcap_path)
    #reconstruction_to_pcap(formatted_nprint_path, rebuilt_pcap_path)

    


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='pcap reconstruction')
    parser.add_argument('--generated_nprint_path', required = True, help='Path to the generated nPrint file')
    parser.add_argument('--formatted_nprint_path', required = True, help='Path to the formatted nPrint file')
    parser.add_argument('--output', required = True, help='Path to the reconstructed pcap file')
    parser.add_argument('--nprint', required = True, help='Path to the reconstructed nprint file')
    parser.add_argument('--src_ip', 
                    help='Desired source IP address, randomly generated if not specified',
                    default='0.0.0.0')
    parser.add_argument('--dst_ip', 
                help='Desired destination IP address, randomly generated if not specified',
                default='0.0.0.0')
    args = parser.parse_args()
    main(args.generated_nprint_path, args.formatted_nprint_path, args.output, args.nprint)