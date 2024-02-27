import os
org_data_dir = '../data/generated_nprint'
out_put_data_dir = '../data/replayable_generated_pcaps'
out_put_nprint_dir = '../data/replayable_generated_nprints'
for org_nprint in os.listdir(org_data_dir):
    org_nprint_path = org_data_dir+ '/'+org_nprint
    output_pcap_path = out_put_data_dir+ '/'+org_nprint.replace('.nprint','.pcap')
    output_nprint_path = out_put_nprint_dir+ '/'+org_nprint

    print(org_nprint_path)
    print(output_pcap_path)

    os.system('python3 reconstruction.py --generated_nprint_path '+org_nprint_path+' --formatted_nprint_path correct_format.nprint --output '+output_pcap_path+' --nprint '+output_nprint_path)
