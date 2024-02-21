import os
import sys
org_data_dir = './kohya_ss_fork/model_training/'+sys.argv[1]
for i in os.listdir(org_data_dir):
    if 'txt' in i:
        with open (org_data_dir+'/'+i,'w') as f:
            if 'netflix' in i:
                f.write('pixelated network data, type-0')
