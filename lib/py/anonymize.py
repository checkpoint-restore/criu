# This file contains methods to anonymize criu images.

# In order to anonymize images three steps are followed:
#     - decode the binary image to json
#     - strip the necessary information from the json dict
#     - encode the json dict back to a binary image, which is now anonymized

# The following contents are being anonymized:
#     - Paths to files

import hashlib


def files_anon(image):
    levels = {}

    fname_key = 'reg'
    checksum = hashlib.sha1()

    for e in image['entries']:
        if fname_key in e:
            f_path = e[fname_key]['name']

            f_path = f_path.split('/')
            lev_num = 0

            for i, p in enumerate(f_path):
                if p == '':
                    continue
                if lev_num not in levels:
                    levels[lev_num] = {}
                if p not in levels[lev_num]:
                    if i == 1:
                        levels[lev_num][p] = p
                    else:
                        checksum.update(p)
                        levels[lev_num][p] = checksum.hexdigest()
                lev_num += 1

    for i, e in enumerate(image['entries']):
        if fname_key in e:
            f_path = e[fname_key]['name']

            if f_path == '/':
                continue

            f_path = f_path.split('/')
            lev_num = 0

            for j, p in enumerate(f_path):
                if p == '':
                    continue
                f_path[j] = levels[lev_num][p]
                lev_num += 1
            f_path = '/'.join(f_path)
            image['entries'][i][fname_key]['name'] = f_path

    return image


anonymizers = {
    'FILES': files_anon
}


def anon_handler(image):
    magic = image['magic']

    if magic != 'FILES':
        return -1

    handler = anonymizers[magic]
    anon_img = handler(image)

    return anon_img
