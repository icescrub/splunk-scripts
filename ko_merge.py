#!/usr/bin/python

"""
This script merges user content from multiple, separate search heads.
The final output is a directory containing merged configuration files for all users, with collisions noted in each configuration file and in stdout.
The final output also includes a collisions.txt file outlining those same collisions.

=================
Relevant details:

1. User content from each search head is contained in a zip file. The user content is expected to be from the directory $SPLUNK_HOME/etc/users.
2. This script doesn't merge lookups, metadata, history, or <app>/local/data directory data for each user. This script ONLY merges configuration files located in $SPLUNK_HOME/etc/users/<app>/local/*.conf.
3. Script assumes user content onfiguration files do NOT contain comments. Usually, comments (or lines that are commented out) are found in the local directory of TAs, but user content is usually clean.
4. The script can handle an arbitrary number of search heads.
5. The script has a '--map-users' flag that requires a 'map_users.csv' file in the working directory. This maps users from environment 1 to the new, desired users in environment 2.
6. The script expects zip files with the naming convention '<environment_name>_users.zip'. The environment can be called anything, but the underscore separator is essential.

======================
How to run the script:

1. Put all zip files in the same location.
2. Make sure script has execute permissions for the user running it.
3. Run the command: '/full/path/to/ko_merge.py <zip_file1> <zip_file2> <zip_file3> ...'

===================================
The script runs roughly as follows:

Part 1. Create new working directory and unzip files.
Part 2. Traverse directories and find all configuration files. Map (user, app, local, filename) --> file_location.
Part 3. Merge above mappings. Now, for a given (user, app, local, filename), there may be multiple files originating from separate search heads.
Part 4. Resolve above merge by merging those configuration files into one configuration file.
Part 5. Print out collisions.
"""


########
# IMPORTS
#########

import sys
import os
import tempfile
import shutil
import zipfile
import csv
import re
import functools
from collections import defaultdict


##################
# GLOBAL VARIABLES
##################

global RUNTIME_VERSION
RUNTIME_VERSION = sys.version_info.major

global INITIAL_WORKING_DIRECTORY
INITIAL_WORKING_DIRECTORY = os.getcwd()

global CURRENT_WORKING_DIRECTORY
CURRENT_WORKING_DIRECTORY = os.getcwd()

global MAP_USERS

#####################
# DECORATOR FUNCTIONS
#####################
    
def clean_temp_dirs(func):
    """Removes temporary directories after use."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        temp_dirs = func(*args, **kwargs)
        for temp_dir in temp_dirs:
            shutil.rmtree(temp_dir)

    return wrapper


################
# MAIN FUNCTIONS
################

@clean_temp_dirs
def merge_all(*zip_files):
    """
    INPUT: arbitrary number of zip files.
    OUTPUT: directory with new merged files.
    Unzips files into temporary directory.
    Extracts info for all files.
    For each (user, app, *.conf) context, merge configuration file for all search heads.
    Merges files for each (user, app, *.conf) context.
    Cleans up temp files.
    """

    # Zip files are using relative path. Use absolute path.
    zip_files = [os.path.abspath(file) for file in zip_files]
    
    ### Create working directory in the *current* directory. This should already be the directory where the zip files are located.
    child_directory = os.path.join(INITIAL_WORKING_DIRECTORY, "merged_user_content")
    os.mkdir(child_directory)
    os.chdir(child_directory)

    global CURRENT_WORKING_DIRECTORY
    CURRENT_WORKING_DIRECTORY = os.getcwd()

    ### Extract dictionary representation of each zip file and keep track of temp directories for future cleanup.
    extracted_dicts = list()
    temp_dirs = list()

    for file in zip_files:
        d, temp_dir = extract_files(file)
        extracted_dicts.append(d)
        temp_dirs.append(temp_dir)

    ### Merge dictionary representation of all zip files.
    merged_dict = defaultdict(list)
    for d in extracted_dicts:
        for k,v in d.items():
            merged_dict[k].append(v)

    ### Merge each .conf file.
    # The merged dictionary keeps track of whether there is one or more files for each .conf file.
    # Now the merge_single file expects files that are .conf files (or stanza based files).
    for k,v in merged_dict.items():
        files, origins = zip(*v)

        # Case 1: if files are *.conf files or local.meta files, then they can be merged with stanzas.
        current_filename = k[-1]
        if ('local' in k and 'conf' in current_filename) or ('metadata' in k):
            s = merge_single(*files)

            ### Create final merged configuration file and write to it.
            generated_filepath = os.path.join(*k)
            new_file = os.path.join(CURRENT_WORKING_DIRECTORY, generated_filepath)
            # If directory already exists, that's okay. Doesn't overwrite.
            # Runtime version check.
            if RUNTIME_VERSION == 3:
                os.makedirs(os.path.dirname(new_file), exist_ok=True)
            elif RUNTIME_VERSION == 2:
                if not os.path.exists(os.path.dirname(new_file)):
                    os.makedirs(os.path.dirname(new_file))

            with open(new_file, 'w+') as f:
                f.write(s)

        # Case 2: history files. Concatenate these CSV files.
        elif 'history' in k:
            history_list = list()
            for file in files:
                with open(file, 'r') as f:
                    history_list.append(f.read())
            full_search_history = '\n'.join(history_list)

            ### Create final merged configuration file and write to it.
            generated_filepath = os.path.join(*k)
            new_file = os.path.join(CURRENT_WORKING_DIRECTORY, generated_filepath, 'history.csv')
            # If directory already exists, that's okay. Doesn't overwrite.
            # Runtime version check.
            if RUNTIME_VERSION == 3:
                os.makedirs(os.path.dirname(new_file), exist_ok=True)
            elif RUNTIME_VERSION == 2:
                if not os.path.exists(os.path.dirname(new_file)):
                    os.makedirs(os.path.dirname(new_file))

            with open(new_file,'w+') as f:
                f.write(full_search_history)


        # Case 3: lookups (CSV) or views/panels (XML). These are CSV/XML files and get renamed.
        elif ('local' in k and 'views' in k) or ('local' in k and 'panels' in k) or ('lookups' in k):

            # created_files = list()

            for file, origin in v:

                ### Create final merged configuration file and write to it.

                # Check whether the CSV/XML file exists 2+ times in the list. If so, add the origin to the name.
                base_filename = os.path.basename(file)
                all_files, _ = zip(*v)

                count = sum(bool(base_filename in file) for file in all_files)
                if count > 1:
                    filename_with_origin = base_filename + '__' + origin
                else:
                    filename_with_origin = base_filename

                # NOTE that the new path doesn't include the last part of k, which has the current filename in it.
                generated_subpath = os.path.join(*k[:-1])
                generated_filepath = os.path.join(generated_subpath, filename_with_origin)
                new_file = os.path.join(CURRENT_WORKING_DIRECTORY, generated_filepath)
                # If directory already exists, that's okay. Doesn't overwrite.
                # Runtime version check.
                if RUNTIME_VERSION == 3:
                    os.makedirs(os.path.dirname(new_file), exist_ok=True)
                elif RUNTIME_VERSION == 2:
                    if not os.path.exists(os.path.dirname(new_file)):
                        os.makedirs(os.path.dirname(new_file))

                # Create new file and copy contents to renamed file.
                with open(new_file,'w+') as f:
                    shutil.copyfile(file, new_file)

    # Splunk has a history directory for all users in Check if there's a history file in each user's directory. Add it if not.

    # Get list of users.
    users_dir = os.path.join(child_directory, 'users')
    cmd = "ls {}".format(users_dir)
    stream = os.popen("ls {}".format(users_dir))
    output = stream.read()
    users = [user for user in output.split('\n') if user]

    # Walk merged_user_content directory and create history directory if it doesn't exist.
    # If parent directory is a user, then you're in an app context.
    # In which case, check for the history directory in that app context.
    for root, dirs, files in os.walk(child_directory):
        current_app = os.path.basename(root)
        current_user = os.path.basename(os.path.dirname(root))
        if current_user in users and current_app != 'user_prefs' and 'history' not in dirs:
            history_dir = os.path.join(root, 'history')
            # Runtime version check.
            if RUNTIME_VERSION == 3:
                os.makedirs(history_dir, exist_ok=True)
            elif RUNTIME_VERSION == 2:
                if not os.path.exists(history_dir):
                    os.makedirs(history_dir)
    
    ### Obtain all collisions. Print to screen and write to file.
    collisions_text, other_collisions_text = get_collisions()

    f_collisions = os.path.join(INITIAL_WORKING_DIRECTORY, 'collisions.txt')
    with open(f_collisions, 'w+') as f:
        f.write(collisions_text)

    f_other_collisions = os.path.join(INITIAL_WORKING_DIRECTORY, 'other_collisions.txt')
    with open(f_other_collisions, 'w+') as f:
        f.write(other_collisions_text)

    ### Returns list of temporary directories to the clean_temp_dirs decorator.
    return temp_dirs


def extract_files(zip_filepath):
    """
    INPUT: zip file.
    OUTPUT: dictionary with extracted contents properly correlated.
    Unzip file.
    Extract contents.
    """

    ### Extract file to directory.
    with zipfile.ZipFile(zip_filepath, 'r') as zip_ref:
        temp_dir = tempfile.mkdtemp()
        zip_ref.extractall(temp_dir)

    # Ensures that the only directory that is traversed is the extracted '*users*' directory.
    for dir in os.listdir(temp_dir):
        if 'users' in dir:
            user_dir = dir

    # Extracts origin from the zipped filename.
    zip_basename = os.path.basename(zip_filepath)
    origin = zip_basename.split('_')[0]

    ### Traverse extracted directory, identify all .conf files, append to a list.
    full_path = os.path.join(temp_dir, user_dir)
    # traverse directory and list all full paths for all .conf files.
    list_conf_files = list()
    for root, dirs, files in os.walk(full_path):
        for file in files:

            # Get parent directory.
            parent_dir = os.path.basename(root)

            # Case 1: .conf files from /local. This merges by stanza.
            is_conf = (parent_dir == 'local' and file.endswith('.conf'))

            # Case 2: metadata files from /metadata. This merges by stanza.
            is_metadata = (parent_dir == 'metadata' and file.endswith('.meta'))

            # Case 3: history files from /history. This contains a CSV file and will just be a concatenation of the history CSV files.
            is_history = (parent_dir == 'history' and file.endswith('csv'))

            # Case 4: lookup files from /lookups. This contains CSV files and merging will just be renaming.
            is_lookup = (parent_dir == 'lookups')

            # Case 5: dashboard XML from .../local/data/ui/views or .../local/data/ui/panels. This contains XML files and merging will just be renaming.

            is_local_data = (parent_dir == 'views' or parent_dir == 'panels')

            if is_conf or is_metadata or is_lookup or is_history or is_local_data:
                full_path_file = os.path.join(root, file)
                list_conf_files.append(full_path_file)

    d_files = dict()

    # If MAP_USER flag not set, then we assume users are consistent across all environments.
    if not MAP_USERS:
        ### For each configuration file, map (user, app, local, conf) to the full path.
        # The calling function takes care of merging these dictionaries for collisions.
        for path in list_conf_files:
            split_path = path.split(os.sep)
            # History files have DIFFERENT filenames for each host. Need to cut the filename out of the mapping to allow for multiple files in the merging.
            if 'history' in split_path:
                tup = tuple(split_path[7:-1])
            else:
                tup = tuple(split_path[7:])
            d_files[tup] = (path, origin)

    # If MAP_USER flag is set, then users in environment 1 != users in environment 2.
    # Need to use provided map_users.csv file to map from environment 1 to environment 2.
    elif MAP_USERS:
        d_map_users = dict()

        # Create user map.
        csv_filepath = os.path.join(INITIAL_WORKING_DIRECTORY, "map_users.csv")
        with open(csv_filepath, 'r') as f:
            reader = csv.reader(f, delimiter=' ')
            for row in reader:
                user_env1, user_env2 = row
                d_map_users[user_env1] = user_env2

        for path in list_conf_files:
            split_path = path.split(os.sep)
            # History files have DIFFERENT filenames for each host. Need to cut the filename out of the mapping to allow for multiple files in the merging.
            if 'history' in split_path:
                tup = tuple(split_path[7:-1])
            else:
                tup = tuple(split_path[7:])

            # If user is in mapping, then map user to new environment.
            user = tup[1]
            if user in d_map_users:
                new_user = d_map_users[user]
                tup = (split_path[7],) + (new_user,) + tuple(split_path[9:])

            d_files[tup] = (path, origin)

    return d_files, temp_dir


def merge_single(*files):
    """
    INPUT: arbitrary number of configuration files.
    OUTPUT: string representing merged file.
    Convert text in configuration file to dictionary for comparison.
    Identify unique keys for each file for comparison.
    Merge files. Collisions are handled as follows:
    - Use defaultdict(list) which allows for more complex values in a k-v pair.
    - Resolve by printing out BOTH values in the merged configuration file and then noting which file caused the collision.
    """

    ### Read single configuration file and convert to dictionary representation for merging.
    files_as_dict = list()
    for file in files:
        with open(file, 'r') as f:
            f_text = f.read()
            dict_stanzas = convert_text_to_dict(f_text)
            files_as_dict.append(dict_stanzas)

    ### Identifies unique stanzas for each configuration file.
    # For merging logic below, we only want to check a stanza once (in all configuration files).
    # When we're done looking at the first configuration file and move on to the next one...
    # ...we should only be looking at stanzas unique to that configuration file.
    # Technique: For each configuration file, identify stanzas and subtract all stanzas from previous configuration files - this leaves behind only unique stanzas.
    d_unique_keys = list()
    for i,d in enumerate(files_as_dict):
        s = set(d.keys())
        previous_dicts = files_as_dict[:i]
        previous_keys = (set(prev.keys()) for prev in previous_dicts)
        unique_keys_for_current_dict = s.difference(*previous_keys)
        d_unique_keys.append(unique_keys_for_current_dict)

    ### Merging logic.
    # Technique: Part 1: Load in unique stanzas from configuration file.
    # Part 2: For each stanza, check all other configuration files for collisions.
    d = dict()
    for i,z in enumerate(zip(files_as_dict, d_unique_keys)):
        current_dict, keys = z
        for stanza in keys:

            # Part 1: Load in stanzas from current configuration file.
            d[stanza] = defaultdict(list)
            for k,v in current_dict[stanza].items():
                d[stanza][k].append(v)

            # Part 2: Check for collisions in current stanza for all other configuration files.
            remaining_dicts = files_as_dict[i+1:]
            for j, rem_dict in enumerate(remaining_dicts):
                if stanza in rem_dict:
                    for k,v in rem_dict[stanza].items():

                        # Case 1: Unique key. Add it to merged file.
                        if k not in d[stanza].keys():
                            d[stanza][k].append(v)

                        # Case 2: Not unique key. Check if there's a collision.
                        else:

                            # Case 2a: key exists and value is identical to current value. Pass.
                            if v in d[stanza][k]:
                                pass

                            # Case 2b: key exists and value is *new*. This is a collision.
                            elif v not in d[stanza][k]:
                                d[stanza][k].append((v,"file" + str(j+2)))

    merged_stanzas = convert_dict_to_text(d)
    return merged_stanzas


###################
# UTILITY FUNCTIONS
###################

def get_collisions():
    """Prints out collisions for merged configuration files."""

    ### Part 1. Use 'grep' command to print out files containing a collision.
    current_directory = os.getcwd()
    stream = os.popen("grep -rl {} -e 'COLLISION'".format(current_directory))
    output = stream.read()
    output_list = output.split('\n')
    collisions = list()
    for file in output_list:
        if file:
            ### Find all stanzas with 'COLLISION' in them and ending with either two newlines or end of file.
            pattern = "(\[.*\][\s\S]+?#\sCOLLISION[\s\S]+?)(?:\n\n|\Z)"
            with open(file, 'r') as f:
                f_text = f.read()
                colls = re.findall(pattern, f_text)
                collisions.append((file,colls))

    ### Print out collisions.
    collisions_text = ""
    for file, collision in collisions:
        collisions_text += "LOCATION: {}".format(file) + '\n'
        collisions_text += '\n\n'.join(collision) + '\n\n'

    collisions_text = collisions_text.strip()


    ### Part 2. Use 'find' command to identify CSV/XML files that have collisions.
    stream = os.popen("find {} -type f -name '*.csv__*' -o -name '*.xml__*'".format(current_directory))
    output = stream.read()
    output_list = output.split('\n')

    other_collisions = defaultdict(list)

    for file in output_list:
        if file:
            file_split = file.split(os.sep)
            users_index = file_split.index('users')
            user = file_split[users_index + 1]
            other_collisions[user].append(file)

    other_collisions_text = ""
    for user in other_collisions:
        other_collisions_text += "USER: " + user + '\n'
        other_collisions_text += '\n'.join(other_collisions[user]) + '\n\n'

    other_collisions_text.strip()


    return collisions_text, other_collisions_text


def convert_text_to_dict(s):
    """
    INPUT: string representing configuration file.
    OUTPUT: dictionary representing stanzas in configuration file.
    """

    d = dict()

    # Splits file into stanzas.
    L = s.split('\n\n')
    for stanza_string in L:

        ### Split on newline ONLY if preceded by character that is NOT a slash.
        # Why? Because all kv-pairs like "search = ..." have a trailing \ at the end. Ignore this to get all of the search.
        pattern = r'(?<=[^\\])\n'
        ss = re.split(pattern, stanza_string)

        stanza_line, rest_of_stanza = ss[0], ss[1:]
        # First line is stanza. Isolate text in stanza.
        stanza_key = stanza_line.lstrip('[').rstrip(']')

        # For each stanza, build dictionary representing k-v pairs.
        d_ko = dict()
        for kv_pair in rest_of_stanza:
            if kv_pair:
                # Runtime version check.
                if RUNTIME_VERSION == 3:
                    k,v = kv_pair.split(' = ', maxsplit=1)
                elif RUNTIME_VERSION == 2:
                    k,v = kv_pair.split(' = ', 1)
                d_ko[k] = v
        d[stanza_key] = d_ko

    return d


def convert_dict_to_text(d):
    """
    INPUT: dictionary representation of configuration file.
    OUTPUT: string repesentation of configuration file.
    """

    # Note that, if value isn't "file2" or "file3", it's from file 1 by default.
    full_string = ""
    for stanza in d:
        stanza_string = '[' + stanza + ']'
        kv_pairs = d[stanza]
        kv_strings = list()
        for k,v in kv_pairs.items():
            # Case 1. List has length 1. No collision. Present value directly.
            if len(v) == 1:
                kv_strings.append(k + ' = ' + v[0])
            # Case 2. List has length > 1. Collision. Resolve tuple.
            else:
                kv_strings.append("# COLLISION")
                kv_strings.append("===========")
                for value in v:
                    if isinstance(value, str):
                        kv_strings.append(k + ' = ' + value)
                    elif isinstance(value, tuple):
                        true_value, location = value
                        kv_strings.append(k + ' = ' + true_value + ' #' + location)
                kv_strings.append("===========")
        full_string += stanza_string + '\n' + '\n'.join(kv_strings) + '\n\n'

    full_string = full_string.rstrip('\n')
    return full_string


################
# CLI INVOCATION
################

if __name__ == '__main__':

    global MAP_USERS
    if sys.argv[-1] == "--map-users":
        file_parameters = sys.argv[1:-1]
        MAP_USERS = True
    else:
        file_parameters = sys.argv[1:]
        MAP_USERS = False

    merge_all(*file_parameters)
