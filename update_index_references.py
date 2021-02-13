#!/usr/bin/python

"""
Usage:

Stage 1 RUN:     <script> -target T -instance I -map M --stage-1 --disable-dry-run
Stage 1 CONFIRM: <script> -target T -instance I -map M --stage-1 --accept-changes
Stage 2 RUN:     <script> -target T -instance I -map M --stage-2 --disable-dry-run
Stage 2 CONFIRM: <script> -target T -instance I -map M --stage-2 --accept-changes
Stage 3: manual review.

============================================================

Description:

1-1 mapping is simple.
1-many mappings require manual review for inputs/transforms.

Files that are reviewed for 1-1 mapping.

inputs.conf
    - http_input app has 'indexes' key.
    - alert_logevent app has 'param.index = main' key.
transforms.conf
savedsearches.conf
macros.conf
history (CSV files)
dashboards (XML files)

Files that are not reviewed for 1-MANY mapping.

inputs.conf
transforms.conf

Files that are not reviewed at all.

indexes.conf
    vix.output.buckets.from.indexes = <comma separated list of splunk indexes>
metric_alerts.conf
    metric_indexes = <metric index name>
metric_rollups.conf
    rollup.<summary number>.rollupIndex = <string Index name>
wmi.conf
    index = <string>
"""


########
# IMPORTS
#########

import sys
import os
import logging
import socket
import shutil
import csv
import re
import argparse
import functools
import collections
import string


##################
# GLOBAL VARIABLES
##################

global TARGET_DIRECTORY
global INDEX_MAP
global DRY_RUN
global INSTANCE
global STAGE_1
global STAGE_2
global MANAGED_DIRECTORY

global INITIAL_WORKING_DIRECTORY
INITIAL_WORKING_DIRECTORY = os.getcwd()

global BACKUP_FILE_LOG
BACKUP_FILE_LOG = os.path.join(INITIAL_WORKING_DIRECTORY, "backup_file_log.txt")

global MANUAL_CHANGES_LOG
MANUAL_CHANGES_LOG = os.path.join(INITIAL_WORKING_DIRECTORY, "manual_changes_log.txt")

global MANUAL_CHANGES_DICT
MANUAL_CHANGES_DICT = collections.defaultdict(list)

global HOSTNAME
HOSTNAME = socket.gethostname()


#############################
# WRAPPER/DECORATOR FUNCTIONS
############################

def check_dry(func):
    """
    Wrapper function for functions that would perform write-level actions.
    Not used for context managers.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if DRY_RUN:
            logging.debug("DRY RUN executed for function {0} with the following arguments: {1}".format(func.__name__, args))
        else:
            logging.debug("DRY_RUN = False. Making write-level changes with args {0}.".format(*args))
            func(*args, **kwargs)
    return wrapper


def log(func):
    """
    Sets up logging functionality.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Set up logging.
        filename = "{0}__update_index_references.log".format(HOSTNAME)
        log_path = os.path.join(INITIAL_WORKING_DIRECTORY, filename)
        format = "%(asctime)s - %(levelname)s:  %(message)s"
        logging.basicConfig(filename=log_path,
                            filemode='a',
                            format=format,
                            datefmt='%m/%d/%Y %I:%M:%S %p',
                            level=logging.DEBUG)
        value = func(*args, **kwargs)
        return value
    return wrapper


def debug(func):
    """
    Print the function signature (name and arguments).
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        args_repr = [repr(a) for a in args]

        kwargs_repr = list()
        for k,v in kwargs.items():
            kwargs_repr.append("{0}={1}".format(k,v))
            if isinstance(v, dict):
                kwargs_repr.extend("{0}={1}".format(v_k, v_v) for v_k, v_v in v.items())

        args_signature = "\n".join(args_repr)
        kwargs_signature = "\n".join(kwargs_repr)

        debug_string = "Calling function {0} with the following arguments:\n" \
                       + "=== ARGS ===\n{1}\n=============="*bool(args_signature) \
                       + "=== KWARGS ===\n{2}\n=============="*bool(kwargs_signature)

        if args_signature and kwargs_signature:
            debug_string = debug_string.format(func.__name__, args_signature, kwargs_signature)
        elif args_signature:
            debug_string = debug_string.format(func.__name__, args_signature)
        elif kwargs_signature:
            debug_string = debug_string.format(func.__name__, kwargs_signature)
        else:
            debug_string = debug_string.format(func.__name__)

        logging.debug(debug_string)
        value = func(*args, **kwargs)
        if value:
            logging.debug("{0} returned {1}".format(func.__name__, value))
        return value
    return wrapper


def get_function_name():
    """
    Get name of function this is called from.
    """

    return sys._getframe(1).f_code.co_name


###############
# MAIN FUNCTION
###############

@log
@debug
def update_references():

    # Set up logging.
    t = string.Template("$function: $message")
    log_format = t.safe_substitute(function=f_name)
    #f_name = get_function_name()
    #log_format = f_name + ": " + "{0}"

    # Get mapping from <old_index> to <new_indexes>.
    d_map = get_index_map(INDEX_MAP)

    # Get directories appropriate to the instance.
    instance_dirs = get_dirs(INSTANCE)

    log_text = "Created list of directories appropriate for the {0} instance: {1}".format(INSTANCE, instance_dirs)
    # logging.debug(log_format.format(log_text))
    logging.debug(log_format.substitute(message=log_text))

    for dir in instance_dirs:
        for root, _, files in os.walk(dir):
            # Exclude lookups and anything in a default directory.
            if not ('lookups' in root or 'default' in root):
                for file in files:

                    # Exclude files without the right extension.
                    # This provides the filtering necessary to quickly get the text of the files we care about.
                    if not (file.endswith(('inputs.conf', 'transforms.conf', 'macros.conf', 'savedsearches.conf', \
                                            'indexes.conf', 'wmi.conf', 'metric_alerts.conf', 'metric_rollups.conf')) \
                            or (file.endswith('xml') and 'views' in root) \
                            or (file.endswith('xml') and 'panels' in root) \
                            or (file.endswith('.csv') and 'history' in root)):
                        continue

                    file = os.path.join(root, file)

                    # Reads file for processing.
                    with open(file, 'r') as f:
                        f_text = f.read()

                    for old_index, new_indexes in d_map.items():

                        is_single_map = len(new_indexes) == 1

                        # CASE 1: 1-1 map.
                        if is_single_map:

                            new_index = new_indexes[0]

                            # CASE 1A: SEARCHES
                            if STAGE_1 and \
                               (file.endswith(('macros.conf', 'savedsearches.conf')) or \
                               file.endswith('.xml') and 'views' in root or \
                               file.endswith('.xml') and 'panels' in root or \
                               file.endswith('.csv') and 'history' in root):

                                logging.info(log_format.format("FOUND FILE: {0}".format(file)))

                                # Checks for case where IN operator is used.
                                # Example: "index IN (main,os,netops,hadoop)"
                                pattern_IN = r'index\s*IN.*?{0}\b'.format(old_index)
                                if re.search(pattern_IN, f_text, flags=re.IGNORECASE):
                                    logging.warning(log_format.format("FOUND MATCH FOR PATTERN {0} IN TEXT {1}".format(pattern_IN, f_text)))
                                    check_dry(backup_file)(file)
                                    for match in re.finditer(pattern_IN, f_text, flags=re.IGNORECASE):
                                        new_pattern = match.expand('\g<0>') + "," + new_index
                                        f_text = re.sub(pattern_IN, new_pattern, f_text, flags=re.IGNORECASE)

                                # Second possibility of IN operator being used.
                                # Example: "IN(index,main,os,netops,hadoop)"
                                pattern_IN_2 = r'IN\(index,.*{0}\b'.format(old_index)
                                if re.search(pattern_IN_2, f_text, flags=re.IGNORECASE):
                                    logging.warning(log_format.format("FOUND MATCH FOR PATTERN {0} IN TEXT {1}".format(pattern_IN_2, f_text)))
                                    check_dry(backup_file)(file)
                                    for match in re.finditer(pattern_IN_2, f_text, flags=re.IGNORECASE):
                                        new_pattern = match.expand('\g<0>') + "," + new_index
                                        f_text = re.sub(pattern_IN_2, new_pattern, f_text, flags=re.IGNORECASE)


                                # Checks for case where wildcard is used.
                                # Manually reviewed.
                                pattern_wildcard = r'index\s*=\s*"*{0}\*'.format(old_index)
                                if re.search(pattern_wildcard, f_text, flags=re.IGNORECASE):
                                    logging.warning(log_format.format("FOUND WILDCARD. REVIEW MANUALLY."))
                                    MANUAL_CHANGES_DICT[file].append((old_index, "Wildcard found."))

                                # Checks for all permutations of "index = <index>", including those in dashboards.
                                pattern_index = re.compile(r"""
                                                            index
                                                            (?:\s|%20)*=(?:\s|%20)*    # separates key from value
                                                            (?:
                                                                  {index}\b
                                                                | "{index}\b"
                                                                | ""{index}\b""
                                                                | %22{index}\b%22      # accounts for URL-encoded double quote
                                                            )
                                                            (?!\*)                     # ignore pattern if index has wildcard
                                                            """.format(index=old_index), re.VERBOSE)
                                # pattern_index = r'index(?:\s|%20)*=(?:\s|%20)*(?:{index}\b|"{index}\b"|""{index}\b""|%22{index}\b%22)(?!\*)'.format(index=old_index)
                                if re.search(pattern_index, f_text, flags=re.IGNORECASE):
                                    logging.warning(log_format.format("FOUND MATCH FOR PATTERN {0} IN TEXT {1}".format(pattern_index, f_text)))
                                    check_dry(backup_file)(file)
                                    new_pattern = "(index={0} OR index={1})".format(old_index, new_index)
                                    f_text = re.sub(pattern_index, new_pattern, f_text, flags=re.IGNORECASE)

                                # Fixes up the URL-encoded section of dashboards and replaces spaces with %20.
                                # This replacement is necessary for URL-encoded sections.
                                pattern_target = r'target=.*?index={}.*?</link>'.format(old_index)
                                if re.search(pattern_target, f_text, flags=re.IGNORECASE):
                                    logging.warning(log_format.format("FOUND MATCH FOR PATTERN {0} IN TEXT {1}".format(pattern_target, f_text)))
                                    check_dry(backup_file)(file)
                                    for match in re.finditer(pattern_target, f_text, flags=re.IGNORECASE):
                                        # Replace spaces with %20, the HTML formatted value for a space.
                                        new_pattern = match.expand('\g<0>').replace(' ', '%20')
                                        f_text = re.sub(pattern_target, new_pattern, f_text, flags=re.IGNORECASE)


                            # CASE 1B: INDEXES
                            if STAGE_1 and file.endswith('indexes.conf'):
                                pass

                            # CASE 1C: WMI/METRICS
                            if STAGE_1 and (file.endswith('wmi.conf') or \
                                 file.endswith('metric_alerts.conf') or \
                                 file.endswith('metric_rollups.conf')):

                                # This is where we CHECK that the search found something before we log it.

                                logging.info(log_format.format("FOUND FILE: {0}".format(file)))
                                logging.debug(log_format.format("PERFORM MANUAL REVIEW FOR MISC."))
                                MANUAL_CHANGES_DICT[file].append((old_index, "Miscellaneous file found."))

                            # CASE 1D: INPUTS
                            if STAGE_2 and file.endswith('inputs.conf'):

                                logging.info(log_format.format("FOUND FILE: {0}".format(file)))

                                # Standard check.
                                # Example: "index = main"
                                pattern_base = r'index\s*=\s*{0}\b'.format(old_index)
                                if re.search(pattern_base, f_text, flags=re.IGNORECASE):
                                    logging.warning(log_format.format("FOUND MATCH FOR PATTERN {0} IN TEXT {1}".format(pattern_base, f_text)))
                                    check_dry(backup_file)(file)
                                    new_pattern = "index = {0}".format(new_index)
                                    f_text = re.sub(pattern_base, new_pattern, f_text, flags=re.IGNORECASE)


                                # Checks for comma-separated indexes, as in http_inputs.
                                # Example: "indexes = index1,index2,...,<old_index>,indexn,..."
                                pattern_indexes = r'((?P<prefix>indexes\s*=\s*[\w,]*?){0})\b'.format(old_index)
                                if re.search(pattern_indexes, f_text, flags=re.IGNORECASE):
                                    logging.warning(log_format.format("FOUND MATCH FOR PATTERN {0} IN TEXT {1}".format(pattern_indexes, f_text)))
                                    check_dry(backup_file)(file)
                                    for match in re.finditer(pattern_indexes, f_text, flags=re.IGNORECASE):
                                        new_pattern = '\g<prefix>' + new_index
                                        f_text = re.sub(match, new_pattern, f_text, flags=re.IGNORECASE)


                            # CASE 1E: TRANSFORMS
                            if STAGE_2 and file.endswith('transforms.conf'):

                                logging.info(log_format.format("FOUND FILE: {0}".format(file)))

                                # Standard check for transforms.
                                # Example: "FORMAT = new_index"
                                pattern_format = r'FORMAT\s*=\s*{0}\b'.format(old_index)
                                if re.search(pattern_format, f_text, flags=re.IGNORECASE):
                                    logging.warning(log_format.format("FOUND MATCH FOR PATTERN {0} IN TEXT {1}".format(pattern_format, f_text)))
                                    check_dry(backup_file)(file)
                                    new_pattern = "FORMAT = {0}".format(new_index)
                                    f_text = re.sub(pattern_format, new_pattern, f_text, flags=re.IGNORECASE)


                        # CASE 2: 1-MANY map.
                        else:

                            # CASE 2A: SEARCHES
                            if STAGE_1 and \
                               (file.endswith(('macros.conf', 'savedsearches.conf')) or \
                               file.endswith('.xml') and 'views' in root or \
                               file.endswith('.xml') and 'panels' in root or \
                               file.endswith('.csv') and 'history' in root):

                                logging.info(log_format.format("FOUND FILE: {0}".format(file)))

                                # Checks for case where IN operator is used.
                                # Example: "index IN (main,os,netops,hadoop)"
                                pattern_IN = r'index\s*IN.*?{0}\b'.format(old_index)
                                if re.search(pattern_IN, f_text, flags=re.IGNORECASE):
                                    logging.warning(log_format.format("FOUND MATCH FOR PATTERN {0} IN TEXT {1}".format(pattern_IN, f_text)))
                                    check_dry(backup_file)(file)
                                    for match in re.finditer(pattern_IN, f_text, flags=re.IGNORECASE):
                                        new_pattern = match.expand('\g<0>') + "," + ",".join(new_indexes)
                                        f_text = re.sub(pattern_IN, new_pattern, f_text, flags=re.IGNORECASE)

                                # Second possibility of IN operator being used.
                                # Example: "IN(index,main,os,netops,hadoop)"
                                pattern_IN_2 = r'IN\(index,.*{0}\b'.format(old_index)
                                if re.search(pattern_IN_2, f_text, flags=re.IGNORECASE):
                                    logging.warning(log_format.format("FOUND MATCH FOR PATTERN {0} IN TEXT {1}".format(pattern_IN_2, f_text)))
                                    check_dry(backup_file)(file)
                                    for match in re.finditer(pattern_IN_2, f_text, flags=re.IGNORECASE):
                                        new_pattern = match.expand('\g<0>') + "," + ','.join(new_indexes)
                                        f_text = re.sub(pattern_IN_2, new_pattern, f_text, flags=re.IGNORECASE)

                                # Checks for case where wildcard is used. This must be manually reviewed.
                                pattern_wildcard = r'index\s*=\s*"*{0}\*'.format(old_index)
                                if re.search(pattern_wildcard, f_text, re.IGNORECASE):
                                    logging.warning(log_format.format("FOUND WILDCARD. REVIEW MANUALLY."))
                                    MANUAL_CHANGES_DICT[file].append((old_index, "Wildcard found."))

                                # Checks for all permutations of "index = <index>", including those in dashboards.
                                pattern_index = re.compile(r"""
                                                            index
                                                            (?:\s|%20)*=(?:\s|%20)*    # separates key from value
                                                            (?:
                                                                  {index}\b
                                                                | "{index}\b"
                                                                | ""{index}\b""
                                                                | %22{index}\b%22      # accounts for URL-encoded double quote
                                                            )
                                                            (?!\*)                     # ignore pattern if index has wildcard
                                                            """.format(index=old_index), re.VERBOSE)
                                # pattern_index = r'index(?:\s|%20)*=(?:\s|%20)*(?:{index}\b|"{index}\b"|""{index}\b""|%22{index}\b%22)(?!\*)'.format(index=old_index)
                                if re.search(pattern_index, f_text, flags=re.IGNORECASE):
                                    logging.warning(log_format.format("FOUND MATCH FOR PATTERN {0} IN TEXT {1}".format(pattern_index, f_text)))
                                    check_dry(backup_file)(file)
                                    new_pattern = "(" \
                                                 + "index={0}".format(old_index) \
                                                 + " OR index=" \
                                                 + " OR index=".join(new_indexes) \
                                                 + ")"

                                    f_text = re.sub(pattern_index, new_pattern, f_text, flags=re.IGNORECASE)

                                # Fixes up the URL-encoded section of dashboards and replaces spaces with %20.
                                # This replacement is necessary for URL-encoded sections.
                                pattern_target = r'target=.*?index={}.*?</link>'.format(old_index)
                                if re.search(pattern_target, f_text, flags=re.IGNORECASE):
                                    logging.warning(log_format.format("FOUND MATCH FOR PATTERN {0} IN TEXT {1}".format(pattern_target, f_text)))
                                    check_dry(backup_file)(file)
                                    for match in re.finditer(pattern_target, f_text, flags=re.IGNORECASE):
                                        # Replace spaces with %20, the HTML formatted value for a space.
                                        new_pattern = match.expand('\g<0>').replace(' ', '%20')
                                        f_text = re.sub(pattern_target, new_pattern, f_text, flags=re.IGNORECASE)

                            # CASE 2B: INDEXES
                            if STAGE_1 and file.endswith('indexes.conf'):
                                pass

                            # CASE 2C: WMI/METRICS
                            if STAGE_1 and (file.endswith('wmi.conf') or \
                               file.endswith('metric_alerts.conf') or \
                               file.endswith('metric_rollups.conf')):
                                # This is where we CHECK that the search found something before we log it.
                                logging.info(log_format.format("FOUND FILE: {0}".format(file)))
                                logging.debug(log_format.format("PERFORM MANUAL REVIEW FOR MISC."))
                                MANUAL_CHANGES_DICT[file].append((old_index, "Miscellaneous file found."))
                                pass

                            # CASE 2D: INPUTS
                            if STAGE_2 and file.endswith('inputs.conf'):

                                pattern = r'index\s*=\s*{0}\b'.format(old_index)

                                if re.search(pattern, f_text, flags=re.IGNORECASE):
                                    logging.info(log_format.format("FOUND FILE: {0}".format(file)))
                                    logging.debug(log_format.format("PERFORM MANUAL REVIEW FOR INPUTS."))
                                    MANUAL_CHANGES_DICT[file].append((old_index, "1-MANY input found."))
                                    pass

                            # CASE 2E: TRANSFORMS
                            if STAGE_2 and file.endswith('transforms.conf'):

                                pattern = r'FORMAT\s*=\s*{0}\b'.format(old_index)
                                if re.search(pattern, f_text, flags=re.IGNORECASE):
                                    logging.info(log_format.format("FOUND FILE: {0}".format(file)))
                                    logging.debug(log_format.format("PERFORM MANUAL REVIEW FOR TRANSFORMS."))
                                    MANUAL_CHANGES_DICT[file].append((old_index, "1-MANY transform found."))
                                    pass



                    # After all changes to f_text are made, append to file.
                    if not DRY_RUN:
                        with open(file, 'a') as f:
                            f.write(f_text)


    # After all manual changed have been identified, record in txt file.
    if MANUAL_CHANGES_DICT:
        with open(MANUAL_CHANGES_LOG, 'a') as f:
            for file, data in MANUAL_CHANGES_DICT.items():
                f.write("==========\nFILE: {0}\n==========\n".format(file))
                for index, description in data:
                    f.write("INDEX: {0}\n".format(index))
                    f.write("DESCRIPTION: {0}\n\n".format(description))

    # Signifies end of current stage. Useful for following stage.
    # This is problematic because the backup file log is used to read in data...
    # Could create a 'shelve' file for write/read and a 'log' file for append.
    #if not DRY_RUN:
    #    with open(BACKUP_FILE_LOG, 'a') as f:
    #        stage_text = "END OF " + "STAGE 1\n"*STAGE_1 + "STAGE 2\n"*STAGE_2
    #        f.write("===============\n")
    #        f.write(stage_text)
    #        f.write("===============")
    #        if STAGE_1:
    #            f.write("\n\n")


###################
# UTILITY FUNCTIONS
###################


@log
@debug
def get_index_map(map_file):
    """
    Takes CSV file and converts it to a dictionary for use in main function.
    """

    f_name = get_function_name()
    log_format = "{0}: {1}".format(f_name)
    log_format = f_name + ": " + "{0}"

    logging.debug(log_format.format("Mapping old index to new indexes."))

    # Create dictionary that maps old index to new indexes.
    d_indexes = dict()
    with open(map_file, 'r') as f:
        reader = csv.reader(f, delimiter=',')
        for row in reader:
            if row:
                # This unpacks the remaining new indexes in that row into a list.
                # new_indexes is always a list.
                old_index, new_indexes = row[0], row[1:]
                d_indexes[old_index] = new_indexes

    logging.debug(log_format.format("Mapping complete. Returning dictionary."))

    return d_indexes


@log
@debug
def get_dirs(instance):
    """
    Each instance has a set of directories that should be checked.
    Some directories won't be checked if the DS already deploys to those directories.
    """

    # check on all.
    dir_system = os.path.join(TARGET_DIRECTORY, 'etc/system')
    dir_disabled_apps = os.path.join(TARGET_DIRECTORY, 'etc/disabled-apps')
    dir_users = os.path.join(TARGET_DIRECTORY, 'etc/users')

    # check on DS.
    dir_deployment_apps = os.path.join(TARGET_DIRECTORY, 'etc/deployment-apps')

    # Check on CM unless managed.
    dir_master_apps = os.path.join(TARGET_DIRECTORY, 'etc/master-apps')

    # Check on Deployer unless managed.
    dir_shcluster_apps = os.path.join(TARGET_DIRECTORY, 'etc/shcluster/apps')

    # Check on DS.
    # Check on CM only if repositoryLocation = /master-apps.
    # Check on Deployer only if repositoryLocation = /shcluster/apps.
    # Check on SH/IDX/HF if not managed.
    dir_apps = os.path.join(TARGET_DIRECTORY, 'etc/apps')

    dirs = list()
    dirs_all = [dir_system, dir_disabled_apps, dir_users]

    if instance == 'DS':
        dirs = dirs_all + [dir_deployment_apps, dir_apps]
    if instance == 'CM':
        if not MANAGED_DIRECTORY:
            dirs = dirs_all + [dir_apps, dir_master_apps]
        elif MANAGED_DIRECTORY == 'etc/apps':
            dirs = dirs_all + [dir_master_apps]
        elif MANAGED_DIRECTORY == 'etc/master-apps':
            dirs = dirs_all + [dir_apps]
    if instance in ['SH', 'IDX', 'HF']:
        if not MANAGED_DIRECTORY:
            dirs = dirs_all + [dir_apps]
        elif MANAGED_DIRECTORY == 'etc/apps':
            dirs = dirs_all
    if instance == 'DEPLOYER':
        if not MANAGED_DIRECTORY:
            dirs = dirs_all + [dir_apps, dir_shcluster_apps]
        elif MANAGED_DIRECTORY == 'etc/apps':
            dirs = dirs_all + [dir_shcluster_apps]
        elif MANAGED_DIRECTORY == 'etc/shcluster/apps':
            dirs = dirs_all + [dir_apps]
    if instance == 'OTHER':
        if not MANAGED_DIRECTORY:
            dirs = dirs_all + [dir_apps]
        elif MANAGED_DIRECTORY == 'etc/apps':
            dirs = dirs_all

    return dirs


@log
@debug
def backup_file(file):
    """
    Creates copy of file before changes are made to it.
    The bak.script file can be removed or re-instated with the revert_changes() or accept_changes() functions.
    """

    f_name = get_function_name()
    log_format = get_function_name() + ": " + "{0}"

    # Confirms that DRY_RUN = False and confirms that the file has not already been backed up.
    backup_file = file + ".bak.script"

    if os.path.isfile(backup_file):
        logging.debug(log_format.format("File already exists. Not backing up."))
        return

    if not DRY_RUN:

        # Record file in backup_file_log.txt file. This is used for reversion.
        with open(BACKUP_FILE_LOG, 'a') as f:
            f.write('{}\n'.format(file))

        # Make backup.
        try:
            shutil.copy(file, backup_file)
        except FileNotFoundError:
            logging.warning(log_format.format("Backup failed. File does not exist."))
            return
        else:
            logging.debug(log_format.format("Backup successful."))


@log
@debug
def revert_changes():
    """
    Copies bak.script files over changed files. Reverts to original state.
    """

    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"


    # Exit if backup_file_log.txt doesn't exist.
    try:
        with open(BACKUP_FILE_LOG, 'r') as f:
            files_text = f.read()
            files_text_list = files_text.split('\n')
            files = list(filter(None, files_text_list))
    except FileNotFoundError:
        logging.debug(log_format.format("backup_file_log.txt does not exist."))
        return

    issues_found = False

    for file in files:
        
        # Make reversion.
        try:
            backup_file = file + ".bak.script"
            shutil.move(backup_file, file)
        except FileNotFoundError:
            logging.debug(log_format.format("Reversion failed. Backup file not found."))
            issues_found = True
        else:
            logging.debug(log_format.format("Reversion successful."))

    # If no issues were found, removes backup_file_log.txt.
    # Else, identifies remaining bak.script files.
    if not issues_found:
        logging.debug(log_format.format("Now removing file: {0}".format(BACKUP_FILE_LOG)))
        if os.path.isfile(BACKUP_FILE_LOG):
            os.remove(BACKUP_FILE_LOG)
        if os.path.isfile(MANUAL_CHANGES_LOG):
            os.remove(MANUAL_CHANGES_LOG)
    else:
        find_command = "find {0} -type f -name '*bak.script'".format(TARGET_DIRECTORY)
        stream = os.popen(find_command)
        cmd_output = stream.read().split('\n')
        bak_files = list(filter(None, cmd_output))

        logging.error("Failed to revert changes. The following backup files were found: {0}".format(bak_files))


def accept_changes():
    """
    Removes all bak.script files.
    """

    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"

    issues_found = False

    # Reads in files that were changed.
    try:
        with open(BACKUP_FILE_LOG, 'r') as f:
            files_text = f.read()
            files_text_list = files_text.split('\n')
            files = list(filter(None, files_text_list))
    except FileNotFoundError:
        logging.debug(log_format.format("backup_file_log.txt does not exist. Cancelling execution..."))
        return

    # Removes original file since changes have been accepted.
    for file in files:

        try:
            backup_file = file + ".bak.script"
            os.remove(backup_file)
        except FileNotFoundError:
            logging.debug(log_format.format("File deletion failed for {0}.".format(file)))
            issues_found = True
        else:
            logging.debug(log_format.format("File deletion successful."))

    # Remove file if no issues were found.
    if not issues_found:
        logging.debug(log_format.format("Now removing backup file: {0}".format(BACKUP_FILE_LOG)))
        os.remove(BACKUP_FILE_LOG)
    else:
        logging.error("Failed to delete all backup files. Review logs.")


################
# CLI INVOCATION
################

if __name__ == '__main__':

    # Create parser and arguments.
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '-target', action='store', dest='target', required=True, help='Directory to execute script on.')
    parser.add_argument('-m', '-map', action='store', dest='map', required=True, help='The full name of the CSV file that maps the old index to new indexes.')
    parser.add_argument('-i', '-instance', action='store', dest='instance', required=True, choices=['DS', 'CM', 'SH', 'IDX', 'HF', 'DEPLOYER', 'OTHER'], help='The instance the script is running on. Used to select the directories that will be searched.')
    parser.add_argument('--managed-directory', action='store', dest='managed_directory', required=False, choices=['etc/apps', 'etc/master-apps', 'etc/shcluster/apps'], help='If managed, indicate the directory that the DC loads their configurations.')

    mutex_group = parser.add_mutually_exclusive_group(required=True)
    mutex_group.add_argument('--stage-1', action='store_true', help='Runs script on macros/searches/dashboards/history, etc.')
    mutex_group.add_argument('--stage-2', action='store_true', help='Runs script on inputs/transforms.')

    mutex_group_2 = parser.add_mutually_exclusive_group(required=False)
    mutex_group_2.add_argument('--disable-dry-run', action='store_false', dest='dry_run_state', help='Disables the safety feature that prevents the script from making production changes.')
    mutex_group_2.add_argument('--revert-changes', action='store_true', help='Used to remove the backup files if the changes have been accepted.')
    mutex_group_2.add_argument('--accept-changes', action='store_true', help='Used to delete backup files if changes have been accepted.')


    # Access arguments.
    args = parser.parse_args()

    global TARGET_DIRECTORY
    global INSTANCE
    global DRY_RUN
    global INDEX_MAP
    global STAGE_1
    global STAGE_2
    global MANAGED_DIRECTORY

    TARGET_DIRECTORY = args.target
    INSTANCE = args.instance
    DRY_RUN = args.dry_run_state
    INDEX_MAP = args.map
    STAGE_1 = args.stage_1
    STAGE_2 = args.stage_2
    MANAGED_DIRECTORY = args.managed_directory


    # Pre-flight checks.
    splunk_home = os.environ.get('SPLUNK_HOME', '/opt/splunk')

    if not DRY_RUN and TARGET_DIRECTORY == splunk_home:
            input = raw_input("Are you sure you'd like to run the script in production? (Y/N) ")
            input = input.strip().upper()
            if input != 'Y':
                sys.exit("Exited script by user request.")
            else:
                pass

    if not INDEX_MAP.endswith('csv'):
        sys.exit("The file given by the -map parameter should be a CSV file.")

    if os.path.getsize(INDEX_MAP) == 0:
        sys.exit("The file given by the -map parameter is empty.")

    if not os.path.isdir(TARGET_DIRECTORY):
        sys.exit("The directory given by the -target parameter is empty.")

    # Execute functions.
    if args.revert_changes:
        revert_changes()
    elif args.accept_changes:
        accept_changes()
    else:
        update_references()
