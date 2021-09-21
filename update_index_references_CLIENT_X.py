#!/usr/bin/python

"""
Usage:

Stage 1 RUN:     <script> -target T -instance I -map M --stage-1 --disable-dry-run
Stage 1 CONFIRM: <script> -target T -instance I -map M --stage-1 --accept-changes
Stage 2 RUN:     <script> -target T -instance I -map M --stage-2 --disable-dry-run
Stage 2 CONFIRM: <script> -target T -instance I -map M --stage-2 --accept-changes
Stage 3 RUN:     python3 -Wi <script> -target T -instance CAPTAIN -map M --stage-3
    NOTE: -Wi suppresses InsecureRequestWarning and DeprecationWarning.
Stage 4: manual review.

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
import time
import logging
import socket
import shutil
import csv
import re
import argparse
import functools
import collections
import requests
import getpass
import datetime
import itertools
import math

##################
# GLOBAL VARIABLES
##################

global TARGET_DIRECTORY
global INDEX_MAP
global SOURCETYPE_MAP
global DRY_RUN
global INSTANCE
global KO_FILE
global STAGE_1
global STAGE_2
global MANAGED_DIRECTORY
global BASE_URL
global GET_ENDPOINT_SAVED_SEARCHES
global GET_ENDPOINT_EVENTTYPES
global GET_ENDPOINT_TAGS

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

global BASE_URL
# BASE_URL = "https://192.168.0.5:8089"
BASE_URL = "https://192.168.1.242:8089"
# BASE_URL = "https://{}:8089".format(socket.getfqdn(socket.gethostname()))

global GET_ENDPOINT_USERS
GET_ENDPOINT_USERS = "services/authentication/users?count=0"

global GET_ENDPOINT_SAVED_SEARCHES
GET_ENDPOINT_SAVED_SEARCHES = "servicesNS/-/-/saved/searches?count=0"

global GET_ENDPOINT_EVENTTYPES
GET_ENDPOINT_EVENTTYPES = "servicesNS/-/-/saved/eventtypes?count=0"

global GET_ENDPOINT_MACROS
GET_ENDPOINT_MACROS = "servicesNS/-/-/admin/macros?count=0"

global GET_ENDPOINT_VIEWS
GET_ENDPOINT_VIEWS = "servicesNS/-/-/data/ui/views?count=0"


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


def setup_logger(name, log_file, level=logging.INFO):
    """To set up loggers on command."""

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

    handler = logging.FileHandler(log_file)        
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


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

        debug_string = "Calling function {} with the following arguments:\n" \
                       + "=== ARGS ===\n{}\n=============="*bool(args_signature) \
                       + "=== KWARGS ===\n{}\n=============="*bool(kwargs_signature)

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
def update_configuration_files():

    # Set up logging.
    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"

    # Get directories appropriate to the instance.
    instance_dirs = get_dirs(INSTANCE)

    # logging.debug(log_format.format(log_text))
    message = log_format.format("Created list of directories appropriate for the {0} instance: {1}".format(INSTANCE, instance_dirs))
    logging.debug(message)

    for dir in instance_dirs:
        for root, _, files in os.walk(dir):
            # Exclude lookups and anything in a default directory.
            # CLIENT_X: REMOVING 'default' in root to solve custom TA issue. Put back in for future executions.
            if not 'lookups' in root:
                for file in files:

                    # Exclude files without the right extension.
                    # This provides the filtering necessary to quickly get the text of the files we care about.
                    if not (file.endswith(('inputs.conf', 'transforms.conf', 'macros.conf', 'eventtypes.conf', \
                                            'savedsearches.conf', 'indexes.conf', 'wmi.conf', \
                                            'metric_alerts.conf', 'metric_rollups.conf')) \
                            or (file.endswith('xml') and 'views' in root) \
                            or (file.endswith('xml') and 'panels' in root) \
                            or (file.endswith('.csv') and 'history' in root)):
                        continue

                    file = os.path.join(root, file)

                    # Reads file for processing.
                    with open(file, 'r') as f:
                        f_text = f.read()

                    f_text, valid_KO = modify_KO(f_text, file=file, root_node=root)

                    # After all changes to f_text are made, write to file.
                    if not DRY_RUN and valid_KO:
                        with open(file, 'w') as f:
                            f.write(f_text)


    # After all manual changed have been identified, record in manual_changes_log.txt.
    if MANUAL_CHANGES_DICT:
        with open(MANUAL_CHANGES_LOG, 'a') as f:
            for file, data in MANUAL_CHANGES_DICT.items():
                f.write("==========\nFILE/ENDPOINT: {0}\n==========\n".format(file))
                for index, description in data:
                    f.write("INDEX/SOURCETYPE: {0}\n".format(index))
                    f.write("DESCRIPTION: {0}\n\n".format(description))


###################
# UTILITY FUNCTIONS
###################


@log
@debug
def get_index_map(map_file):
    """
    Takes CSV file and converts it to a dictionary for use in main function.
    """

    # Set up logging.
    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"

    logging.debug(log_format.format("Mapping old index to new indexes."))

    # Create dictionary that maps old index to new indexes.
    d_indexes = dict()
    with open(map_file, 'r') as f:
        reader = csv.reader(f, delimiter=',')
        for row in reader:
            if row:
                true_row = [element for element in row if element]
                # This unpacks the remaining new indexes in that row into a list.
                # new_indexes is always a list.
                old_index, new_indexes = true_row[0], true_row[1:]
                d_indexes[old_index] = new_indexes

    logging.debug(log_format.format("Mapping complete. Returning dictionary."))

    return d_indexes

@log
@debug
def get_sourcetype_map(map_file):
    """
    Takes CSV file and converts it to a dictionary for use in main function.
    """

    # Set up logging.
    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"

    logging.debug(log_format.format("Mapping old sourcetype to new sourcetypes."))

    # Create dictionary that maps old sourcetype to new sourcetypes.
    d_sourcetypes = dict()
    with open(map_file, 'r') as f:
        reader = csv.reader(f, delimiter=',')
        for row in reader:
            if row:
                true_row = [element for element in row if element]
                old_sourcetype, new_sourcetypes = true_row[0], true_row[1:]
                d_sourcetypes[old_sourcetype] = new_sourcetypes

    logging.debug(log_format.format("Mapping complete. Returning dictionary."))

    return d_sourcetypes


@log
@debug
def get_dirs(instance):
    """
    Each instance has a set of directories that should be checked.
    Some directories won't be checked if the DS already deploys to those directories.
    """

    # Set up logging.
    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"

    logging.debug(log_format.format("Identifying appropriate directories for the instance."))

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


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i+n]


@log
@debug
def backup_file(file):
    """
    Creates copy of file before changes are made to it.
    The bak.script file can be removed or re-instated with the revert_changes() or accept_changes() functions.
    """

    # Set up logging.
    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"

    # Confirms that DRY_RUN = False and confirms that the file has not already been backed up.
    backup_file = file + ".bak.script"

    if os.path.isfile(backup_file):
        logging.warning(log_format.format("File already exists. Not backing up."))
        return

    if not DRY_RUN:

        # Record file in backup_file_log.txt file. This is used for reversion.
        with open(BACKUP_FILE_LOG, 'a') as f:
            f.write('{}\n'.format(file))

        # Make backup.
        try:
            shutil.copy(file, backup_file)
        except OSError:
            logging.error(log_format.format("Backup failed. File does not exist."))
            return
        else:
            logging.debug(log_format.format("Backup successful."))


@log
@debug
def revert_changes():
    """
    Copies bak.script files over changed files. Reverts to original state.
    """

    # Set up logging.
    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"


    # Exit if backup_file_log.txt doesn't exist.
    try:
        with open(BACKUP_FILE_LOG, 'r') as f:
            files_text = f.read()
            files_text_list = files_text.split('\n')
            files = list(filter(None, files_text_list))
    except OSError:
        logging.error(log_format.format("backup_file_log.txt does not exist."))
        return

    issues_found = False

    for file in files:
        
        # Make reversion.
        try:
            backup_file = file + ".bak.script"
            shutil.move(backup_file, file)
        except OSError:
            logging.error(log_format.format("Reversion failed. Backup file not found."))
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

        message = "Failed to revert changes. The following backup files were found: {0}".format(bak_files)
        logging.error(log_format.format(message))


def accept_changes():
    """
    Removes all bak.script files.
    """

    # Set up logging.
    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"

    issues_found = False

    # Reads in files that were changed.
    try:
        with open(BACKUP_FILE_LOG, 'r') as f:
            files_text = f.read()
            files_text_list = files_text.split('\n')
            files = list(filter(None, files_text_list))
    except OSError:
        logging.error(log_format.format("backup_file_log.txt does not exist. Cancelling execution..."))
        return

    # Removes original file since changes have been accepted.
    for file in files:

        try:
            backup_file = file + ".bak.script"
            os.remove(backup_file)
        except OSError:
            logging.error(log_format.format("File deletion failed for {0}.".format(file)))
            issues_found = True
        else:
            logging.debug(log_format.format("File deletion successful."))

    # Remove file if no issues were found.
    if not issues_found:
        logging.debug(log_format.format("Now removing backup file: {0}".format(BACKUP_FILE_LOG)))
        os.remove(BACKUP_FILE_LOG)
    else:
        logging.error(log_format.format("Failed to delete all backup files. Review logs."))


@log
@debug
def modify_KO(original_content, file=None, identifier=None, root_node=None):
    """'original_content' is very general and refers to the file's text OR to the modified search provided via REST."""

    # Set up logging.
    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"

    # Get mapping from <old_index> to <new_indexes>.
    d_map = get_index_map(INDEX_MAP)

    # Get mapping from <old_sourcetype> to <new_sourcetype>.
    d_stmap = get_sourcetype_map(SOURCETYPE_MAP)

    if INSTANCE == "CAPTAIN":
        standard_message = "Found match for pattern: {0} in KO content: {1}"
    elif INSTANCE != "CAPTAIN":
        standard_message = "Found match for pattern: {0} in file: {1}"





    new_indexes = itertools.chain(*d_map.values())

    pattern_match = r"""match\('index',\s*"{}"\)"""
    pattern_IN = r'index\s*IN.*?{0}\b'
    pattern_IN_2 = r'IN\(index,.*{0}\b'
    pattern_wildcard = r'index\s*=\s*"*{0}\*'
    pattern_target = r'target=.*?index={}.*?</link>'
    pattern_index = r"""(?<!\|\scollect\s)index(?:\s|%20)*==?(?:\s|%20)*(?:{0}\b|"{0}\b"|""{0}\b""|%22{0}\b%22)(?!\*)"""
    patterns_list = [pattern_match, pattern_IN, pattern_IN_2, pattern_wildcard, pattern_target, pattern_index]

    matched_new_indexes = False
    for index in new_indexes:
        for pattern in patterns_list:
            new_pattern = pattern.format(index)
            if re.search(new_pattern, original_content):
                matched_new_indexes = True
                MANUAL_CHANGES_DICT[file or identifier].append((index, "New index found in KO."))
                break





    new_sourcetypes = itertools.chain(*d_stmap.values())

    pattern_match_st = r"""match\('sourcetype',\s*"{}"\)"""
    pattern_IN_st = r'sourcetype\s*IN.*?{0}\b'
    pattern_IN_2_st = r'IN\(sourcetype,.*{0}\b'
    pattern_target_st = r'target=.*?sourcetype={}.*?</link>'
    pattern_index_st = r"""(?<!\|\scollect\s)sourcetype(?:\s|%20)*==?(?:\s|%20)*(?:{0}\b|"{0}\b"|""{0}\b""|%22{0}\b%22)(?!\*)"""
    patterns_list_st = [pattern_match_st, pattern_IN_st, pattern_IN_2_st, pattern_target_st, pattern_index_st]

    matched_new_sourcetypes = False
    for sourcetype in new_sourcetypes:
        for pattern in patterns_list_st:
            new_pattern = pattern.format(sourcetype)
            if re.search(new_pattern, original_content):
                matched_new_sourcetypes = True
                MANUAL_CHANGES_DICT[file or identifier].append((sourcetype, "New sourcetype found in KO."))
                break

    matched_syslog2 = False
    for sourcetype in new_sourcetypes:
        for pattern in patterns_list_syslog2:
            if re.search(pattern, original_content):
                matched_syslog2 = True
                MANUAL_CHANGES_DICT[file or identifier].append((sourcetype, "syslog2 sourcetype found in KO."))
                break


    # Checks for case where *_sec is used.
    matched_star_sec = False
    pattern_sec = r'index\s*=\s*"*\*_sec"*'
    if re.search(pattern_sec, original_content, flags=re.IGNORECASE):
        matched_star_sec = True
        message = log_format.format(standard_message.format(pattern_sec, file or original_content))
        logging.info(message)
        MANUAL_CHANGES_DICT[file or identifier].append(("*_sec", "Wildcard reference found."))



    # Checks for case where util_* is used.
    matched_util_star = False
    pattern_util = r'index\s*=\s*"*util_\*"*'
    if re.search(pattern_util, original_content, flags=re.IGNORECASE):
        matched_util_star = True
        message = log_format.format(standard_message.format(pattern_util, file or original_content))
        logging.info(message)
        MANUAL_CHANGES_DICT[file or identifier].append(("util_*", "Wildcard reference found."))


    if not any([matched_new_indexes, matched_new_sourcetypes, matched_syslog2, matched_star_sec, matched_util_star]):

        # Now we know that the file hasn't been modified with new info before, including:
        # no new indexes;
        # no new sourcetypes;
        # no references to util_*;
        # no references to *_sec
        modified_content = original_content

        # CASE 1: SEARCHES
        if STAGE_1 and (file is None or \
            (file.endswith(('macros.conf', 'eventtypes.conf', 'savedsearches.conf')) or \
                file.endswith('.xml') and 'views' in root_node or \
                file.endswith('.xml') and 'panels' in root_node or \
                file.endswith('.csv') and 'history' in root_node)):


            for old_sourcetype, new_sourcetypes in d_stmap.items():

                # Only makes changes for 1-1 sourcetype changes.
                if len(new_sourcetypes) == 1:

                    new_sourcetype = new_sourcetypes[0]

                    # Checks for case where match('sourcetype', "<sourcetype>") is used.
                    pattern_match = r"""match\('sourcetype',\s*"{}"\)""".format(old_sourcetype)
                    if re.search(pattern_match, modified_content, flags=re.IGNORECASE):
                        message = log_format.format(standard_message.format(pattern_match, file or original_content))
                        logging.info(message)
                        if file is not None:
                            check_dry(backup_file)(file)
                        else:
                            for match in re.finditer(pattern_match, modified_content, flags=re.IGNORECASE):
                                new_pattern = "(" + match.expand('\g<0>') + """ OR match('sourcetype',"{}")""".format(new_sourcetype) + ")"
                                modified_content = re.sub(pattern_match, new_pattern, modified_content, flags=re.IGNORECASE)



                    # Checks for case where IN operator is used.
                    # Example: "sourcetype IN (st1,st2,...)"
                    pattern_IN = r'sourcetype\s*IN.*?{0}\b'.format(old_sourcetype)
                    if re.search(pattern_IN, modified_content, flags=re.IGNORECASE):
                        message = log_format.format(standard_message.format(pattern_IN, file or original_content))
                        logging.info(message)
                        if file is not None:
                            check_dry(backup_file)(file)
                        else:
                            for match in re.finditer(pattern_IN, modified_content, flags=re.IGNORECASE):
                                new_pattern = match.expand('\g<0>') + ",{},".format(new_sourcetype)
                                modified_content = re.sub(pattern_IN, new_pattern, modified_content, flags=re.IGNORECASE)

                    # Second possibility of IN operator being used.
                    # Example: "IN(sourcetype,st1,st2,...)"
                    pattern_IN_2 = r'IN\(sourcetype,.*{0}\b'.format(old_sourcetype)
                    if re.search(pattern_IN_2, modified_content, flags=re.IGNORECASE):
                        message = log_format.format(standard_message.format(pattern_IN_2, file or original_content))
                        logging.info(message)
                        if file is not None:
                            check_dry(backup_file)(file)
                        else:
                            for match in re.finditer(pattern_IN_2, modified_content, flags=re.IGNORECASE):
                                new_pattern = match.expand('\g<0>') + ",{},".format(new_sourcetype)
                                modified_content = re.sub(pattern_IN_2, new_pattern, modified_content, flags=re.IGNORECASE)


                    # Checks for all permutations of "sourcetype = <old_sourcetype>", including those in dashboards.
                    # ==? accounts for places where they use == instead of =, such as in case() statements.
                    pattern_sourcetype = re.compile(r"""
                                                sourcetype
                                                (?:\s|%20)*==?(?:\s|%20)*    # separates key from value
                                                (?:
                                                      {sourcetype}(?:\s)
                                                    | "{sourcetype}"(?:\s)
                                                    | ""{sourcetype}""(?:\s)
                                                    | %22{sourcetype}\b%22      # accounts for URL-encoded double quote
                                                )
                                                (?!\*)                     # ignore pattern if index has wildcard
                                                """.format(sourcetype=old_sourcetype), re.VERBOSE | re.IGNORECASE)
                    if re.search(pattern_sourcetype, modified_content):
                        message = log_format.format(standard_message.format(pattern_sourcetype, file or original_content))
                        logging.info(message)
                        if file is not None:
                            check_dry(backup_file)(file)
                        else:
                            new_pattern = '''(sourcetype="{}" OR sourcetype="{}") '''.format(old_sourcetype, new_sourcetype)
                            modified_content = re.sub(pattern_sourcetype, new_pattern, modified_content)

                    # Fixes up the URL-encoded section of dashboards and replaces spaces with %20.
                    # This replacement is necessary for URL-encoded sections.
                    pattern_target = r'target=.*?sourcetype={}.*?</link>'.format(old_sourcetype)
                    if re.search(pattern_target, modified_content, flags=re.IGNORECASE):
                        message = log_format.format(standard_message.format(pattern_target, file or original_content))
                        logging.info(message)
                        if file is not None:
                            check_dry(backup_file)(file)
                        else:
                            for match in re.finditer(pattern_target, modified_content, flags=re.IGNORECASE):
                                # Replace spaces with %20, the HTML formatted value for a space.
                                new_pattern = match.expand('\g<0>').replace(' ', '%20')
                                modified_content = re.sub(pattern_target, new_pattern, modified_content, flags=re.IGNORECASE)




            for old_index, new_indexes in d_map.items():

                is_single_map = len(list(new_indexes)) == 1

                # Checks for case where match('index', "<index>") is used.
                pattern_match = r"""match\('index',\s*"{}"\)""".format(old_index)
                if re.search(pattern_match, modified_content, flags=re.IGNORECASE):
                    message = log_format.format(standard_message.format(pattern_match, file or original_content))
                    logging.info(message)
                    if file is not None:
                        check_dry(backup_file)(file)
                    for match in re.finditer(pattern_match, modified_content, flags=re.IGNORECASE):
                        new_pattern = "(" + match.expand('\g<0>') + " " + " ".join("""OR match('index',"{}")""".format(index) for index in new_indexes) + ")"
                        modified_content = re.sub(pattern_match, new_pattern, modified_content, flags=re.IGNORECASE)



                # Checks for case where IN operator is used.
                # Example: "index IN (main,os,netops,hadoop)"
                pattern_IN = r'index\s*IN.*?{0}\b'.format(old_index)
                if re.search(pattern_IN, modified_content, flags=re.IGNORECASE):
                    message = log_format.format(standard_message.format(pattern_IN, file or original_content))
                    logging.info(message)
                    if file is not None:
                        check_dry(backup_file)(file)
                    for match in re.finditer(pattern_IN, modified_content, flags=re.IGNORECASE):
                        new_pattern = match.expand('\g<0>') + "," + ",".join(new_indexes) + ","
                        modified_content = re.sub(pattern_IN, new_pattern, modified_content, flags=re.IGNORECASE)

                # Second possibility of IN operator being used.
                # Example: "IN(index,main,os,netops,hadoop)"
                pattern_IN_2 = r'IN\(index,.*{0}\b'.format(old_index)
                if re.search(pattern_IN_2, modified_content, flags=re.IGNORECASE):
                    message = log_format.format(standard_message.format(pattern_IN_2, file or original_content))
                    logging.info(message)
                    if file is not None:
                        check_dry(backup_file)(file)
                    for match in re.finditer(pattern_IN_2, modified_content, flags=re.IGNORECASE):
                        new_pattern = match.expand('\g<0>') + "," + ','.join(new_indexes)
                        modified_content = re.sub(pattern_IN_2, new_pattern, modified_content, flags=re.IGNORECASE)


                # Checks for case where wildcard is used.
                # Manually reviewed.
                pattern_wildcard = r'index\s*=\s*"*{0}\*'.format(old_index)
                if re.search(pattern_wildcard, modified_content, flags=re.IGNORECASE):
                    message = log_format.format(standard_message.format(pattern_wildcard, file or original_content))
                    logging.warning(message)
                    MANUAL_CHANGES_DICT[file or identifier].append((old_index, "Wildcard found."))

                # Checks for all permutations of "index = <index>", including those in dashboards.
                # ==? accounts for places where they use == instead of =, such as in case() statements.
                # Updated to NOT include "| collect index=<index> sections, hence the negative lookbehind."
                pattern_index = re.compile(r"""
                                            (?<!\|\scollect\s)index
                                            (?:\s|%20)*==?(?:\s|%20)*    # separates key from value
                                            (?:
                                                  {index}\b
                                                | "{index}\b"
                                                | ""{index}\b""
                                                | %22{index}\b%22      # accounts for URL-encoded double quote
                                            )
                                            (?!\*)                     # ignore pattern if index has wildcard
                                            """.format(index=old_index), re.VERBOSE | re.IGNORECASE)
                if re.search(pattern_index, modified_content):
                    message = log_format.format(standard_message.format(pattern_index, file or original_content))
                    logging.info(message)
                    if file is not None:
                        check_dry(backup_file)(file)
                    new_pattern = "(" + '''index="{0}"'''.format(old_index) + " " + " ".join('''OR index="{}"'''.format(index) for index in new_indexes) + ")"
                    modified_content = re.sub(pattern_index, new_pattern, modified_content)

                # Fixes up the URL-encoded section of dashboards and replaces spaces with %20.
                # This replacement is necessary for URL-encoded sections.
                pattern_target = r'target=.*?index={}.*?</link>'.format(old_index)
                if re.search(pattern_target, modified_content, flags=re.IGNORECASE):
                    message = log_format.format(standard_message.format(pattern_target, file or original_content))
                    logging.info(message)
                    if file is not None:
                        check_dry(backup_file)(file)
                    for match in re.finditer(pattern_target, modified_content, flags=re.IGNORECASE):
                        # Replace spaces with %20, the HTML formatted value for a space.
                        new_pattern = match.expand('\g<0>').replace(' ', '%20')
                        modified_content = re.sub(pattern_target, new_pattern, modified_content, flags=re.IGNORECASE)


        # CASE 2: INDEXES
        if STAGE_1 and (file is not None and file.endswith('indexes.conf')):
            pass

        # CASE 3A: WMI
        if STAGE_1 and (file is not None and file.endswith('wmi.conf')):

            is_single_map = len(list(new_indexes)) == 1

            for old_index, new_indexes in d_map.items():

                pattern_base = r'index\s*=\s*{0}\b'.format(old_index)
                if re.search(pattern_base, modified_content, flags=re.IGNORECASE):
                    message = log_format.format(standard_message.format(pattern_base, file or original_content))
                    logging.warning(message)
                    message = log_format.format("Perform manual review.")
                    logging.warning(message)
                    MANUAL_CHANGES_DICT[file or identifier].append((old_index, "Found in wmi.conf."))

        # CASE 3B: METRIC_ALERTS
        if STAGE_1 and (file is not None and file.endswith('metric_alerts.conf')):

            is_single_map = len(list(new_indexes)) == 1

            for old_index, new_indexes in d_map.items():

                pattern_metrics = r'metric_indexes\s*=\s*.*?{0}\b'.format(old_index)
                if re.search(pattern_metrics, modified_content, flags=re.IGNORECASE):
                    message = log_format.format(standard_message.format(pattern_metrics, file or original_content))
                    logging.warning(message)
                    message = log_format.format("Perform manual review.")
                    logging.warning(message)
                    MANUAL_CHANGES_DICT[file or identifier].append((old_index, "Found in metric_alerts.conf."))

        # CASE 3C: METRIC_ROLLUPS
        if STAGE_1 and (file is not None and file.endswith('metric_rollups.conf')):

            is_single_map = len(list(new_indexes)) == 1

            for old_index, new_indexes in d_map.items():

                pattern_rollups = r'rollupIndex\s*=\s*{0}\b'.format(old_index)
                if re.search(pattern_rollups, modified_content, flags=re.IGNORECASE):
                    message = log_format.format(standard_message.format(pattern_rollups, file or original_content))
                    logging.warning(message)
                    message = log_format.format("Perform manual review.")
                    logging.warning(message)
                    MANUAL_CHANGES_DICT[file or identifier].append((old_index, "Found in metric_rollups.conf."))


        # CASE 4: INPUTS
        if STAGE_2 and (file is not None and file.endswith('inputs.conf')):

            is_single_map = len(list(new_indexes)) == 1

            for old_index, new_indexes in d_map.items():

                # Standard check.
                # Example: "index = main"
                pattern_base = r'index\s*=\s*{0}\b'.format(old_index)
                if re.search(pattern_base, modified_content, flags=re.IGNORECASE):
                    message = log_format.format(standard_message.format(pattern_base, file or original_content))
                    logging.info(message)
                    if is_single_map:
                        if file is not None:
                            check_dry(backup_file)(file)
                        new_pattern = "index = {0}".format(new_indexes[0])
                        modified_content = re.sub(pattern_base, new_pattern, modified_content, flags=re.IGNORECASE)
                    else:
                        message = log_format.format("1-MANY map found for inputs.conf.")
                        logging.warning(message)
                        message = log_format.format("Perform manual review.")
                        logging.warning(message)
                        MANUAL_CHANGES_DICT[file or identifier].append((old_index, "1-MANY map for inputs.conf found."))


                # Checks for comma-separated indexes, as in http_inputs.
                # Example: "indexes = index1,index2,...,<old_index>,indexn,..."
                pattern_indexes = r'((?P<prefix>indexes\s*=\s*[\w,]*?){0})\b'.format(old_index)
                if re.search(pattern_indexes, modified_content, flags=re.IGNORECASE):
                    message = log_format.format(standard_message.format(pattern_indexes, file or original_content))
                    logging.info(message)
                    if is_single_map:
                        if file is not None:
                            check_dry(backup_file)(file)
                        for match in re.finditer(pattern_indexes, modified_content, flags=re.IGNORECASE):
                            new_pattern = '\g<prefix>' + new_indexes[0]
                            modified_content = re.sub(match, new_pattern, modified_content, flags=re.IGNORECASE)
                    else:
                        message = log_format.format("1-MANY map found for inputs.conf.")
                        logging.warning(message)
                        message = log_format.format("Perform manual review.")
                        logging.warning(message)
                        MANUAL_CHANGES_DICT[file or identifier].append((old_index, "1-MANY map for inputs.conf found."))


        # CASE 5: TRANSFORMS
        if STAGE_2 and (file is not None and file.endswith('transforms.conf')):

            is_single_map = len(list(new_indexes)) == 1

            for old_index, new_indexes in d_map.items():

                if is_single_map:
                    logging.info(log_format.format("FOUND FILE: {0}".format(file)))

                    # Standard check for transforms.
                    # Example: "FORMAT = new_index"
                    pattern_format = r'FORMAT\s*=\s*{0}\b'.format(old_index)
                    if re.search(pattern_format, modified_content, flags=re.IGNORECASE):
                        message = log_format.format("Found match for pattern: {0} in file: {1}".format(pattern_format, file or original_content))
                        logging.info(message)
                        if is_single_map:
                            if file is not None:
                                check_dry(backup_file)(file)
                            new_pattern = "FORMAT = {0}".format(new_index)
                            modified_content = re.sub(pattern_format, new_pattern, modified_content, flags=re.IGNORECASE)
                        else:
                            message = log_format.format("1-MANY map found for transforms.conf.")
                            logging.warning(message)
                            message = log_format.format("Perform manual review.")
                            logging.warning(message)
                            MANUAL_CHANGES_DICT[file or identifier].append((old_index, "1-MANY map for transforms.conf found."))

        return modified_content, True

    else:

        return original_content, False


@log
@debug
def update_SHC_KOs(ops=False, audit=True, chunk_size=5, sleep_period=300):
    """Assumes 5 KO executions per period and a 5-minute rest period."""

    """
    TESTING:
    #### Create KO for a user (saved search where 'index=DUMMY_INDEX_SHC_TEST').
    #### Create index_map.csv that maps DUMMY_INDEX_SHC_TEST to TEST_SUCCESSFUL. Confirm replication via CLI.
    #### Run script and confirm that authentication works and that the script captures the KO. Confirm replication via CLI.

    *** User-owned knowledge objects are identified as content that does NOT have 'nobody' in the REST endpoint's 'id' field.

    COULD use 'eai:acl.removable=1' k:v pair to identify content that is in the /local folder and NOT in the 'default' folder.
    """

    # Set up logging.
    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"

    # Requests credentials for admin-level user. Password is not persisted.
    username = input('Username: ')
    onetime_password = getpass.getpass(prompt='Password: ')
    auth_payload = (username, onetime_password)

    # INSTANCE = OPS and requires rate-limiting.
    if ops:

        # Obtain KOs as a list. Each KO is itself a list with 2+ elements.
        list_kos = list()
        with open(KO_FILE, 'r') as f:
            reader = csv.reader(f)
            header = next(reader, None)
            for row in reader:
                list_kos.append(row)

        execution_count = math.ceil(len(list_kos)/chunk_size)
        print("This script will be executed at most {} times.".format(execution_count))
        print("This will take roughly {} minutes to run due to rate limiting.".format(execution_count*sleep_period/60))

        # Split KOs into chunks and pause execution after POSTs are executed for that chunk of KOs.
        for subset in chunks(list_kos, chunk_size):
            print("Script is now executing POST calls for KO subset.")
            for ko in subset:
                endpoint, original_search = ko
                modified_search, valid_KO = modify_KO(original_search, identifier=endpoint)

                if modified_search != original_search and valid_KO:

                    if 'data/ui/views' in endpoint:
                        data_payload = {"eai:data": modified_search}
                    else:
                        data_payload = {"search": modified_search}

                    try:
                        if audit:
                            print("=== EXPECTED OUTPUT ===")
                            print(endpoint)
                            print()
                            print()
                            print("=== ORIGINAL SEARCH ===")
                            print(original_search)
                            print()
                            print()
                            print("=== MODIFIED SEARCH ===")
                            print(modified_search)
                            print()
                            print()
                        else:
                            print("Executing REST call to modify KO at endpoint={}.".format(endpoint))
                            r = requests.post(endpoint, verify=False, data=data_payload, auth=auth_payload)
                    except:
                        if r.status_code == 401:
                            message = log_format.format("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
                            logging.error(message)
                            sys.exit("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
                        elif r.status_code == 403:
                            message = log_format.format("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
                            logging.error(message)
                            sys.exit("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
                        elif r.status_code != 200:
                            message = log_format.format("Unknown (error code = {}). Please review.".format(r.status_code))
                            logging.error(message)
                            sys.exit("Unknown (error code = {}). Please review.".format(r.status_code))

                else:
                    print("=== The KO is invalid or modifications were not necessary. ===")
                    print()


            print("Script has finished executing POST calls for KO subset. Now sleeping for {} seconds.".format(sleep_period))
            time.sleep(sleep_period)


    # INSTANCE != OPS and executes normally.
    else:

        if audit:
            ko_list = list()

        # Data sent as XML by default. This changes the output mode to JSON.
        get_json = {'output_mode': 'json'}

        # CASE 1: SAVED SEARCHES
        endpoint_get_saved_searches = os.path.join(BASE_URL, GET_ENDPOINT_SAVED_SEARCHES.format('-'))
        try:
            message = log_format.format("Requesting saved searches.")
            logging.debug(message)
            r=requests.get(endpoint_get_saved_searches, verify=False, data=get_json, auth=auth_payload)
        except:
            message = log_format.format("Failed to obtain saved searches via REST.")
            logging.error(message)
            sys.exit("Failed to obtain saved searches via REST.")
        else:
            if r.status_code == 401:
                message = log_format.format("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
                logging.error(message)
                sys.exit("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
            elif r.status_code == 403:
                message = log_format.format("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
                logging.error(message)
                sys.exit("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
            elif r.status_code != 200:
                message = log_format.format("Unknown (error code = {}). Please review.".format(r.status_code))
                logging.error(message)
                sys.exit("Unknown (error code = {}). Please review.".format(r.status_code))

            search_list = r.json()['entry']
            user_KOs_exist = False
            for saved_search in search_list:

                author = saved_search['author']
                endpoint_saved_search = saved_search['id']
                title_saved_search = saved_search['name']
                original_search = saved_search['content']['search']

                if author != 'nobody':

                    # Compares KO against all index mappings and modifies accordingly.

                    modified_search, valid_KO = modify_KO(original_search, identifier=endpoint_saved_search)

                    if modified_search != original_search and valid_KO:

                        if audit:
                            ko_list.append({\
                                'id': endpoint_saved_search, \
                                'title': title_saved_search, \
                                'original_content': original_search, \
                                'modified_content': modified_search})

                        else:

                            print("**************************************************")
                            message = log_format.format("Saved search endpoint: {}".format(endpoint_saved_search))
                            logging.info(message)
                            print("Saved search endpoint: {}".format(endpoint_saved_search))
                            message = log_format.format("Saved search title: {}".format(title_saved_search))
                            logging.info(message)
                            print("Saved search title: {}".format(title_saved_search))
                            message = log_format.format("Saved search query: {}".format(original_search))
                            logging.info(message)
                            print()
                            print("+++ Saved search query: {}".format(original_search))
                            message = log_format.format("Saved search query (MODIFIED): {}".format(modified_search))
                            logging.info(message)
                            print()
                            print("+++ Saved search query (MODIFIED): {}".format(modified_search))
                            print("**************************************************")
                            message = log_format.format("Saved search is being modified.", end='\n\n')
                            logging.info(message)
                            print("Saved search is being modified.", end='\n\n')
                            data_payload = {"search": modified_search}
                            try:
                                r = requests.post(endpoint_saved_search, verify=False, data=data_payload, auth=auth_payload)
                            except:
                                if r.status_code == 401:
                                    message = log_format.format("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
                                    logging.error(message)
                                    sys.exit("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
                                elif r.status_code == 403:
                                    message = log_format.format("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
                                    logging.error(message)
                                    sys.exit("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
                                elif r.status_code != 200:
                                    message = log_format.format("Unknown (error code = {}). Please review.".format(r.status_code))
                                    logging.error(message)
                                    sys.exit("Unknown (error code = {}). Please review.".format(r.status_code))


        # CASE 2: EVENTTYPES
        endpoint_get_eventtypes = os.path.join(BASE_URL, GET_ENDPOINT_EVENTTYPES)
        try:
            message = log_format.format("Requesting eventtypes.")
            logging.debug(message)
            r=requests.get(endpoint_get_eventtypes, verify=False, data=get_json, auth=auth_payload)
        except:
            message = log_format.format("Failed to obtain eventtypes via REST.")
            logging.error(message)
            sys.exit("Failed to obtain eventtypes via REST.")
        else:
            if r.status_code == 401:
                message = log_format.format("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
                logging.error(message)
                sys.exit("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
            elif r.status_code == 403:
                message = log_format.format("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
                logging.error(message)
                sys.exit("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
            elif r.status_code != 200:
                message = log_format.format("Unknown (error code = {}). Please review.".format(r.status_code))
                logging.error(message)
                sys.exit("Unknown (error code = {}). Please review.".format(r.status_code))

            eventtypes_list = r.json()['entry']
            user_KOs_exist = False
            for eventtype in eventtypes_list:

                author = eventtype['author']
                endpoint_eventtype = eventtype['id']
                title_eventtype = eventtype['name']
                original_search = eventtype['content']['search']

                if author != 'nobody':

                    # Compares KO against all index mappings and modifies accordingly.
                    modified_search, valid_KO = modify_KO(original_search, identifier=endpoint_eventtype)

                    if modified_search != original_search and valid_KO:


                        if audit:
                            ko_list.append({\
                                'id': endpoint_eventtype, \
                                'title': title_eventtype, \
                                'original_content': original_search, \
                                'modified_content': modified_search})

                        else:

                            print("**************************************************")
                            message = log_format.format("Eventtype endpoint: {}".format(endpoint_eventtype))
                            logging.info(message)
                            print("Eventtype endpoint: {}".format(endpoint_eventtype))
                            message = log_format.format("Eventtype title: {}".format(title_eventtype))
                            logging.info(message)
                            print("Eventtype title: {}".format(title_eventtype))
                            message = log_format.format("Eventtype query: {}".format(original_search))
                            logging.info(message)
                            print()
                            print("+++ Eventtype query: {}".format(original_search))
                            message = log_format.format("Eventtype query (MODIFIED): {}".format(modified_search))
                            logging.info(message)
                            print()
                            print("+++ Eventtype query (MODIFIED): {}".format(modified_search))
                            print("**************************************************")
                            message = log_format.format("Eventtype is being modified.", end='\n\n')
                            logging.info(message)
                            print("Eventtype is being modified.", end='\n\n')
                            data_payload = {"search": modified_search}
                            try:
                                r = requests.post(endpoint_eventtype, verify=False, data=data_payload, auth=auth_payload)
                            except:
                                if r.status_code == 401:
                                    message = log_format.format("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
                                    logging.error(message)
                                    sys.exit("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
                                elif r.status_code == 403:
                                    message = log_format.format("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
                                    logging.error(message)
                                    sys.exit("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
                                elif r.status_code != 200:
                                    message = log_format.format("Unknown (error code = {}). Please review.".format(r.status_code))
                                    logging.error(message)
                                    sys.exit("Unknown (error code = {}). Please review.".format(r.status_code))


        # CASE 3: MACROS
        # NOTE: there is no REST endpoint for modifying macros.
        # Macros can be programmatically modified via the /configs endpoint, otherwise must be modified via the UI.
        # This section merely prints out user-level macros.
        endpoint_get_macros = os.path.join(BASE_URL, GET_ENDPOINT_MACROS.format('-'))
        try:
            message = log_format.format("Requesting macros.")
            logging.debug(message)
            r=requests.get(endpoint_get_macros, verify=False, data=get_json, auth=auth_payload)
        except:
            message = log_format.format("Failed to obtain macros via REST.")
            logging.error(message)
            sys.exit("Failed to obtain macros via REST.")
        else:
            if r.status_code == 401:
                message = log_format.format("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
                logging.error(message)
                sys.exit("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
            elif r.status_code == 403:
                message = log_format.format("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
                logging.error(message)
                sys.exit("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
            elif r.status_code != 200:
                message = log_format.format("Unknown (error code = {}). Please review.".format(r.status_code))
                logging.error(message)
                sys.exit("Unknown (error code = {}). Please review.".format(r.status_code))

            macros_list = r.json()['entry']
            for macro in macros_list:

                author = macro['author']
                endpoint_macro = macro['id']
                title_macro = macro['name']
                original_search = macro['content'].get('definition')

                if author != 'nobody':

                    # Compares KO against all index mappings and modifies accordingly.
                    modified_search, valid_KO = modify_KO(original_search, identifier=endpoint_macro)

                    if modified_search != original_search and valid_KO:

                        if audit:
                            ko_list.append({\
                                'id': endpoint_macro, \
                                'title': title_macro, \
                                'original_content': original_search, \
                                'modified_content': modified_search})

                        else:

                            print("**************************************************")
                            print("Update this macro via UI to let changes propagate.")
                            message = log_format.format("Macro endpoint: {}".format(endpoint_macro))
                            logging.info(message)
                            print("Macro endpoint: {}".format(endpoint_macro))
                            message = log_format.format("Macro title: {}".format(title_macro))
                            logging.info(message)
                            print("Macro title: {}".format(title_macro))
                            message = log_format.format("+++ Macro query: {}".format(original_search))
                            logging.info(message)
                            print("+++ Macro query: {}".format(original_search))
                            message = log_format.format("Macro query (MODIFIED): {}".format(modified_search))
                            logging.info(message)
                            print("Macro query (MODIFIED): {}".format(modified_search))
                            print("**************************************************")


        # CASE 4: REPORTS + DASHBOARDS
        # There IS content where author=admin BUT true_owner=nobody for views.
        # NOT ALLOWED to filter, apparently?
        endpoint_get_views = os.path.join(BASE_URL, GET_ENDPOINT_VIEWS.format('-'))
        try:
            message = log_format.format("Requesting views.")
            logging.debug(message)
            r=requests.get(endpoint_get_views, verify=False, data=get_json, auth=auth_payload)
        except:
            message = log_format.format("Failed to obtain views via REST.")
            logging.error(message)
            sys.exit("Failed to obtain views via REST.")
        else:
            if r.status_code == 401:
                message = log_format.format("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
                logging.error(message)
                sys.exit("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
            elif r.status_code == 403:
                message = log_format.format("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
                logging.error(message)
                sys.exit("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
            elif r.status_code != 200:
                message = log_format.format("Unknown (error code = {}). Please review.".format(r.status_code))
                logging.error(message)
                sys.exit("Unknown (error code = {}). Please review.".format(r.status_code))

            views_list = r.json()['entry']
            user_KOs_exist = False
            for view in views_list:

                author = view['author']
                endpoint_view = view['id']
                title_view = view['name']
                original_search = view['content']['eai:data']
                user_KOs_exist = True

                if author != 'nobody':

                    # Compares KO against all index mappings and modifies accordingly.
                    modified_search, valid_KO = modify_KO(original_search, identifier=endpoint_view)

                    if modified_search != original_search and valid_KO:

                        if audit:
                            ko_list.append({\
                                'id': endpoint_view, \
                                'title': title_view, \
                                'original_content': original_search, \
                                'modified_content': modified_search})

                        else:

                            print("**************************************************")
                            message = log_format.format("View endpoint: {}".format(endpoint_view))
                            logging.debug(message)
                            print("View endpoint: {}".format(endpoint_view))
                            message = log_format.format("View title: {}".format(title_view))
                            logging.debug(message)
                            print("View title: {}".format(title_view))
                            message = log_format.format("View query: {}".format(original_search))
                            logging.debug(message)
                            print()
                            print("+++ View query: {}".format(original_search))
                            message = log_format.format("View query (MODIFIED): {}".format(modified_search))
                            logging.debug(message)
                            print()
                            print("+++ View query (MODIFIED): {}".format(modified_search))
                            print("**************************************************")
                            message = log_format.format("View is being modified.", end='\n\n')
                            logging.info(message)
                            print("View is being modified.", end='\n\n')
                            data_payload = {"eai:data": modified_search}
                            try:
                                r = requests.post(endpoint_view, verify=False, data=data_payload, auth=auth_payload)
                            except:
                                if r.status_code == 401:
                                    message = log_format.format("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
                                    logging.error(message)
                                    sys.exit("Unauthorized (error code = {}). Please re-enter credentials.".format(r.status_code))
                                elif r.status_code == 403:
                                    message = log_format.format("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
                                    logging.error(message)
                                    sys.exit("Forbidden (error code = {}). User is not permitted to access the users REST endpoint.".format(r.status_code))
                                elif r.status_code != 200:
                                    message = log_format.format("Unknown (error code = {}). Please review.".format(r.status_code))
                                    logging.error(message)
                                    sys.exit("Unknown (error code = {}). Please review.".format(r.status_code))

        if audit:
            current_time = datetime.datetime.utcnow().isoformat()
            audit_changes_log = os.path.join(INITIAL_WORKING_DIRECTORY, 'audit_KOs_{}.csv'.format(current_time))
            with open(audit_changes_log, 'w') as csv_file:
                fieldnames = ['id', 'title', 'original_content', 'modified_content']
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()
                for ko_payload in ko_list:
                    writer.writerow(ko_payload)

    # After all manual changed have been identified, record in manual_changes_log.txt.
    if MANUAL_CHANGES_DICT:
        with open(MANUAL_CHANGES_LOG, 'a') as f:
            for file, data in MANUAL_CHANGES_DICT.items():
                f.write("==========\nFILE/ENDPOINT: {0}\n==========\n".format(file))
                for index, description in data:
                    f.write("INDEX/SOURCETYPE: {0}\n".format(index))
                    f.write("DESCRIPTION: {0}\n\n".format(description))


################
# CLI INVOCATION
################

if __name__ == '__main__':

    # Create parser and arguments.
    parser = argparse.ArgumentParser()

    parser.add_argument('-t', '-target', action='store', dest='target', required=True, help='Directory to execute script on.')
    parser.add_argument('-i', '-instance', action='store', dest='instance', required=True, choices=['DS', 'CM', 'SH', 'IDX', 'HF', 'DEPLOYER', 'CAPTAIN', 'OTHER'], help='The instance the script is running on. Used to select the directories that will be searched.')
    parser.add_argument('-m', '-map', action='store', dest='map', required=True, help='The full name of the CSV file that maps the old index to new indexes.')
    parser.add_argument('-sm', '-stmap', action='store', dest='stmap', required=True, help='The full name of the CSV file that maps the old sourcetype to the new sourcetype.')
    parser.add_argument('--managed-directory', action='store', dest='managed_directory', required=False, choices=['etc/apps', 'etc/master-apps', 'etc/shcluster/apps'], help='If managed, indicate the directory that the DC loads their configurations.')
    parser.add_argument('-kos', action='store', help='The full name of the CSV file containing KOs to update for ops SHC.')
    parser.add_argument('-d', dest='debug', action='store_true')

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
    global SOURCETYPE_MAP
    global KO_FILE
    global STAGE_1
    global STAGE_2
    global MANAGED_DIRECTORY

    TARGET_DIRECTORY = args.target
    INSTANCE = args.instance
    DRY_RUN = args.dry_run_state
    KO_FILE = args.kos
    INDEX_MAP = args.map
    SOURCETYPE_MAP = args.stmap
    STAGE_1 = args.stage_1
    STAGE_2 = args.stage_2
    MANAGED_DIRECTORY = args.managed_directory

    if args.debug:
        print("Executing debug actions.")
        sys.exit()


    # Pre-flight checks.
    # splunk_home = os.environ.get('SPLUNK_HOME', '/opt/splunk')
    splunk_home = os.environ.get('SPLUNK_HOME', '/opt/splunk/sh') # CLIENT_X-specific

    if not DRY_RUN and TARGET_DIRECTORY == splunk_home:
            answer = input("Are you sure you'd like to run the script in production? (Y/N) ")
            answer = answer.strip().upper()
            if answer != 'Y':
                sys.exit("Exited script by user request.")
            else:
                pass

    if not INDEX_MAP.endswith('csv'):
        sys.exit("The file given by the -map parameter should be a CSV file.")

    if not SOURCETYPE_MAP.endswith('csv'):
        sys.exit("The file given by the -stmap parameter should be a CSV file.")

    if os.path.getsize(INDEX_MAP) == 0:
        sys.exit("The file given by the -map parameter is empty.")

    if not os.path.isdir(TARGET_DIRECTORY):
        sys.exit("The directory given by the -target parameter is empty.")

    # Execute functions.
    if args.revert_changes:
        revert_changes()
    elif args.accept_changes:
        accept_changes()
    elif INSTANCE != "CAPTAIN":
        update_configuration_files()
    elif INSTANCE == "CAPTAIN":
        answer = input("Is this the OPS captain? (Y/N) ")
        answer = answer.strip().upper()
        if answer == 'Y':
            if not KO_FILE:
                sys.exit("The OPS captain needs a KO file to execute changes.")
            else:
                if DRY_RUN:
                    update_SHC_KOs(ops=True, audit=True, chunk_size=1, sleep_period=10)
                else:
                    update_SHC_KOs(ops=True, audit=False, chunk_size=5, sleep_period=300)
        elif answer == 'N':
            if DRY_RUN:
                update_SHC_KOs(ops=False, audit=True)
            else:
                update_SHC_KOs(ops=False, audit=False)
