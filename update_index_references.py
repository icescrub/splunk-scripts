#!/usr/bin/python

"""
Requires index_map.csv file that maps each index to a new index or set of indexes.
1-1 mapping is easy.
1-many mapping is not easy for inputs/transforms but CAN be easy for macros and saved searches.
As Matt noted, if data source is going to MULTIPLE new indexes now then that's another issue.
Requires TCP routing and such.

We check the following places:

etc/system (ALL - NOTE that this cannot be checked on the DS);
etc/apps (DS);
etc/deployment-apps (DS);
etc/master-apps (CM - although it should be getting its configurations from DS);
etc/master-apps/_cluster (CM - this may have unique configurations here);
etc/users (SH - should have macros.conf and savedsearches.conf settings - ALSO be wary of local.meta because someone may have created index in a LOCAL space);
etc/disabled-apps (maybe? just in case?)
NOTE: nothing in shcluster in this case because of environment. Probably tough to do this if on SH cluster...
NOTE: this script should be run on every system possible. Ignore apps for non-DS and users for forwarders (does it even have users dir?)

INCLUSIONS (check all of these in dry run)

inputs.conf (data collection tier);
transforms.conf (indexing tier);
savedsearches.conf;
macros.conf
    this contains user-created macros AND those created by CIM for mapping indexes to DMs
NOTE: http_input app has 'indexes' key.
    THIS is actually a weird one. It could be hidden inside of this kv pair. "indexes = main,notable,firewall"
    There's a reference to it in this line but it's not actually captured. needs new capture for it.
NOTE: alert_logevent app has 'param.index = main'.
local.meta - needs to be changed here IF it exists. This occurs if index is created IN an app. Check in dry run.
history file? debatable if this is desirable...

WEIRD INCLUSIONS

indexes.conf
    vix.output.buckets.from.indexes = <comma separated list of splunk indexes>
metric_alerts.conf
    metric_indexes = <metric index name>
metric_rollups.conf
    rollup.<summary number>.rollupIndex = <string Index name>
wmi.conf
    index = <string>

EXCLUSIONS:

indexes.conf (anything here must not be touched by this script - ensure with dry_run logic);
index=main and index=lastchance (this shouldn't be in the index_map.csv file anyways but ensure);
bootstrapsearches.txt
searchbnf.conf
json files. I've seen this before.

DRY RUN:

check if anything in default. Shouldn't be anything changeable here. That's a config that the app expects.
in loop, print out whether index mapping is 1-1 or not and SAY that it needs manual review.

INPUTS.CONF
index\s*=\s*<old_index>

TRANSFORMS.CONF

FORMAT\s*=\s*<old_index>
"""

########
# IMPORTS
#########

import sys
import os
import logging
import socket
import tempfile
import shutil
import zipfile
import csv
import re
from functools import wraps

##################
# GLOBAL VARIABLES
##################

global INITIAL_WORKING_DIRECTORY
# INITIAL_WORKING_DIRECTORY = os.getcwd()
# INITIAL_WORKING_DIRECTORY = '/Applications/Splunk'

global CURRENT_WORKING_DIRECTORY
CURRENT_WORKING_DIRECTORY = os.getcwd()

global DRY_RUN

global INSTANCE

global HOSTNAME
HOSTNAME = socket.gethostname()


#############################
# WRAPPER/DECORATOR FUNCTIONS
############################

def check_dry(func):
    """
    Wrapper function for functions that would write to a file. Not strictly a decorator.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        if DRY_RUN:
            logging.debug("DRY RUN executed for function %s with the following arguments: %s" % (func.__name__, args))
        else:
            logging.debug("DRY_RUN = False. Making write-level changes with args {0}.".format(*args))
            func(*args, **kwargs)
    return wrapper


def log(func):
    """
    Sets up logging for function.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Set up logging.
        cwd = os.getcwd()
        filename = "{}__update_index_references.log".format(HOSTNAME)
        log_path = os.path.join(cwd, filename)
        format = '%(asctime)s - %(levelname)s:  %(message)s'
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
    Print the function signature and return value.
    """
    @wraps(func)
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


################
# MAIN FUNCTIONS
################

@log
@debug
def update_references(d_map):
    # Now we have a mapping from old_index to a set of new_indexes.




    ### Set up for logging.

    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"





    ### Set up for directories to look for.
    # ASSUMES YOU ARE IN $SPLUNK_HOME.
    # Creates the directories under consideration.
    # Depending on which instance you're running the script on, certain directories will be checked AND CHANGED.

    # check on all.
    dir_system = os.path.join(INITIAL_WORKING_DIRECTORY, "etc/system")

    # check on all. pretty sure this isn't centrally managed anywhere.
    dir_disabled_apps = os.path.join(INITIAL_WORKING_DIRECTORY, "etc/disabled-apps")

    # check on all but instances where splunk web is disabled (IDX, typically). However, no issue with checking null directory.
    dir_users = os.path.join(INITIAL_WORKING_DIRECTORY, "etc/users")

    # check on DS. Should be nowhere else.
    dir_deployment_apps = os.path.join(INITIAL_WORKING_DIRECTORY, "etc/deployment-apps")

    # check on CM (DS --> /master-apps on CM, NOT /apps); IDX (CM --> /slave-apps on IDX, NOT /apps).
    # do not check on SHs and HF and UF. these get apps from dep-apps.
    # DO check on DS.
    dir_apps = os.path.join(INITIAL_WORKING_DIRECTORY, "etc/apps")

    # master-apps. DO NOT check on CM, since CM gets apps from DS here.
    # dir_master_apps = os.path.join(INITIAL_WORKING_DIRECTORY, "etc/master-apps")


    dirs_all = [dir_system, dir_disabled_apps, dir_users]
    dirs_DS = dirs_all + [dir_apps, dir_deployment_apps]
    dirs_CM_IDX = dirs_all + [dir_apps]

    dirs = list()

    if INSTANCE == 'DS':
        dirs = dirs_DS
    elif INSTANCE == 'CM':
        dirs = dirs_CM_IDX
    elif INSTANCE == 'IDX':
        dirs = dirs_CM_IDX
    else:
        dirs = dirs_all

    add_apps = raw_input("do you want to add etc/apps to the list? Do this only for instances not controlled by DS. (Y/N)")
    if add_apps in ['Y', 'y', 'N', 'n']:
       dirs.append(dir_apps)

    logging.debug(log_format.format("Created list of directories appropriate for the {0} instance: {1}".format(INSTANCE, dirs)))


    ### Set up commands to run on each instance on the directories outlined above.

    find_command = "find {0} -type f -name '*.conf' -o -name '*.xml' -o -name '*.csv'"\
                 "| grep -v 'example$'"\
                 "| grep -v 'spec$'"\
                 "| grep -v 'txt$'"\
                 "| grep -v 'json$'"\
                 "| grep -v 'py$'"\
                 "| grep -v 'pyc$'"\
                 "| grep -v 'lookups'"\
                 "| grep -v 'default'"

    # First -e captures commands found in inputs.conf, macros.conf, etc.
    grep_inputs_searches = find_command \
                        + " | xargs grep -irl -e 'index\s*=\s*{1}'"

    # Second -e captures commands found in transforms.conf.
    grep_transforms =      find_command \
                        + " | xargs grep -irl -e 'FORMAT\s*=\s*{1}'"

    # Third -e captures commands found in http_input, typically.
    grep_misc =            find_command \
                        + " | xargs grep -irl -e 'indexes\s*=\s*[,\w]+{1}' "\
                             "-e 'rollupIndex\s*=\s*.*{1}'"








    # Splits d_map into 1-1 mappings and NOT 1-1 mappings.

    d_map_11 = dict()
    d_map_not_11 = dict()

    for k,v in d_map.items():
        if len(v) == 1:
            d_map_11[k] = v
        else:
            d_map_not_11[k] = v

    logging.debug(log_format.format("The following indexes are 1-1: %s" % str(list(d_map_11.keys()))))
    logging.debug(log_format.format("The following indexes are NOT 1-1: %s" % str(list(d_map_not_11.keys()))))



    # CASE 1. 1-1 map. Both subcases (inputs/transforms and also KO objects) are easy to change.

    for old_index in d_map_11:

        new_index = d_map_11[old_index][0]

        logging.debug(log_format.format("CASE 1 for {0} index: Now identifying files that can be immediately changed with the 1-1 map.".format(old_index)))




        #################################################

        # This should be its own function.

        # At this point, we've selected the dirs that are appropriate for the instance. We're safe here.
        for dir in dirs:

            logging.debug(log_format.format("Checking {} directory.".format(dir)))

            # Search 1. Check for inputs, macros, dashboards, and history in this directory.

            stream = os.popen(grep_inputs_searches.format(dir, old_index))
            cmd_output = stream.read().split('\n')
            files_1 = list(filter(None, cmd_output))

            # Search 2. Check for transforms in this directory.

            stream = os.popen(grep_transforms.format(dir, old_index))
            cmd_output = stream.read().split('\n')
            files_2 = list(filter(None, cmd_output))

            # Search 3. Check for miscellaneous possibilities.

            stream = os.popen(grep_misc.format(dir, old_index))
            cmd_output = stream.read().split('\n')
            files_3 = list(filter(None, cmd_output))

            if files_1:
                logging.debug(log_format.format("Identified files that need to be changed: {}".format(files_1)))
            if files_2:
                logging.debug(log_format.format("Identified files that need to be changed: {}".format(files_2)))
            if files_3:
                logging.debug(log_format.format("Identified files that need to be changed: {}".format(files_3)))
            if not any((files_1, files_2, files_3)):
                logging.debug(log_format.format("No files identified."))


            # Now we have a list of files containing references to the old index.
            # We can loop over them separately because they have different rules depending on inputs, transforms, etc.

            # INPUTS AND SEARCHES
            for file in files_1:

                check_dry(backup_file)(file)

                if 'inputs' in file:
                    with open(file, 'r') as f:
                        f_text = f.read()

                    new_text = re.sub(old_index, new_index, f_text)

                    if not DRY_RUN:
                        with open(file, 'w') as f:
                            f.write(new_text)

                elif 'macros' in file or \
                     'savedsearches' in file or \
                     'views' in file or \
                     'panels' in file or \
                     'history' in file:

                    with open(file, 'r') as f:
                        f_text = f.read()

                    # Uses IN operator.
                    if "index IN" in f_text:
                        pattern = "(index\s*IN.*?){0}".format(old_index)
                        index_prefix = re.findall(pattern, f_text)[0]
                        new_pattern = index_prefix + new_index
                        new_text = re.sub(pattern, new_pattern, f_text)

                    else:
                        pattern = "index\s*=\s*{0}".format(old_index)
                        new_pattern = "index={0} OR index={1}".format(old_index, new_index)
                        new_text = re.sub(pattern, new_pattern, f_text)

                    if not DRY_RUN:
                        with open(file, 'w') as f:
                            f.write(new_text)

            # TRANSFORMS
            for file in files_2:

                check_dry(backup_file)(file)

                with open(file, 'r') as f:
                    f_text = f.read()

                new_text = re.sub(old_index, new_index, f_text)

                if not DRY_RUN:
                    with open(file, 'w') as f:
                        f.write(new_text)

            # MISC
            for file in files_3:
                logging.debug(log_format.format("PERFORM MANUAL REVIEW FOR {0}.".format(file)))



    # CASE 2. NOT 1-1 map. KO object subcase is easy to change but inputs/transforms are NOT.
    # 2a. inputs and transforms: needs manual review. 
    # 2b. macros and savedsearches: replace index=old_index with index=old_index OR index=new_index1 OR ...

    # What about wildcards? firewall --> firewall_palo_alto, firewall_fortigate, ...
    # this SHOULD just resolve to firewall*, so it could be that easy...
    # ...make sure by testing that all(firewall, firewall_palo_alto, ...) are satisfied by firewall*
    # check whether the old_index is a subset of ALL of the new_indexes. if so, then replace old_index with old_index*.
    # if not, then it's more complicated and needs a concat.
    # CASE 1: old_index is substring of ALL new indexes. new_index.startswith(old_index) for all ..... old_index --> old_index*
    # CASE 2: NOT substring.


    for old_index in d_map_not_11:
            
        new_indexes = d_map_not_11[old_index]

        logging.debug(log_format.format("CASE 2 for {0} index: Now identifying files that may or may not be changed with the multi-map.".format(old_index)))

        # At this point, we've selected the dirs that are appropriate for the instance. We're safe here.
        for dir in dirs:

            logging.debug(log_format.format("Checking {} directory.".format(dir)))

            # Search 1. Check for inputs, macros, dashboards, and history in this directory.

            stream = os.popen(grep_inputs_searches.format(dir, old_index))
            cmd_output = stream.read().split('\n')
            files_1 = list(filter(None, cmd_output))

            # Search 2. Check for transforms in this directory.

            stream = os.popen(grep_transforms.format(dir, old_index))
            cmd_output = stream.read().split('\n')
            files_2 = list(filter(None, cmd_output))

            # Search 3. Check for miscellaneous possibilities.

            stream = os.popen(grep_misc.format(dir, old_index))
            cmd_output = stream.read().split('\n')
            files_3 = list(filter(None, cmd_output))

            if files_1:
                logging.debug(log_format.format("Identified files that need to be changed: {}".format(files_1)))
            if files_2:
                logging.debug(log_format.format("Identified files that need to be changed: {}".format(files_2)))
            if files_3:
                logging.debug(log_format.format("Identified files that need to be changed: {}".format(files_3)))
            if not any((files_1, files_2, files_3)):
                logging.debug(log_format.format("No files identified."))

            # Now we have a list of files containing references to the old index.
            # We can loop over them separately because they have different rules depending on inputs, transforms, etc.

            # INPUTS AND SEARCHES
            for file in files_1:
                # IGNORE INPUTS. Only history/macros/savedsearches are relevant.

                check_dry(backup_file)(file)

                if 'inputs' in file:
                    logging.debug(log_format.format("PERFORM MANUAL REVIEW FOR INPUTS."))
                    pass

                elif 'macros' in file or \
                     'savedsearches' in file or \
                     'views' in file or \
                     'panels' in file or \
                     'history' in file:
                    with open(file, 'r') as f:
                        f_text = f.read()

                    # Uses IN operator.
                    if "index IN" in f_text:
                        pattern = "(index\s*IN.*?){0}".format(old_index)
                        old_pattern = pattern + old_index
                        index_prefix = re.findall(pattern, f_text)[0]
                        new_pattern = index_prefix \
                                    + old_index \
                                    + "," \
                                    + ",".join(new_indexes)
                        new_text = re.sub(old_pattern, new_pattern, f_text)

                    else:
                        pattern = "index\s*=\s*{0}".format(old_index)
                        new_pattern = "index={0}".format(old_index) \
                                    + " OR index=" \
                                    + " OR index=".join(new_indexes)
                        new_text = re.sub(pattern, new_pattern, f_text)

                    if not DRY_RUN:
                        with open(file, 'w') as f:
                            f.write(new_text)

            # TRANSFORMS
            for file in files_2:
                logging.debug(log_format.format("PERFORM MANUAL REVIEW FOR TRANSFORMS."))
                pass

            # MISC
            for file in files_3:
                logging.debug(log_format.format("PERFORM MANUAL REVIEW FOR MISC."))
                pass

###################
# UTILITY FUNCTIONS
###################

@log
@debug
def get_index_map(map_file):

    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"

    logging.debug(log_format.format("Mapping old index to new indexes."))

    # Create dictionary that maps old index to new indexes.
    d_i = dict()
    with open(map_file, 'r') as f:
        reader = csv.reader(f, delimiter=',')
        for row in reader:
            # This unpacks the remaining new indexes in that row into a list.
            # new_indexes is ALWAYS a list.
            old_index, new_indexes = row[0], row[1:]
            d_i[old_index] = new_indexes

    logging.debug(log_format.format("Mapping complete. Returning dictionary."))

    return d_i


@log
@debug
def revert_changes():

    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"

    # Open file located in same directory that script was run in. Read it.
    backup_files = os.path.join(INITIAL_WORKING_DIRECTORY, 'backup_file_log.txt')

    with open(backup_files, 'r') as f:
        files_text = f.read()
        files = list(filter(None, files_text.split('\n')))

    for file in files:

        # Check directory contents before change.
        cwd = os.path.dirname(file)
        stream = os.popen("ls {}".format(cwd))
        ls1 = stream.read()

        # Make reversion.
        backup_file = file + ".bak.script"
        stream = os.popen("mv {0} {1}".format(backup_file, file))

        # Check directory contents after change.
        cwd = os.path.dirname(file)
        stream = os.popen("ls {}".format(cwd))
        ls2 = stream.read()

        logging.debug(log_format.format("ls1 = {0}".format(ls1)))
        logging.debug(log_format.format("ls2 = {0}".format(ls2)))

        # Check whether backup of file was successful.
        if ls1 == ls2:
            logging.debug(log_format.format("Something went wrong! No reversion."))
        else:
            logging.debug(log_format.format("Reversion successful."))


@log
@debug
def backup_file(file):

    f_name = get_function_name()
    log_format = f_name + ": " + "{0}"

    if not DRY_RUN:

        backup_file = os.path.join(INITIAL_WORKING_DIRECTORY, "backup_file_log.txt")

        # Record file in backup_file_log.txt file. This can be used for reversion.
        with open(backup_file, 'a') as f:
            f.write('\n{}'.format(file))

        # Check directory contents before change.
        cwd = os.path.dirname(file)
        stream = os.popen("ls {}".format(cwd))
        ls1 = stream.read()

        # Make backup.
        # Note that THIS is where the backup function doesn't get executed if DRY_RUN = True.
        stream = check_dry(os.popen)("cp {}".format(file) + "{,.bak.script}")
                   
        # Check directory contents after change.
        cwd = os.path.dirname(file)
        stream = os.popen("ls {}".format(cwd))
        ls2 = stream.read()

        # Check whether backup of file was successful.
        if ls1 == ls2:
            logging.debug(log_format.format("Something went wrong! No backup."))
        else:
            logging.debug(log_format.format("Backup successful."))
    

def check_list():
    # Identify files on the instance that are backup files. This could complicate the backup function, so maybe rename them to bak1?
    find_command = "find {0} -type f -name '*.bak'".format(INITIAL_WORKING_DIRECTORY)
    stream = os.popen(find_command)
    cmd_output = stream.read().split('\n')
    bak_files = list(filter(None, cmd_output))
    logging.debug("The following backup files were found: {0}".format(bak_files))


################
# CLI INVOCATION
################

if __name__ == '__main__':
    """
    --instance ALL/DS/CM/IDX
    --disable-dry-run
    --revert-changes
    """

    global DRY_RUN
    global INSTANCE
    global INITIAL_WORKING_DIRECTORY

    DRY_RUN = True

    # Ensures we don't make changes to the production systems unless necessary.
    value = raw_input("Please enter the target directory for the script. If you want to run the script in production, enter /opt/splunk.")
    INITIAL_WORKING_DIRECTORY = value

    map_indexes = sys.argv[1]

    if map_indexes != "index_map.csv":
        logging.debug("Index map file not given. Please include the index_map.csv file.")

    if '--instance' in sys.argv:
        index = sys.argv.index('--instance')
        INSTANCE = sys.argv[index + 1]

    if '--disable-dry-run' in sys.argv:
        DRY_RUN = False
        d_map = get_index_map(map_indexes)
        update_references(d_map)
    elif '--revert-changes' in sys.argv:
        revert_changes()
    else:
        d_map = get_index_map(map_indexes)
        update_references(d_map)
