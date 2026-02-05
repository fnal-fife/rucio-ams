import argparse
import json
import os
import pprint

_config = {}
CONFIG_FILE_PATH = 'config.json'
ENV_PREFIX = 'FERRY_SYNC_'

# analysis account attributes
ANALYSIS_ATTRIBUTES = [
    "add_rule",
    "add_replicas",
    "add_did",
    "add_dids",
    "update_replicas_states"
]


def set_nested_value(data_dict, keys, value):
    """
    Traverses the dict and sets the value. 
    Creates missing keys along the way.
    """
    for key in keys[:-1]:
        # If the key doesn't exist or isn't a dict, create a new dict
        if key not in data_dict or not isinstance(data_dict[key], dict):
            data_dict[key] = {}
        data_dict = data_dict[key]
    
    # Set the final value
    data_dict[keys[-1]] = value


def load_config(env_prefix=ENV_PREFIX):
    """Loads or reloads the configuration from the JSON file."""
    global _config
    config_file_path = os.getenv("FERRY_SYNC_CONFIG_FILE", CONFIG_FILE_PATH)
    if os.path.exists(config_file_path):
        with open(config_file_path, 'r') as f:
            data = json.load(f)
    else:
        data = {}

    for env_key, env_value in os.environ.items():
        if env_key.startswith(env_prefix):
            # Transform APP_DB__PORT -> ['db', 'port']
            hierarchy = env_key[len(env_prefix):].lower().split("__")
            
            final_value = _auto_cast(env_value)
            
            # Add or update the key
            set_nested_value(data, hierarchy, final_value)

    args = parse_args()

    for arg, value in vars(args).items():
        hierarchy = arg.lower().split("__")
        set_nested_value(data, hierarchy, value)
    
    _config = data

    return _config


def parse_args():
    parser = argparse.ArgumentParser(
        description='Sync FERRY Users',
        epilog='Syncs FERRY Users of a VO with Rucio')

    parser.add_argument('--commit',
                        help='commit users to Rucio',
                        action='store_true')
    parser.add_argument('--delete_accounts',
                        help='allow deleting/disabling of accounts. --commit is required',
                        action='store_true')
    parser.add_argument('--add_scopes',
                        help='add user scope',
                        dest='add_scopes',
                        action='store_true')
    parser.add_argument('--add_analysis_attributes',
                        help=f'add the following analysis account attributes: {ANALYSIS_ATTRIBUTES}',
                        dest='add_analysis',
                        action='store_true')

    args = parser.parse_args()

    return args



def _auto_cast(value):
    """Basic type inference for environment strings."""
    if value.lower() in ("true", "yes"): return True
    if value.lower() in ("false", "no"): return False
    try:
        if "." in value: return float(value)
        return int(value)
    except ValueError:
        return value


def get(key, default=None):
    """Accesses a configuration value."""
    return _config.get(key, default)


try:
    config = load_config()
    pprint.pprint(config)
except FileNotFoundError as e:
    print(e)
