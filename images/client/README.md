# Rucio Client for Fermi FIFE experiments

This contains Rucio scripts used by FIFE experiments

## `sync_ferry_users.py`
* Syncs FERRY users to Rucio

### Usage
```
usage: sync_ferry_users.py [-h] [--commit] [--delete_accounts] [--add_scopes] [--add_analysis_attributes]

Sync FERRY Users

options:
  -h, --help            show this help message and exit
  --commit              commit users to Rucio
  --delete_accounts     allow deleting/disabling of accounts. --commit is required
  --add_scopes          add user scope
  --add_analysis_attributes
                        add the following analysis account attributes: ['add_rule', 'add_replicas', 'add_did', 'add_dids', 'update_replicas_states']

Syncs FERRY Users of a VO with Rucio
```


### Environment Variables
* `FERRY_VO`: Virtual Organization to filter in FERRY
* `FILTER_USERS` (optional): Filter for specific usernames
* `TOKEN_ISS`: Token Issuer
