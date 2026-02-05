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


### Configuration


`sync_ferry_users.py` can be configured with a `json` file, which is set with `FERRY_SYNC_CONFIG_FILE` environment variable.


Example `sync_config.json`

```json
{
  "vo": "",
  "username_format": "{}",
  "scope_format": "{}",
  "identities": [],
  "attributes": {},
  "rse_limits": {},
  "from_ferry": true,
  "create_scopes": true,
  "add_attributes": true,
  "set_limits": true,
  "token_issuer": "",
  "log_level": "debug"
}
```

#### Configuration options
* `vo`: *str*, Virtual Organization or unittname in FERRY
* `username_format`: *str*, Template of the username to be added to Rucio. The FERRY username is substituted into the format string. This string is processed with the string `.format(username)`.
* `scope_format`: *str*, Template for the scope to be made. Similar to `username_format`
* `identities`: *list*, List of json object/dictionary identities. Each dict/json object needs `identity` and `id_type` keys. For `"id_type": "OIDC"`, `identity` should container the `sub` (token subject) and `iss` (token issuer) keys. `id_type` only supports `OIDC|X509`
* `attributes`: *dict/object*, Account attributes to add. Format is a dict/object with `"attribute": "value"`
* `rse_limits`: *dict/object*, RSE limits to set. Format is `"rse": "limit in bytes",
* `from_ferry`: *bool*, Whether to set identities from FERRY
* `create_scopes`: *bool*, Whether to create scopes defined by `scope_format`
* `add_attributes`: *bool,* Whether to add attributes in `attributes`
* `set_limits`: *bool*, Whether to set RSE limits in `rse_limits`
* `token_issuer`: *str*, Default token issuer
* `log_level`: *str*, Log Level, currently `debug|info`

### Environment Variables
* `FERRY_SYNC_CONFIG_FILE`: Path to config file
* `FERRY_SYNC_VO`: Virtual Organization to filter in FERRY
* `FERRY_SYNC_FILTER_USERS` (optional): Filter for specific usernames
* `FERRY_SYNC_TOKEN_ISS`: Token Issuer

