#!/usr/bin/env python3
"""
Script to sync FERRY users to Rucio based on vo/afffiliation

Adds FERRY users and identities to Rucio as account type USER.
Also applies analysis account attributes/policy to these accounts.

The DN of the cert used to access FERRY needs Read-only access
"""

from dataclasses import dataclass
import logging
import os
import sys
from typing import Union

from rucio.client import Client as RucioClient
from rucio.common.exception import (AccountNotFound,
                                    Duplicate,
                                    RSENotFound)

import config
from FerryClient import (FerryClient,
                         UserLDAPError,
                         create_ferry_client,
                         get_ferry_client)

log_level = config.get("log_level", "info")
print(log_level)
if log_level == "info":
    level = logging.INFO
if log_level == "debug":
    level = logging.DEBUG

# setup logger
logger = logging.getLogger()
logger.setLevel(level)
ch = logging.StreamHandler(stream=sys.stdout)
ch.setLevel(level)
logger.addHandler(ch)

# analysis account attributes
ANALYSIS_ATTRIBUTES = [
    "add_rule",
    "add_replicas",
    "add_did",
    "add_dids",
    "update_replicas_states"
]


@dataclass
class Identity:
    """
    Values for a Rucio identity
    """
    identity: Union[dict[str, str], str]
    id_type: str


@dataclass
class User:
    """
    Dataclass that has values required to create
    a Rucio Account
    """
    name: str
    rucio_name: str
    # email: str
    identities: list[Identity]
    scope: str
    # uuid: str
    # issuer: str


def get_email(ferry: FerryClient, username: str) -> str:
    """Fetch email from FERRY using LDAP"""
    try:
        userLdap = ferry.getUserLdapInfo(username)
        return userLdap['mail']
    except Exception as e:
        raise UserLDAPError(e)


def gather_ferry_identities(user: dict, user_dns: list) -> list[Identity]:
    """Gather FERRY Identities"""
    token_iss = config.get("token_issuer", None)

    identities: list[Identity] = []

    # OIDC identities
    # Only inactive users have no token
    if token_iss and user.get('tokensubject', None):
        identity = Identity(id_type='OIDC',
                            identity={'sub': user['tokensubject'],
                                      'iss': token_iss})
        identities.append(identity)

    # get x509 identities
    if user_dns:
        dns = user_dns[0]['certificates']
        for dn in dns:
            identity = Identity(id_type='X509',
                                identity=dn['dn'])
            identities.append(identity)
    else:
        logger.error(f"No dns for {user['username']} found")

    return identities


def main():
    """
    Fetches users from FERRY and adds them to Rucio with analysis attributes
    """
    # setup clients
    create_ferry_client(logger=logger)

    ferry = get_ferry_client()
    client = RucioClient()

    unitname = config.get("vo", "int")
    username_format = config.get("username_format", "{}")
    scope_format = config.get("scope_format", "user.{}")
    from_ferry = config.get("from_ferry", False)
    commit = config.get("commit", False)
    delete_accounts = config.get("delete_accounts", False)

    filtered_users = os.getenv("FILTER_USERS", None)

    # get all members and all DNs for an affiliation
    try:
        members = ferry.getAffiliationMembers(unitname)[0]
    except Exception as e:
        logger.error("Could not get users in affiliation %s", unitname)
        logger.error(e)
        raise

    # filter out specific users
    if filtered_users:
        filtered = filtered_users.split(',')
        members['users'] = [m for m in members['users'] if m['username'] in filtered]

    # get DNs if from Ferry
    all_dns = []
    if from_ferry:
        try:
            all_dns = ferry.getAllUsersCertificateDNs(unitname)
        except Exception as e:
            logger.error("Could not get all_dns in affiliation %s", unitname)
            logger.error(e)
            raise

    users_to_add = [] 
    for user in members['users']:
        username = user['username']
        rucio_name = username_format.format(username)

        scope = scope_format.format(username)

        # ignore banned or deactivated users
        try:
            user = ferry.getUserInfo(username)
            if not user['status'] or user['banned']:
                continue
        except:
            continue

        # Add identities
        if from_ferry:
            user_dns = list(filter(lambda x: x['username'] == username, all_dns))
            identities: list[Identity] = gather_ferry_identities(user,
                                                                 user_dns)
        else:
            config_ids = config.get("identities", [])
            identities = [Identity(**d) for d in config_ids]

        users_to_add.append(User(name=username,
                                 rucio_name=rucio_name,
                                 scope=scope,
                                 identities=identities))
    
    # Add or update users to Rucio
    for user in users_to_add:
        logger.info("Adding user %s with %s", user.name, user.rucio_name)
        if commit:
            sync_user(client, user)
        else:
            logger.info("User had %s identities to add", len(user.identities))
            logger.debug("User identities: %s", user.identities)

    # delete rucio accounts not in FERRY members or if their status has changed
    if delete_accounts:
        delete_users(client, members, commit)


def sync_user(client: RucioClient, user: User):
    """
    Add or sync users to Rucio
    """
    ferry = get_ferry_client()

    name = user.name
    username = user.rucio_name
    email = ''
    try:
        account = client.get_account(username)
        email = account['email']
    except AccountNotFound:
        logger.info(f"Creating account for {username}")
        try:
            email = get_email(ferry, name)
        except UserLDAPError as e:
            logger.error("Could not get userLdapInfo for %s, skipping", name)
            logger.error(e)
            return
        client.add_account(username, 'USER', email)
        account = client.get_account(username)

    # add user identities
    logger.info("Adding identities for %s", username)
    logger.debug("Identities %s", user.identities) 

    # First, see what is currently attached to the user so we can skip adding duplicates
    existing = list(client.list_identities(username))
    logger.debug("All existing identities %s", existing)

    for user_identity in user.identities:
        if user_identity.id_type == 'OIDC':
            # Create Rucio formatted account OIDC identity
            sub = user_identity.identity['sub']
            iss = user_identity.identity['iss']
            identity_str = f'SUB={sub}, ISS={iss}'
            id_type = user_identity.id_type
        elif user_identity.id_type == 'X509':
            identity_str = user_identity.identity
            id_type = user_identity.id_type
        else:
            continue
        logger.debug("Adding identity %s, %s", identity_str, id_type)

        try:
            existing_ids = [v['identity'] for v in existing if v['type'] == id_type]
            logger.debug("Existing identities for %s: %s", username, existing_ids)
            if identity_str not in existing_ids:
                client.add_identity(username, identity_str, id_type, email)
                logger.info(f"Added {id_type} for user {username}")
            else:
                raise Duplicate
        except Duplicate:
            logger.info("Identity already exists %s", id_type)
            logger.debug("Identity exists %s", identity_str)

    # create a scope
    if config.get('add_scopes', False):
        logger.info("Adding scope for user: %s", username)
        try:
            client.add_scope(username, user.scope)
        except Duplicate:
            logger.info(f"Scope for user {username} already exists")

    # add attributes, default False
    if config.get('add_attributes', False):
        logger.info(f"Adding analysis attributes")
        for a in ANALYSIS_ATTRIBUTES:
            try:
                client.add_account_attribute(username, a, "1")
            except Duplicate as e:
                logger.error(e)
                continue

    if config.get("set_limits", False):
        logger.info("Setting RSE limits")
        limits = config.get("rse_limits", {})
        for rse, limit in limits.items():
            try:
                client.set_account_limit(username,
                                         rse,
                                         limit,
                                         "local")
            except RSENotFound as e:
                logger.error("Could not set limits on %s for %s",
                             rse, username)
                logger.error(e)
                continue
            except Exception as e:
                logger.error("Could not set limits on %s for %s",
                             rse, username)
                logger.error(e)
                continue


def delete_users(client: RucioClient, members, commit=False):
    """
    Checks and delete/disable users from Rucio
    """
    rucio_accounts = client.list_accounts(account_type="USER")
    ferry_accounts = [m['username'] for m in members['users']]
    for a in rucio_accounts:
        if a['account'] not in ferry_accounts:
            logger.info(f"Disabling account {a}, account not affiliated")
            if commit:
                client.delete_account(a)
        else:
            index = ferry_accounts.index(a['account'])
            user = members[index]
            if not user['status'] or user['banned']:
                logger.info(f"Disabling account {a}, FERRY disabled or banned")
                if commit:
                    client.delete_account(a)


if __name__ == "__main__":
    main()
