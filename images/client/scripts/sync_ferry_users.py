#!/usr/bin/env python3
"""
Script to sync FERRY users to Rucio based on vo/afffiliation

Adds FERRY users and identities to Rucio as account type USER.
Also applies analysis account attributes/policy to these accounts.

The DN of the cert used to access FERRY needs Read-only access
"""

import argparse
from dataclasses import dataclass, asdict
import logging
import os
import sys
from typing import Union

from rucio.client import Client as RucioClient
from rucio.common.exception import AccountNotFound, Duplicate

from FerryClient import FerryClient, UserLDAPError

# setup logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)
ch = logging.StreamHandler(stream=sys.stdout)
ch.setLevel(logging.INFO)
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
    # email: str
    identities: list[Identity]
    # uuid: str
    # issuer: str


def get_email(ferry: FerryClient, username: str) -> str:
    """Fetch email from FERRY using LDAP"""
    try:
        userLdap = ferry.getUserLdapInfo(username)
        return userLdap['mail']
    except Exception as e:
        raise UserLDAPError(e)


def sync_ferry_users(commit=False,
                     delete_accounts=False,
                     add_scopes=False,
                     add_analysis=False,
                     vo='int'):
    """
    Fetches users from FERRY and adds them to Rucio with analysis attributes
    """
    # setup clients
    ferry = FerryClient(logger=logger)
    client = RucioClient()

    unitname = os.getenv("FERRY_VO", vo)
    filtered_users = os.getenv("FILTER_USERS", None)
    token_iss = os.getenv("TOKEN_ISS", None)

    # get all members and all DNs for an affiliation
    try:
        members = ferry.getAffiliationMembers(unitname)[0]
        all_dns = ferry.getAllUsersCertificateDNs(unitname)
    except Exception as e:
        logger.error("Could not get users in affiliation %s", unitname)
        logger.error(e)
        raise

    # filter out specific users
    if filtered_users:
        filtered = filtered_users.split(',')
        members['users'] = [m for m in members['users'] if m['username'] in filtered]

    users_to_add = [] 
    for user in members['users']:
        username = user['username']

        # ignore banned or deactivated users
        try:
            user = ferry.getUserInfo(username)
            if not user['status'] or user['banned']:
                continue
        except:
            continue

        # Add identities
        identities: list[Identity] = []

        # OIDC identities
        # Only inactive users have no token
        if token_iss and user.get('tokensubject', None):
            identity = Identity(id_type='OIDC',
                                identity={'sub': user['tokensubject'],
                                          'iss': token_iss})
            identities.append(identity)

        # get x509 identities
        user_dns = list(filter(lambda x: x['username'] == username, all_dns))
        if user_dns:
            dns = user_dns[0]['certificates']
            for dn in dns:
                identity = Identity(id_type='X509',
                                    identity=dn['dn'])
                identities.append(identity)
        else:
            logger.error(f"No dns for {username} found")

        users_to_add.append(User(name=username, identities=identities))
    
    # Add or update users to Rucio
    for user in users_to_add:
        logger.info("Adding user %s", user.name)
        if commit:
            add_user(ferry, client, user, add_scopes, add_analysis)
        else:
            logger.info("User had %s identities to add", len(user.identities))
            logger.debug("User identities: %s", user.identities)

    # delete rucio accounts not in FERRY members or if their status has changed
    if delete_accounts:
        delete_users(client, members, commit)


def add_user(ferry: FerryClient, client: RucioClient, user: User, add_scopes=False, add_analysis=False):
    """
    Add users to Rucio
    """
    username = user.name
    email = ''
    try:
        account = client.get_account(username)
        email = account['email']
    except AccountNotFound:
        logger.info(f"Creating account for {username}")
        try:
            email = get_email(ferry, username)
        except UserLDAPError as e:
            logger.error(f"Could not get userLdapInfo for {username}, skipping")
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
    if add_scopes:
        logger.info(f"Adding scope for user: {username}")
        try:
            client.add_scope(username, f'user.{username}')
        except Duplicate:
            logger.info(f"Scope for user {username} already exists")

    # add attributes, default False
    if add_analysis:
        logger.info(f"Adding analysis attributes")
        for a in ANALYSIS_ATTRIBUTES:
            try:
                client.add_account_attribute(username, a, "1")
            except Duplicate as e:
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


def main():
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
                        dest='scopes',
                        action='store_true')
    parser.add_argument('--add_analysis_attributes',
                        help=f'add the following analysis account attributes: {ANALYSIS_ATTRIBUTES}',
                        dest='analysis',
                        action='store_true')

    args = parser.parse_args()

    sync_ferry_users(commit=args.commit,
                     delete_accounts=args.delete_accounts,
                     add_scopes=args.scopes,
                     add_analysis=args.analysis)


if __name__ == "__main__":
    main()
