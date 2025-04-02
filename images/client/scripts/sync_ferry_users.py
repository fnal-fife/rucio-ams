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

from rucio.client import Client as RucioClient
from rucio.common.exception import AccountNotFound, Duplicate

from FerryClient import FerryClient, UserLDAPError

# setup logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
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
class User:
    """
    Dataclass that has values required to create
    a Rucio Account
    """
    name: str
    # email: str
    identities: list[str]
    uuid: str
    issuer: str


def sync_ferry_users(commit=False,
                     delete_accounts=False,
                     scopes=False,
                     analysis=False,
                     vo='int'):
    """
    Fetches users from FERRY and adds them to Rucio with analysis attributes
    """
    # setup clients
    ferry = FerryClient(logger=logger)
    client = RucioClient()

    unitname = os.getenv("FERRY_VO", vo)
    filtered_users = os.getenv("FILTER_USERS", None)

    # get all members and all DNs for an affiliation
    try:
        members = ferry.getAffiliationMembers(unitname)[0]
        all_dns = ferry.getAllUsersCertificateDNs(unitname)
    except Exception as e:
        logger.error(f"Could not get users in affiliation {unitname}")
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

        # Only incative users have no token
        uuid = user['tokensubject']
        issuer = 'https://cilogon.org/'

        # get identities
        user_dns = list(filter(lambda x: x['username'] == username, all_dns))
        if user_dns:
            dn = user_dns[0]['certificates']
        else:
            logger.error(f"No dns for {username} found")
            dn = []

        users_to_add.append(User(name=username, identities=dn, uuid=uuid, issuer=issuer))
    
    # Add or update users to Rucio
    if commit:
        for user in users_to_add:
            logger.info(f"Adding user {user.name}")
            add_user(ferry, client, user, scopes, analysis)

    # delete rucio accounts not in FERRY members or if their status has changed
    if delete_accounts:
        delete_users(client, members, commit)


def get_email(ferry: FerryClient, username: str) -> str:
    """Fetch email from FERRY using LDAP"""
    try:
        userLdap = ferry.getUserLdapInfo(username)
        return userLdap['mail']
    except Exception as e:
        raise UserLDAPError(e)


def add_user(ferry: FerryClient, client: RucioClient, user: User, scopes=False, analysis=False):
    """
    Add users to Rucio
    """
    username = user.name
    email = ''
    try:
        account = client.get_account(username)
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

    email = account['email']

    # Create Rucio formatted account identity
    token_subject = f'SUB={user.uuid}, ISS={user.issuer}'

    # add user identities
    logger.info(f"Adding identities for {username}")
    # First, see what is currently attached to the user so we can skip adding duplicates
    existing = client.list_identities(username)
    # Add a token if there is not one for this user
    try:
        if token_subject not in existing:
            email = get_email(ferry, username)
            client.add_identity(username, token_subject, "OIDC", email)
            logger.info(f"Added token for user {username}")
    except Duplicate:
        pass
    except UserLDAPError as e:
        logger.error(f"Could not get email for {username}, skipping")
        logger.error(e)
        pass

    # Add certificate DNs that don't exist yet for this user
    for d in user.identities:
        try:
            if d['dn'] not in existing:
                if not email:
                    email = get_email(ferry, username)
                client.add_identity(username, d['dn'], "X509", email)
                logger.info(f"Added X509 DN for user {username}: {d['dn']}")
        except Duplicate:
            continue
        except UserLDAPError as e:
            logger.error(f"Could not get email for {username}, skipping")
            logger.error(e)
            continue

    # create a scope
    if scopes:
        logger.info(f"Adding scope for user: {username}")
        try:
            client.add_scope(username, f'user.{username}')
        except Duplicate:
            logger.info(f"Scope for user {username} already exists")

    # add attributes, default False
    if analysis:
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
                    scopes=args.scopes,
                    analysis=args.analysis)


if __name__ == "__main__":
    main()