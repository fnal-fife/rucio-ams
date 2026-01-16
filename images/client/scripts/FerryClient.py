"""
FerryClient

Module to connect to FERRY
"""
import logging
import os

import requests
from requests.exceptions import HTTPError


class UserLDAPError(Exception):
    pass


class FerryClient:
    """
    Client to access FERRY
    """
    logger: logging.Logger
    server: str
    capath: str
    cert: str
    key: str

    def __init__(self, logger: logging.Logger = None):
        self.logger = logger or logging.getLogger()
        self.server = os.getenv("FERRY_URL", "https://ferry.fnal.gov:8445")
        self.capath = os.getenv("CA_PATH", "/etc/grid-security/certificates")
        self.cert = os.getenv("X509_USER_CERT", "/opt/rucio/certs/usercert.pem")
        self.key = os.getenv("X509_USER_KEY", "/opt/rucio/keys/userkey.pem")

    def get(self, url: str, params: dict = None) -> dict:
        """
        Get method for FERRY

        Adds SSL for request
        """
        try:
            r = requests.get(url,
                params=params,
                cert=(self.cert, self.key),
                verify=self.capath)
            r.raise_for_status()
        except HTTPError as e:
            self.logger.error(e)
            raise

        data = r.json()
        return data["ferry_output"]
    
    def getGroupMembers(self, groupname: str) -> dict:
        """
        Returns all the members of the specified group
        """
        url = f"{self.server}/getGroupMembers"
        params = {"groupname": groupname}
        r = self.get(url, params)
        return r

    def getUserInfo(self, username: str) -> dict:
        """
        Fetches user information for a given username
        """
        url = f"{self.server}/getUserInfo"
        params = {"username": username}
        r = self.get(url, params)
        return r

    def getGridMapFile(self, unitname: str) -> list[dict]:
        """
        Fetches user information for a given username
        """
        url = f"{self.server}/getGridMapFile"
        params = {"unitname": unitname}
        r = self.get(url, params)
        return r

    def getAffiliationMembers(self, unitname: str) -> dict:
        """
        Fetches members of an affiliation a given unitname
        """
        url = f"{self.server}/getAffiliationMembers"
        params = {"unitname": unitname}
        r = self.get(url, params)
        return r

    def getAffiliationUnitMembers(self, unitname: str) -> dict:
        """
        Fetches members of an affiliation a given unitname from SNOW
        """
        url = f"{self.server}/getAffiliationUnitMembers"
        params = {"unitname": unitname}
        r = self.get(url, params)
        return r
    
    def getUserCertificateDNs(self, unitname: str, username: str) -> dict:
        """
        Fetches a user's DNs for a specific affiliation
        """
        url = f"{self.server}/getUserCertificateDNs"
        params = {"unitname": unitname, "username": username}
        r = self.get(url, params)
        return r[0]['certificates']

    def getAllUsersCertificateDNs(self, unitname: str = None) -> dict:
        """
        Fetches all user's DNs
        """
        url = f"{self.server}/getAllUsersCertificateDNs"
        params = {}
        if unitname:
            params['unitname'] = unitname
        r = self.get(url, params)
        return r

    def getUserLdapInfo(self, username: str) -> dict:
        """
        Fetches user's LDAP information
        """
        url = f"{self.server}/getUserLdapInfo"
        params = {"username": username}
        r = self.get(url, params)
        return r
