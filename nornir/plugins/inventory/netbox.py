import os
import warnings
from typing import Any, Dict, List, Optional, Union

from nornir.core.deserializer.inventory import Inventory, HostsDict

import requests


class NBInventory(Inventory):
    def __init__(
        self,
        nb_url: Optional[str] = None,
        nb_token: Optional[str] = None,
        use_slugs: bool = True,
        ssl_verify: Union[bool, str] = True,
        flatten_custom_fields: bool = True,
        filter_parameters: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """
        Netbox plugin

        netbox.NBInventory is deprecated, use netbox.NetboxInventory2 instead

        Arguments:
            nb_url: Netbox url, defaults to http://localhost:8080.
                You can also use env variable NB_URL
            nb_token: Netbokx token. You can also use env variable NB_TOKEN
            use_slugs: Whether to use slugs or not
            ssl_verify: Enable/disable certificate validation or provide path to CA bundle file
            flatten_custom_fields: Whether to assign custom fields directly to the host or not
            filter_parameters: Key-value pairs to filter down hosts
        """
        msg = "netbox.NBInventory is deprecated, use netbox.NetboxInventory2 instead"
        warnings.warn(msg, DeprecationWarning)

        filter_parameters = filter_parameters or {}
        nb_url = nb_url or os.environ.get("NB_URL", "http://localhost:8080")
        nb_token = nb_token or os.environ.get(
            "NB_TOKEN", "0123456789abcdef0123456789abcdef01234567"
        )

        session = requests.Session()
        session.headers.update({"Authorization": f"Token {nb_token}"})
        session.verify = ssl_verify

        # Fetch all devices from Netbox
        # Since the api uses pagination we have to fetch until no next is provided

        url = f"{nb_url}/api/dcim/devices/?limit=0"
        nb_devices: List[Dict[str, Any]] = []

        while url:
            r = session.get(url, params=filter_parameters)

            if not r.status_code == 200:
                raise ValueError(f"Failed to get devices from Netbox instance {nb_url}")

            resp = r.json()
            nb_devices.extend(resp.get("results"))

            url = resp.get("next")

        hosts = {}
        for d in nb_devices:
            host: HostsDict = {"data": {}}

            # Add value for IP address
            if d.get("primary_ip", {}):
                host["hostname"] = d["primary_ip"]["address"].split("/")[0]

            # Add values that don't have an option for 'slug'
            host["data"]["serial"] = d["serial"]
            host["data"]["vendor"] = d["device_type"]["manufacturer"]["name"]
            host["data"]["asset_tag"] = d["asset_tag"]

            if flatten_custom_fields:
                for cf, value in d["custom_fields"].items():
                    host["data"][cf] = value
            else:
                host["data"]["custom_fields"] = d["custom_fields"]

            # Add values that do have an option for 'slug'
            if use_slugs:
                host["data"]["site"] = d["site"]["slug"]
                host["data"]["role"] = d["device_role"]["slug"]
                host["data"]["model"] = d["device_type"]["slug"]

                # Attempt to add 'platform' based of value in 'slug'
                host["platform"] = d["platform"]["slug"] if d["platform"] else None

            else:
                host["data"]["site"] = d["site"]["name"]
                host["data"]["role"] = d["device_role"]
                host["data"]["model"] = d["device_type"]
                host["platform"] = d["platform"]

            # Assign temporary dict to outer dict
            # Netbox allows devices to be unnamed, but the Nornir model does not allow this
            # If a device is unnamed we will set the name to the id of the device in netbox
            hosts[d.get("name") or d.get("id")] = host

        # Pass the data back to the parent class
        super().__init__(hosts=hosts, groups={}, defaults={}, **kwargs)

class NetboxInventory2(Inventory):
    """
    Inventory plugin that uses `Netbox <https://github.com/netbox-community/netbox>`_ as backend.

    Note:
        Additional data provided by the Netbox devices API endpoint will be
        available through the Netbox Host data attribute.

    Environment Variables:
        * ``NB_URL``: Corresponds to nb_url argument
        * ``NB_TOKEN``: Corresponds to nb_token argument
        * ``NB_PRIVATE_KEY``: Corresponds to nb_private_key

    Arguments:
        nb_url: Netbox url (defaults to ``http://localhost:8080``)
        nb_token: Netbox API token
        ssl_verify: Enable/disable certificate validation or provide path to CA bundle file
            (defaults to True)
        flatten_custom_fields: Assign custom fields directly to the host's data attribute
            (defaults to False)
        filter_parameters: Key-value pairs that allow you to filter the Netbox inventory.
        nb_private_key: Netbox user private key
        nb_cred_role_slug: Netbox secret role slug for which type of credentials to pull in.
    """

    def __init__(
        self,
        nb_url: Optional[str] = None,
        nb_token: Optional[str] = None,
        use_slugs: bool = True,
        ssl_verify: Union[bool, str] = True,
        flatten_custom_fields: bool = False,
        filter_parameters: Optional[Dict[str, Any]] = None,
        nb_private_key: Optional[str] = None,
        nb_cred_role_slug: Optional[str] = "login-creds",
        **kwargs: Any,
    ) -> None:
        filter_parameters = filter_parameters or {}
        nb_url = nb_url or os.environ.get("NB_URL", "http://localhost:8080")
        nb_token = nb_token or os.environ.get(
            "NB_TOKEN", "0123456789abcdef0123456789abcdef01234567"
        )

        # Load in user private key from environment var or file load
        nb_private_key = nb_private_key or os.environ.get("NB_PRIVATE_KEY", None)

        if os.environ.get('NB_PRIVATE_KEY') is not None:
            nb_private_key = os.environ.get('NB_PRIVATE_KEY')
        elif os.environ.get('NB_PRIVATE_KEY') is None and nb_private_key:
            with open(nb_private_key, 'r') as f:
                nb_private_key = f.read()

        session = requests.Session()
        session.headers.update({"Authorization": f"Token {nb_token}"})
        session.verify = ssl_verify

        # Fetch all secrets from Netbox
        # Since the api uses pagination we have to fetch until no next is provided
        if nb_private_key:
            # Get session key first in order to get decrypted secrets

            url = f"{nb_url}/api/secrets/get-session-key/"
            nb_session_key: str = None

            headers = {
                'Connection': 'keep-alive',
                'Accept': 'application/json, text/javascript, */*; q=0.01',
                'DNT': '1',
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'en-US,en;q=0.9',
            }

            payload = {
                "private_key": nb_private_key
            }
            r = session.post(url, headers=headers, data=payload)

            if not r.status_code == 200:
                raise ValueError(f"Failed to get session key from Netbox instance {nb_url}")

            # Add session key to cookie jar for session
            session_key_cookie = r.json()
            session.cookies.set(name="session_key", value=session_key_cookie.get("session_key"))


            # Get all secrets

            url = f"{nb_url}/api/secrets/secrets/?limit=0"
            nb_secrets: List[Dict[str, Any]] = []

            while url:
                r = session.get(url)

                if not r.status_code == 200:
                    raise ValueError(f"Failed to get secrets from Netbox instance {nb_url}")

                resp = r.json()
                nb_secrets.extend(resp.get("results"))

                url = resp.get("next")

        # Fetch all devices from Netbox
        # Since the api uses pagination we have to fetch until no next is provided

        url = f"{nb_url}/api/dcim/devices/?limit=0"
        nb_devices: List[Dict[str, Any]] = []

        while url:
            r = session.get(url, params=filter_parameters)

            if not r.status_code == 200:
                raise ValueError(f"Failed to get devices from Netbox instance {nb_url}")

            resp = r.json()
            nb_devices.extend(resp.get("results"))

            url = resp.get("next")

        hosts = {}
        for dev in nb_devices:
            host: HostsDict = {"data": {}}

            # Add value for IP address
            if dev.get("primary_ip", {}):
                host["hostname"] = dev["primary_ip"]["address"].split("/")[0]

            host["platform"] = dev["platform"]["name"] if dev["platform"] else None

            # populate all netbox data into the hosts data attribute
            for k, v in dev.items():
                host["data"][k] = v

            if flatten_custom_fields:
                for cf, value in dev["custom_fields"].items():
                    host["data"][cf] = value
                host["data"].pop("custom_fields")

            # Add secrets to host if it has one in Netbox
            if nb_private_key:
                # Filter secrets based on netbox secret role slug
                f_secrets = [s for s in nb_secrets if s.get("role").get("slug") == nb_cred_role_slug]
                # Add secrets to device if they exist
                host_secret = [s for s in f_secrets if s.get("device").get("id") == dev.get("id")]
                if host_secret:
                    host_secret = host_secret[0]
                    host["username"] = host_secret.get("name")
                    host["password"] = host_secret.get("plaintext")

            # management port from netbox config_context if it's available
            if host.get("data").get("config_context").get("nornir").get("port"):
                host["port"] = host.get("data").get("config_context").get("nornir").get("port")

            # Attempt to add 'platform' based of value in 'slug'
            host["platform"] = dev["platform"]["slug"] if dev["platform"] else None

            # Assign temporary dict to outer dict
            # Netbox allows devices to be unnamed, but the Nornir model does not allow this
            # If a device is unnamed we will set the name to the id of the device in netbox
            hosts[dev.get("name") or dev.get("id")] = host

        # Pass the data back to the parent class
        super().__init__(hosts=hosts, groups={}, defaults={}, **kwargs)

