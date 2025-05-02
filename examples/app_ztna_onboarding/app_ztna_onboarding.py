import json
import os
import sys
import yaml


# Add parent directory to path to import scmc
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import (
    ResourceNotFoundError
)
from scmc import MScm


base_params = {}

def readConfiguration(scm_creds_file=None):
    if scm_creds_file:
        pcf = scm_creds_file
    else:
        if os.path.isfile("scm_creds.json"):
            pcf = os.path.join("scm_creds.json")
        else:
            pcf = os.path.join(os.path.expanduser("~"), "scm_creds.json")
    with open(pcf) as f:
        data = json.load(f)
        base_params["tsg_id"] = data["tsg_id"]
        base_params["client_id"] = data["client_id"]
        base_params["client_secret"] = data["client_secret"]
        base_params["auth_url"] = data["auth_url"]
        base_params["region"] = data["region"]



class AzureVaultClient:
    secret_client   = None

    def __init__(self, vault_url):
        credential = DefaultAzureCredential()
        self.secret_client = SecretClient(vault_url=vault_url, credential=credential)

    def deleteSecret(self, name):
        return self.secret_client.begin_delete_secret(name).result()
    
    def getSecret(self, name):
        return self.secret_client.get_secret(name)

    def setSecret(self, name, value):
        return self.secret_client.set_secret(name, value)

    def setZTNASecret(self, name, token_key, token_secret):
        value = {
            "key": token_key,
            "secret": token_secret,
        }
        self.setSecret(name, json.dumps(value))

class ZTNAManager:
    connector_groups_to_manage = [
        "Azure-DC21-g1",
        "Azure-DC21-g2",
        "Azure-DC22-g1",
        "Azure-DC22-g2",
    ]
    connectors_to_manage = [
        "ztna211",
        "ztna212",
        "ztna221",
        "ztna222",
    ]
    app_prefixes_to_manage = [
        "app21",
        "app22",
    ]
    scm_client = None
    azure_vault_client = None
    zcfg = None

    def __init__(self, scm_client, azure_vault_client):
        self.scm_client = scm_client
        self.azure_vault_client = azure_vault_client
        with open("ztna_config.yaml", "r") as cfg_in:
            self.zcfg = yaml.safe_load(cfg_in)

    def manage_applications_create(self):
        if self.zcfg["applications"] is None:
            return
        applications_to_create = set(self.zcfg["applications"]).difference(self.scm_client.applications.keys())
        print(f"Need to create {len(applications_to_create)} applications")
        for app in applications_to_create:
            for pfx in self.app_prefixes_to_manage:
                if app.startswith(pfx):
                    break
            else:
                assert False, f"About to create an aplication {app} I'm not supposed to manage"
            cgids = []
            print(f"Creating application {app}")
            for cg in self.zcfg["applications"][app]["connector_groups"]:
                cgids.append(self.scm_client.connector_groups[cg]["oid"])
            oidsstr = ",".join(cgids)
            self.scm_client.createZTNAApplication(app, oidsstr, "80")

    def manage_applications_delete(self):
        for app in self.scm_client.applications.keys():
            for pfx in self.app_prefixes_to_manage:
                if app.startswith(pfx):
                    break
            else:
                # not managed app
                continue
            if self.zcfg["applications"] is not None and app in self.zcfg["applications"]:
                continue
            print(f"Deleting application {app}")
            oid = self.scm_client.applications[app]["oid"]
            self.scm_client.deleteZTNAApplication(oid)

    def manage_connector_groups_create(self):
        connector_groups_to_create = set(self.zcfg["connector_groups"]).difference(self.scm_client.connector_groups.keys())
        print(f"Need to create {len(connector_groups_to_create)} connector groups")
        for cg in connector_groups_to_create:
            assert cg in self.connector_groups_to_manage, "About to create a connector group I'm not supposed to manage"
            print(f"Creating {cg}")
            try:
                desc = self.zcfg["connector_groups"][cg].get("description", "")
            except:
                desc = ""
            self.scm_client.createZTNAConnectorGroup(cg, desc)
        self.scm_client.refreshZTNAConnectorGroups()

    def manage_connector_groups_delete(self):
        cg_existing_managed = set(self.scm_client.connector_groups.keys()).intersection(self.connector_groups_to_manage)
        connector_groups_to_delete = cg_existing_managed.difference(self.zcfg["connector_groups"])
        print(f"Need to delete {len(connector_groups_to_delete)} connector groups")
        for cg in connector_groups_to_delete:
            assert cg in self.connector_groups_to_manage, "About to delete a connector group I'm not supposed to manage"
            print(f"Deleting {cg}")
            oid = self.scm_client.connector_groups[cg]["oid"]
            self.scm_client.deleteZTNAConnectorGroup(oid)

    def manage_connectors_create(self):
        cg_existing_managed = set(self.scm_client.connector_groups.keys()).intersection(self.connector_groups_to_manage)
        for cg in cg_existing_managed:
            try:
                conns = self.zcfg["connector_groups"][cg]["connectors"]
            except:
                # no connectors
                continue
            for conn in conns:
                if conn in self.scm_client.connectors:
                    continue
                assert conn in self.connectors_to_manage, "About to create a connector I'm not supposed to manage"
                print(f"Creating connector {conn} in {cg}")
                cgid = self.scm_client.connector_groups[cg]["oid"]
                self.scm_client.createZTNAConnector(conn, cgid)

    def manage_connectors_delete(self):
        connectors_existing_managed = set(self.scm_client.connectors.keys()).intersection(self.connectors_to_manage)
        cg_existing_managed = set(self.scm_client.connector_groups.keys()).intersection(self.connector_groups_to_manage)
        connectors_need_to_exist = []
        for cg in cg_existing_managed:
            try:
                connectors_need_to_exist += self.zcfg["connector_groups"][cg]["connectors"]
            except:
                # no connectors
                pass
        for conn in connectors_existing_managed:
            if not conn in connectors_need_to_exist:
                assert conn in self.connectors_to_manage, "About to delete a connector I'm not supposed to manage"
                print(f"Deleting connector {conn}")
                oid = self.scm_client.connectors[conn]["oid"]
                self.scm_client.deleteZTNAConnector(oid)


    def go(self):
        self.scm_client.refreshZTNAConnectors()
        self.scm_client.refreshZTNAConnectorGroups()
        self.scm_client.refreshZTNAApplications()
        print(f"we have: {set(self.scm_client.connector_groups.keys())}")
        self.manage_connector_groups_create()
        self.manage_connectors_create()
        self.manage_applications_create()
        self.manage_applications_delete()
        self.manage_connectors_delete()
        self.manage_connector_groups_delete()



def main():
    if os.getenv("SCM_CLIENT_ID") is not None:
        base_params['client_id']     = os.getenv("SCM_CLIENT_ID")
        base_params['client_secret'] = os.getenv("SCM_CLIENT_SECRET")
        base_params['tsg_id']        = os.getenv("SCM_TSG_ID")
        base_params['region']        = os.getenv("PA_REGION")
    else:
        readConfiguration()
    print(base_params['tsg_id'])

    scm_client = MScm(
        client_id=base_params["client_id"],
        client_secret=base_params["client_secret"],
        tsg_id=base_params["tsg_id"],
        region=base_params["region"],
    )
    azure_vault_client = AzureVaultClient(os.getenv("AZURE_VAULT_URL"))
    zm = ZTNAManager(scm_client, azure_vault_client)
    zm.go()
    sys.exit(0)
    s = "ztna99"
    try:
        secret = azure_vault_client.getSecret(s)
        print(secret.name)
        print(secret.value)
    except ResourceNotFoundError as e:
        print("Not there yet")
    azure_vault_client.setZTNASecret(s, "aaa", "bbb")
    secret = azure_vault_client.getSecret(s)
    print(secret.name)
    print(secret.value)


if __name__ == '__main__':
    sys.exit(main())
