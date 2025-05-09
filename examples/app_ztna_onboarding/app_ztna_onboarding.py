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
    ResourceNotFoundError,
)
from scmc import MScm
from scm.exceptions import (
    NameNotUniqueError,
)

SNIPPET = "api-configured"


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
    connector_group_prefixes_to_manage = [
        "Azure-DC21",
        "Azure-DC22",
        "Azure-DC23",
    ]
    connector_prefixes_to_manage = [
        "ztna21",
        "ztna22",
        "ztna23",
    ]
    application_prefixes_to_manage = [
        "app21",
        "app22",
        "app23",
    ]
    scm_client = None
    azure_vault_client = None
    zcfg = None

    def __init__(self, scm_client, azure_vault_client):
        self.scm_client = scm_client
        self.azure_vault_client = azure_vault_client
        try:
            with open("ztna_config.yaml", "r") as cfg_in:
                self.zcfg = yaml.safe_load(cfg_in)
        except yaml.parser.ParserError as e:
            print("Failed to parse yaml ztna_config file")
            sys.exit(1)

    def is_managed(self, name, prefix_list):
        for pfx in prefix_list:
            if name.startswith(pfx):
                return True
        return False

    def is_managed_application(self, name):
        return self.is_managed(name, self.application_prefixes_to_manage)

    def is_managed_connector(self, name):
        return self.is_managed(name, self.connector_prefixes_to_manage)

    def is_managed_connector_group(self, name):
        return self.is_managed(name, self.connector_group_prefixes_to_manage)

    def get_existing_managed_connectors(self):
        l = []
        for conn in self.scm_client.connectors.keys():
            if self.is_managed_connector(conn):
                l.append(conn)
        return l

    def get_existing_managed_connector_groups(self):
        l = []
        for cg in self.scm_client.connector_groups.keys():
            if self.is_managed_connector_group(cg):
                l.append(cg)
        return l

    def manage_applications_create(self):
        if self.zcfg["applications"] is None:
            return
        applications_to_create = set(self.zcfg["applications"]).difference(self.scm_client.applications.keys())
        print("Verifying if applications need to be created")
        for app in applications_to_create:
            assert self.is_managed_application(app), f"About to create an aplication {app} I'm not supposed to manage"
            cgids = []
            print(f"  Creating application {app}")
            for cg in self.zcfg["applications"][app]["connector_groups"]:
                cgids.append(self.scm_client.connector_groups[cg]["oid"])
            oidsstr = ",".join(cgids)
            self.scm_client.createZTNAApplication(app, oidsstr, "80")
        self.scm_client.refreshZTNAApplications()

    def manage_applications_group_assignment(self):
        if self.zcfg["applications"] is None:
            return
        applications = self.zcfg["applications"]
        print("Verifying applications mapping to connector groups")
        for app in applications:
            assert self.is_managed_application(app), f" About to manage an aplication {app} I'm not supposed to manage"
            cgids = []
            cgs = self.zcfg["applications"][app]["connector_groups"]
            assert cgs!=None, "Application must be assigned to connector group"
            for cg in cgs:
                cgids.append(self.scm_client.connector_groups[cg]["oid"])
            oidsstr = ",".join(cgids)
            existing_groups = self.scm_client.applications[app]["group"].split(",")
            if set(cgids)!=set(existing_groups):
                print(f" App {app} is different, updating")
                self.scm_client.updateZTNAApplication(self.scm_client.applications[app]["oid"], app, oidsstr, "80")

    def manage_applications_delete(self):
        print("Verifying if apps need to be deleted")
        for app in self.scm_client.applications.keys():
            if not self.is_managed_application(app):
                continue
            if self.zcfg["applications"] is not None and app in self.zcfg["applications"]:
                continue
            print(f"  Deleting application {app}")
            oid = self.scm_client.applications[app]["oid"]
            self.scm_client.deleteZTNAApplication(oid)

    def manage_connector_groups_create(self):
        connector_groups_to_create = set(self.zcfg["connector_groups"]).difference(self.scm_client.connector_groups.keys())
        print("Verifying if connector groups need to be created")
        for cg in connector_groups_to_create:
            assert self.is_managed_connector_group(cg), f"About to create a connector group {cg} I'm not supposed to manage"
            print(f"  Creating {cg}")
            try:
                desc = self.zcfg["connector_groups"][cg].get("description", "")
            except:
                desc = ""
            self.scm_client.createZTNAConnectorGroup(cg, desc)
        self.scm_client.refreshZTNAConnectorGroups()

    def manage_connector_groups_delete(self):
        cg_existing_managed = self.get_existing_managed_connector_groups()
        connector_groups_to_delete = set(cg_existing_managed).difference(self.zcfg["connector_groups"])
        print("Verifying if connector groups need to be deleted")
        for cg in connector_groups_to_delete:
            assert self.is_managed_connector_group(cg), f"About to delete a connector group {cg} I'm not supposed to manage"
            print(f"  Deleting {cg}")
            oid = self.scm_client.connector_groups[cg]["oid"]
            self.scm_client.deleteZTNAConnectorGroup(oid)

    def manage_connectors_create(self):
        cg_existing_managed = self.get_existing_managed_connector_groups()
        new_connectors = []
        print("Verifying if connectors need to be created")
        for cg in cg_existing_managed:
            try:
                conns = self.zcfg["connector_groups"][cg]["connectors"]
            except:
                # no connectors
                continue
            if conns is None:
                # no connectors
                continue
            for conn in conns:
                if conn in self.scm_client.connectors:
                    continue
                assert self.is_managed_connector(conn), f"About to create a connector {conn} I'm not supposed to manage"
                print(f"  Creating connector {conn} in {cg}")
                cgid = self.scm_client.connector_groups[cg]["oid"]
                self.scm_client.createZTNAConnector(conn, cgid)
                new_connectors.append(conn)
        self.scm_client.refreshZTNAConnectors()
        if len(new_connectors)==0:
            return
        print("Creating secrets")
        for conn in new_connectors:
            conn_d = self.scm_client.connectors[conn]
            print(f"  Creating secret for {conn}")
            self.azure_vault_client.setZTNASecret(conn, conn_d["token_active"], conn_d["token_secret"])


    def manage_connectors_delete(self):
        connectors_existing_managed = self.get_existing_managed_connectors()
        cg_existing_managed = self.get_existing_managed_connector_groups()
        connectors_need_to_exist = []
        print("Verifying if connectors need to be deleted")
        for cg in cg_existing_managed:
            try:
                connectors_need_to_exist += self.zcfg["connector_groups"][cg]["connectors"]
            except:
                # no connectors
                pass
        for conn in connectors_existing_managed:
            if not conn in connectors_need_to_exist:
                assert self.is_managed_connector(conn), f"About to delete a connector {conn} I'm not supposed to manage"
                print(f"  Deleting connector {conn}")
                oid = self.scm_client.connectors[conn]["oid"]
                self.scm_client.deleteZTNAConnector(oid)


    def _create_rule_and_address(self, app, source_user, snippet):
        address = {
            "snippet": snippet,
            "name": app,
            "fqdn": app,
        }
        try:
            print(f"  Creating address for {app}")
            self.scm_client.address.create(address)
        except NameNotUniqueError as e:
            print(f"  Address object {app} already exists")
        rule = {
            "snippet": snippet,
            "name": app,
            "from_": ["any"],
            "to_": ["any"],
            "source": ["any"],
            "source_user": source_user,
            "destination": [app],
            "application": ["any"],
            "service": ["application-default"],
            "action": "allow",
            "category": "any",
            "log_setting": 'Cortex Data Lake',
            "log_end": True,
            "profile_setting": {
                "group": ["best-practice"]
            },
        }
        print(f"  Creating rule for {app}")
        self.scm_client.security_rule.create(rule)

    def manage_rules_create(self):
        print("Verifying if rules need to be created")
        if self.zcfg["applications"] is None:
            return
        for app,app_def in self.zcfg["applications"].items():
            source_user = app_def.get('source_user', ["any"])
            existing_rules = self.scm_client.security_rule.list(snippet=SNIPPET, exact_match=True)
            for rule in existing_rules:
                if rule.name==app:
                    # print(f"Rule for {app} already exists")
                    break
            else:
                print(f" Creating rule and address for {app}")
                self._create_rule_and_address(app, source_user, SNIPPET)
        return 

    def manage_rules_update(self):
        print("Verifying if rules need to be updated")
        if self.zcfg["applications"] is None:
            return
        existing_rules = self.scm_client.security_rule.list(snippet=SNIPPET, exact_match=True)
        for rule in existing_rules:
            app = rule.name
            existing_rule_users = rule.source_user
            desired_rule_users =  self.zcfg["applications"][app].get('source_user', ["any"])
            if set(existing_rule_users)==set(desired_rule_users):
                print(f" {app} is correct")
                continue
            print(f" {app} updating")
            rule.source_user = desired_rule_users
            self.scm_client.security_rule.update(rule)
        return

    def manage_rules_delete(self):
        print("Verifying if rules need to be deleted")
        existing_rules = self.scm_client.security_rule.list(snippet=SNIPPET, exact_match=True)
        for rule in existing_rules:
            app = rule.name
            if app in self.zcfg["applications"]:
                continue
            print(f"  Deleting rule for app {app}")
            oid = rule.id
            self.scm_client.security_rule.delete(object_id=oid)
        existing_addresses = self.scm_client.address.list(snippet=SNIPPET, exact_match=True)
        for address in existing_addresses:
            app = address.name
            if app in self.zcfg["applications"]:
                continue
            print(f"  Deleting address object for app {app}")
            obj = self.scm_client.address.fetch(name=app, snippet=SNIPPET)
            oid = obj.id
            self.scm_client.address.delete(object_id=oid)

    def go(self):
        self.scm_client.refreshZTNAConnectors()
        self.scm_client.refreshZTNAConnectorGroups()
        self.scm_client.refreshZTNAApplications()
        self.manage_connector_groups_create()
        self.manage_connectors_create()
        self.manage_applications_create()
        self.manage_applications_group_assignment()
        self.manage_rules_create()
        self.manage_rules_delete()
        self.manage_applications_delete()
        self.manage_rules_update()
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


if __name__ == '__main__':
    sys.exit(main())
