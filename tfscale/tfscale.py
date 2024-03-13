#!/usr/bin/env python3
import argparse
import base64
import copy
import datetime
import json
import re
import sys
import time


def security_rule(name):
  return {
    "name": name,
    "source_zones": ["any"],
    "source_addresses": ["any"],
    "source_users": ["any"],
    "destination_zones": ["any"],
    "destination_addresses": ["any"],
    "applications": ["any"],
    "services": ["application-default"],
    "categories": ["any"],
    "action": "allow",
  }

def generate_panos_security_rule_group():
  psrg = {
     "resource": {
        "panos_device_group": {
          "perf1": {
            "name": "perf1",
            "lifecycle": {
              "create_before_destroy": "true",
            },
          },
        },
        "panos_security_rule_group": {
           "perf1": {
              "device_group": "${resource.panos_device_group.perf1.name}",
              "position_keyword": "top",
              "rule": []
           }
        }
      }
  }
  for i in range(1,1000):
    nsr = security_rule("dummy-{:04}".format(i))
    psrg["resource"]["panos_security_rule_group"]["perf1"]["rule"].append(nsr)
  with open("panorama1.tf.json", "w") as tfj:
    tfj.write(json.dumps(psrg))


def main():
   generate_panos_security_rule_group()


if __name__ == '__main__':
    sys.exit(main())
