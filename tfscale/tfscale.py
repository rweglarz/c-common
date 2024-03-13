#!/usr/bin/env python3
import argparse
import base64
import copy
import datetime
import json
import re
import subprocess
import sys
import time

TFJ_FILE_NAME = "panorama.tf.json"
PLAN_FILE_NAME = "p1"



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



def generate_panos_security_rule_group(rule_count):
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
  for i in range(1, rule_count+1):
    nsr = security_rule("dummy-{:04}".format(i))
    psrg["resource"]["panos_security_rule_group"]["perf1"]["rule"].append(nsr)
  with open(TFJ_FILE_NAME, "w") as tfj:
    tfj.write(json.dumps(psrg))



def tf_plan():
    cmd = ['terraform', 'plan', '-out', PLAN_FILE_NAME]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("Plan stderr")
    print(r.stderr.decode())
    print("Plan stdout")
    print(r.stdout.decode())


def tf_destroy():
    cmd = ['terraform', 'plan', '-destroy', '-out', PLAN_FILE_NAME]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("Plan stderr")
    print(r.stderr.decode())
    print("Plan stdout")
    print(r.stdout.decode())


def tf_apply():
    cmd = ['terraform', 'apply', PLAN_FILE_NAME]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("Plan stderr")
    print(r.stderr.decode())
    print("Plan stdout")
    print(r.stdout.decode())



def time_function_exec(func, timing):
  timing['start'] = time.time()
  func()
  timing['end'] = time.time()



def main():
  timing = {
     "create_plan": {},
     "create_apply": {},
     "modify_plan": {},
     "modify_apply": {},
     "destroy_plan": {},
     "destroy_apply": {},
  }

  base_rules = 10
  extra_rules = round(0.1 * base_rules)
  generate_panos_security_rule_group(base_rules)
  time_function_exec(tf_plan,  timing['create_plan'])
  time_function_exec(tf_apply, timing['create_apply'])

  print("Taking a 10s break")
  time.sleep(10)

  generate_panos_security_rule_group(base_rules + extra_rules)
  time_function_exec(tf_plan,  timing['modify_plan'])
  time_function_exec(tf_apply, timing['modify_apply'])

  print("Taking a 10s break")
  time.sleep(10)

  time_function_exec(tf_destroy, timing['destroy_plan'])
  time_function_exec(tf_apply,   timing['destroy_apply'])

  print()
  print("====")
  print("Used {} and then {} rules".format(base_rules, extra_rules))
  for t,v in timing.items():
    t_diff = v['end'] - v['start']
    print("{:15} took {:2.0f}m {:2.0f}s".format(t, t_diff/60, t_diff%60))



if __name__ == '__main__':
    sys.exit(main())
