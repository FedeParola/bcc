#!/usr/bin/python3

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('routes', help='Number of (/32) routes to generate',
                    type=int)
args = parser.parse_args()

with open('routes.csv', 'w') as routes:
  for i in range(args.routes):
    first = i & 0xff
    second = i >> 8 & 0xff
    third = i >> 16 & 0xff
    routes.write(f'10.{third}.{second}.{first};2.0.0.2\n')