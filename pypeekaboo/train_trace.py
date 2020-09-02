import argparse
import os

from squirrelflow.squirrelflow import SquirrelFlow
from pypeekaboo import PyPeekaboo
from squirrel.squirrel import load_config

def train_peekaboo(trace_path):
    # parse the 
    pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('trace_path', type=str, help='Path to a peekaboo trace.')
    args = parser.parse_args()
    peekaboo = PyPeekaboo(args.trace_path)


    config = load_config('squirrelflow', 'squirrelflow.cfg')
    sf_hostname= config['squirrelflow']['conn']
    sf_port = config['squirrelflow']['port']
    squirrelflow = SquirrelFlow(sf_hostname, sf_port)

    insn_set = set()
    for addr in peekaboo.bytesmap:
        bytestring = ''.join(['{:02x}'.format(x) for x in peekaboo.bytesmap[addr]])
        insn_set.add(bytestring)
    insn_list = list(insn_set)
    print("Unique instructions: {}. Checking availability...".format(len(insn_list)))

    #print("Running with Group {}".format(i))
    #sublist = insn_list[400:1400]
    missing = squirrelflow.check_rules(peekaboo.arch_str, insn_list)
    if missing:
        print("Missing instructions: {}".format((len(missing))))
        squirrelflow.train_rules(peekaboo.arch_str, missing)



if __name__ == "__main__":
    main()
