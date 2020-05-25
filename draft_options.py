import argparse

import cryptography as cr

def main(**args):
    #using arguments
    print(args['integer'])
    print(args['important_arg'])

    if args['algorithm'] == "":
        print("Algorithm: "+args['algorithm'] )







if __name__ == '__main__':
    #Terminal arguments.
    # to run python name.py --integer <integer value>
    #Example:
    parser = argparse.ArgumentParser()
    parser.add_argument('--integer', type=int, default=0, help='short descritpion of argument')
    parser.add_argument('--important_arg', type=str, default="Hello there",required=False ,help="important argument")
    #
    parser.add_argument('-a','--algorithm', type=str, default="RSA", required=False, help="Encryption algorithm")
    parser.add_argument('-l', '--length', type=int, default=2048, required=False, help="Length of key used to encrypt.")
    parser.add_argument('-f','--file',type=str, required=True, help="Path to file.")
    #Arguments for our little script
    #
    parser.set_defaults()
    args = parser.parse_args()
    args = vars(args)
    main(**args)
