import argparse
from mypackage import utilities
import random


def main(a):
    random.seed(a.random_seed)
    if a.action == 'ransomware':
        utilities.do_ransomware(a.path, a.path_to_excluded_files, a.random_seed)
        
    elif a.action == 'unransomware':
        utilities.undo_ransomware(a.path, a.path_to_excluded_files)
    
    else:
        pass

    print('ACTION: ', a.action)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Say hello')
    parser.add_argument('-path',
                        '--path', required=True, help='path to target directory (absolute path)')
    parser.add_argument('-path_to_excluded_files',
                        '--path_to_excluded_files', required=True, help='path to excluded files (absolute path)')
    parser.add_argument('-action', '--action', required=True, type=str,
                        help='action to do: "ransomware" or "unransomeware"')
    parser.add_argument('-random_seed', '--random_seed', default=10, type=int,
                        help='seed to generate random numbers for encryption')
    args = parser.parse_args()

    main(args)
