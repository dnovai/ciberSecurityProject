import argparse
from mypackage import utilities


def main(a):

    if a.url is not None:
        if a.method == 'cloudflare':
            utilities.get_headers(a.url, a.method)
        elif a.method == 'dns':
            utilities.get_server_name(a.url)
        else:
            print('not recognized method!')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Say hello')
    parser.add_argument('-url', '--url', required=True, type=str, help='url to check')
    parser.add_argument('-method_cloudflare', '--method', required=True, default='dns', type=str,
                        help='Enter the method. "dns" or "headers"')
    args = parser.parse_args()

    main(args)
