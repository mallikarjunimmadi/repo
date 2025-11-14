#!/bin/python

import json
import sys
import argparse
import re
import socket
from collections import Counter

def is_valid_ip_address(ip):
    try:
        # Detecting an IPv4 address.
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            # Detecting an IPv6 address.
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

def process_sans(subject_alt_names):
    invalid_san_values = []
    formatted_sans_values = []
    fqdn_regex = re.compile(
        r'^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+(?:(?!-)[A-Za-z]{2,63}(?<!-))$'
    )

    short_hostname_regex = re.compile(
        r'^(?=.{1,63}$)(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-_]*[A-Za-z0-9])$'
    )

    for san_value in subject_alt_names:
        # trim leading and trailing spaces
        trimed_san = san_value.strip()

        # remove *. prefix for valdiation check
        validation_san = trimed_san
        if validation_san.startswith("*."):
            validation_san = validation_san[2:]
        if is_valid_ip_address(trimed_san):
            if trimed_san == "::1":
                trimed_san = ":1"
            formatted_sans_values.append('IP:%s' % trimed_san)
        elif bool(fqdn_regex.match(validation_san)):
            formatted_sans_values.append('DNS:%s' % trimed_san)
        elif bool(short_hostname_regex.match(validation_san)):
            formatted_sans_values.append('DNS:%s' % trimed_san)
        else:
            invalid_san_values.append(trimed_san)
    return formatted_sans_values, invalid_san_values

def check_san_validity_in_cert(certificate, dup, invalid, in_and_dup, verbose=False):

    #def get_duplicates(values):
    #    counts = Counter(values)
    #    return [value for value, count in counts.items() if count > 1]

    sans = certificate.get('certificate', {}).get("subject_alt_names",[])
    if sans:
        #if verbose:
        #    print("=" * 60)
        #    print(f'Processing SAN for cert: {certificate.get("name")}')
        formatted_sans_values, invalid_san_values = process_sans(sans)
        error_message_invalid = ""
        #error_message_duplicate = ""
        if invalid_san_values:
            error_message_invalid += f"Invalid SAN values found for certificate: {invalid_san_values}."
        #if formatted_sans_values:
        #    duplicates = get_duplicates(formatted_sans_values)
        #    if duplicates:
        #        error_message_duplicate += f"Duplicate SAN values found for certificate: {duplicates}."
        #if error_message_invalid and error_message_duplicate:
        #    in_and_dup.append(certificate.get("name"))
        #    if verbose:
        #        print(error_message_duplicate)
        #        print(error_message_invalid)
        if error_message_invalid:
            #print("Found Invalid SAN values:")
            invalid.append(certificate.get("name"))
            if verbose:
                print("=" * 60)
                print(f'Processing SAN for cert: {certificate.get("name")}')
                print(error_message_invalid)
        #if error_message_duplicate and not error_message_invalid:
            #print("Found Duplicate SAN values:")
        #    dup.append(certificate.get("name"))
        #    if verbose:
        #        print(error_message_duplicate)
        #if error_message_invalid == "":
        #    if verbose:
        #        print(f'Certificate {certificate.get("name")} has no offending values.')
        #print("=" * 60)
    return dup, invalid, in_and_dup

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, required=True)
    parser.add_argument('--verbose', action="store_true")
    args = parser.parse_args()
    config_file = args.config
    v = args.verbose
    try:
        with open(config_file, 'r', encoding='utf-8') as file:
            data = json.load(file)
    except FileNotFoundError:
        raise Exception(f"File not found: {config_file}")
    except json.JSONDecodeError as e:
        raise Exception(f"Invalid JSON format in file '{config_file}': {e}")
    except Exception as e:
        raise Exception(f"An unexpected error occurred while loading '{config_file}': {e}")

    ssl_certs = data['SSLKeyAndCertificate']
    dup = []
    invalid = []
    in_and_dup = []
    for s in ssl_certs:
        dup, invalid, in_and_dup = check_san_validity_in_cert(s, dup, invalid, in_and_dup, v)
    if v:
        print("=" * 60)
    #if in_and_dup != []:
    #    print(f'There are {len(in_and_dup)} certificates with both duplicate and invalid SAN values.')
    #    print(in_and_dup)
    #if dup != []:
    #    print(f'There are {len(dup)} certificates with duplicate SAN values.')
    #    print(dup)
    if invalid != []:
        print(f'There are {len(invalid)} certificates with invalid SAN values.')
        print(invalid)
    if in_and_dup == [] and dup == [] and invalid == []:
        print('There are no offending certificates in the configuration.')




if __name__ == "__main__":
    main()