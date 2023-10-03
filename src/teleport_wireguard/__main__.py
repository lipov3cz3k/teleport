import argparse
import logging
import os

from teleport_wireguard.teleport import (
    connect_device,
    generate_client_hint,
    get_device_token,
)

parser = argparse.ArgumentParser(description="Unofficial AmpliFi Teleport client")

parser.add_argument("--pin", help="PIN from the AmpliFi app, eg. AB123")
parser.add_argument(
    "--uuid-file",
    default="teleport_uuid",
    help="File to store client UUID in. "
    "Can be shared between different tokens. (default: teleport_uuid)",
)
parser.add_argument(
    "--token-file",
    default="teleport_token_0",
    help="File to store router token in (default: teleport_token_0)",
)
parser.add_argument("--verbose", "-v", action="count")

args = parser.parse_args()

if args.verbose:
    logging.basicConfig(level=logging.DEBUG)

deviceToken = None
if os.path.isfile(args.token_file):
    if args.pin:
        parser.error(
            "Token file %s already exists, please choose a different "
            "output file if you want to generate a new token or omit --pin."
            % args.token_file
        )
    with open(args.token_file) as f:
        deviceToken = f.readlines()[0]
else:
    if not args.pin:
        parser.error("Missing token file, please enter a new PIN using --pin.")
    if os.path.isfile(args.uuid_file):
        with open(args.uuid_file) as f:
            clientHint = f.readlines()[0]
    else:
        with open(args.uuid_file, mode="w") as f:
            clientHint = generate_client_hint()
            f.write(clientHint)
    try:
        deviceToken = get_device_token(clientHint, args.pin)
    except Exception as e:
        logging.error(e)
        exit(1)
    with open(args.token_file, mode="w") as f:
        f.write(deviceToken)

try:
    print(connect_device(deviceToken))
except Exception as e:
    logging.error(e)
    exit(1)
