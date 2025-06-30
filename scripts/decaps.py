import sys
import getopt
from kyber_py.ml_kem.pkcs import (
    dk_from_pem,
    dk_from_der,
)


def help_msg():
    print(
        f"""Usage: {sys.argv[0]} [options]
 --dk FILE       Decapsulation key file name
 --dk-form FORM  Decapsulation key format name: "DER" or "PEM, with "PEM"
                 being the default.
 --secret FILE   Name of file to write the derived secret to
 --ciphertext FILE Name of file to read the ciphertext from
 --help          This message
"""
    )


def main():
    dk_file = None
    dk_form = "PEM"
    secret_file = None
    ciphertext_file = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(
        argv,
        "",
        ["dk=", "dk-form=", "secret=", "ciphertext=", "help"],
    )

    for opt, arg in opts:
        if opt == "--dk":
            dk_file = arg
        elif opt == "--dk-form":
            dk_form = arg
        elif opt == "--secret":
            secret_file = arg
        elif opt == "--ciphertext":
            ciphertext_file = arg
        elif opt == "--help":
            help_msg()
            sys.exit(0)
        else:
            print(f"Unrecognised option: {opt}")
            sys.exit(1)

    if args:
        print(f"Unrecognised options: {args}")

    if not dk_file:
        print("Specify encapsulation key name with --dk option")
        help_msg()
        sys.exit(1)

    if not secret_file:
        print("Specify file name to write the derived secret to")
        help_msg()
        sys.exit(1)

    if not ciphertext_file:
        print("Specify file name to read the ciphertext from")
        help_msg()
        sys.exit(1)

    if dk_form == "PEM":
        dk_dec_func = dk_from_pem
    elif dk_form == "DER":
        dk_dec_func = dk_from_der
    else:
        print(f"Wrong name of key format: {dk_form}")
        help_msg()
        sys.exit(1)

    with open(dk_file, "rb") as file:
        kem, dk, _, _ = dk_dec_func(file.read())

    with open(ciphertext_file, "rb") as file:
        ciphertext = file.read()

    secret = kem.decaps(dk, ciphertext)

    with open(secret_file, "wb") as file:
        file.write(secret)


if __name__ == "__main__":
    main()
