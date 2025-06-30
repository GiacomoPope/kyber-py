import sys
import getopt
from kyber_py.ml_kem.pkcs import (
    ek_from_pem,
    ek_from_der,
)


def help_msg():
    print(
        f"""Usage: {sys.argv[0]} [options]
 --ek FILE       Encapsulation key file name
 --ek-form FORM  Encapsulation key format name: "DER" or "PEM, with "PEM"
                 being the default.
 --secret FILE   Name of file to write the derived secret to
 --ciphertext FILE Name of file to write the ciphertext to
 --help          This message
"""
    )


def main():
    ek_file = None
    ek_form = "PEM"
    secret_file = None
    ciphertext_file = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(
        argv,
        "",
        ["ek=", "ek-form=", "secret=", "ciphertext=", "help"],
    )

    for opt, arg in opts:
        if opt == "--ek":
            ek_file = arg
        elif opt == "--ek-form":
            ek_form = arg
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

    if not ek_file:
        print("Specify encapsulation key name with --ek option")
        help_msg()
        sys.exit(1)

    if not secret_file:
        print("Specify file name to write the derived secret to")
        help_msg()
        sys.exit(1)

    if not ciphertext_file:
        print("Specify file name to write the ciphertext to")
        help_msg()
        sys.exit(1)

    if ek_form == "PEM":
        ek_dec_func = ek_from_pem
    elif ek_form == "DER":
        ek_dec_func = ek_from_der
    else:
        print(f"Wrong name of key format: {ek_form}")
        help_msg()
        sys.exit(1)

    with open(ek_file, "rb") as file:
        kem, ek = ek_dec_func(file.read())

    secret, ciphertext = kem.encaps(ek)

    with open(secret_file, "wb") as file:
        file.write(secret)

    with open(ciphertext_file, "wb") as file:
        file.write(ciphertext)


if __name__ == "__main__":
    main()
