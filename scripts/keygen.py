import sys
import getopt
import os
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

from kyber_py.ml_kem.pkcs import (
    ek_to_der,
    ek_to_pem,
    dk_to_der,
    dk_to_pem,
)


def help_msg():
    print(
        f"""Usage: {sys.argv[0]} [options]

 --dk FILE      Decapsulation key file name
 --dk-form FORM Decapsulation key format name: "DER" or "PEM", with "PEM"
                being the default.
 --dk-cont CONT Decapsulation key contents: "seed", "expanded", or "both",
                with "both" being the default.
 --ek FILE      Encapsulation key file name, none by default
 --ek-form FORM Encapsulation key format name: "DER" or "PEM", with "PEM"
                being the default.
 --kem NAME     Name of the KEM to use: ML-KEM-512, ML-KEM-768, or ML-KEM-1024
 --help         This message
"""
    )


def main():
    ek_file = None
    ek_form = "PEM"
    dk_file = None
    dk_form = "PEM"
    dk_cont = None
    kem = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(
        argv,
        "",
        ["dk=", "dk-form=", "dk-cont=", "ek=", "ek-form=", "kem=", "help"],
    )
    for opt, arg in opts:
        if opt == "--dk":
            dk_file = arg
        elif opt == "--dk-form":
            dk_form = arg
        elif opt == "--dk-cont":
            dk_cont = arg
        elif opt == "--ek":
            ek_file = arg
        elif opt == "--ek-form":
            ek_form = arg
        elif opt == "--kem":
            kem = arg
        elif opt == "--help":
            help_msg()
            sys.exit(0)
        else:
            print(f"unrecognised option: {opt}")
            sys.exit(1)

    if args:
        print(f"unrecognised options: {args}")
        sys.exit(1)

    if not dk_file:
        print("Specify output file with --dk option")
        help_msg()
        sys.exit(1)

    if not kem:
        print("Specify the kem to generate with --kem option")
        help_msg()
        sys.exit(1)

    if kem == "ML-KEM-512":
        kem = ML_KEM_512
    elif kem == "ML-KEM-768":
        kem = ML_KEM_768
    elif kem == "ML-KEM-1024":
        kem = ML_KEM_1024
    else:
        print(f"Unrecognised KEM name: {kem}")
        help_msg()
        sys.exit(1)

    if ek_form == "PEM":
        ek_out_func = ek_to_pem
    elif ek_form == "DER":
        ek_out_func = ek_to_der
    else:
        print(f"Unrecognised ek format: {ek_form}")
        help_msg()
        sys.exit(1)

    if dk_form == "PEM":
        dk_out_func = dk_to_pem
    elif dk_form == "DER":
        dk_out_func = dk_to_der
    else:
        print(f"Unrecognised dk format: {dk_form}")
        help_msg()
        sys.exit(1)

    seed = os.urandom(64)

    ek, dk = kem.key_derive(seed)

    with open(dk_file, "wb") as file:
        file.write(dk_out_func(kem, dk, seed, dk_cont))

    if ek_file:
        with open(ek_file, "wb") as file:
            file.write(ek_out_func(kem, ek))


if __name__ == "__main__":
    main()
