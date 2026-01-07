#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

void help(char *name) {
    printf("Usage: %s -k key.pem -s secret-out.pem -c ciphertext-out.pem\n",
           name);
    printf("\n");
    printf(" -k file  File with the encapsulation key\n");
    printf(" -s file  File to write the secret\n");
    printf(" -c file  File to write the ciphertext\n");
}

int
main(int argc, char** argv) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pub_key = NULL;
    size_t secretlen = 0, outlen = 0;
    unsigned char *out = NULL, *secret = NULL;
    char *key_file_name = NULL, *secret_file_name = NULL;
    char *ciphertext_file_name = NULL;
    int sec_fd = -1, cip_fd = -1;
    FILE *fp;
    int opt;
    int result = 0;

    while ((opt = getopt(argc, argv, "k:s:c:")) != -1 ) {
        switch (opt) {
            case 'k':
                key_file_name = optarg;
                break;
            case 's':
                secret_file_name = optarg;
                break;
            case 'c':
                ciphertext_file_name = optarg;
                break;
            default:
                fprintf(stderr, "Unknown option: %c\n", opt);
                help(argv[0]);
                exit(1);
                break;
        }
    }

    if (key_file_name == NULL || secret_file_name == NULL ||
            ciphertext_file_name == NULL) {
        fprintf(stderr, "All options must be specified!\n");
        help(argv[0]);
        exit(1);
    }

    if ((sec_fd = open(secret_file_name, O_WRONLY|O_TRUNC|O_CREAT, 0666))
            == -1){
        fprintf(stderr, "can't open output file: %s\n", secret_file_name);
        goto err;
    }

    if ((cip_fd = open(ciphertext_file_name,
                  O_WRONLY|O_TRUNC|O_CREAT, 0666)) == -1) {
        fprintf(stderr, "Can't open output file: %s\n", ciphertext_file_name);
        goto err;
    }

    fp = fopen(key_file_name, "r");
    if (!fp) {
        fprintf(stderr, "Can't open key file: %s\n", key_file_name);
        goto err;
    }

    //if ((pub_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL) {
    if ((pub_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL)) == NULL) {
        fprintf(stderr, "Can't read parse private key\n");
        goto err;
    }

    if (fclose(fp) != 0) {
        fprintf(stderr, "can't close key file\n");
        goto err;
    }
    fp = NULL;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pub_key, NULL);
    if (ctx == NULL) {
        fprintf(stderr, "Can't init key context\n");
        goto err;
    }
    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) {
        fprintf(stderr, "Can't init encapsulation\n");
        goto err;
    }

    /* Determine buffer length */
    if (EVP_PKEY_encapsulate(ctx, NULL, &outlen, NULL, &secretlen) <= 0) {
        fprintf(stderr, "Can't fetch memory size\n");
    }

    out = OPENSSL_malloc(outlen);
    secret = OPENSSL_malloc(secretlen);
    if (out == NULL || secret == NULL) {
        fprintf(stderr, "memory allocation failure\n");
        goto err;
    }

    /*
     * The generated 'secret' can be used as key material.
     * The encapsulated 'out' can be sent to another party who can
     * decapsulate it using their private key to retrieve the 'secret'.
     */
    if (EVP_PKEY_encapsulate(ctx, out, &outlen, secret, &secretlen) <= 0) {
        fprintf(stderr, "Encapsulation failure\n");
        goto err;
    }

    if (write(sec_fd, secret, secretlen) <= 0) {
        fprintf(stderr, "Error writing secret\n");
        goto err;
    }

    if (write(cip_fd, out, outlen) <= 0) {
        fprintf(stderr, "Error writing ciphertext\n");
        goto err;
    }

    printf("done\n");

    goto out;

err:
    result = 1;
    fprintf(stderr, "operation failed\n");
    ERR_print_errors_fp(stderr);

out:
    if (sec_fd >= 0)
        close(sec_fd);
    if (cip_fd >= 0)
        close(cip_fd);
    if (fp)
        fclose(fp);
    if (out)
        OPENSSL_free(out);
    if (secret)
        OPENSSL_free(secret);

    return result;
}
