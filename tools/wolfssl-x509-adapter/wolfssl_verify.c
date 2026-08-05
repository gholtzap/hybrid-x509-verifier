/* Adapted from the Apache-2.0 paper artifact for arXiv:2607.20800. */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/version.h>
#include <stdio.h>
#include <string.h>

#ifdef WOLFSSL_DUAL_ALG_CERTS
#define MODE "mode2-dualalg"
#else
#define MODE "mode1-default"
#endif

int main(int argc, char **argv) {
    const char *scheme = "unknown";
    const char *root = NULL;
    const char *leaf = NULL;
    const char *cas[8];
    int nca = 0;

    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("wolfSSL %s %s\n", LIBWOLFSSL_VERSION_STRING, MODE);
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--scheme") == 0 && i + 1 < argc)
            scheme = argv[++i];
        else if (strcmp(argv[i], "--root") == 0 && i + 1 < argc)
            root = argv[++i];
        else if (strcmp(argv[i], "--leaf") == 0 && i + 1 < argc)
            leaf = argv[++i];
        else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc && nca < 8)
            cas[nca++] = argv[++i];
        else {
            fprintf(stderr, "invalid argument\n");
            return 2;
        }
    }
    if (root == NULL || leaf == NULL) {
        fprintf(stderr, "need --root and --leaf\n");
        return 2;
    }

    wolfSSL_Init();
    WOLFSSL_CERT_MANAGER *manager = wolfSSL_CertManagerNew();
    if (manager == NULL) {
        fprintf(stderr, "CertManagerNew failed\n");
        return 2;
    }
    int result = wolfSSL_CertManagerLoadCA(manager, root, NULL);
    const char *stage = "root";
    for (int i = 0; i < nca && result == WOLFSSL_SUCCESS; i++) {
        result = wolfSSL_CertManagerLoadCA(manager, cas[i], NULL);
        stage = "intermediate";
    }
    if (result != WOLFSSL_SUCCESS) {
        fprintf(stderr, "scheme=%s mode=%s stage=%s code=%d err=%s\n",
                scheme, MODE, stage, result, wolfSSL_ERR_reason_error_string(result));
        puts("{\"verdict\":\"unsupported\",\"trace\":[{\"operation\":\"load-ca-certificate\",\"target\":\"certificate-path\",\"algorithm\":null,\"outcome\":\"unsupported\"}],\"extensions\":[]}");
    } else {
        result = wolfSSL_CertManagerVerify(manager, leaf, WOLFSSL_FILETYPE_PEM);
        if (result == WOLFSSL_SUCCESS)
            puts("{\"verdict\":\"accept\",\"trace\":[{\"operation\":\"load-ca-certificate\",\"target\":\"certificate-path\",\"algorithm\":null,\"outcome\":\"pass\"},{\"operation\":\"verify-certificate-path\",\"target\":\"leaf\",\"algorithm\":null,\"outcome\":\"accept\"}],\"extensions\":[]}");
        else {
            fprintf(stderr, "scheme=%s mode=%s code=%d err=%s\n",
                    scheme, MODE, result, wolfSSL_ERR_reason_error_string(result));
            puts("{\"verdict\":\"reject\",\"trace\":[{\"operation\":\"load-ca-certificate\",\"target\":\"certificate-path\",\"algorithm\":null,\"outcome\":\"pass\"},{\"operation\":\"verify-certificate-path\",\"target\":\"leaf\",\"algorithm\":null,\"outcome\":\"reject\"}],\"extensions\":[]}");
        }
    }
    wolfSSL_CertManagerFree(manager);
    wolfSSL_Cleanup();
    return 0;
}
