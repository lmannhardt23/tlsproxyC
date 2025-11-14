/*
 * Demo based on Mbed TLS's ssl_client1.c, which is Copyright The Mbed
 * TLS Contributors and distributed under the Apache-2.0 license.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "certs.h"
#include "mbedtls/build_info.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

int main(int argc, char *argv[])
{
	const char *PORT1, *HOST, *PORT2;
	int ret = 1, len;
	int exit_code = EXIT_FAILURE;
	mbedtls_net_context server_fd, client_fd, listen_fd;
	uint32_t flags;
	unsigned char buf[1024];
	const char *pers = "ssl_client1";
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;

	char http_req[102401]; //max bytes for request plus null terminator 
	int req_len = 0;

	if (argc != 4) {
		fprintf(stderr, "usage: %s PORT HOST PORT\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	PORT1 = argv[1];
	HOST = argv[2];
	PORT2 = argv[3];

	/*
	* 0. Initialize the random-number generator and the session data.
	*/
	mbedtls_net_init(&server_fd);
	mbedtls_net_init(&client_fd);
	mbedtls_net_init(&listen_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	printf("\n  . Seeding the random number generator...");
	fflush(stdout);

	mbedtls_entropy_init(&entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers))) != 0) {
		printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
		goto exit;
	}

	printf(" ok\n");

	/*
	 * 0. Load certificates.
	 */
	printf("  . Loading the CA root certificate ...");
	fflush(stdout);

	ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len);
	if(ret < 0) {
		printf(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", (unsigned int) -ret);
		goto exit;
	}

	printf(" ok (%d skipped)\n", ret);

	/*
	 * 1. Start the connection.
	 */
	printf("  . Connecting to tcp/%s/%s...", HOST, PORT2);
	fflush(stdout);

	if ((ret = mbedtls_net_connect(&server_fd, HOST, PORT2, MBEDTLS_NET_PROTO_TCP)) != 0) {
		printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
		goto exit;
	}

	printf(" ok\n");

	/*
	 * 2. Setup stuff.
	 */
	printf("  . Setting up the SSL/TLS structure...");
	fflush(stdout);

	if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
		goto exit;
	}

	printf(" ok\n");

	/*
	 * OPTIONAL is not optimal for security,
	 * but makes interop easier in this simplified example
	 */
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
		printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
		goto exit;
	}

	if ((ret = mbedtls_ssl_set_hostname(&ssl, HOST)) != 0) {
		printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
		goto exit;
	}

	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	/*
	 * 4. TLS handshake.
	 */
	printf("  . Performing the SSL/TLS handshake...");
	fflush(stdout);

	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int) -ret);
			goto exit;
		}
	}

	printf(" ok\n");

	/*
	 * 5. Verify the server certificate.
	 */
	printf("  . Verifying peer X.509 certificate...");

	/* In real life, we probably want to bail out when ret != 0 */
	if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
		char vrfy_buf[512];

		printf(" failed\n");
		mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
		printf("%s\n", vrfy_buf);
	} else {
		printf(" ok\n");
	}

	/*
	 * 3. Write the GET request.
	 */
	printf("  > Write to server:");
	fflush(stdout);

	//remove request replace with bind and listen
	//len = sprintf((char *) buf, GET_REQUEST);

	if((ret = mbedtls_net_bind(&listen_fd, NULL, PORT1, MBEDTLS_NET_PROTO_TCP)) != 0) {
		printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
		goto exit;
	}
	//if this executed, we have connected successfully
	printf(" ok (listening on %s)\n", PORT1);
	printf("Waiting for connection on %s\n", PORT1);

	//check connection
	if((ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL)) != 0){
		printf(" failed\n ! mbedtls_net_accept returned %d\n\n", ret);
		goto exit;
	}
	//connect success
	printf(" . Client Connected.");

	//Read from client until \r\n\r\n or buffer is full
	req_len = 0;
	memset(http_req, 0, sizeof(http_req));
	while (req_len < 10241){
		int toret = mbedtls_net_recv(&client_fd, http_req + req_len, 1);
		if(toret <= 0){
			if(toret == 0){
				printf("Closed Connection");
			}else{
				printf("mbedtls_net_recv returned %d\n", toret);
			}
			break;
		}
		req_len += toret;
		http_req[req_len] = '\0';
		if(req_len >= 4 && strstr(http_req, "\r\n\r\n") != NULL){
			break;
		}
	}
	if(req_len == 0){
		printf("No data read to return.");
	}

	//Send to HTTP server
	{
		int total = 0;
		while(total < req_len){
			ret = mbedtls_ssl_write(&ssl, http_req + total, req_len - total);
			if(ret > 0){
				total += ret; //update written bites
				continue;
			}
			if(ret == MBEDTLS_ERR_SSL_WANT_READ || MBEDTLS_ERR_SSL_WANT_WRITE){
				continue;
			}
			printf(" failed\n ! mbedtls_ssl_write returned %d\n\n", ret);
			goto exit;
		}
	}

	/*
	 * 7. Read the HTTP response
	 */
	printf("  < Read from server:");
	fflush(stdout);

	req_len = 0;
	memset(http_req, 0, sizeof(http_req));
	do {
		len = sizeof(buf) - 1;
		memset(buf, 0, sizeof(buf));
		ret = mbedtls_ssl_read(&ssl, buf, len);

		if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			continue;
		}

		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			break;
		}

		if (ret < 0) {
			printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
			break;
		}

		if (ret == 0) {
			printf("\n\nEOF\n\n");
			break;
		}
		len = ret;

		{
			int sent = 0;
			while(sent < len){ //send bytes to client
				int sret = mbedtls_net_send(&client_fd, buf + sent, len - sent);
				if(sret = 0){
					printf("failed ! mbedtls_net_send returned %d\n\n", sret);
				}
				sent += sret;
			}
		}
	} while (true);

	mbedtls_ssl_close_notify(&ssl);

	exit_code = EXIT_SUCCESS;

exit:

	if (exit_code != EXIT_SUCCESS) {
		char error_buf[100];
		mbedtls_strerror(ret, error_buf, 100);
		printf("Last error was: %d - %s\n\n", ret, error_buf);
	}

	mbedtls_net_free(&server_fd);
        mbedtls_net_free(&client_fd);
        mbedtls_net_free(&listen_fd);
	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	exit(exit_code);
}
