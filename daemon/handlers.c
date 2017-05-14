#include "handlers.h"
#include "logger.h"

/**
 * Handler for SYS_delegatortest. Simply sets the return value to 0
 * and sets errno to the given value.
 */
void handle_delegatortest(struct sip_request_test *request, struct sip_response *response) {
	response->rv = 0;
	response->err = request->err;
}

/**
 * Handler for faccessat.
 */
void handle_faccessat(struct sip_request_faccessat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for fchmodat.
 */
void handle_fchmodat(struct sip_request_fchmodat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for fchownat.
 */
void handle_fchownat(struct sip_request_fchownat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for fstatat.
 */
void handle_fstatat(struct sip_request_fstatat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for statvfs.
 */
void handle_statvfs(struct sip_request_statvfs *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for linkat.
 */
void handle_linkat(struct sip_request_linkat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for mkdirat.
 */
void handle_mkdirat(struct sip_request_mkdirat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for mknodat.
 */
void handle_mknodat(struct sip_request_mknodat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for openat.
 */
void handle_openat(struct sip_request_openat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for renameat2.
 */
void handle_renameat2(struct sip_request_renameat2 *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for symlinkat.
 */
void handle_symlinkat(struct sip_request_symlinkat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for unlinkat.
 */
void handle_unlinkat(struct sip_request_unlinkat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for utime.
 */
void handle_utime(struct sip_request_utime *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for utimes.
 */
void handle_utimes(struct sip_request_utimes *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for utimensat.
 */
void handle_utimensat(struct sip_request_utimensat *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for bind. Note that the client side expects this handler to create a NEW
 * socket, bind it to the given address, and return the new socket's descriptor.
 */
void handle_bind(struct sip_request_bind *request, struct sip_response *response) {
	// TODO
}

/**
 * Handler for connect. Note that the client side expects this handler to create a NEW
 * socket, connect it to the given address, and return the new socket's descriptor.
 */
void sip_request_connect(struct sip_request_connect *request, struct sip_response *response) {
	// TODO
}