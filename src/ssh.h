/* ssh.h
 *
 */

#ifndef LSH_SSH_H_INCLUDED
#define LSH_SSH_H_INCLUDED

/* 1-19 Transport layer generic (e.g. disconnect, ignore, debug, etc) */

#define SSH_MSG_DISCONNECT             1
#define SSH_MSG_IGNORE                 2
#define SSH_MSG_UNIMPLEMENTED          3
#define SSH_MSG_DEBUG                  4
#define SSH_MSG_SERVICE_REQUEST        5
#define SSH_MSG_SERVICE_ACCEPT         6

/* 20-29 Algorithm negotiation */

#define SSH_MSG_KEXINIT                20
#define SSH_MSG_NEWKEYS                21

/* 30-49 Key exchange method specific (numbers can be reused for
 *       different authentication methods) */

#define SSH_MSG_KEXDH_INIT             30
#define SSH_MSG_KEXDH_REPLY            31

/* 50-59 User authentication generic */

#define SSH_MSG_USERAUTH_REQUEST 50 
#define SSH_MSG_USERAUTH_FAILURE 51 
#define SSH_MSG_USERAUTH_SUCCESS 52 
#define SSH_MSG_USERAUTH_BANNER 53

/* 60-79 User authentication method specific (numbers can be reused
 * for different authentication methods) */

#define SSH_MSG_USERAUTH_PK_OK 60
#define SSH_MSG_USERAUTH_PASSWD_CHANGEREQ 60

/* 80-89 Connection protocol generic */

#define SSH_MSG_GLOBAL_REQUEST 80 
#define SSH_MSG_REQUEST_SUCCESS 81 
#define SSH_MSG_REQUEST_FAILURE 82 

/* 90-127 Channel related messages */

#define SSH_MSG_CHANNEL_OPEN 90 
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91 
#define SSH_MSG_CHANNEL_OPEN_FAILURE 92 
#define SSH_MSG_CHANNEL_WINDOW_ADJUST 93 
#define SSH_MSG_CHANNEL_DATA 94 
#define SSH_MSG_CHANNEL_EXTENDED_DATA 95 
#define SSH_MSG_CHANNEL_EOF 96 
#define SSH_MSG_CHANNEL_CLOSE 97 
#define SSH_MSG_CHANNEL_REQUEST 98 
#define SSH_MSG_CHANNEL_SUCCESS 99 
#define SSH_MSG_CHANNEL_FAILURE 100

/* 128-191 Reserved */
/* 192-255 Local extensions */

/* Disconnecting */

#define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT      1
#define SSH_DISCONNECT_PROTOCOL_ERROR                   2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED              3
#define SSH_DISCONNECT_HOST_AUTHENTICATION_FAILED       4
#define SSH_DISCONNECT_MAC_ERROR                        5
#define SSH_DISCONNECT_COMPRESSION_ERROR                6
#define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE            7
#define SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED   8
#define SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE          9
#define SSH_DISCONNECT_CONNECTION_LOST                 10
#define SSH_DISCONNECT_BY_APPLICATION                  11

/* Channels */
#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED 1 
#define SSH_OPEN_CONNECT_FAILED 2 
#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE 3 
#define SSH_OPEN_RESOURCE_SHORTAGE 4

/* Extended data */

#define SSH_EXTENDED_DATA_STDERR 1

/* Limits */

/* Default max length of packet payload */
/* FIXME: When compression is implemented, the 35000 limit
 * on total packet length must also be considered. */
#define SSH_MAX_PACKET 0x8000

#endif /* LSH_SSH_H_INCLUDED */
