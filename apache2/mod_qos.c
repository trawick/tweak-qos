/* -*-mode: c; indent-tabs-mode: nil; c-basic-offset: 2; -*-
 */

/**
 * Quality of service module for Apache Web Server.
 *
 * The Apache Web Servers requires threads and processes to serve
 * requests. Each TCP connection to the web server occupies one
 * thread or process. Sometimes, a server gets too busy to serve
 * every request due the lack of free processes or threads.
 *
 * This module implements control mechanisms that can provide
 * different priority to different requests.
 *
 * See http://opensource.adnovum.ch/mod_qos/ for further
 * details.
 *
 * Copyright (C) 2007-2014 Pascal Buchbinder
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is released under the GPL with the additional
 * exemption that compiling, linking, and/or using OpenSSL is allowed.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 */

/************************************************************************
 * Version
 ***********************************************************************/
static const char revision[] = "$Id: mod_qos.c,v 5.486 2014/03/24 19:42:38 pbuchbinder Exp $";
static const char g_revision[] = "10.30";

/************************************************************************
 * Includes
 ***********************************************************************/
/* std */
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

/* apache */
#include <httpd.h>
#include <http_main.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_connection.h>
#define CORE_PRIVATE
#include <http_config.h>
#include <http_log.h>
#include <util_filter.h>
#include <ap_mpm.h>
#include <scoreboard.h>
#include <ap_config.h>
#include <mpm_common.h>

/* apr / scrlib */
#include <pcre.h>
#include <apr_atomic.h>
#include <apr_strings.h>
#include <apr_file_info.h>
#include <apr_base64.h>
#include <apr_hooks.h>
#include <apr_lib.h>
#ifdef AP_NEED_SET_MUTEX_PERMS
#include <unixd.h>
#endif

/* mod_qos requires OpenSSL */
#include <openssl/rand.h>
#include <openssl/evp.h>

/* additional modules */
#include "mod_status.h"

/* this */
#ifdef QS_MOD_EXT_HOOKS
#include "mod_qos.h"
#endif

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(qos);
#endif

/************************************************************************
 * defines
 ***********************************************************************/
#define QOS_LOG_PFX(id)  "mod_qos("#id"): "
#define QOS_LOGD_PFX  "mod_qos(): "
#define QOS_RAN 10
#define QOS_MAX_AGE "3600"
#define QOS_COOKIE_NAME "MODQOS"
#define QOS_USER_TRACKING "mod_qos_user_id"
#define QOS_USER_TRACKING_NEW "QOS_USER_ID_NEW"
#define QOS_MILESTONE "mod_qos_milestone"
#define QOS_MILESTONE_TIMEOUT 3600
#define QOS_MILESTONE_COOKIE "QSSCD"
#define QS_SIM_IP_LEN 100
#define QS_USR_SPE "mod_qos::user"
#define QS_REC_COOKIE "mod_qos::gc"
#define QS_R010_ALREADY_BLOCKED "R010B"
#define QS_R012_ALREADY_BLOCKED "R012B"
#define QS_R013_ALREADY_BLOCKED "R013B"
#define QS_PKT_RATE_TH    3
#define QS_BW_SAMPLING_RATE 10
// split linear QS_SrvMaxConnPerIP* entry (conn->conn_ip) search:
#define QS_MEM_SEG 1

#ifndef QS_LOG_REPEAT
#define QS_LOG_REPEAT     20
#endif

#define QS_IP4IN6         "::ffff:"

#define QS_PARP_Q         "qos-parp-query"
#define QS_PARP_QUERY     "qos-query"
#define QS_PARP_PATH      "qos-path"
#define QS_PARP_LOC       "qos-loc"

#define QS_CONNID         "QS_ConnectionId"
#define QS_COUNTRY        "QS_Country"
#define QS_SERIALIZE      "QS_Serialize"
#define QS_ErrorNotes     "QS_ErrorNotes"
#define QS_BLOCK          "QS_Block"
#define QS_BLOCK_SEEN     "QS_Block_seen"
#define QS_LIMIT_DEFAULT  "QS_Limit"
#define QS_LIMIT_SEEN     "QS_Limit_seen"
#define QS_COUNTER_SUFFIX "_Counter"
#define QS_LIMIT_CLEAR    "_Clear"
#define QS_EVENT          "QS_Event"
#define QS_COND           "QS_Cond"
#define QS_ISVIPREQ       "QS_IsVipRequest"
#define QS_VipRequest     "QS_VipRequest"
#define QS_KEEPALIVE      "QS_KeepAliveTimeout"
#define QS_CLOSE          "QS_SrvMinDataRate"
#define QS_EMPTY_CON      "NullConnection"
#define QS_RuleId         "QS_RuleId"
#define QS_MFILE          "/var/tmp/"

// enable connection counter if one of the following feature is used
#define QS_COUNT_CONNECTIONS(sconf) (sconf->max_conn != -1) || \
                                    (sconf->min_rate_max != -1) || \
                                    (sconf->max_conn_close != -1) || \
                                    (sconf->max_conn_per_ip_connections != 1) || \
                                     sconf->geodb


// "3758096128","3758096383","AU"
#define QS_GEO_PATTERN "\"([0-9]+)\",\"([0-9]+)\",\"([A-Z0-9]{2})\""

static const char *m_env_variables[] = {
  QS_ErrorNotes,
  QS_SERIALIZE,
  QS_BLOCK,
  QS_BLOCK_SEEN,
  QS_LIMIT_DEFAULT,
  QS_LIMIT_SEEN,
  QS_EVENT,
  QS_COND,
  QS_ISVIPREQ,
  QS_VipRequest,
  QS_KEEPALIVE,
  QS_CLOSE,
  QS_EMPTY_CON,
  QS_RuleId,
  NULL
};

static const char *m_note_variables[] = {
  QS_PARP_PATH,
  QS_PARP_QUERY,
  NULL
};

#define QS_INCTX_ID inctx->id

/* this is the measure rate for QS_SrvRequestRate/QS_SrvMinDataRate which may
   be increased to 10 or 30 seconds in order to compensate bandwidth variations */
#ifndef QS_REQ_RATE_TM
#define QS_REQ_RATE_TM    5
#endif

#ifndef QS_EXTRA_MATCH_LIMIT
#define QS_EXTRA_MATCH_LIMIT 1500
#endif

#define QS_MAX_DELAY 5000

#define QOS_DEC_MODE_FLAGS_URL        0x00
#define QOS_DEC_MODE_FLAGS_HTML       0x01
#define QOS_DEC_MODE_FLAGS_UNI        0x02
#define QOS_DEC_MODE_FLAGS_ANSI       0x04

#define QOS_CC_BEHAVIOR_THR 50000
#define QOS_CC_BEHAVIOR_THR_SINGLE 50
#ifdef QS_INTERNAL_TEST
#undef QOS_CC_BEHAVIOR_THR
#undef QOS_CC_BEHAVIOR_THR_SINGLE
#define QOS_CC_BEHAVIOR_THR 50
#define QOS_CC_BEHAVIOR_THR_SINGLE 20
#endif
#define QOS_CC_BEHAVIOR_TOLERANCE_STR "20"

#define QS_ERR_TIME_FORMAT "%a %b %d %H:%M:%S %Y"

#define QSMOD 4
#define QOS_DELIM ";"

#define QOS_MAGIC_LEN 8
static char qs_magic[QOS_MAGIC_LEN] = "qsmagic";

// Apache 2.4 compat (experimental)
#if (AP_SERVER_MINORVERSION_NUMBER == 4)
#define QS_APACHE_24 1
#define QS_CONN_REMOTEIP(c) c->client_ip
#define QS_CONN_REMOTEADDR(c) c->client_addr
#define QOS_MY_GENERATION(g) ap_mpm_query(AP_MPMQ_GENERATION, &g)
#define qos_unixd_set_global_mutex_perms ap_unixd_set_global_mutex_perms
#define QS_ISDEBUG(s) APLOG_IS_LEVEL(s, APLOG_DEBUG)
#else
#define QS_APACHE_22 1
#define QS_CONN_REMOTEIP(c) c->remote_ip
#define QS_CONN_REMOTEADDR(c) c->remote_addr
#define QOS_MY_GENERATION(g) g = ap_my_generation
#define qos_unixd_set_global_mutex_perms unixd_set_global_mutex_perms
#define QS_ISDEBUG(s) s->loglevel >= APLOG_DEBUG
#endif

#ifdef QS_MOD_EXT_HOOKS
APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(qos, QOS, apr_status_t, path_decode_hook,
                                    (request_rec *r, char **path, int *len),
                                    (r, path, len),
                                    OK, DECLINED)
APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(qos, QOS, apr_status_t, query_decode_hook,
                                    (request_rec *r, char **query, int *len),
                                    (r, query, len),
                                    OK, DECLINED)
#endif

/************************************************************************
 * structures
 ***********************************************************************/
typedef struct {
  const char *name;             /* variable name */
#ifdef AP_REGEX_H
  ap_regex_t *preg;
#else
  regex_t *preg;
#endif
  const char *url;              /* redirect url */
} qos_redirectif_entry_t;

typedef struct {
  unsigned long start;
  unsigned long end;
  char country[3];
} qos_geo_t;

typedef struct {
  const char *url;
  const char *path;
} qos_errelt_t;

static const qos_errelt_t m_error_pages[] = {
  { "/errorpages/server_error.html", "work/errorpages/server_error.html" },
  { "/errorpages/forbidden.html", "work/errorpages/forbidden.html" },
  { "/errorpages/500.html", "work/errorpages/500.html" },
  { "/errorpages/error.html", "work/errorpages/error.html" },
  { "/errorpages/error500.html", "work/errorpages/error500.html" },
  { "/errorpages/gateway_error.html", "work/errorpages/gateway_error.html" },
  { NULL, NULL }
};

typedef struct {
  short int limit;
  time_t limit_time;
} qos_s_entry_limit_t;

typedef struct {
  short int limit;
  time_t limit_time;
  const char *eventClearStr; // name of the var clearing the counter
  const char *condStr;
#ifdef AP_REGEX_H
  ap_regex_t *preg;
#else
  regex_t *preg;
#endif
} qos_s_entry_limit_conf_t;

typedef struct {
  apr_uint64_t ip6[2];
  time_t lowrate;
  /* behavior */
  unsigned int html;
  unsigned int cssjs;
  unsigned int img;
  unsigned int other;
  unsigned int notmodified;
  unsigned int serialize;
  unsigned int events;
  /* prefer */
  short int vip;
  /* ev block */
  short int block;
  short int blockMsg;
  time_t time;
  time_t block_time;
  qos_s_entry_limit_t *limit;
  /* ev/sec */
  time_t interval;
  long req;
  long req_per_sec;
  int req_per_sec_block_rate;
  int event_req;
} qos_s_entry_t;

typedef struct {
  time_t t;
  /* index */
  qos_s_entry_t **ipd;
  qos_s_entry_t **timed;
  /* shm */
  apr_shm_t *m;
  char *lock_file;
  apr_global_mutex_t *lock;
  /* size */
  int num;
  int max;
  int msize;
  /* limit table settings */
  apr_table_t *limitTable;
  /* av. behavior */
  unsigned long long html;
  unsigned long long cssjs;
  unsigned long long img;
  unsigned long long other;
  unsigned long long notmodified;
  /* data */
  int connections;
} qos_s_t;

typedef enum  {
  QS_IP_V6_DEFAULT = 0,
  QS_IP_V6,
  QS_IP_V4
} qs_ip_type_e;

typedef enum  {
  QS_CONN_STATE_NEW = 0,
  QS_CONN_STATE_HEAD,
  QS_CONN_STATE_BODY,
  QS_CONN_STATE_CHUNKED,
  QS_CONN_STATE_KEEP,
  QS_CONN_STATE_RESPONSE,
  QS_CONN_STATE_END,
  QS_CONN_STATE_DESTROY
} qs_conn_state_e;

typedef enum  {
  QS_HEADERFILTER_OFF_DEFAULT = 0,
  QS_HEADERFILTER_OFF,
  QS_HEADERFILTER_ON,
  QS_HEADERFILTER_SIZE_ONLY,
  QS_HEADERFILTER_SILENT
} qs_headerfilter_mode_e;

typedef enum  {
  QS_FLT_ACTION_DROP,
  QS_FLT_ACTION_DENY
} qs_flt_action_e;

typedef enum  {
  QS_EVENT_ACTION_DENY = 0
} qs_event_action_e;

typedef enum  {
  QS_DENY_REQUEST_LINE,
  QS_DENY_PATH,
  QS_DENY_QUERY,
  QS_DENY_EVENT,
  QS_PERMIT_URI
} qs_rfilter_type_e;

typedef enum  {
  QS_LOG = 0,
  QS_DENY,
  QS_OFF_DEFAULT,
  QS_OFF
} qs_rfilter_action_e;

typedef struct {
  char *variable1;
  char *variable2;
  char *name;
  char *value;
} qos_setenvif_t;

typedef struct {
#ifdef AP_REGEX_H
  ap_regex_t *preg;
#else
  regex_t *preg;
#endif
  char *name;
  char *value;
} qos_setenvifquery_t;

typedef struct {
  pcre *preg;
  pcre_extra *extra;
#ifdef AP_REGEX_H
  ap_regex_t *pregx;
#else
  regex_t *pregx;
#endif  
  char *name;
  char *value;
} qos_setenvifparpbody_t;

/**
 * generic request filter
 */
typedef struct {
  pcre *pr;
  pcre_extra *extra;
  char *text;
  char *id;
  qs_rfilter_type_e type;
  qs_rfilter_action_e action;
} qos_rfilter_t;

/**
 * list of in_filter ctx
 */
typedef struct {
  apr_table_t *table;
#if APR_HAS_THREADS
  apr_thread_mutex_t *lock;
  apr_thread_t *thread;
#endif
  int exit;
} qos_ifctx_list_t;

/**
 * ip entry
 */
typedef struct qs_ip_entry_st {
  apr_uint64_t ip6[2];
  int counter;
  int error;
} qs_ip_entry_t;

typedef struct {
  qs_ip_entry_t *conn_ip;
  int conn_ip_len;
  int connections;
} qs_conn_t;

/**
 * session cookie
 */
typedef struct {
  unsigned char ran[QOS_RAN];
  char magic[QOS_MAGIC_LEN];
  time_t time;
} qos_session_t;

/**
 * cfg/act entry for event limitation
 */
typedef struct {
  const char *env_var;// configured environment variable name
  int max;            // configured max. num
  int seconds;        // configured duration
  int limit;          // event counter
  time_t limit_time;  // timer
  qs_event_action_e action;
} qos_event_limit_entry_t;

/** 
 * access control table entry
 */
typedef struct qs_acentry_st {
  int id;
  /** pointer to lock of the actable */
  apr_global_mutex_t *lock;
  /** location rules */
  char *url;
  int url_len;
  char *event;
#ifdef AP_REGEX_H
  ap_regex_t *regex;
  ap_regex_t *regex_var;
  ap_regex_t *condition;
#else
  regex_t *regex;
  regex_t *regex_var;
  regex_t *condition;
#endif
  int counter;
  int limit;
  /* measurement */
  apr_time_t interval;
  long req;
  long req_per_sec;
  long req_per_sec_limit;
  int req_per_sec_block_rate;
  long bytes;
  long kbytes_per_sec;
  long kbytes_per_sec_limit;
  apr_off_t hard_kbytes_per_sec_limit;
  apr_uint32_t hard_limit_concurrency;
  int kbytes_per_sec_block_rate;
  struct qs_acentry_st *next;
} qs_acentry_t;

/**
 * access control table (act)
 */
typedef struct qs_actable_st {
  apr_size_t size;
  apr_shm_t *m;
  apr_pool_t *pool;
  /** process pool is used to create user space data */
  apr_pool_t *ppool;
  /** rule entry list */
  qs_acentry_t *entry; /* shm pointer */
  int has_events;
  /** event limit list */
  qos_event_limit_entry_t *event_entry;
  /** mutex */
  char *lock_file;
  apr_global_mutex_t *lock;
  /** ip/conn data */
  qs_conn_t *conn; /* shm pointer */
  unsigned int timeout;
  /* settings */
  int child_init;
  int generation;
} qs_actable_t;

/**
 * network table (total connections, vip connections, first update, last update)
 */
typedef struct qs_netstat_st {
  //  int counter;
  int vip;
  //  time_t first;
  //  time_t last;
} qs_netstat_t;

/**
 * user space
 */
typedef struct {
  int server_start;
  apr_table_t *act_table;
  /* client control */
  qos_s_t *qos_cc;
  int generation;
} qos_user_t;

/**
 * directory config
 */
typedef struct {
  char *path;
  apr_table_t *rfilter_table;
  int inheritoff;
  qs_headerfilter_mode_e headerfilter;
  qs_headerfilter_mode_e resheaderfilter;
  int bodyfilter_d;
  int bodyfilter_p;
  int dec_mode;
  apr_off_t maxpost;
  qs_rfilter_action_e urldecoding;
  char *response_pattern;
  char *response_pattern_var;
  apr_array_header_t *redirectif;
  int decodings; 
  apr_table_t *disable_reqrate_events;
  apr_table_t *setenvstatus_t;
} qos_dir_config;

/**
 * server configuration
 */
typedef struct {
  apr_pool_t *pool;
  int is_virtual;
  server_rec *base_server;
  const char *chroot;
  char *mfile;
  qs_actable_t *act;
  const char *error_page;
  apr_table_t *location_t;
  apr_table_t *setenv_t;
  apr_table_t *setreqheader_t;
  apr_table_t *setreqheaderlate_t;
  apr_table_t *unsetresheader_t;
  apr_table_t *setenvif_t;
  apr_table_t *setenvifquery_t;
  apr_table_t *setenvifparp_t;
  apr_table_t *setenvifparpbody_t;
  apr_table_t *setenvstatus_t;
  apr_table_t *setenvresheader_t;
  apr_table_t *setenvresheadermatch_t;
  apr_table_t *setenvres_t;
  qs_headerfilter_mode_e headerfilter;
  qs_headerfilter_mode_e resheaderfilter;
  apr_array_header_t *redirectif;
  char *cookie_name;
  char *cookie_path;
  char *user_tracking_cookie;
  char *user_tracking_cookie_force;
  int max_age;
  unsigned char key[EVP_MAX_KEY_LENGTH];
  int keyset;
  char *header_name;
  int header_name_drop;
#ifdef AP_REGEX_H
  ap_regex_t *header_name_regex;
#else
  regex_t *header_name_regex;
#endif
  apr_table_t *disable_reqrate_events;
  char *ip_header_name;
  int ip_header_name_drop;
#ifdef AP_REGEX_H
  ap_regex_t *ip_header_name_regex;
#else
  regex_t *ip_header_name_regex;
#endif
  int vip_user;
  int vip_ip_user;
  int max_conn;
  int max_conn_close;
  int max_conn_close_percent;
  int max_conn_per_ip;
  int max_conn_per_ip_connections;
  apr_table_t *exclude_ip;
  qos_ifctx_list_t *inctx_t;
  apr_table_t *hfilter_table; /* GLOBAL ONLY */
  apr_table_t *reshfilter_table; /* GLOBAL ONLY */
  /* event rule (enables rule validation) */
  int has_event_filter;
  int has_event_limit;
  apr_array_header_t *event_limit_a;
  /* min data rate */
  int req_rate;               /* GLOBAL ONLY */
  int req_rate_start;         /* GLOBAL ONLY */
  int min_rate;               /* GLOBAL ONLY */
  int min_rate_max;           /* GLOBAL ONLY */
  int min_rate_off;
  int max_clients;
#ifdef QS_INTERNAL_TEST
  apr_table_t *testip;
  int enable_testip;
#endif
  int disable_handler;
  /* client control */
  int log_only;               /* GLOBAL ONLY */
  int has_qos_cc;             /* GLOBAL ONLY */
  int qos_cc_size;            /* GLOBAL ONLY */
  int qos_cc_prefer;          /* GLOBAL ONLY */
  int qos_cc_prefer_limit;
  int qos_cc_event;           /* GLOBAL ONLY */
  int qos_cc_event_req;       /* GLOBAL ONLY */
  int qos_cc_block;           /* GLOBAL ONLY */
  int qos_cc_block_time;      /* GLOBAL ONLY */
  apr_table_t *qos_cc_limitTable;    /* GLOBAL ONLY */
  char *qos_cc_forwardedfor;  /* GLOBAL ONLY */
  int qos_cc_serialize;       /* GLOBAL ONLY */
  apr_off_t maxpost;
  int cc_tolerance;           /* GLOBAL ONLY */
  int cc_tolerance_max;       /* GLOBAL ONLY */
  int cc_tolerance_min;       /* GLOBAL ONLY */
  int qs_req_rate_tm;         /* GLOBAL ONLY */
  qos_geo_t *geodb;           /* GLOBAL ONLY */
  int geodb_size;             /* GLOBAL ONLY */
  int geo_limit;              /* GLOBAL ONLY */
  apr_table_t *geo_priv;      /* GLOBAL ONLY */
  qs_ip_type_e ip_type;       /* GLOBAL ONLY */
  int server_limit;
  int thread_limit;
  apr_table_t *milestones;
  time_t milestone_timeout;
  /* predefined client behavior */
  int static_on;
  unsigned long long static_html;
  unsigned long long static_cssjs;
  unsigned long long static_img;
  unsigned long long static_other;
  unsigned long long static_notmodified;
} qos_srv_config;

/**
 * in_filter ctx
 */
typedef struct {
  apr_socket_t *client_socket;
  qs_conn_state_e status;
  apr_off_t cl_val;
  conn_rec *c;
  request_rec *r;
  /* upload bandwidth (received bytes and start time) */
  time_t time;
  apr_size_t nbytes;
  int shutdown;
  int errors;
  int disabled;
  /* packet recv size rate: */
  apr_size_t bytes;
  int count;
  int lowrate;
  char *id;
  qos_srv_config *sconf;
} qos_ifctx_t;

/**
 * connection configuration
 */
typedef struct {
  apr_uint64_t ip6[2];
  conn_rec *c;
  char *evmsg;
  qos_srv_config *sconf;
  int is_vip;           /* is vip, either by request or by session or by ip */
  int is_vip_by_header; /* received vip header from application/or auth. user */
  int has_lowrate;
  qs_conn_t *conn;
} qs_conn_ctx;

typedef struct {
  qs_conn_ctx *cconf;
  conn_rec *c;
  qos_srv_config *sconf;
  int requests; // number of requests processed (received) by this connection  
} qs_conn_base_ctx;

/**
 * request configuration
 */
typedef struct {
  qs_acentry_t *entry;
  qs_acentry_t *entry_cond;
  apr_table_t *event_entries;
  char *evmsg;
  int is_vip;
  apr_off_t maxpostcount;
  int event_kbytes_per_sec_block_rate;
  int cc_event_req_set;
  int cc_serialize_set;
  char *body_window;
  qs_acentry_t *hard_limit_e;
} qs_req_ctx;

/**
 * rule set
 */
typedef struct {
  char *url;
  char *event;
  int limit;
#ifdef AP_REGEX_H
  /* apache 2.2 */
  ap_regex_t *regex;
  ap_regex_t *regex_var;
  ap_regex_t *condition;
#else
  /* apache 2.0 */
  regex_t *regex;
  regex_t *regex_var;
  regex_t *condition;
#endif
  long req_per_sec_limit;
  long kbytes_per_sec_limit;
  apr_off_t hard_kbytes_per_sec_limit;
} qs_rule_ctx_t;

typedef struct {
  const char* name;
  const char* pcre;
  qs_flt_action_e action;
  int size;
} qos_her_t;

typedef struct {
#ifdef AP_REGEX_H
  ap_regex_t *preg;
#else
  regex_t *preg;
#endif
  char *name;
  char *value;
} qos_pregval_t;

typedef struct {
  const char* pattern;
  pcre *preg;
  pcre_extra *extra;
  qs_rfilter_action_e action;
} qos_milestone_t;

typedef struct {
  char *text;
  pcre *pcre;
  pcre_extra *extra;
  qs_flt_action_e action;
  int size;
} qos_fhlt_r_t;

typedef struct {
  apr_time_t request_time;
  unsigned int in_addr;
  unsigned int conn;
  unsigned int pid;
  unsigned int tid;
  unsigned int unique_id_counter;
} qos_unique_id_t;

/************************************************************************
 * globals
 ***********************************************************************/

module AP_MODULE_DECLARE_DATA qos_module;
static int m_retcode = HTTP_INTERNAL_SERVER_ERROR;
static int m_worker_mpm = 1; // note: mod_qos shall be used for Apache 2.2 worker MPM only
static unsigned int m_hostcode = 0;
static int m_generation = 0;
static int m_qos_cc_partition = QSMOD;
static qos_unique_id_t m_unique_id;
static const char qos_basis_64[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

/* mod_parp, forward and optional function */
static apr_status_t qos_cleanup_conn(void *p);
static apr_status_t qos_base_cleanup_conn(void *p);

static qs_ip_type_e m_ip_type = QS_IP_V6_DEFAULT;

APR_DECLARE_OPTIONAL_FN(apr_table_t *, parp_hp_table, (request_rec *));
APR_DECLARE_OPTIONAL_FN(char *, parp_body_data, (request_rec *, apr_size_t *));
static APR_OPTIONAL_FN_TYPE(parp_hp_table) *qos_parp_hp_table_fn = NULL;
static APR_OPTIONAL_FN_TYPE(parp_body_data) *parp_appl_body_data_fn = NULL;
static int m_requires_parp = 0;
static int m_enable_audit = 0;
/* mod_ssl, forward and optional function */
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *qos_is_https = NULL;

/* simple header rules allowing "the usual" header formats only (even drop requests using
   extensions which are used rarely) */
/* reserved (to be escaped): {}[]()^$.|*+?\ */
static const qos_her_t qs_header_rules[] = {
#define QS_URL_UNRESERVED  "a-zA-Z0-9\\._~% \\-"
#define QS_URL_GEN         ":/\\?#\\[\\]@"
#define QS_URL_SUB         "!\\$&'\\(\\)\\*\\+,;="
#define QS_URL             "["QS_URL_GEN""QS_URL_SUB""QS_URL_UNRESERVED"]"
#define QS_2616TOKEN       "[\\x21\\x23-\\x27\\x2a-\\x2e0-9A-Z\\x5-\\x60a-z\\x7e]+"
#define QS_B64_SP          "[a-zA-Z0-9 \\+/\\$=:]"
#define QS_PIPE            "\\|"
#define QS_WEAK            "(W/)?"
#define QS_H_ACCEPT        "[a-zA-Z0-9_\\*\\+\\-]+/[a-zA-Z0-9_\\*\\+\\.\\-]+(;[ ]?[a-zA-Z0-9]+=[0-9]+)?[ ]?(;[ ]?q=[0-9\\.]+)?"
#define QS_H_ACCEPT_C      "[a-zA-Z0-9\\*\\-]+(;[ ]?q=[0-9\\.]+)?"
#define QS_H_ACCEPT_E      "[a-zA-Z0-9\\*\\-]+(;[ ]?q=[0-9\\.]+)?"
#define QS_H_ACCEPT_L      "[a-zA-Z\\*\\-]+(;[ ]?q=[0-9\\.]+)?"
#define QS_H_CACHE         "no-cache|no-store|max-age=[0-9]+|max-stale(=[0-9]+)?|min-fresh=[0-9]+|no-transform|only-if-chached"
#define QS_H_CONTENT       "[\"a-zA-Z0-9\\*/; =\\-]+"
#define QS_H_COOKIE        "["QS_URL_GEN""QS_URL_SUB"\""QS_URL_UNRESERVED"]"
#define QS_H_EXPECT        "[a-zA-Z0-9= ;\\.,\\-]"
#define QS_H_PRAGMA        "[a-zA-Z0-9= ;\\.,\\-]"
#define QS_H_FROM          "[a-zA-Z0-9=@;\\.,\\(\\)\\-]"
#define QS_H_HOST          "[a-zA-Z0-9\\.\\-]+(:[0-9]+)?"
#define QS_H_IFMATCH       "[a-zA-Z0-9=@;\\.,\\*\"\\-]"
#define QS_H_DATE          "[a-zA-Z0-9 :,]"
#define QS_H_TE            "[a-zA-Z0-9\\*\\-]+(;[ ]?q=[0-9\\.]+)?"
  { "Accept", "^("QS_H_ACCEPT"){1}([ ]?,[ ]?"QS_H_ACCEPT")*$", QS_FLT_ACTION_DROP, 300 },
  { "Accept-Charset", "^("QS_H_ACCEPT_C"){1}([ ]?,[ ]?"QS_H_ACCEPT_C")*$", QS_FLT_ACTION_DROP, 300 },
  { "Accept-Encoding", "^("QS_H_ACCEPT_E"){1}([ ]?,[ ]?"QS_H_ACCEPT_E")*$", QS_FLT_ACTION_DROP, 500 },
  { "Accept-Language", "^("QS_H_ACCEPT_L"){1}([ ]?,[ ]?"QS_H_ACCEPT_L")*$", QS_FLT_ACTION_DROP, 200 },
  { "Authorization", "^"QS_B64_SP"+$", QS_FLT_ACTION_DROP, 4000 },
  { "Cache-Control", "^("QS_H_CACHE"){1}([ ]?,[ ]?"QS_H_CACHE")*$", QS_FLT_ACTION_DROP, 100 },
  { "Connection", "^([teTE]+,[ ]?)?([a-zA-Z0-9\\-]+){1}([ ]?,[ ]?[teTE]+)?$", QS_FLT_ACTION_DROP, 100 },
  { "Content-Encoding", "^[a-zA-Z0-9\\-]+(,[ ]*[a-zA-Z0-9\\-]+)*$", QS_FLT_ACTION_DENY, 100 },
  { "Content-Language", "^([0-9a-zA-Z]{0,8}(-[0-9a-zA-Z]{0,8})*)(,[ ]*([0-9a-zA-Z]{0,8}(-[0-9a-zA-Z]{0,8})*))*$", QS_FLT_ACTION_DROP, 100 },
  { "Content-Length", "^[0-9]+$", QS_FLT_ACTION_DENY, 10 },
  { "Content-Location", "^"QS_URL"+$", QS_FLT_ACTION_DENY, 200 },
  { "Content-md5", "^"QS_B64_SP"+$", QS_FLT_ACTION_DENY, 50 },
  { "Content-Range", "^(bytes[ ]+([0-9]+-[0-9]+)/([0-9]+|\\*))$", QS_FLT_ACTION_DENY, 50 },
  { "Content-Type", "^("QS_H_CONTENT"){1}([ ]?,[ ]?"QS_H_CONTENT")*$", QS_FLT_ACTION_DENY, 200 },
  { "Cookie", "^"QS_H_COOKIE"+$", QS_FLT_ACTION_DROP, 3000 },
  { "Cookie2", "^"QS_H_COOKIE"+$", QS_FLT_ACTION_DROP, 3000 },
  { "DNT", "^[0-9]+$", QS_FLT_ACTION_DROP, 3 },
  { "Expect", "^"QS_H_EXPECT"+$", QS_FLT_ACTION_DROP, 200 },
  { "From", "^"QS_H_FROM"+$", QS_FLT_ACTION_DROP, 100 },
  { "Host", "^"QS_H_HOST"$", QS_FLT_ACTION_DROP, 100 },
  { "If-Invalid", "^[a-zA-Z0-9_\\.:;\\(\\) /\\+!\\-]+$", QS_FLT_ACTION_DROP, 500 },
  { "If-Match", "^"QS_WEAK""QS_H_IFMATCH"+$", QS_FLT_ACTION_DROP, 100 },
  { "If-Modified-Since", "^"QS_H_DATE"+$", QS_FLT_ACTION_DROP, 100 },
  { "If-None-Match", "^"QS_WEAK""QS_H_IFMATCH"+$", QS_FLT_ACTION_DROP, 100 },
  { "If-Range", "^"QS_H_IFMATCH"+$", QS_FLT_ACTION_DROP, 100 },
  { "If-Unmodified-Since", "^"QS_H_DATE"+$", QS_FLT_ACTION_DROP, 100 },
  { "If-Valid", "^[a-zA-Z0-9_\\.:;\\(\\) /\\+!\\-]+$", QS_FLT_ACTION_DROP, 500 },
  { "Keep-Alive", "^[0-9]+$", QS_FLT_ACTION_DROP, 20 },
  { "Max-Forwards", "^[0-9]+$", QS_FLT_ACTION_DROP, 20 },
  { "Proxy-Authorization", "^"QS_B64_SP"+$", QS_FLT_ACTION_DROP, 400 },
  { "Pragma", "^"QS_H_PRAGMA"+$", QS_FLT_ACTION_DROP, 200 },
  { "Range", "^[a-zA-Z0-9=_\\.:;\\(\\) /\\+!\\-]+$", QS_FLT_ACTION_DROP, 200 },
  { "Referer", "^"QS_URL"+$", QS_FLT_ACTION_DROP, 2000 },
  { "TE", "^("QS_H_TE"){1}([ ]?,[ ]?"QS_H_TE")*$", QS_FLT_ACTION_DROP, 100 },
  { "Transfer-Encoding", "^chunked|Chunked|compress|Compress|deflate|Deflate|gzip|Gzip|identity|Identity$", QS_FLT_ACTION_DENY, 100 },
  { "Unless-Modified-Since", "^"QS_H_DATE"+$", QS_FLT_ACTION_DROP, 100 },
  { "User-Agent", "^[a-zA-Z0-9]+[a-zA-Z0-9_\\.:;\\(\\)@ /\\+!=,\\-]+$", QS_FLT_ACTION_DROP, 300 },
  { "Via", "^[a-zA-Z0-9_\\.:;\\(\\) /\\+!\\-]+$", QS_FLT_ACTION_DROP, 100 },
  { "X-Forwarded-For", "^[a-zA-Z0-9_\\.:\\-]+(, [a-zA-Z0-9_\\.:\\-]+)*$", QS_FLT_ACTION_DROP, 100 },
  { "X-Forwarded-Host", "^[a-zA-Z0-9_\\.:\\-]+$", QS_FLT_ACTION_DROP, 100 },
  { "X-Forwarded-Server", "^[a-zA-Z0-9_\\.:\\-]+$", QS_FLT_ACTION_DROP, 100 },
  { "X-lori-time-1", "^[0-9]+$", QS_FLT_ACTION_DROP, 20 },
  { "X-Do-Not-Track", "^[0-9]+$", QS_FLT_ACTION_DROP, 20 },
  { NULL, NULL, 0, 0 }
};

/* list of allowed standard response headers */
static const qos_her_t qs_res_header_rules[] = {
  { "Age", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Accept-Ranges", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Access-Control-Allow-Origin", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Allow", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Cache-Control", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Content-Disposition", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Content-Encoding", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Content-Language", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Content-Length", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Content-Location", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Content-MD5", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Content-Range", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Content-Security-Policy", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 8000 },
  { "Content-Type", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Connection", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Date", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "ETag", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Expect", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Expires", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Keep-Alive", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Last-Modified", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Location", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Proxy-Authenticate", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Retry-After", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Pragma", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Server", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Set-Cookie", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 }, 
  { "Set-Cookie2", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Strict-Transport-Security", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "Vary", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "WWW-Authenticate", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "X-Content-Security-Policy", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 8000 },
  { "X-Content-Type-Options", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "X-Frame-Options", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { "X-XSS-Protection", "^[\\x20-\\xFF]*$", QS_FLT_ACTION_DROP, 4000 },
  { NULL, NULL, 0, 0 }
};

/************************************************************************
 * private functions
 ***********************************************************************/

/**
 * Converts an ip long array back to a string representation
 *
 * @param pool
 * @param src Array of two unsigned long
 * @return String or null for an invalid address
 */
static char *qos_ip_long2str(apr_pool_t *pool, const void *src) {
  char *dst = apr_pcalloc(pool, INET6_ADDRSTRLEN);
  char *ret = (char *)inet_ntop(AF_INET6, src, dst, INET6_ADDRSTRLEN);
  if(ret) {
    if((strncmp(ret, QS_IP4IN6, 7) == 0) &&
       strchr(ret, '.')) {
      ret = &ret[7];
    }
  }
  return ret;
}

/**
 * Converts an ip string to long array (128 bit) representation
 *
 * @param src String representation, e.g. 139.12.33.1 or 1::8
 * @param dst Pointer to array of unsigned long (2) (contains "{ 0, 0 }" on errror)
 * @return 1 on success, 0 on error
 */
static int qos_ip_str2long(const char *src, void *dst) {
  char str[INET6_ADDRSTRLEN];
  const char *convert = src;
  apr_uint64_t *n = dst;
  n[0] = 0;
  n[1] = 0;
  if(convert == NULL) {
    return 0;
  }
  if((ap_strchr_c(convert, ':') == NULL) && 
     (strlen(convert) <= 15)) {
    // looks like an IPv4 address
    sprintf(str, QS_IP4IN6"%s", src);
    convert = str;
  }
  return inet_pton(AF_INET6, convert, dst);
}

/**
 * Studies pcre pattern (for perfomance improvement) and sets match limits.
 * @param pool Pool to allocate structure from (or to register cleanup)
 * @param pc Pattern to study
 * @return extra data
 */
static pcre_extra *qos_pcre_study(apr_pool_t *pool, pcre *pc) {
  pcre_extra *extra = NULL;
#ifdef QOS_EXTRA_USE_PCRE_STUDY
  const char *errptr = NULL;
  extra = pcre_study(pc, 0, &errptr);
#endif
  if(extra != NULL) {
    apr_pool_cleanup_register(pool, extra, (int(*)(void*))pcre_free, apr_pool_cleanup_null);
  } else {
    extra = apr_pcalloc(pool, sizeof(pcre_extra));
  }
#ifdef PCRE_EXTRA_MATCH_LIMIT
  extra->match_limit = QS_EXTRA_MATCH_LIMIT;
  extra->flags |= PCRE_EXTRA_MATCH_LIMIT;
#endif
#ifdef PCRE_EXTRA_MATCH_LIMIT_RECURSION
  extra->match_limit_recursion = QS_EXTRA_MATCH_LIMIT;
  extra->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
#endif
#ifdef PCRE_EXTRA_MATCH_LIMIT_RECURSION
  extra->match_limit_recursion = QS_EXTRA_MATCH_LIMIT;
  extra->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
#endif

  return extra;
}

static int qos_encode64_binary(char *encoded,
                               const char *string, int len) {
  int i;
  char *p;
  
  p = encoded;
  for (i = 0; i < len - 2; i += 3) {
    *p++ = qos_basis_64[(string[i] >> 2) & 0x3F];
    *p++ = qos_basis_64[((string[i] & 0x3) << 4) |
                        ((int) (string[i + 1] & 0xF0) >> 4)];
    *p++ = qos_basis_64[((string[i + 1] & 0xF) << 2) |
                        ((int) (string[i + 2] & 0xC0) >> 6)];
    *p++ = qos_basis_64[string[i + 2] & 0x3F];
  }
  if (i < len) {
    *p++ = qos_basis_64[(string[i] >> 2) & 0x3F];
    if (i == (len - 1)) {
      *p++ = qos_basis_64[((string[i] & 0x3) << 4)];
      *p++ = '=';
    }
    else {
      *p++ = qos_basis_64[((string[i] & 0x3) << 4) |
                          ((int) (string[i + 1] & 0xF0) >> 4)];
      *p++ = qos_basis_64[((string[i + 1] & 0xF) << 2)];
    }
    *p++ = '=';
  }
  
  *p++ = '\0';
  return (int)(p - encoded);
}

/**
 * loads the default header rules into the server configuration (see rules
 * above).
 * @param pool To allocate memory
 * @param hfilter_table Table to add rules to
 * @param hs built-in header rules
 * @return error message (NULL on success)
 */
static char *qos_load_headerfilter(apr_pool_t *pool, apr_table_t *hfilter_table,
                                   const qos_her_t *hs) {
  const char *errptr = NULL;
  int erroffset;
  const qos_her_t* elt;
  for(elt = hs; elt->name != NULL ; ++elt) {
    qos_fhlt_r_t *he = apr_pcalloc(pool, sizeof(qos_fhlt_r_t));
    he->text = apr_pstrdup(pool, elt->pcre);
    he->pcre = pcre_compile(elt->pcre, PCRE_DOTALL, &errptr, &erroffset, NULL);
    he->action = elt->action;
    he->size = elt->size;
    if(he->pcre == NULL) {
      return apr_psprintf(pool, "could not compile pcre %s at position %d,"
                          " reason: %s", 
                          elt->name,
                          erroffset, errptr);
    }
    he->extra = qos_pcre_study(pool, he->pcre);
    apr_table_setn(hfilter_table, elt->name, (char *)he);
    apr_pool_cleanup_register(pool, he->pcre, (int(*)(void*))pcre_free, apr_pool_cleanup_null);
  }
  return NULL;
}

/**
 * Returns string representation of filter type (for logging purposes)
 * @param pool To allocate string
 * @param type Rule type
 * @retrun Name of the directive used to configure the rule
 */
static char *qos_rfilter_type2text(apr_pool_t *pool, qs_rfilter_type_e type) {
  if(type == QS_DENY_REQUEST_LINE) return apr_pstrdup(pool, "QS_DenyRequestLine");
  if(type == QS_DENY_PATH) return apr_pstrdup(pool, "QS_DenyPath");
  if(type == QS_DENY_QUERY) return apr_pstrdup(pool, "QS_DenyQuery");
  if(type == QS_DENY_EVENT) return apr_pstrdup(pool, "QS_DenyEvent");
  if(type == QS_PERMIT_URI) return apr_pstrdup(pool, "QS_PermitUri");
  return apr_pstrdup(pool, "UNKNOWN");
}

/**
 * Sets unique apache instance id (hopefully) to the global m_hostcore variable
 * @param ptemp Pool to allocate memroy from
 * @param s Base server record
 */
static void qos_hostcode(apr_pool_t *ptemp, server_rec *s) {
  char *key = apr_psprintf(ptemp, "%s%s%s%d%s"
#ifdef ap_http_scheme
/* Apache 2.2 */
                           "%s"
#endif
                           "%s",
                           s->defn_name ? s->defn_name : "",
                           s->server_admin ? s->server_admin : "",
                           s->server_hostname ? s->server_hostname : "",
                           s->addrs ? s->addrs->host_port : 0,
                           s->path ? s->path : "",
                           s->error_fname ? s->error_fname : ""
#ifdef ap_http_scheme
/* Apache 2.2 */
                           ,s->server_scheme ? s->server_scheme : ""
#endif
                           );
  int len = strlen(key);
  int i;
  char *p;
  for(p = key, i = len; i; i--, p++) {
    m_hostcode = m_hostcode * 33 + *p;
  }
}

/**
 * temp file name for the main/virtual serve
 * @param pool Pool to allocate the file name from
 * @param s Server record
 * @return path
 */
static char *qos_tmpnam(apr_pool_t *pool, server_rec *s) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
  char *path = QS_MFILE;
  char *id;
  char *e;
  if(sconf && sconf->mfile) {
    path = sconf->mfile;
  }
  if(s) {
    unsigned int scode = 0;
    char *key = apr_psprintf(pool, "%u%s.%s.%d",
                             m_hostcode,
                             s->is_virtual ? "v" : "b",
                             s->server_hostname == NULL ? "-" : s->server_hostname,
                             s->addrs == NULL ? 0 : s->addrs->host_port);
    int len = strlen(key);
    int i;
    char *p;
    for(p = key, i = len; i; i--, p++) {
      scode = scode * 33 + *p;
    }
    id = apr_psprintf(pool, "%s%u", path, scode);
    
  } else {
    id = apr_psprintf(pool, "%s%u", path, m_hostcode);
  }
  e = &id[strlen(path)];
  e[0] += 25; /* non numeric */
  return id;
}

/**
 * QS_LimitRequestBody settings. Environment variable (dynamic) has higher prio than
 * configuration (static) value.
 * @param r
 * @param sconf
 * @param dconf
 */
static apr_off_t qos_maxpost(request_rec *r, qos_srv_config *sconf, qos_dir_config *dconf) {
  if(r->subprocess_env) {
    const char *bytes = apr_table_get(r->subprocess_env, "QS_LimitRequestBody");
    if(bytes) {
      apr_off_t s;
#ifdef ap_http_scheme
      /* Apache 2.2 */
      char *errp = NULL;
      if(APR_SUCCESS == apr_strtoff(&s, bytes, &errp, 10)) {
        return s;
      }
#else
      if((s = apr_atoi64(bytes)) >= 0) {
        return s;
      }
#endif
    }
  }
  if(dconf->maxpost != -1) {
    return dconf->maxpost;
  }
  return sconf->maxpost;
}


/**
 * Similar to strstr but restricting the length of s1 (supports strings which
 * are not NULL terminated).
 *
 * @param s1 String to search in
 * @param s2 Pattern to ind
 * @param len Length of s1
 * @return pointer to the beginning of the substring s2 within s1, or NULL
 *         if the substring is not found
 */
static char *qos_strnstr(const char *s1, const char *s2, int len) {
  const char *e1 = &s1[len-1];
  char *p1, *p2;
  if (*s2 == '\0') {
    /* an empty s2 */
    return((char *)s1);
  }
  while(1) {
    for ( ; (*s1 != '\0') && (s1 <= e1) && (apr_tolower(*s1) != apr_tolower(*s2)); s1++);
    if (*s1 == '\0' || s1 > e1) {
      return(NULL);
    }
    /* found first character of s2, see if the rest matches */
    p1 = (char *)s1;
    p2 = (char *)s2;
    for (++p1, ++p2; (apr_tolower(*p1) == apr_tolower(*p2)) && (p1 <= e1); ++p1, ++p2) {
      if((p1 > e1) && (*p2 != '\0')) {
        // reached the end without match
        return NULL;
      }
      if (*p2 == '\0') {
        /* both strings ended together */
        return((char *)s1);
      }
    }
    if (*p2 == '\0') {
      /* second string ended, a match */
      break;
    }
    /* didn't find a match here, try starting at next character in s1 */
    s1++;
  }
  return((char *)s1);
}

/**
 * Comperator (ip search) for the client ip store qos_cc_*() functions (used by bsearch/qsort)
 */
static int qos_cc_comp(const void *_pA, const void *_pB) {
  qos_s_entry_t *pA=*(( qos_s_entry_t **)_pA);
  qos_s_entry_t *pB=*(( qos_s_entry_t **)_pB);
  if(pA->ip6[0] > pB->ip6[0]) return 2;
  if(pA->ip6[0] < pB->ip6[0]) return -2;
  if(pA->ip6[1] > pB->ip6[1]) return 1;
  if(pA->ip6[1] < pB->ip6[1]) return -1;
  return 0;
}

static int qos_cc_compv4(const void *_pA, const void *_pB) {
  qos_s_entry_t *pA=*(( qos_s_entry_t **)_pA);
  qos_s_entry_t *pB=*(( qos_s_entry_t **)_pB);
  if(pA->ip6[1] > pB->ip6[1]) return 1;
  if(pA->ip6[1] < pB->ip6[1]) return -1;
  return 0;
}

/**
 * Comperator (time search) for the client ip store qos_cc_*() functions (used by bsearch/qsort)
 */
static int qos_cc_comp_time(const void *_pA, const void *_pB) {
  qos_s_entry_t *pA=*(( qos_s_entry_t **)_pA);
  qos_s_entry_t *pB=*(( qos_s_entry_t **)_pB);
  if(pA->time > pB->time) return 1;
  if(pA->time < pB->time) return -1;
  return 0;
}

/**
 * creates new per client store
 * @param pool Persistent process pool
 * @param srec Server rec for sem/mutex
 * @param size Number of entries
 * @param limitTable Table of "QS_Limit" events
 * @return pointer to the per client data array
 */
static qos_s_t *qos_cc_new(apr_pool_t *pool, server_rec *srec, int size, apr_table_t *limitTable) {
  char *file = "-";
  apr_shm_t *m;  // per client memory table
  apr_shm_t *lm; // "limit" memory table
  apr_status_t res;
  int limitTableSize = apr_table_elts(limitTable)->nelts;
  int lsize = 0;
  int msize = APR_ALIGN_DEFAULT(sizeof(qos_s_t)) + 
    (APR_ALIGN_DEFAULT(sizeof(qos_s_entry_t)) * size) + 
    (2 * APR_ALIGN_DEFAULT(sizeof(qos_s_entry_t *)) * size);
  int i;
  qos_s_t *s;
  qos_s_entry_t *e;
  qos_s_entry_limit_t *limitTableEntry = NULL;
  msize = msize + 1024;
  if(limitTableSize > 0) {
    lsize = APR_ALIGN_DEFAULT(sizeof(qos_s_entry_limit_t)) * limitTableSize * size;
    lsize = lsize + 1024;
  }
  /* use anonymous shm by default */
  if(limitTableSize > 0) {
    apr_shm_create(&lm, lsize, NULL, pool);
  }
  res = apr_shm_create(&m, msize, NULL, pool);
  if(APR_STATUS_IS_ENOTIMPL(res)) {
    char *lfile = apr_psprintf(pool, "%s_cc_ml.mod_qos",
                               qos_tmpnam(pool, srec));
    file = apr_psprintf(pool, "%s_cc_m.mod_qos",
                        qos_tmpnam(pool, srec));
#ifdef ap_http_scheme
    /* Apache 2.2 */
    if(limitTableSize > 0) {
      apr_shm_remove(lfile, pool);
    }
    apr_shm_remove(file, pool);
#endif
    if(limitTableSize > 0) {
      apr_shm_create(&lm, lsize, lfile, pool);
    }
    res = apr_shm_create(&m, msize, file, pool);
  }
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, srec, 
               QOS_LOGD_PFX"create shared memory (client control)(%s): %d bytes",
               file, msize + lsize);
  if(res != APR_SUCCESS) {
    char buf[MAX_STRING_LEN];
    apr_strerror(res, buf, sizeof(buf));
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, srec,
                 QOS_LOG_PFX(002)"failed to create shared memory (client control)(%s): %s (%d bytes)",
                 file, buf, msize);
    return NULL;
  }
  s = apr_shm_baseaddr_get(m);
  s->m = m;
  if(limitTableSize > 0) {
    apr_table_entry_t *te = (apr_table_entry_t *)apr_table_elts(limitTable)->elts;
    limitTableEntry = apr_shm_baseaddr_get(lm);
    s->limitTable = apr_table_make(pool, limitTableSize+10);
    for(i = 0; i < limitTableSize; i++) {
      char *eventName = apr_pstrdup(pool, te[i].key);
      qos_s_entry_limit_conf_t *eventLimitConf = apr_pcalloc(pool, sizeof(qos_s_entry_limit_conf_t));
      qos_s_entry_limit_conf_t *src = (qos_s_entry_limit_conf_t*)te[i].val;
      eventLimitConf->limit = src->limit;
      eventLimitConf->limit_time = src->limit_time;
      eventLimitConf->eventClearStr = apr_pstrcat(pool, eventName, QS_LIMIT_CLEAR, NULL);
      eventLimitConf->condStr = NULL;
      eventLimitConf->preg = NULL;
      if(src->condStr) {
        eventLimitConf->condStr = apr_pstrdup(pool, src->condStr);
#ifdef AP_REGEX_H
        eventLimitConf->preg = ap_pregcomp(pool, src->condStr, AP_REG_EXTENDED);
#else
        eventLimitConf->preg = ap_pregcomp(pool, src->condStr, REG_EXTENDED);
#endif
      }
      apr_table_addn(s->limitTable, eventName, (char *)eventLimitConf);
    }
  } else {
    s->limitTable = NULL;
  }
  s->lock_file = apr_psprintf(pool, "%s_ccl.mod_qos", 
                              qos_tmpnam(pool, srec));
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, srec, 
               QOS_LOGD_PFX"create mutex (client control)(%s)",
               s->lock_file);
  res = apr_global_mutex_create(&s->lock, s->lock_file, APR_LOCK_DEFAULT, pool);
  if(res != APR_SUCCESS) {
    char buf[MAX_STRING_LEN];
    apr_strerror(res, buf, sizeof(buf));
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, srec,
                 QOS_LOG_PFX(004)"failed to create mutex (client control)(%s): %s", 
                 s->lock_file, buf);
    apr_shm_destroy(s->m);
    return NULL;
  }
#ifdef AP_NEED_SET_MUTEX_PERMS
  qos_unixd_set_global_mutex_perms(s->lock);
#endif
  e = (qos_s_entry_t *)&s[1];
  s->ipd = (qos_s_entry_t **)&e[size];
  s->timed = (qos_s_entry_t **)&s->ipd[size];
  s->num = 0;
  s->max = size;
  s->msize = msize;
  s->connections = 0;
  s->html = 0;
  s->cssjs = 0;
  s->img = 0;
  s->other = 0;
  s->notmodified = 0;
  for(i = 0; i < size; i++) {
    s->ipd[i] = e;
    s->timed[i] = e;
    if(limitTableSize > 0) {
      e->limit = limitTableEntry;
      limitTableEntry += limitTableSize;
    } else {
      e->limit = NULL;
    }
    e++;
  }
  s->t = time(NULL);
  return s;
}

/**
 * Destroys the client data store
 * -- not yet implemented (errors for DSO) --
 */
static void qos_cc_free(qos_s_t *s) {
  if(s->lock) {
    // called by apr_pool_cleanup_register():
    // apr_global_mutex_destroy(s->lock);
  }
  if(s->m) {
    // called by apr_pool_cleanup_register():
    // apr_shm_destroy(s->m);
  }
}

/** 
 * searches an entry
 * @param s Client store (locked)
 * @param pA IP to search
 * @param now Current time (update access to the entry)
 * @return client entry or NULL if not available
 */
static qos_s_entry_t **qos_cc_get0(qos_s_t *s, qos_s_entry_t *pA, time_t now) {
  qos_s_entry_t **pB;
  unsigned char *b = (void *)&pA->ip6[1];
  int mod = b[7] % m_qos_cc_partition;
  // int mod = pA->ip6[1] % m_qos_cc_partition;
  int max = (s->max / m_qos_cc_partition);
  int start = mod * max;
  if(m_ip_type == QS_IP_V4) {
    pB = bsearch((const void *)&pA, (const void *)&s->ipd[start], 
                 max, sizeof(qos_s_entry_t *), qos_cc_compv4);
  } else {
    pB = bsearch((const void *)&pA, (const void *)&s->ipd[start], 
                 max, sizeof(qos_s_entry_t *), qos_cc_comp);
  }
  if(pB) {
    if(now != 0) {
      s->t = now;
    }
    (*pB)->time = s->t;
  }
  return pB;
}

/**
 * inerts a new entry to the client data store
 * @param s Client store (locked)
 * @param pA IP to insert
 * @param now Current time (last access)
 * @return inserted entry
 */
static qos_s_entry_t **qos_cc_set(qos_s_t *s, qos_s_entry_t *pA, time_t now) {
  qos_s_entry_t **pB;
  unsigned char *b = (void *)&pA->ip6[1];
  int mod = b[7] % m_qos_cc_partition;
  //  int mod = pA->ip6[1] % m_qos_cc_partition;
  int max = (s->max / m_qos_cc_partition);
  int start = mod * max;
  s->t = now;
  qsort(&s->timed[start], max, sizeof(qos_s_entry_t *), qos_cc_comp_time);
  if(s->num < s->max) {
    s->num++;
  }
  pB = &s->timed[start];
  (*pB)->ip6[0] = pA->ip6[0];
  (*pB)->ip6[1] = pA->ip6[1];
  (*pB)->time = now;
  if(m_ip_type == QS_IP_V4) {
    qsort(&s->ipd[start], max, sizeof(qos_s_entry_t *), qos_cc_compv4);
  } else {
    qsort(&s->ipd[start], max, sizeof(qos_s_entry_t *), qos_cc_comp);
  }

  (*pB)->vip = 0;
  (*pB)->lowrate = 0;
  (*pB)->block = 0;
  (*pB)->blockMsg = 0;
  (*pB)->block_time = 0;
  if(s->limitTable) {
    int i;
    for(i = 0; i < apr_table_elts(s->limitTable)->nelts; i++) {
      (*pB)->limit[i].limit = 0;
      (*pB)->limit[i].limit_time = 0;
    }
  }
  (*pB)->interval = now;
  (*pB)->req = 0;
  (*pB)->req_per_sec = 0;
  (*pB)->req_per_sec_block_rate = 0;
  (*pB)->event_req = 0;
  (*pB)->serialize = 0;
  (*pB)->html = 1;
  (*pB)->cssjs = 1;
  (*pB)->img = 1;
  (*pB)->other = 1;
  (*pB)->notmodified = 1;
  (*pB)->events = 0;
  return pB;
}

/* 000-255 */
#ifdef UNUSED
static int qos_dec32c(const char *x) {
  char buf[4];
  strncpy(buf, x, 3);
  buf[3] = '\0';
  return atoi(buf);
}

static int qos_dec22c(const char *x) {
  char buf[4];
  strncpy(buf, x, 2);
  buf[2] = '\0';
  return atoi(buf);
}
#endif

/**
 * hex value for the char
 * @param x
 * @return hex value
 */
static int qos_hex2c(const char *x) {
  int i, ch;
  ch = x[0];
  if (isdigit(ch)) {
    i = ch - '0';
  }else if (isupper(ch)) {
    i = ch - ('A' - 10);
  } else {
    i = ch - ('a' - 10);
  }
  i <<= 4;
  
  ch = x[1];
  if (isdigit(ch)) {
    i += ch - '0';
  } else if (isupper(ch)) {
    i += ch - ('A' - 10);
  } else {
    i += ch - ('a' - 10);
  }
  return i;
}

#define QOS_ISHEX(x) (((x >= '0') && (x <= '9')) || \
                      ((x >= 'a') && (x <= 'f')) || \
                      ((x >= 'A') && (x <= 'F')))


/**
 * url unescaping (%xx, \xHH, '+')
 * optional decoding:
 * - uni: MS IIS unicode %uXXXX
 * - ansi: ansi c esc (\n, \r, ...), not implemented
 * - char: charset conv, not implemented
 * - html: (amp/angelbr, &#xHH;, &#DDD;, &#DD;), not implemented ('&' is delimiter)
 */
static int qos_unescaping(char *x, int mode, int *error) {
  /* start with standard url decoding*/
  int i, j, ch;
  if(x == 0) {
    return 0;
  }
  if(x[0] == '\0') {
    return 0;
  }
  for(i = 0, j = 0; x[i] != '\0'; i++, j++) {
    ch = x[i];
    if(ch == '%') {
      if(QOS_ISHEX(x[i + 1]) && QOS_ISHEX(x[i + 2])) {
        /* url %xx */
        ch = qos_hex2c(&x[i + 1]);
        i += 2;
      } else if((mode & QOS_DEC_MODE_FLAGS_UNI) && 
                ((x[i + 1] == 'u') || (x[i + 1] == 'U')) &&
                QOS_ISHEX(x[i + 2]) &&
                QOS_ISHEX(x[i + 3]) &&
                QOS_ISHEX(x[i + 4]) &&
                QOS_ISHEX(x[i + 5])) {
        /* unicode %uXXXX */
        ch = qos_hex2c(&x[i + 4]);
        if((ch > 0x00) && (ch < 0x5f) &&
           ((x[i + 2] == 'f') || (x[i + 2] == 'F')) &&
           ((x[i + 3] == 'f') || (x[i + 3] == 'F'))) {
          ch += 0x20;
        }
        i += 5;
      } else {
        (*error)++;
      }
    } else if((ch == '\\') &&
              (mode & QOS_DEC_MODE_FLAGS_UNI) &&
              ((x[i + 1] == 'u') || (x[i + 1] == 'U'))) {
      if(QOS_ISHEX(x[i + 2]) &&
         QOS_ISHEX(x[i + 3]) &&
         QOS_ISHEX(x[i + 4]) &&
         QOS_ISHEX(x[i + 5])) {
        /* unicode \uXXXX */
        ch = qos_hex2c(&x[i + 4]);
        if((ch > 0x00) && (ch < 0x5f) &&
           ((x[i + 2] == 'f') || (x[i + 2] == 'F')) &&
           ((x[i + 3] == 'f') || (x[i + 3] == 'F'))) {
          ch += 0x20;
        }
        i += 5;
      } else {
        (*error)++;
      }
    } else if(ch == '\\' && (x[i + 1] == 'x')) {
      if(QOS_ISHEX(x[i + 2]) && QOS_ISHEX(x[i + 3])) {
        /* url \xHH */
        ch = qos_hex2c(&x[i + 2]);
        i += 3;
      } else {
        (*error)++;
      }
    } else if(ch == '+') {
      ch = ' ';
    }
    x[j] = ch;
  }
  x[j] = '\0';
  return j;
}

/**
 * returns the request id from mod_unique_id (if available)
 */
static const char *qos_unique_id(request_rec *r, const char *eid) {
  const char *uid = apr_table_get(r->subprocess_env, "UNIQUE_ID");
  if(eid) {
    apr_table_set(r->notes, "error-notes", eid);
    apr_table_set(r->subprocess_env, QS_ErrorNotes, eid);
  }
  if(uid == NULL) {
    /* generate simple id if mod_unique_id has not been not loaded */
    qos_unique_id_t id;
    char *uidstr;
    int len;

    m_unique_id.unique_id_counter++;
    id.request_time = r->request_time;
    id.in_addr = m_unique_id.in_addr;
    id.pid = m_unique_id.pid;
    id.tid = apr_os_thread_current();
    id.conn = r->connection->id;
    id.unique_id_counter = m_unique_id.unique_id_counter;
    uidstr = (char *)apr_pcalloc(r->pool, apr_base64_encode_len(sizeof(qos_unique_id_t)));
    len = qos_encode64_binary(uidstr, (const char *)&id, sizeof(qos_unique_id_t));
    uidstr[len-2] = '\0';
    uid = uidstr;
    apr_table_set(r->subprocess_env, "UNIQUE_ID", uid);
  }
  return uid;
}

/**
 * returns the version number of mod_qos
 * @param p Pool to alloc version string from
 * @return Version string
 */
static char *qos_revision(apr_pool_t *p) {
  return apr_pstrdup(p, g_revision);
}

/**
 * Encrypts and base64 encodes the provided buffer
 * @param r
 * @param sconf Key to use (sconf->key)
 * @param b Buffer to encrypt
 * @param l Length of the buffer
 * @return Encrypted string (NULL on error)
 */
static char *qos_encrypt(request_rec *r, qos_srv_config *sconf, const unsigned char *b, int l) {
  EVP_CIPHER_CTX cipher_ctx;
  int buf_len = 0;
  int len = 0;
  unsigned char *buf = apr_pcalloc(r->pool, l + EVP_CIPHER_block_size(EVP_des_ede3_cbc()));

  /* sym enc, should be sufficient for this use case */
  EVP_CIPHER_CTX_init(&cipher_ctx);
  EVP_EncryptInit(&cipher_ctx, EVP_des_ede3_cbc(), sconf->key, NULL);
  if(!EVP_EncryptUpdate(&cipher_ctx, &buf[buf_len], &len, b, l)) {
    goto failed;
  }
  buf_len+=len;
  if(!EVP_EncryptFinal(&cipher_ctx, &buf[buf_len], &len)) {
    goto failed;
  }
  buf_len+=len;
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
  
  /* encode */
  {
    char *data = (char *)apr_pcalloc(r->pool, 1 + apr_base64_encode_len(buf_len));
    len = apr_base64_encode(data, (const char *)buf, buf_len);
    data[len] = '\0';
    return data;
  }

 failed:
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
  return NULL;
}

/**
 * Decryptes the base64 encoded string (see qos_encrypt())
 */
static int qos_decrypt(request_rec *r, qos_srv_config* sconf, unsigned char **ret_buf, const char *value) {
  EVP_CIPHER_CTX cipher_ctx;
  /* decode */
  char *dec = (char *)apr_pcalloc(r->pool, 1 + apr_base64_decode_len(value));
  int dec_len = apr_base64_decode(dec, value);
  *ret_buf = NULL;
  if(dec_len == 0) {
    return 0;
  } else {
    /* decrypt */
    int len = 0;
    int buf_len = 0;
    unsigned char *buf = apr_pcalloc(r->pool, dec_len);
    EVP_CIPHER_CTX_init(&cipher_ctx);
    EVP_DecryptInit(&cipher_ctx, EVP_des_ede3_cbc(), sconf->key, NULL);
    if(!EVP_DecryptUpdate(&cipher_ctx, (unsigned char *)&buf[buf_len], &len,
                          (const unsigned char *)dec, dec_len)) {
      goto failed;
    }
    buf_len+=len;
    if(!EVP_DecryptFinal(&cipher_ctx, (unsigned char *)&buf[buf_len], &len)) {
      goto failed;
    }
    buf_len+=len;
    EVP_CIPHER_CTX_cleanup(&cipher_ctx);
    *ret_buf = buf;
    return buf_len;
  }
 failed:
  EVP_CIPHER_CTX_cleanup(&cipher_ctx);
  return 0;
}

/**
 * Adds the user tracking cookie to r->headers_out if QOS_USER_TRACKING_NEW env variable
 * has been set.
 * @param r
 * @param sconf
 * @param status (302 or other)
 */
static void qos_send_user_tracking_cookie(request_rec *r, qos_srv_config* sconf, int status) {
  const char *new_user = apr_table_get(r->subprocess_env, QOS_USER_TRACKING_NEW);
  if(new_user) {
    char *sc;
    apr_size_t retcode;
    char tstr[MAX_STRING_LEN];
    apr_time_exp_t n;
    int len = QOS_RAN + QOS_MAGIC_LEN + 2 + strlen(new_user);
    unsigned char *value = apr_pcalloc(r->pool, len + 1);
    char *c;
    apr_time_exp_gmt(&n, r->request_time);
    apr_strftime(tstr, &retcode, sizeof(tstr), "%m", &n);
    RAND_bytes(value, QOS_RAN);
    memcpy(&value[QOS_RAN], qs_magic, QOS_MAGIC_LEN);
    memcpy(&value[QOS_RAN+QOS_MAGIC_LEN], tstr, 2);
    memcpy(&value[QOS_RAN+QOS_MAGIC_LEN+2], new_user, strlen(new_user));
    value[len] = '\0';
    c = qos_encrypt(r, sconf, value, len + 1);
    /* valid for 300 days */
    sc = apr_psprintf(r->pool, "%s=%s; Path=/; Max-Age=25920000",
                      sconf->user_tracking_cookie, c);
    if(status != HTTP_MOVED_TEMPORARILY) {
      apr_table_add(r->headers_out, "Set-Cookie", sc);
    } else {
      apr_table_add(r->err_headers_out, "Set-Cookie", sc);
    }
  }
  return;
}

/**
 * Verifies and sets the user tracking cookie
 * - QOS_USER_TRACKING if the cookie was available
 * - QOS_USER_TRACKING_NEW if a new cookie needs to be set
 *
 * syntax: b64(enc(<rand><magic><month><UNIQUE_ID>))
 *
 * shall be called after(!) mod_unique_id has created an id
 *
 * @param r
 * @param sconf
 * @param value Cookie received from the client, possibly null (see qos_get_remove_cookie())
 */
static void qos_get_create_user_tracking(request_rec *r, qos_srv_config* sconf,
                                         const char *value) {
  const char *uid = qos_unique_id(r, NULL);
  const char *verified = NULL;
  if(value != NULL) {
    int buf_len = 0;
    unsigned char *buf;
    buf_len = qos_decrypt(r, sconf, &buf, value);
    if((buf_len > (QOS_MAGIC_LEN + QOS_RAN)) &&
       (strncmp((char *)&buf[QOS_RAN], qs_magic, QOS_MAGIC_LEN) == 0)) {
      verified = (char *)&buf[QOS_RAN+QOS_MAGIC_LEN];
    }
  }
  if(verified == NULL) {
    verified = uid;
    apr_table_set(r->subprocess_env, QOS_USER_TRACKING_NEW, verified);
  } else if(strlen(verified) > 2) {
    /* renew, if not from this month */
    apr_size_t retcode;
    char tstr[MAX_STRING_LEN];
    apr_time_exp_t n;
    apr_time_exp_gmt(&n, r->request_time);
    apr_strftime(tstr, &retcode, sizeof(tstr), "%m", &n);
    if(strncmp(tstr, verified, 2) != 0) {
      apr_table_set(r->subprocess_env, QOS_USER_TRACKING_NEW, &verified[2]);
    }
    verified = &verified[2];
  } else {
    verified = uid;
    apr_table_set(r->subprocess_env, QOS_USER_TRACKING_NEW, verified);
  }
  apr_table_set(r->subprocess_env, QOS_USER_TRACKING, verified);
  return;
}

/**
 * Adds new milestone cookie to the response headers if QOS_MILESTONE_COOKIE has been set.
 * See qos_verify_milestone() about the syntax.
 */
static void qos_update_milestone(request_rec *r, qos_srv_config* sconf) {
  const char *new_ms = apr_table_get(r->subprocess_env, QOS_MILESTONE_COOKIE);
  if(new_ms) {
    apr_time_t now = apr_time_sec(r->request_time);
    int len = QOS_RAN + QOS_MAGIC_LEN  + sizeof(apr_time_t) + strlen(new_ms);
    unsigned char *value = apr_pcalloc(r->pool, len + 1);
    char *c;
    RAND_bytes(value, QOS_RAN);
    memcpy(&value[QOS_RAN], qs_magic, QOS_MAGIC_LEN);
    memcpy(&value[QOS_RAN+QOS_MAGIC_LEN], &now, sizeof(apr_time_t));
    memcpy(&value[QOS_RAN+QOS_MAGIC_LEN+sizeof(apr_time_t)], new_ms, strlen(new_ms));
    value[len] = '\0';
    c = qos_encrypt(r, sconf, value, len + 1);
    apr_table_add(r->headers_out, "Set-Cookie",
                  apr_psprintf(r->pool, "%s=%s; Path=/;",
                               QOS_MILESTONE_COOKIE, c));
  }
  return;
}

/**
 * Verifies the milestone. Evaluates rule and enforces it. Does also set the
 * QOS_MILESTONE_COOKIE variable if a new milestone has been reached.
 *
 * milestone cookie syntax: b64(enc(<rand><magic><time><milestone>))
 *
 * @param r
 * @param sconf
 * @param value Cookie received from the client (contains the already reached milestones)
 * @return APR_SUCCESS if request is allowed, otherwise HTTP_FORBIDDEN 
 */

static int qos_verify_milestone(request_rec *r, qos_srv_config* sconf, const char *value) {
  char *the_request;
  int the_request_len;
  int escerr = 0;
  qos_milestone_t *milestone = NULL;
  apr_table_entry_t *entry;
  int i;
  int ms = -1; // milestone the user has reached
  int required = -1; // required for this request
  if(value != NULL) {
    int buf_len = 0;
    unsigned char *buf;
    buf_len = qos_decrypt(r, sconf, &buf, value);
    if((buf_len > (QOS_MAGIC_LEN + QOS_RAN)) &&
       (strncmp((char *)&buf[QOS_RAN], qs_magic, QOS_MAGIC_LEN) == 0)) {
      apr_time_t *t = (apr_time_t *)&buf[QOS_RAN+QOS_MAGIC_LEN];
      apr_time_t now = apr_time_sec(r->request_time);
      if(now <= (*t + sconf->milestone_timeout)) {
        ms = atoi((char *)&buf[QOS_RAN+QOS_MAGIC_LEN+sizeof(apr_time_t)]);
      }
    }
  }
  the_request = apr_pstrdup(r->pool, r->the_request);
  the_request_len = qos_unescaping(the_request, QOS_DEC_MODE_FLAGS_URL, &escerr);
  entry = (apr_table_entry_t *)apr_table_elts(sconf->milestones)->elts;
  for(i = 0; i < apr_table_elts(sconf->milestones)->nelts; i++) {
    milestone = (qos_milestone_t *)entry[i].val;
    if(pcre_exec(milestone->preg, milestone->extra, the_request, the_request_len, 0, 0, NULL, 0) == 0) {
      required = atoi(entry[i].key);
      break;
    }
  }
  if(milestone && (required >= 0)) {
    if(ms < (required - 1)) {
      /* not allowed */
      int severity = milestone->action == QS_DENY ? APLOG_ERR : APLOG_WARNING;
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|severity, 0, r,
                    QOS_LOG_PFX(047)"access denied, reached milestone '%d' (%s),"
                    " user has already passed '%s',"
                    " action=%s, c=%s, id=%s",
                    required, milestone->pattern,
                    ms == -1 ? "none" : apr_psprintf(r->pool, "%d", ms),
                    milestone->action == QS_DENY ? "deny" : "log only (pass milestone)",
                    QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                    qos_unique_id(r, "047"));
      if(milestone->action == QS_DENY) {
        return HTTP_FORBIDDEN;
      }
    }
    if(required > ms) {
      /* update milestone */
      apr_table_set(r->subprocess_env, QOS_MILESTONE_COOKIE, apr_psprintf(r->pool, "%d", required));
    }
  }
  return APR_SUCCESS;
}

/**
 * Extracts the cookie from the request.
 * @param r
 * @param cooke_name Name of the cookie to remove from the request headers
 * @param Cookie if available of NULL if not
 */
static char *qos_get_remove_cookie(request_rec *r, const char *cookie_name) {
  const char *cookie_h = apr_table_get(r->headers_in, "cookie");
  if(cookie_h) {
    char *cn = apr_pstrcat(r->pool, cookie_name, "=", NULL);
    char *p = ap_strcasestr(cookie_h, cn);
    if(p) {
      char *sp = p;
      char *value = NULL;
      p[0] = '\0'; /* terminates the beginning of the cookie header */
      sp--; /* deletes spaces "in front" of the qos cookie */
      while((sp > cookie_h) && (sp[0] == ' ')) {
        sp[0] = '\0';
        sp--;
      }
      p = &p[strlen(cn)];
      value = ap_getword(r->pool, (const char **)&p, ';');
      while(p && (p[0] == ' ')) p++;
      /* skip a path, if there is any */
      if(p && (strncasecmp(p, "$path=", strlen("$path=")) == 0)) {
        ap_getword(r->pool, (const char **)&p, ';');
      }
      /* restore cookie header appending the part left*/
      if(p && p[0]) {
        if(cookie_h[0]) {
          if(p[0] == ' ') {
            cookie_h = apr_pstrcat(r->pool, cookie_h, p, NULL);
          } else {
            cookie_h = apr_pstrcat(r->pool, cookie_h, " ", p, NULL);
          }
        } else {
          cookie_h = apr_pstrcat(r->pool, p, NULL);
        }
      }
      if(strlen(cookie_h) == 0) {
        apr_table_unset(r->headers_in, "cookie");
      } else {
        if((strncasecmp(cookie_h, "$Version=", strlen("$Version=")) == 0) &&
           (strlen(cookie_h) <= strlen("$Version=X; "))) {
          /* nothing left */
          apr_table_unset(r->headers_in, "cookie");
        } else {
          apr_table_set(r->headers_in, "cookie", cookie_h);
        }
      }
      return value;
    }
  }
  return NULL;
}

/**
 * verifies the session cookie 0=failed, 1=succeeded
 */
static int qos_verify_session(request_rec *r, qos_srv_config* sconf) {
  int buf_len = 0;
  unsigned char *buf;
  char *value = qos_get_remove_cookie(r, sconf->cookie_name);
  if(value == NULL) return 0;
  buf_len = qos_decrypt(r, sconf, &buf, value);
  if(buf_len != sizeof(qos_session_t)) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                  QOS_LOG_PFX(021)"session cookie verification failed, "
                  "decoding failed, id=%s", qos_unique_id(r, "021"));
    return 0;
  } else {
    qos_session_t *s = (qos_session_t *)buf;
    s->magic[QOS_MAGIC_LEN-1] = '\0';
    if(strcmp(qs_magic, s->magic) != 0) {
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                    QOS_LOG_PFX(022)"session cookie verification failed, "
                    "invalid magic, id=%s", qos_unique_id(r, "022"));
      return 0;
    }
    if(s->time < (apr_time_sec(r->request_time) - sconf->max_age)) {
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                    QOS_LOG_PFX(023)"session cookie verification failed, "
                    "expired, id=%s", qos_unique_id(r, "023"));
      return 0;
    }
  }
  /* success */
  apr_table_set(r->notes, QS_REC_COOKIE, "");
  return 1;
}

/**
 * set/update the session cookie
 */
static void qos_set_session(request_rec *r, qos_srv_config *sconf) {
  qos_session_t *s = (qos_session_t *)apr_pcalloc(r->pool, sizeof(qos_session_t));
  char *cookie;
  char *session;
  /* payload */
  strcpy(s->magic, qs_magic);
  s->magic[QOS_MAGIC_LEN-1] = '\0';
  s->time = time(NULL);
  RAND_bytes(s->ran, sizeof(s->ran));
  session = qos_encrypt(r, sconf, (const unsigned char *)s, sizeof(qos_session_t));
  if(session == NULL) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                  QOS_LOG_PFX(025)"failed to create session cookie, id=%s",
                  qos_unique_id(r, "025"));
    return;
  }
  cookie = apr_psprintf(r->pool, "%s=%s; Path=%s; Max-Age=%d",
                        sconf->cookie_name, session,
                        sconf->cookie_path, sconf->max_age);
  apr_table_add(r->headers_out,"Set-Cookie", cookie);
  return;
}

/**
 * returns the request context
 */
static qs_req_ctx *qos_rctx_config_get(request_rec *r) {
  qs_req_ctx *rctx = ap_get_module_config(r->request_config, &qos_module);
  if(rctx == NULL) {
    rctx = apr_pcalloc(r->pool, sizeof(qs_req_ctx));
    rctx->entry = NULL;
    rctx->entry_cond = NULL;
    rctx->evmsg = NULL;
    rctx->is_vip = 0;
    rctx->event_entries = apr_table_make(r->pool, 1);
    rctx->maxpostcount = 0;
    rctx->event_kbytes_per_sec_block_rate = 0;
    rctx->cc_event_req_set = 0;
    rctx->cc_serialize_set = 0;
    rctx->body_window = NULL;
    ap_set_module_config(r->request_config, &qos_module, rctx);
  }
  return rctx;
}

/**
 * destroy shared memory and mutexes
 */
static void qos_destroy_act(qs_actable_t *act) {
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL,
               QOS_LOGD_PFX"cleanup shared memory: %"APR_SIZE_T_FMT" bytes",
               act->size);
  act->child_init = 0;
  if(act->lock_file && act->lock_file[0]) {
    // called by apr_pool_cleanup_register():
    // apr_global_mutex_destroy(act->lock);
    act->lock_file[0] = '\0';
    act->lock_file = NULL;
  }
  //apr_shm_destroy(act->m);
  apr_pool_destroy(act->pool);
}

/**
 * returns the persistent configuration (restarts)
 */
static qos_user_t *qos_get_user_conf(apr_pool_t *ppool) {
  void *v;
  qos_user_t *u;
  apr_pool_userdata_get(&v, QS_USR_SPE, ppool);
  u = v;
  if(v) {
    return v;
  }
  u = (qos_user_t *)apr_pcalloc(ppool, sizeof(qos_user_t));
  u->server_start = 0;
  u->act_table = apr_table_make(ppool, 2);
  u->generation = 0;
  apr_pool_userdata_set(u, QS_USR_SPE, apr_pool_cleanup_null, ppool);
  u->qos_cc = NULL;
  return u;
}

/**
 * tells if server is terminating immediately or not
 */
static int qos_is_graceful(qs_actable_t *act) {
  int mpm_gen;
  QOS_MY_GENERATION(mpm_gen);
  if(mpm_gen != act->generation) return 1;
  return 0;
}

/* clear all counters of the per client data store at graceful restart
   used to prevent counter grow due blocked/crashed client processes*/
static void qos_clear_cc(qos_user_t *u) {
  if(u->qos_cc) {
    qos_s_entry_t **entry;
    int i;
    apr_global_mutex_lock(u->qos_cc->lock);          /* @CRT37 */
    u->qos_cc->connections = 0;
    entry = u->qos_cc->ipd;
    for(i = 0; i < u->qos_cc->max; i++) {
      (*entry)->event_req = 0;
      (*entry)->serialize = 0;
      entry++;
    }
    apr_global_mutex_unlock(u->qos_cc->lock);        /* @CRT37 */
  }
}

/**
 * destroys the act
 * shared memory must not be destroyed before graceful restart has
 * been finished due running requests still need the shared memory
 * till they have finished.
 * keep the memory leak as little as possible ...
 */
static apr_status_t qos_cleanup_shm(void *p) {
  qs_actable_t *act = p;
  qos_user_t *u = qos_get_user_conf(act->ppool);
  /* this_generation id is never deleted ... */
  int mpm_gen;
  char *this_generation;
  char *last_generation;
  int i;
  apr_table_entry_t *entry;
  QOS_MY_GENERATION(mpm_gen);
  this_generation = apr_psprintf(act->ppool, "%d", mpm_gen);
  u->generation = mpm_gen;
  qos_clear_cc(u);
  if(qos_is_graceful(act)) {
    last_generation = apr_psprintf(act->pool, "%d", mpm_gen-1);
  } else {
    last_generation = this_generation;
  }
  /* delete acts from the last graceful restart */
  entry = (apr_table_entry_t *)apr_table_elts(u->act_table)->elts;
  for(i = 0; i < apr_table_elts(u->act_table)->nelts; i++) {
    if(strcmp(entry[i].key, last_generation) == 0) {
      qs_actable_t *a = (qs_actable_t *)entry[i].val;
      qos_destroy_act(a);
    }
  }
  apr_table_unset(u->act_table, last_generation);
  if(qos_is_graceful(act)) {
    /* don't delete this act now, but at next server restart ... */
    apr_table_addn(u->act_table, this_generation, (char *)act);
  } else {
    if(u->qos_cc) {
      qos_cc_free(u->qos_cc);
      u->qos_cc = NULL;
    }
    qos_destroy_act(act);
  }
  return APR_SUCCESS;
}

/**
 * init the shared memory of the act
 *  act->conn          <- start
 *  act->conn->conn_ip <- start + sizeof(conn) * QS_MEM_SEG
 *                      + [max_ip]
 *  act->entry         <- 
 *                      + [rule_entries]
 *  act->event_limit   <-
 *                      + [event_limit_entries]
 */
static apr_status_t qos_init_shm(server_rec *s, qos_srv_config *sconf, qs_actable_t *act,
                                 apr_table_t *table, int maxclients) {
  char *file = "-";
  apr_status_t res;
  int i;
  int rule_entries = apr_table_elts(table)->nelts;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(table)->elts;
  int event_limit_entries = sconf->event_limit_a->nelts;
  qs_acentry_t *e = NULL;
  int max_ip;
  ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &sconf->server_limit);
  ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &sconf->thread_limit);
  if(sconf->thread_limit == 0) sconf->thread_limit = 1; /* mpm prefork */
  max_ip = sconf->thread_limit * sconf->server_limit;
  max_ip = maxclients > 0 ? maxclients : max_ip;
  act->size = (max_ip * QS_MEM_SEG * APR_ALIGN_DEFAULT(sizeof(qs_ip_entry_t))) +
    (rule_entries * APR_ALIGN_DEFAULT(sizeof(qs_acentry_t))) +
    (event_limit_entries * APR_ALIGN_DEFAULT(sizeof(qos_event_limit_entry_t))) +
    APR_ALIGN_DEFAULT(sizeof(qs_conn_t)) +
    2048;
  /* use anonymous shm by default */
  res = apr_shm_create(&act->m, act->size, NULL, act->pool);
  if(APR_STATUS_IS_ENOTIMPL(res)) {
    file = apr_psprintf(act->pool, "%s_m.mod_qos",
                        qos_tmpnam(act->pool, s));
#ifdef ap_http_scheme
    /* Apache 2.2 */
    apr_shm_remove(file, act->pool);
#endif
    res = apr_shm_create(&act->m, act->size, file, act->pool);
  }
  ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, 
               QOS_LOGD_PFX"%s(%s), create shared memory (ACT)(%s): %"APR_SIZE_T_FMT" bytes"
               " (r=%d,ip=%d)", 
               s->server_hostname == NULL ? "-" : s->server_hostname,
               s->is_virtual ? "v" : "b",
               file,
               act->size,
               rule_entries, max_ip);
  if(res != APR_SUCCESS) {
    char buf[MAX_STRING_LEN];
    apr_strerror(res, buf, sizeof(buf));
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, 
                 QOS_LOG_PFX(002)"failed to create shared memory (ACT)(%s): %s"
                 " (%"APR_SIZE_T_FMT" bytes)",
                 file, buf, act->size);
    return res;
  } else {
    qs_conn_t *c = apr_shm_baseaddr_get(act->m);
    qs_ip_entry_t *ce = (qs_ip_entry_t *)&c[1];
    act->conn = c;
    act->conn->conn_ip_len = max_ip * QS_MEM_SEG;
    act->conn->conn_ip = ce;
    act->conn->connections = 0;
    for(i = 0; i < act->conn->conn_ip_len; i++) {
      ce->ip6[0] = 0;
      ce->ip6[1] = 0;
      ce->counter = 0;
      ce->error = 0;
      ce++;
    }
    if(rule_entries) {
      act->entry = (qs_acentry_t *)ce;
      e = act->entry;
    } else {
      act->entry = NULL;
    }
    /* init rule entries (link data, init mutex) */
    for(i = 0; i < rule_entries; i++) {
      qs_rule_ctx_t *rule = (qs_rule_ctx_t *)entry[i].val;
      e->next = &e[1];
      e->id = i;
      e->url = rule->url;
      e->url_len = strlen(e->url);
      e->event = rule->event;
      if(e->event) {
        act->has_events++;
      }
      e->regex = rule->regex;
      e->condition = rule->condition;
      e->regex_var = rule->regex_var;
      e->limit = rule->limit;
      if(e->limit == 0 ) {
        if((e->condition == NULL) && (e->event == NULL)) {
          ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, s,
                       QOS_LOG_PFX(003)"request level rule %s has no concurrent request limitations",
                       e->url);
        }
      }
      e->interval = apr_time_sec(apr_time_now());
      e->req_per_sec_limit = rule->req_per_sec_limit;
      e->kbytes_per_sec_limit = rule->kbytes_per_sec_limit;
      e->hard_kbytes_per_sec_limit = rule->hard_kbytes_per_sec_limit;
      e->counter = 0;
      e->lock = act->lock;
      if(i < rule_entries - 1) {
        e = e->next;
      } else {
        e->next = NULL;
      }
    }
    if(event_limit_entries == 0) {
      act->event_entry = NULL;
    } else {
      // source (config) event limit array
      qos_event_limit_entry_t *eves = (qos_event_limit_entry_t *)sconf->event_limit_a->elts;
      // target (act) event limit array
      qos_event_limit_entry_t *evet;
      if(e) {
        // end of the last act rule entry
        act->event_entry = (qos_event_limit_entry_t *)&e[1];
      } else {
        // end of the last connection entry
        act->event_entry = (qos_event_limit_entry_t *)ce;
      }
      evet = act->event_entry;
      // set config
      for(i = 0; i < event_limit_entries; i++) {
        evet->env_var = eves->env_var;
        evet->max = eves->max;
        evet->seconds = eves->seconds;
        evet->limit = 0;
        evet->limit_time = 0;
        evet->action = eves->action;
        evet++;
        eves++;
      }
    }
  }
  return APR_SUCCESS;
}

/**
 * Loads the geo database. See QS_GEO_PATTERN about the file format.
 * @param pool To allocate memory from
 * @param db Path to the database file (CSV)
 * @param size Number of entries in the db (size of the returned array)
 * @param msg Error message if something went wrong while loading the db
 * @param Array with all enties
 */
static qos_geo_t *qos_loadgeo(apr_pool_t *pool, const char *db, int *size, char **msg) {
#ifdef AP_REGEX_H
  ap_regmatch_t ma[AP_MAX_REG_MATCH];
  ap_regex_t *preg;
#else
  regmatch_t ma[AP_MAX_REG_MATCH];
  regex_t *preg;
#endif
  qos_geo_t *geo = NULL;
  qos_geo_t *g = NULL;
  qos_geo_t *last = NULL;
  int lines = 0;
  char line[HUGE_STRING_LEN];
  FILE *file;
  *size = 0;
#ifdef AP_REGEX_H
  preg = ap_pregcomp(pool, QS_GEO_PATTERN, AP_REG_EXTENDED);
#else
  preg = ap_pregcomp(pool, QS_GEO_PATTERN, REG_EXTENDED);
#endif
  if(preg == NULL) {
    // internal error
    *msg = apr_pstrdup(pool, "failed to compile regular expression "QS_GEO_PATTERN);
    return NULL;
  }
  file = fopen(db, "r");
  if(!file) {
    *msg = apr_psprintf(pool, "could not open file %s (%s)", db, strerror(errno));
    return NULL;
  }
  while(fgets(line, sizeof(line), file) != NULL) {
    if(strlen(line) > 0) {
      if(ap_regexec(preg, line, 0, NULL, 0) == 0) {
        lines++;
      } else {
        *msg = apr_psprintf(pool, "invalid entry in database: '%s'", line);
      }
    }
  }
  *size = lines;
  geo = apr_pcalloc(pool, sizeof(qos_geo_t) * lines);
  g = geo;
  fseek(file, 0, SEEK_SET);
  lines = 0;
  while(fgets(line, sizeof(line), file) != NULL) {
    lines++;
    if(strlen(line) > 0) {
      if(ap_regexec(preg, line, AP_MAX_REG_MATCH, ma, 0) == 0) {
        line[ma[1].rm_eo] = '\0';
        line[ma[2].rm_eo] = '\0';
        line[ma[3].rm_eo] = '\0';
        g->start = atoll(&line[ma[1].rm_so]);
        g->end = atoll(&line[ma[2].rm_so]);
        strncpy(g->country, &line[ma[3].rm_so], 2);
        if(last) {
          if(g->start < last->start) {
            *msg = apr_psprintf(pool, "wrong order/lines not sorted (line %d)", lines);
          }
        }
        last = g;
        g++;
      }
    }
  }
  fclose(file);
  return geo;
}

/**
 * Verifies if the string is a number
 * @param num Number to test
 * @param 1 if numeric (0 if not)
 */
static int qos_is_num(const char *num) {
  int i = 0;
  while(num[i]) {
    if(!isdigit(num[i])) {
      return 0;
    }
    i++;
  }
  return 1;
}

/**
 * Helper for the status viewer (unsigned long to char).
 */
static void qos_collect_ip(request_rec *r, qos_srv_config *sconf,
                           apr_table_t *entries, int limit,
                           int html) {
  int i = sconf->act->conn->conn_ip_len;
  qs_ip_entry_t *conn_ip = sconf->act->conn->conn_ip;
  apr_global_mutex_lock(sconf->act->lock);   /* @CRT8 */
  while(i) {
    if(conn_ip->ip6[0] || conn_ip->ip6[1]) {
      char *red = "style=\"background-color: rgb(240,153,155);\"";
      if(html) {
        apr_table_addn(entries, apr_psprintf(r->pool, "%s</td><td %s colspan=\"3\">%d",
                                             qos_ip_long2str(r->pool, conn_ip->ip6),
                                             ((limit != -1) && conn_ip->counter >= limit) ? red : "",
                                             conn_ip->counter), "");
      } else {
        apr_table_addn(entries, qos_ip_long2str(r->pool, conn_ip->ip6), apr_psprintf(r->pool, "%d", conn_ip->counter));
      }
    }
    conn_ip++;
    i--;
  }
  apr_global_mutex_unlock(sconf->act->lock); /* @CRT8 */
}


/**
 * Count's the number of free ip entries (for the status viewer only)
 */
static int qos_count_free_ip(qos_srv_config *sconf) {
  int c = sconf->act->conn->conn_ip_len / QS_MEM_SEG;
  int i = sconf->act->conn->conn_ip_len;
  qs_ip_entry_t *conn_ip = sconf->act->conn->conn_ip;
  apr_global_mutex_lock(sconf->act->lock);   /* @CRT7 */
  while(i) {
    if((conn_ip->ip6[0] != 0) ||
       (conn_ip->ip6[1] != 0)) {
      c--;
    }
    conn_ip++;
    i--;
  }
  apr_global_mutex_unlock(sconf->act->lock); /* @CRT7 */
  return c;
}

/**
 * adds an ip entry (insert or increment)
 *
 * @param sconf
 * @param cconf Configuration record containing the ip table(s)
 * @param e Pointer to the IP entry
 *          NOTE: we can't sort the list since the address of this pointer
 *                must not be change (we don't keep the lock)
 * @return The number of connections open by this IP
 */
static int qos_inc_ip(qos_srv_config *sconf, 
                      qs_conn_ctx *cconf, qs_ip_entry_t **e) {
  int num = -1;
  qs_ip_entry_t *free = NULL;
  int i = cconf->sconf->act->conn->conn_ip_len / QS_MEM_SEG; // size of the array
  int seqnum = (cconf->ip6[1] % QS_MEM_SEG) * i;             // array offset
  qs_ip_entry_t *conn_ip = cconf->sconf->act->conn->conn_ip;
  conn_ip = &conn_ip[seqnum];                                // address of the first entry

  apr_global_mutex_lock(cconf->sconf->act->lock);   /* @CRT1 */

  // search the whole list (until we find an exiting entry for this ip)
  while(i) {
    if((conn_ip->ip6[0] == 0) &&
       (conn_ip->ip6[1] == 0) &&
       (free == NULL)) {
      // first free entry
      free = conn_ip;
    }
    if((conn_ip->ip6[0] == cconf->ip6[0]) &&
       (conn_ip->ip6[1] == cconf->ip6[1])) {
      // found an existing entry
      conn_ip->counter++;
      num = conn_ip->counter;
      *e = conn_ip;
      break;
    }
    conn_ip++;
    i--;
  }
  if(num == -1) {
    // no entry found, use the first free entry
    if(free) {
      free->ip6[0] = cconf->ip6[0];
      free->ip6[1] = cconf->ip6[1];
      free->counter++;
      num = free->counter;
      *e = free;
    } else {
      ap_log_error(APLOG_MARK, APLOG_CRIT, 0, sconf->base_server, 
                   QOS_LOG_PFX(035)"QS_SrvMaxConn: no free IP slot available!"
                   " Check log for unclean child exit and consider"
                   " to do a graceful server restart.");
    }
  }
  
  apr_global_mutex_unlock(cconf->sconf->act->lock); /* @CRT1 */

  return num;
}

/**
 * removes an ip entry (deletes/decrements)
 */
static void qos_dec_ip(qs_conn_ctx *cconf) {
  int i = cconf->sconf->act->conn->conn_ip_len / QS_MEM_SEG;
  int seqnum = (cconf->ip6[1] % QS_MEM_SEG) * i;
  qs_ip_entry_t *conn_ip = cconf->sconf->act->conn->conn_ip;
  conn_ip = &conn_ip[seqnum];
  apr_global_mutex_lock(cconf->sconf->act->lock);   /* @CRT2 */
  while(i) {
    if((conn_ip->ip6[0] == cconf->ip6[0]) &&
       (conn_ip->ip6[1] == cconf->ip6[1])) {
      // entry found, decrement and exit
      conn_ip->counter--;
      if(conn_ip->counter == 0) {
        // entry is no longer used by this ip
        conn_ip->ip6[0] = 0;
        conn_ip->ip6[1] = 0;
        conn_ip->error = 0;
      }
      break;
    }
    conn_ip++;
    i--;
  }
  apr_global_mutex_unlock(cconf->sconf->act->lock); /* @CRT2 */
}

/**
 * send server error, used for connection errors
 */
static int qos_return_error(conn_rec *c) {
  char *line = apr_pstrcat(c->pool, AP_SERVER_PROTOCOL, " ",
                           ap_get_status_line(500), CRLF CRLF, NULL);
  apr_bucket *e = apr_bucket_pool_create(line, strlen(line), c->pool, c->bucket_alloc);
  apr_bucket_brigade *bb = apr_brigade_create(c->pool, c->bucket_alloc);
  APR_BRIGADE_INSERT_HEAD(bb, e);
  e = apr_bucket_flush_create(c->bucket_alloc);
  APR_BRIGADE_INSERT_TAIL(bb, e);
  ap_pass_brigade(c->output_filters, bb);
  return m_retcode;
}

/**
 * returns custom error page
 */
static int qos_error_response(request_rec *r, const char *error_page) {
  if(r->subprocess_env) {
    const char *v = apr_table_get(r->subprocess_env, "QS_ErrorPage");
    if(v) {
      error_page = v;
    }
  }
  if(error_page) {
    /* do (almost) the same as ap_die() does */
    const char *error_notes;
    r->status = m_retcode;
    r->connection->keepalive = AP_CONN_CLOSE;
    r->no_local_copy = 1;
    apr_table_setn(r->subprocess_env, "REQUEST_METHOD", r->method);
    if ((error_notes = apr_table_get(r->notes, 
                                     "error-notes")) != NULL) {
      apr_table_setn(r->subprocess_env, "ERROR_NOTES", error_notes);
    }
    /* external or internal redirect */
    if(strncasecmp(error_page, "http", 4) == 0) {
      apr_table_set(r->headers_out, "Location", error_page);
      return HTTP_MOVED_TEMPORARILY;
    } else {
      r->method = apr_pstrdup(r->pool, "GET");
      r->method_number = M_GET;
      ap_internal_redirect(error_page, r);
      return DONE;
    }
  }
  return DECLINED;
}

/**
 * returns the matching regex with the lowest limitation
 */
static qs_acentry_t *qos_getrule_byregex(request_rec *r, qos_srv_config *sconf) {
  qs_acentry_t *ret = NULL;
  qs_actable_t *act = sconf->act;
  qs_acentry_t *e = act->entry;
  int limit = -1;
  while(e) {
    if((e->event == NULL) && (e->regex != NULL) && (e->condition == NULL)) {
      if((limit == -1) || (e->limit < limit)) {
        if(ap_regexec(e->regex, r->unparsed_uri, 0, NULL, 0) == 0) {
          if(limit == -1) {
            ret = e;
            limit = e->limit;
          } else if(e->limit < limit) {
            ret = e;
            limit = e->limit;
          }
        }
      }
    }
    e = e->next;
  }
  return ret;
}

/**
 * returns the matching conditional regex with the lowest limitation
 */
static qs_acentry_t *qos_getcondrule_byregex(request_rec *r, qos_srv_config *sconf) {
  qs_acentry_t *ret = NULL;
  qs_actable_t *act = sconf->act;
  qs_acentry_t *e = act->entry;
  int limit = -1;
  while(e) {
    if((e->event == NULL) && (e->regex != NULL) && (e->condition != NULL)) {
      if((limit == -1) || (e->limit < limit)) {
        if(ap_regexec(e->regex, r->unparsed_uri, 0, NULL, 0) == 0) {
          if(limit == -1) {
            ret = e;
            limit = e->limit;
          } else if(e->limit < limit) {
            ret = e;
            limit = e->limit;
          }
        }
      }
    }
    e = e->next;
  }
  return ret;
}

/**
 * returns the best matching location entry
 */
static qs_acentry_t *qos_getrule_bylocation(request_rec * r, qos_srv_config *sconf) {
  qs_acentry_t *ret = NULL;
  qs_actable_t *act = sconf->act;
  qs_acentry_t *e = act->entry;
  int match_len = 0;
  while(e) {
    if((e->event == NULL) && (e->regex == NULL) && (r->parsed_uri.path != NULL)) {
      /* per location limitation */
      if(e->url && (strncmp(e->url, r->parsed_uri.path, e->url_len) == 0)) {
        /* best match */
        if(e->url_len > match_len) {
          match_len = e->url_len;
          ret = e;
        }
      }
    }
    e = e->next;
  }
  return ret;
}

/**
 * checks for VIP user (may pass restrictions)
 */
static int qos_is_vip(request_rec *r, qos_srv_config *sconf) {
  if(qos_verify_session(r, sconf)) {
    apr_table_set(r->subprocess_env, QS_VipRequest, "yes");
    apr_table_set(r->subprocess_env, QS_ISVIPREQ, "yes");
    return 1;
  }
  if(r->subprocess_env) {
    const char *v = apr_table_get(r->subprocess_env, QS_VipRequest);
    if(v && (strcasecmp(v, "yes") == 0)) {
      apr_table_set(r->subprocess_env, QS_ISVIPREQ, "yes");
      return 1;
    }
  }
  return 0;
}

/**
 * writes the parp table to a single query line
 */
static const char *qos_parp_query(request_rec *r, apr_table_t *tl, const char *add) {
  int add_len = 0;
  char *query = NULL;
  int len = 0;
  char *p;
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(tl)->elts;
  for(i = 0; i < apr_table_elts(tl)->nelts; i++) {
    len = len + 
      (entry[i].key == NULL ? 0 : strlen(entry[i].key)) +
      (entry[i].val == NULL ? 0 : strlen(entry[i].val)) +
      2;
  }
  if(add && add[0]) {
    add_len = strlen(add);
    len = len + add_len + 1;
  }
  query = apr_pcalloc(r->pool, len + 2);
  query[0] = '?';
  if(add_len) {
    memcpy(&query[1], add, add_len);
    p = &query[add_len];
  } else {
    p = &query[1];
  }
  p[0] = '\0';
  for(i = 0; i < apr_table_elts(tl)->nelts; i++) {
    int l = strlen(entry[i].key);
    if(p != &query[1]) {
      p[0] = '&';
      p++;
      p[0] = '\0';
    }
    memcpy(p, entry[i].key, l);
    p += l;
    p[0] = '=';
    p++;
    l = strlen(entry[i].val);
    memcpy(p, entry[i].val, l);
    p += l;
    p[0] = '\0';
  }
  apr_table_setn(r->notes, apr_pstrdup(r->pool, QS_PARP_QUERY), query);
  return &query[1];
}

/* filter events */
static int qos_per_dir_event_rules(request_rec *r, qos_dir_config *dconf) {
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(dconf->rfilter_table)->elts;
  int i;
  for(i = 0; i < apr_table_elts(dconf->rfilter_table)->nelts; i++) {
    if(entry[i].key[0] == '+') {
      int deny_rule = 0;
      int ex = -1;
      qos_rfilter_t *rfilter = (qos_rfilter_t *)entry[i].val;
      if(rfilter->type == QS_DENY_EVENT) {
        deny_rule = 1;
        if(rfilter->text[0] == '!') {
          if(apr_table_get(r->subprocess_env, &rfilter->text[1]) == NULL) {
            ex = 0;
          }
        } else {
          if(apr_table_get(r->subprocess_env, rfilter->text) != NULL) {
            ex = 0;
          }
        }
      }
      if(deny_rule && (ex == 0)) {
        int severity = rfilter->action == QS_DENY ? APLOG_ERR : APLOG_WARNING;
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|severity, 0, r,
                      QOS_LOG_PFX(040)"access denied, %s rule id: %s (%s),"
                      " action=%s, c=%s, id=%s",
                      qos_rfilter_type2text(r->pool, rfilter->type),
                      rfilter->id,
                      rfilter->text, rfilter->action == QS_DENY ? "deny" : "log only",
                      QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                      qos_unique_id(r, "040"));
        if(rfilter->action == QS_DENY) {
          return HTTP_FORBIDDEN;
        }
      }
    }
  }
  return APR_SUCCESS;
}

/* json parser start ------------------------------------------------------- */
#define QOS_J_ERROR "HTTP_BAD_REQUEST QOS JSON PARSER: FORMAT ERROR"
#define QOS_j_RECURSION 80

static int j_val(apr_pool_t *pool, char **val, apr_table_t *tl, char *name, int rec);

static char *j_escape_url(apr_pool_t *pool, const char *c) {
  char buf[4];
  char special[] = " \t()<>@,;:\\/[]?={}\"'&%+";
  char *r = apr_pcalloc(pool, 3 * strlen(c));
  const char *p = c;
  int i = 0;
  while(p && p[0]) {
    char c = p[0];
    if(!apr_isprint(c) || strchr(special, c)) {
      sprintf(buf, "%02x", p[0]);
      r[i] = '%'; i++;
      r[i] = buf[0]; i++;
      r[i] = buf[1]; i++;
    } else {
      r[i] = c;
      i++;
    }
    p++;
  }
  return r;
}

static char *j_strchr(char *data, char d) {
  char *q = data;
  if(!q) {
    return NULL;
  }
  if(q[0] == d) {
    return q;
  }
  while(q[0]) {
    if((q[0] == d) && (q[-1] != '\\')) {
      return q;
    }
    q++;
  }
  return NULL;
}

static char *j_skip(char *in) {
  if(!in) return NULL;
  while(in[0] && ((in[0] == ' ') ||
		  (in[0] == '\t') ||
		  (in[0] == '\r') ||
		  (in[0] == '\n') ||
		  (in[0] == '\f'))) {
    in++;
  }
  return in;
}

static int j_string(apr_pool_t *pool, char **val, apr_table_t *tl, char *name, char **n) {
  char *d = *val;
  char *v = d;
  char *end = j_strchr(d, '"');
  if(!end) {
    apr_table_add(tl, QOS_J_ERROR, "error while parsing string (no ending double quote)");
    return HTTP_BAD_REQUEST;
  }
  end[0] = '\0';
  end++;
  *val = j_skip(end);
  /* TODO, improve string format validation */
  while(v[0]) {
    if(v[0] < ' ') {
      apr_table_add(tl, QOS_J_ERROR, "error while parsing string (invalid character)");
      return HTTP_BAD_REQUEST;
    }
    v++;
  }
  *n = d;
  return APR_SUCCESS;
}

static int j_num(apr_pool_t *pool, char **val, apr_table_t *tl, char *name, char **n) {
  char *s = *val;
  char *d = *val;
  while(d && ((d[0] >= '0' && d[0] <= '9') ||
	      d[0] == '.' ||
	      d[0] == 'e' ||
	      d[0] == 'E' ||
	      d[0] == '+' ||
	      d[0] == '-')) {
    d++;
  }
  *n = apr_pstrndup(pool, s, d-s);
  *val = d;
  return APR_SUCCESS;
}

static int j_obj(apr_pool_t *pool, char **val, apr_table_t *tl, char *name, int rec) {
  char *d = j_skip(*val);
  int rc;
  while(d && d[0]) {
    if(*d != '\"') {
      apr_table_add(tl, QOS_J_ERROR, "error while parsing object (missing string)");
      return HTTP_BAD_REQUEST;
    } else {
      /* list of string ":" value pairs (sepated by ',') */
      char *v = NULL;
      char *thisname;
      d++;
      rc = j_string(pool, &d, tl, name, &v);
      if(rc != APR_SUCCESS) {
	return rc;
      }
      thisname = apr_pstrcat(pool, name, "_" , v, NULL);
      d = j_skip(d);
      if(!d || d[0] != ':') {
	apr_table_add(tl, QOS_J_ERROR, "error while parsing object (missing value/wrong delimiter)");
	return HTTP_BAD_REQUEST;
      }
      d++;
      rc = j_val(pool, &d, tl, thisname, rec);
      if(rc != APR_SUCCESS) {
	return rc;
      }
      d = j_skip(d);
      if(!d) {
	apr_table_add(tl, QOS_J_ERROR, "error while parsing object (unexpected end)");
	return HTTP_BAD_REQUEST;
      }
      if(d[0] == '}') {
	d++;
	*val = d;
	return APR_SUCCESS;
      } else if(d[0] == ',') {
	d = j_strchr(d, '"');
      } else {
	apr_table_add(tl, QOS_J_ERROR, "error while parsing object (unexpected end/wrong delimiter)");
	return HTTP_BAD_REQUEST;
      }
    }
  }
  return APR_SUCCESS;
}

static int j_ar(apr_pool_t *pool, char **val, apr_table_t *tl, char *name, int rec) {
  char *d = j_skip(*val);
  int rc;
  int index = 0;
  while(d && d[0]) {
    rc = j_val(pool, &d, tl, apr_psprintf(pool, "%s%d", name, index), rec);
    if(rc != APR_SUCCESS) {
      return rc;
    }
    d = j_skip(d);
    if(!d) {
      apr_table_add(tl, QOS_J_ERROR, "error while parsing array (unexpected end)");
      return HTTP_BAD_REQUEST;
    }
    if(d[0] == ']') {
      d++;
      *val = d;
      return APR_SUCCESS;
    } else if(d[0] == ',') {
      d++;
      d = j_skip(d);
    } else {
      apr_table_add(tl, QOS_J_ERROR, "error while parsing array (unexpected end/wrong delimiter)");
      return HTTP_BAD_REQUEST;
    }
    index++;
  }
  return APR_SUCCESS;
}

static int j_val(apr_pool_t *pool, char **val, apr_table_t *tl, char *name, int rec) {
  char *d = j_skip(*val);
  int rc = APR_SUCCESS;
  rec++;
  if(rec > QOS_j_RECURSION) {
    apr_table_add(tl, QOS_J_ERROR, "error while parsing string (reached recursion limit)");
    return HTTP_BAD_REQUEST;
  }
  /* either object, array, string, number, "true", "false", or "null" */
  if(d[0] == '{') {
    d++;
    rc = j_obj(pool, &d, tl, apr_pstrcat(pool, name, "_o", NULL), rec);
  } else if(d[0] == '[') {
    d++;
    rc = j_ar(pool, &d, tl, apr_pstrcat(pool, name, "_a", NULL), rec);
  } else if(strncmp(d,"null",4) == 0) {
    d+=4;
    apr_table_add(tl, apr_pstrcat(pool, j_escape_url(pool, name), "_b", NULL), "null");
  } else if(strncmp(d,"true",4) == 0) {
    apr_table_add(tl, apr_pstrcat(pool, j_escape_url(pool, name), "_b", NULL), "true");
    d+=4;
  } else if(strncmp(d,"false",5) == 0) {
    apr_table_add(tl, apr_pstrcat(pool, j_escape_url(pool, name), "_b", NULL), "false");
    d+=5;
  } else if(*d == '-' || (*d >= '0' && *d <= '9')) {
    char *n = apr_pstrcat(pool, name, "_n", NULL);
    char *v = NULL;
    rc = j_num(pool, &d, tl, n, &v);
    if(rc == APR_SUCCESS) {
      apr_table_addn(tl, j_escape_url(pool, n), j_escape_url(pool, v));
    }
  } else if(*d == '\"') {
    char *n = apr_pstrcat(pool, name, "_v", NULL);
    char *v = NULL;
    d++;
    rc = j_string(pool, &d, tl, n, &v);
    if(rc == APR_SUCCESS) {
      apr_table_addn(tl, j_escape_url(pool, n), j_escape_url(pool, v));
    }
  } else {
    /* error */
    apr_table_add(tl, QOS_J_ERROR, "error while parsing value (invalid type)");
    return HTTP_BAD_REQUEST;
  }
  if(rc != APR_SUCCESS) {
    return rc;
  }
  *val = d;
  rec--;
  return APR_SUCCESS;
}
/* json parser end --------------------------------------------------------- */

/**
 * Process json data retrieved from parp (request body)
 * @param r
 * @param dconf
 * @param query Query to add data
 * @param msg Error message if paring fails
 * @return APR_SUCCESS if processed without errors.
 */
static int qos_json(request_rec *r, qos_dir_config *dconf, const char **query, const char **msg) {
  const char *contenttype = apr_table_get(r->headers_in, "Content-Type");
  if(contenttype && (strncasecmp(contenttype, "application/json", 16) == 0)) {
    apr_size_t len = 0;
    const char *data = NULL;
    /* check if parp has body data to process (requires "PARP_BodyData application/json")
       or if the json message is stored within the query */
    if(parp_appl_body_data_fn) {
      data = parp_appl_body_data_fn(r, &len);
    }
    if(data == NULL) {
      data = *query;
      if(data && (data[0] == '[' || data[0] == '{')) {
        int escerr = 0;
        char *copyq = apr_pstrdup(r->pool, data);
        *query = NULL;
        // the query needs to be unescaped before getting parsed
        len = qos_unescaping(copyq, dconf->dec_mode, &escerr);
#ifdef QS_MOD_EXT_HOOKS
        qos_run_path_decode_hook(r, &copyq, &len);
#endif
        data = copyq;
        if(strlen(data) != len) {
          *msg = apr_pstrdup(r->pool, "null chracter within data structure in query");
          return HTTP_BAD_REQUEST;
        }
      } else {
        // does not look like a json structure (strict)
        data = NULL;
      }
    }
    if(data && (len > 0)) {
      char *value = apr_pstrndup(r->pool, data, len);
      apr_table_t *tl = apr_table_make(r->pool, 200);
      int rc;
      if(strlen(value) != len) {
        *msg = apr_pstrdup(r->pool, "null chracter within data structure");
        return HTTP_BAD_REQUEST;
      }
      rc = j_val(r->pool, &value, tl, "J", 0);
      if(rc != APR_SUCCESS) {
        *msg = apr_table_get(tl, QOS_J_ERROR); 
        apr_table_unset(tl, QOS_J_ERROR);
        return rc;
      }
      if(value && value[0]) {
        value = j_skip(value);
        if(value && value[0]) {
          /* error, there is still some data */
          *msg = apr_pstrdup(r->pool, "more than one element");
        }
      }
      *query = qos_parp_query(r, tl, *query);
      if(*query) {
        apr_table_setn(r->notes, apr_pstrdup(r->pool, QS_PARP_Q), *query);
      }
    }
  }
  return APR_SUCCESS;
}

/**
 * processes the per location rules QS_Permit* and QS_Deny*
 */
static int qos_per_dir_rules(request_rec *r, qos_dir_config *dconf) {
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(dconf->rfilter_table)->elts;
  int i;
  char *path = apr_pstrdup(r->pool, r->parsed_uri.path ? r->parsed_uri.path : "");
  char *query = NULL;
  char *fragment = NULL;
  char *request_line = apr_pstrdup(r->pool, r->the_request);
  char *uri = path;
  int request_line_len;
  int path_len;
  int query_len = 0;
  int fragment_len = 0;
  int uri_len;
  int permit_rule = 0;
  int permit_rule_match = 0;
  int permit_rule_action = QS_DENY;
  int escerr = 0;
  request_line_len = qos_unescaping(request_line, dconf->dec_mode, &escerr);
  path_len = qos_unescaping(path, dconf->dec_mode, &escerr);
#ifdef QS_MOD_EXT_HOOKS
  qos_run_path_decode_hook(r, &path, &path_len);
#endif
  uri_len = path_len;
  if(dconf->bodyfilter_p == 1 || dconf->bodyfilter_d == 1) {
    const char *q = apr_table_get(r->notes, QS_PARP_Q);
    if((q == NULL) && qos_parp_hp_table_fn) {
      const char *msg = NULL;
      apr_table_t *tl = qos_parp_hp_table_fn(r);
      if(tl) {
        if(apr_table_elts(tl)->nelts > 0) {
          q = qos_parp_query(r, tl, NULL);
          if(q) {
            apr_table_setn(r->notes, apr_pstrdup(r->pool, QS_PARP_Q), q);
          }
        }
      } else {
        /* no table provided by mod_parp (unsupported content type?),
           use query string if available */
        if(r->parsed_uri.query) {
          q = r->parsed_uri.query;
        }
      }
      if(qos_json(r, dconf, &q, &msg) != APR_SUCCESS) {
        /* parser error */
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      QOS_LOG_PFX(048)"access denied, invalid JSON syntax (%s),"
                      " action=deny, c=%s, id=%s",
                      msg ? msg : "-",
                      QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                      qos_unique_id(r, "048"));
        return HTTP_FORBIDDEN;
      }
    }
    if(q) {
      /* prepare unescaped body query (parp) */
      char *q1 = apr_pstrdup(r->pool, q);
      int q1_len = 0;
      q1 = apr_pstrdup(r->pool, q);
      q1_len = qos_unescaping(q1, dconf->dec_mode, &escerr);
#ifdef QS_MOD_EXT_HOOKS
      qos_run_query_decode_hook(r, &q1, &q1_len);
#endif
      if(dconf->bodyfilter_d == 1) {
        /* use body for query deny filter */
        query = q1;
        query_len = q1_len;
      } else {
        /* don't use body for query deny filter */
        if(r->parsed_uri.query) {
          query = apr_pstrdup(r->pool, r->parsed_uri.query);
          query_len = qos_unescaping(query, dconf->dec_mode, &escerr);
#ifdef QS_MOD_EXT_HOOKS
          qos_run_query_decode_hook(r, &query, &query_len);
#endif
        }
      }
      if(dconf->bodyfilter_p != 1) {
        /* don' use body for permit filter */
        if(r->parsed_uri.query) {
          q1 = apr_pstrdup(r->pool, r->parsed_uri.query);
          q1_len = qos_unescaping(q1, dconf->dec_mode, &escerr);
#ifdef QS_MOD_EXT_HOOKS
          qos_run_query_decode_hook(r, &q1, &q1_len);
#endif
        } else {
          q1 = NULL;
          q1_len = 0;
        }
      }
      if(q1) {
        uri = apr_pcalloc(r->pool, path_len + 1 + q1_len + 1);
        memcpy(uri, path, path_len);
        uri[path_len] = '?';
        memcpy(&uri[path_len+1], q1, q1_len);
        uri[path_len+1+q1_len] = '\0';
        uri_len = path_len + 1 + q1_len;
      }
    }
  } else {
    if(r->parsed_uri.query) {
      query = apr_pstrdup(r->pool, r->parsed_uri.query);
      query_len = qos_unescaping(query, dconf->dec_mode, &escerr);
#ifdef QS_MOD_EXT_HOOKS
      qos_run_query_decode_hook(r, &query, &query_len);
#endif
      uri = apr_pcalloc(r->pool, path_len + 1 + query_len + 1);
      memcpy(uri, path, path_len);
      uri[path_len] = '?';
      memcpy(&uri[path_len+1], query, query_len);
      uri[path_len+1+query_len] = '\0';
      uri_len = path_len + 1 + query_len;
    }
  }
  if(r->parsed_uri.fragment) {
    fragment = apr_pstrdup(r->pool, r->parsed_uri.fragment);
    fragment_len = qos_unescaping(fragment, dconf->dec_mode, &escerr);
    uri = apr_pcalloc(r->pool, path_len + 1 + fragment_len + 1);
    memcpy(uri, path, path_len);
    uri[path_len] = '?';
    memcpy(&uri[path_len+1], fragment, fragment_len);
    uri[path_len+1+fragment_len] = '\0';
    uri_len = path_len + 1 + fragment_len;
  }
  if(escerr > 0 && (dconf->urldecoding < QS_OFF_DEFAULT)) {
    int severity = dconf->urldecoding == QS_DENY ? APLOG_ERR : APLOG_WARNING;
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|severity, 0, r,
                  QOS_LOG_PFX(046)"access denied, invalid url encoding, action=%s, c=%s, id=%s",
                  dconf->urldecoding == QS_DENY ? "deny" : "log only",
                  QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                  qos_unique_id(r, "046"));
    if(dconf->urldecoding == QS_DENY) {
      return HTTP_FORBIDDEN;
    }
  }
  /* process black and white list rules in one loop */
  for(i = 0; i < apr_table_elts(dconf->rfilter_table)->nelts; i++) {
    if(entry[i].key[0] == '+') {
      int deny_rule = 0;
      int ex = -1;
      qos_rfilter_t *rfilter = (qos_rfilter_t *)entry[i].val;
      if(rfilter->type == QS_DENY_REQUEST_LINE) {
        deny_rule = 1;
        ex = pcre_exec(rfilter->pr, rfilter->extra, request_line, request_line_len, 0, 0, NULL, 0);
      } else if(rfilter->type == QS_DENY_PATH) {
        deny_rule = 1;
        ex = pcre_exec(rfilter->pr, rfilter->extra, path, path_len, 0, 0, NULL, 0);
      } else if(rfilter->type == QS_DENY_QUERY) {
        deny_rule = 1;
        ex = pcre_exec(rfilter->pr, rfilter->extra, query, query_len, 0, 0, NULL, 0);
      } else if(rfilter->type == QS_DENY_EVENT) {
        /* event rules are processed seperately */
      } else {
        permit_rule = 1;
        ex = pcre_exec(rfilter->pr, rfilter->extra, uri, uri_len, 0, 0, NULL, 0);
        permit_rule_action = rfilter->action;
        if(ex == 0) {
          permit_rule_match = 1; 
        }
      }
      if(deny_rule && (ex == 0)) {
        int severity = rfilter->action == QS_DENY ? APLOG_ERR : APLOG_WARNING;
        apr_table_set(r->subprocess_env, QS_RuleId, rfilter->id);
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|severity, 0, r,
                      QOS_LOG_PFX(040)"access denied, %s rule id: %s (%s),"
                      " action=%s, c=%s, id=%s",
                      qos_rfilter_type2text(r->pool, rfilter->type),
                      rfilter->id,
                      rfilter->text, rfilter->action == QS_DENY ? "deny" : "log only",
                      QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                      qos_unique_id(r, "040"));
        if(rfilter->action == QS_DENY) {
          return HTTP_FORBIDDEN;
        }
      }
    }
  }
  if(permit_rule && !permit_rule_match) {
    int severity = permit_rule_action == QS_DENY ? APLOG_ERR : APLOG_WARNING;
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|severity, 0, r,
                  QOS_LOG_PFX(041)"access denied, no permit rule match, action=%s, c=%s, id=%s",
                  permit_rule_action == QS_DENY ? "deny" : "log only",
                  QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                  qos_unique_id(r, "041"));
    if(permit_rule_action == QS_DENY) {
      return HTTP_FORBIDDEN;
    }
  }
  return APR_SUCCESS;
}

/**
 * request/response header filter, drops headers which are not allowed
 */
static int qos_header_filter(request_rec *r, qos_srv_config *sconf,
                             apr_table_t *headers, const char *type,
                             apr_table_t *hfilter_table,
                             qs_headerfilter_mode_e mode) {
  apr_table_t *delete = apr_table_make(r->pool, 1);
  apr_table_t *reason = NULL;
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(headers)->elts;
  for(i = 0; i < apr_table_elts(headers)->nelts; i++) {
    qos_fhlt_r_t *he = (qos_fhlt_r_t *)apr_table_get(hfilter_table, entry[i].key);
    int denied = 0;
    if(he) {
      if(mode != QS_HEADERFILTER_SIZE_ONLY) {
        if(pcre_exec(he->pcre, he->extra, entry[i].val, strlen(entry[i].val), 0, 0, NULL, 0) < 0) {
          denied = 1;
        }
      }
      if(strlen(entry[i].val) > he->size) {
        denied += 2;
      }
      if(denied) {
        char *pattern = apr_psprintf(r->pool, "(pattern=%s, max. lenght=%d)",
                                     he->text, he->size);
        if(he->action == QS_FLT_ACTION_DENY) {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                        QOS_LOG_PFX(043)"access denied, %s header: \'%s: %s\', %s, c=%s, id=%s",
                        type,
                        entry[i].key, entry[i].val,
                        pattern,
                        QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                        qos_unique_id(r, "043"));
          return HTTP_FORBIDDEN;
        }
        if(reason == NULL) {
          reason = apr_table_make(r->pool, 1);
        }
        apr_table_add(delete, entry[i].key, entry[i].val);
        apr_table_add(reason, entry[i].key, pattern);
      }
    } else {
      if(reason == NULL) {
        reason = apr_table_make(r->pool, 1);
      }
      apr_table_add(delete, entry[i].key, entry[i].val);
      apr_table_add(reason, entry[i].key, "(no rule available)");
    }
  }
  entry = (apr_table_entry_t *)apr_table_elts(delete)->elts;
  for(i = 0; i < apr_table_elts(delete)->nelts; i++) {
    if(mode != QS_HEADERFILTER_SILENT) {
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                    QOS_LOG_PFX(042)"drop %s header: \'%s: %s\', %s, c=%s, id=%s",
                    type,
                    entry[i].key, entry[i].val,
                    apr_table_get(reason, entry[i].key),
                    QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                    qos_unique_id(r, "042"));
    }
    apr_table_unset(headers, entry[i].key);
  }
  return APR_SUCCESS;
}

/**
 * returns list of all query name=value pairs
 */
static apr_table_t *qos_get_query_table(request_rec *r) {
  apr_table_t *av = apr_table_make(r->pool, 2);
  if(r->parsed_uri.query) {
    const char *q = apr_pstrdup(r->pool, r->parsed_uri.query);
    while(q && q[0]) {
      const char *t = ap_getword(r->pool, &q, '&');
      const char *name = ap_getword(r->pool, &t, '=');
      const char *value = t;
      if(name && (strlen(name) > 0)) {
        if(value && (strlen(value) > 0)) {
          apr_table_add(av, name, value);
        } else if((strlen(name) > 0)) {
          apr_table_add(av, name, "");
        }
      }
    }
  }
  return av;
}

/** add "\n" */
#define QOS_ALERT_LINE_LEN 65
static char *qos_crline(request_rec *r, const char *line) {
  char *string = "";
  const char *pos = line;
  while(pos && pos[0]) {
    int len = strlen(pos);
    if(len > QOS_ALERT_LINE_LEN) {
      string = apr_pstrcat(r->pool, string,
                           apr_psprintf(r->pool, "%.*s", QOS_ALERT_LINE_LEN, pos), "\n", NULL);
      pos = &pos[QOS_ALERT_LINE_LEN];
    } else {
      string = apr_pstrcat(r->pool, string, pos, NULL);
      pos = NULL;
    }
  }
  return string;
}

/**
 * Calculates the bytes/sec block rate
 */
static void qos_cal_bytes_sec(request_rec *r, qs_acentry_t *e) {
  if(e->kbytes_per_sec > e->kbytes_per_sec_limit) {
    int factor = ((e->kbytes_per_sec * 100) / e->kbytes_per_sec_limit) - 100;
    /* start slowly */
    if(e->kbytes_per_sec_block_rate == 0) {
      factor = factor / 2;
    }
    e->kbytes_per_sec_block_rate = e->kbytes_per_sec_block_rate + factor;
    /* limit max delay */
    if(e->kbytes_per_sec_block_rate > QS_MAX_DELAY) {
      e->kbytes_per_sec_block_rate = QS_MAX_DELAY;
    }
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                  QOS_LOG_PFX(052)"byte rate limit, rule: %s(%ld), kbytes/sec=%ld,"
                  " delay=%dms%s",
                  e->url, e->kbytes_per_sec_limit,
                  e->kbytes_per_sec, e->kbytes_per_sec_block_rate,
                  e->kbytes_per_sec_block_rate == QS_MAX_DELAY ? " (max)" : "");
  } else if(e->kbytes_per_sec_block_rate > 0) {
    if(e->kbytes_per_sec_block_rate < 20) {
      e->kbytes_per_sec_block_rate = 0;
    } else {
      int factor = e->kbytes_per_sec_block_rate / 4;
      e->kbytes_per_sec_block_rate = e->kbytes_per_sec_block_rate - factor;
    }
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                  QOS_LOG_PFX(053)"byte rate limit, rule: %s(%ld), kbytes/sec=%ld,"
                  " delay=%dms",
                  e->url, e->kbytes_per_sec_limit,
                  e->kbytes_per_sec, e->kbytes_per_sec_block_rate);
  }
}

/**
 * calculates the rec/sec block rate
 */
static void qos_cal_req_sec(request_rec *r, qs_acentry_t *e) {
  if(e->req_per_sec > e->req_per_sec_limit) {
    int factor = ((e->req_per_sec * 100) / e->req_per_sec_limit) - 100;
    e->req_per_sec_block_rate = e->req_per_sec_block_rate + factor;
    if(e->req_per_sec_block_rate > QS_MAX_DELAY) {
      e->req_per_sec_block_rate = QS_MAX_DELAY;
    }
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                  QOS_LOG_PFX(050)"request rate limit, rule: %s(%ld), req/sec=%ld,"
                  " delay=%dms%s",
                  e->url, e->req_per_sec_limit,
                  e->req_per_sec, e->req_per_sec_block_rate,
                  e->req_per_sec_block_rate == QS_MAX_DELAY ? " (max)" : "");
  } else if(e->req_per_sec_block_rate > 0) {
    if(e->req_per_sec_block_rate < 50) {
      e->req_per_sec_block_rate = 0;
    } else {
      int factor = e->req_per_sec_block_rate / 4;
      e->req_per_sec_block_rate = e->req_per_sec_block_rate - factor;
    }
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                  QOS_LOG_PFX(051)"request rate limit, rule: %s(%ld), req/sec=%ld,"
                  " delay=%dms",
                  e->url, e->req_per_sec_limit,
                  e->req_per_sec, e->req_per_sec_block_rate);
  }
}

/**
 * QS_DenyEvent enforcement at header parser
 * @param r
 * @param sconf
 * @param dconf
 # returns DECLINED if no events has been detected
 */
static int qos_hp_event_deny_filter(request_rec *r, qos_srv_config *sconf, qos_dir_config *dconf) {
  if(apr_table_elts(dconf->rfilter_table)->nelts > 0) {
    apr_status_t rv = qos_per_dir_event_rules(r, dconf);
    if(rv != APR_SUCCESS) {
      int rc;
      const char *error_page = sconf->error_page;
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
      if(!sconf->log_only) {
        rc = qos_error_response(r, error_page);
        if((rc == DONE) || (rc == HTTP_MOVED_TEMPORARILY)) {
          return rc;
        }
        return rv;
      }
    }
  }
  return DECLINED;
}

/**
 * QS_Permit* / QS_Deny* enforcement at header parser
 * @param r
 * @param sconf
 * @param dconf
 * @return
 */
static int qos_hp_filter(request_rec *r, qos_srv_config *sconf, qos_dir_config *dconf) {
  apr_status_t rv = APR_SUCCESS;
  if(sconf && sconf->milestones) {
    char *value = qos_get_remove_cookie(r, QOS_MILESTONE_COOKIE);
    rv = qos_verify_milestone(r, sconf, value);
  }

  if((rv == APR_SUCCESS) && (apr_table_elts(dconf->rfilter_table)->nelts > 0)) {
    rv = qos_per_dir_rules(r, dconf);
  }

  if(rv != APR_SUCCESS) {
    int rc;
    const char *error_page = sconf->error_page;
    qs_req_ctx *rctx = qos_rctx_config_get(r);
    rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
    if(!sconf->log_only) {
      rc = qos_error_response(r, error_page);
      if((rc == DONE) || (rc == HTTP_MOVED_TEMPORARILY)) {
        return rc;
      }
      return rv;
    }
  }
  return DECLINED;
}

/**
 * QS_SetEnvRes (outfilter)
 * Detects events at response time.
 */
static void qos_setenvres(request_rec *r, qos_srv_config *sconf) {
#ifdef AP_REGEX_H
  ap_regmatch_t regm[AP_MAX_REG_MATCH];
#else
  regmatch_t regm[AP_MAX_REG_MATCH];
#endif
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->setenvres_t)->elts;
  for(i = 0; i < apr_table_elts(sconf->setenvres_t)->nelts; i++) {
    const char *val = apr_table_get(r->subprocess_env, entry[i].key);
    if(val) {
      qos_pregval_t *pregval = (qos_pregval_t *)entry[i].val;
      if(ap_regexec(pregval->preg, val, AP_MAX_REG_MATCH, regm, 0) == 0) {
        if(pregval->value) {
          char *replaced = ap_pregsub(r->pool, pregval->value, val, AP_MAX_REG_MATCH, regm);
          apr_table_set(r->subprocess_env, pregval->name, replaced);
        } else {
          apr_table_set(r->subprocess_env, pregval->name, "1");
        }
      }
    }
  }
}

/**
 * QS_SetEnvResHeader(Match) (outfilter)
 * Matches response headers and sets an event on match.
 * @param r
 * @param sconf
 */
static void qos_setenvresheader(request_rec *r, qos_srv_config *sconf) {
  apr_table_t *headers = r->headers_out;
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->setenvresheader_t)->elts;
  apr_table_entry_t *entrym = (apr_table_entry_t *)apr_table_elts(sconf->setenvresheadermatch_t)->elts;
  while(headers) {
    for(i = 0; i < apr_table_elts(sconf->setenvresheadermatch_t)->nelts; i++) {
      const char *val = apr_table_get(headers, entrym[i].key);
      if(val) {
        pcre *pr = (pcre *)entrym[i].val;
        if(pcre_exec(pr, NULL, val, strlen(val), 0, 0, NULL, 0) == 0) {
          apr_table_set(r->subprocess_env, entrym[i].key, val);
        }
      }
    }
    for(i = 0; i < apr_table_elts(sconf->setenvresheader_t)->nelts; i++) {
      const char *val = apr_table_get(headers, entry[i].key);
      if(val) {
        apr_table_set(r->subprocess_env, entry[i].key, val);
        if(strcasecmp(entry[i].val, "drop") == 0) {
          apr_table_unset(headers, entry[i].key);
        }
      }
    }
    if(headers == r->headers_out) {
      headers = r->err_headers_out;
    } else {
      headers = NULL;
    }
  }
}

/**
 * QS_SetEnvIfStatus
 * Match response status code
 *
 * @param r
 * @param sconf
 * @param dconf
 */
static void qos_setenvstatus(request_rec *r, qos_srv_config *sconf, qos_dir_config *dconf) {
  char *code = apr_psprintf(r->pool, "%d", r->status);
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->setenvstatus_t)->elts;
  for(i = 0; i < apr_table_elts(sconf->setenvstatus_t)->nelts; i++) {
    if(strcmp(entry[i].key, code) == 0) {
      char *var = apr_pstrdup(r->pool, entry[i].val);
      char *value = strchr(var, '=');
      if(value) {
        value[0] = '\0';
        value++;
      } else {
        value = code;
      }
      apr_table_set(r->subprocess_env, var, value);
    }
  }
  if(dconf) {
    entry = (apr_table_entry_t *)apr_table_elts(dconf->setenvstatus_t)->elts;
    for(i = 0; i < apr_table_elts(dconf->setenvstatus_t)->nelts; i++) {
      if(strcmp(entry[i].key, code) == 0) {
        char *var = apr_pstrdup(r->pool, entry[i].val);
        char *value = strchr(var, '=');
        if(value) {
          value[0] = '\0';
          value++;
        } else {
          value = code;
        }
        apr_table_set(r->subprocess_env, var, value);
      }
    }
  }
}

/**
 * Enables mod_parp if mod_qos requires access to the request body.
 * @param r
 */
static void qos_enable_parp(request_rec *r) {
  const char *ct = apr_table_get(r->headers_in, "Content-Type");
  if(ct) {
    if(ap_strcasestr(ct, "application/x-www-form-urlencoded") ||
       ap_strcasestr(ct, "multipart/form-data") ||
       ap_strcasestr(ct, "multipart/mixed") ||
       ap_strcasestr(ct, "application/json")) {
      apr_table_set(r->subprocess_env, "parp", "mod_qos");
    }
  }
}

/** 
 * Generic request validation.
 * We ensure to have at least a valid request uri received (no futher uri validation
 * required in your code).
 * @param r
 * @param sconf
 * @retrun HTTP_BAD_REQUEST for requests which may not be processed by mod_qos, otherwise
 *         APR_SUCCESS
 */
static apr_status_t qos_request_check(request_rec *r, qos_srv_config *sconf) {
  if((r->unparsed_uri == NULL) || (r->parsed_uri.path == NULL)) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOS_LOG_PFX(045)"access denied, invalid request line:"
                  " can't parse uri,%s c=%s, id=%s",
                  sconf->log_only ? " ignores log only mode," : "",
                  QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                  qos_unique_id(r, "045"));
    return HTTP_BAD_REQUEST;
  }
  return APR_SUCCESS;
}

/**
 * QS_SetEnvIfParp (prr), enable parp
 */
static apr_status_t qos_parp_prr(request_rec *r, qos_srv_config *sconf) {
  if(apr_table_elts(sconf->setenvifparp_t)->nelts > 0) {
    qos_enable_parp(r);
  }
  return DECLINED;
}

/**
 * QS_SetEnvIfQuery/QS_SetEnvIfParp
 */
static void qos_setenvif_ex(request_rec *r, const char *query, apr_table_t *table_setenvif) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(table_setenvif)->elts;
  for(i = 0; i < apr_table_elts(table_setenvif)->nelts; i++) {
    qos_setenvifquery_t *setenvif = (qos_setenvifquery_t *)entry[i].val;
    char *name = setenvif->name;
#ifdef AP_REGEX_H
    ap_regmatch_t regm[AP_MAX_REG_MATCH];
#else
    regmatch_t regm[AP_MAX_REG_MATCH];
#endif
    if(ap_regexec(setenvif->preg, query, AP_MAX_REG_MATCH, regm, 0) == 0) {
      if(name[0] == '!') {
        apr_table_unset(r->subprocess_env, &name[1]);
      } else {
        char *replaced = "";
        if(setenvif->value) {
          replaced = ap_pregsub(r->pool, setenvif->value, query, AP_MAX_REG_MATCH, regm);
        }
        apr_table_set(r->subprocess_env, name, replaced);
      }
    }
  }
}

/**
 * Process body events (QS_SetEnvIfBody) and sets the r->subprocess_env variables
 * @param r
 * @param sconf
 */
static void qos_parp_hp_body(request_rec *r, qos_srv_config *sconf) {
  if(apr_table_elts(sconf->setenvifparpbody_t)->nelts > 0) {
    if(parp_appl_body_data_fn) {
      apr_size_t len;
      const char *data = parp_appl_body_data_fn(r, &len);
      if(data && (len > 0)) {
        int ovector[3];
        int i;
        apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->setenvifparpbody_t)->elts;
        for(i = 0; i < apr_table_elts(sconf->setenvifparpbody_t)->nelts; i++) {
          qos_setenvifparpbody_t *setenvif = (qos_setenvifparpbody_t *)entry[i].val;
          int c = pcre_exec(setenvif->preg, setenvif->extra, data, len, 0, 0, ovector, 3);
          if(c >= 0) {
            char *name = setenvif->name;
            char *value = apr_pstrdup(r->pool, setenvif->value);
            if(name[0] == '!') {
              apr_table_unset(r->subprocess_env, &name[1]);
            } else {
              char *p = strstr(value, "$1");
              if(p) {
                char *c = apr_pstrndup(r->pool, &data[ovector[0]], ovector[1] - ovector[0]);
#ifdef AP_REGEX_H
                ap_regmatch_t regm[AP_MAX_REG_MATCH];
#else
                regmatch_t regm[AP_MAX_REG_MATCH];
#endif
                if(ap_regexec(setenvif->pregx, c, AP_MAX_REG_MATCH, regm, 0) == 0) {
                  value = ap_pregsub(r->pool, value, c, AP_MAX_REG_MATCH, regm);
                }
              }
              apr_table_set(r->subprocess_env, name, value != NULL ? value : "");
            }
          }
        }
      }
    }
  }
}

/**
 * Setting events based on request payload (query), QS_SetEnvIfParp (hp)
 * @param r
 * @param sconf
 */
static void qos_parp_hp(request_rec *r, qos_srv_config *sconf) {
  if(apr_table_elts(sconf->setenvifparp_t)->nelts > 0) {
    const char *query = apr_table_get(r->notes, QS_PARP_Q);
    if((query == NULL) && qos_parp_hp_table_fn) {
      apr_table_t *tl = qos_parp_hp_table_fn(r);
      if(tl) {
        if(apr_table_elts(tl)->nelts > 0) {
          query = qos_parp_query(r, tl, NULL);
          if(query) {
            apr_table_setn(r->notes, apr_pstrdup(r->pool, QS_PARP_Q), query);
          }
        }
      } else {
        /* no table provided by mod_parp (unsupported content type?),
           use query string if available */
        if(r->parsed_uri.query) {
          query = r->parsed_uri.query;
        }
      }
    }
    if(query) {
      qos_setenvif_ex(r, query, sconf->setenvifparp_t);
    }
  }
}

/**
 * Replaces ${var} by the value in var
 * @param p Pool for memory allocation
 * @param vars Available variables to lookup
 * @param string String to replace variables
 * @return 1 on success or 0 if string still contains "${"
 */
static int qos_reslove_variable(apr_pool_t *p, apr_table_t *vars, char **string) {
  int i;
  int start;
  int line_end;
  char *var_name;
  char *new_line = *string;
  char *line = *string;
  const char *val;

 once_again:
  i = 0;
  while(line[i] != 0) {
    if((line[i] == '$') && (line[i+1] == '{')) {
      line_end = i;
      i=i+2;
      start = i;
      while((line[i] != 0) && (line[i] != '}')) {
        i++;
      }
      if(line[i] != '}') {
        /* no end found */
        break;
      } else {
        var_name = apr_pstrndup(p, &line[start], i - start);
        val = apr_table_get(vars, var_name);
        if(val) {
          line[line_end] = 0;
          i++;
          new_line = apr_pstrcat(p, line, val, &line[i], NULL);
          line = new_line;
          goto once_again;
        }      
      }
    }
    i++;
  }
  if(!new_line[0] || strstr(new_line, "${")) {
    return 0;
  }
  *string = new_line;
  return 1;
}

/**
 * QS_SetEnvIfQuery (hp)
 * @param r
 * @param sconf
 */
static void qos_setenvifquery(request_rec *r, qos_srv_config *sconf) {
  if(r->parsed_uri.query) {
    qos_setenvif_ex(r, r->parsed_uri.query, sconf->setenvifquery_t);
  }
}

/**
 * QS_SetEnv
 * @param r
 * @param sconf
 */
static void qos_setenv(request_rec *r, qos_srv_config *sconf) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->setenv_t)->elts;
  for(i = 0; i < apr_table_elts(sconf->setenv_t)->nelts; i++) {
    char *variable = entry[i].val;
    char *value = apr_pstrdup(r->pool, strchr(entry[i].key, '='));
    value++;
    if(qos_reslove_variable(r->pool, r->subprocess_env, &value)) {
      apr_table_set(r->subprocess_env, variable, value);
    }
  }
}

/**
 * QS_SetReqHeader
 * @param r
 * @param header_t
 */
static void qos_setreqheader(request_rec *r, apr_table_t *header_t) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(header_t)->elts;
  for(i = 0; i < apr_table_elts(header_t)->nelts; i++) {
    char *header = entry[i].val;
    char *variable = apr_pstrdup(r->pool, strchr(entry[i].key, '='));
    const char *val;
    variable++;
    val = apr_table_get(r->subprocess_env, variable);
    if(val) {
      apr_table_set(r->headers_in, header, val);
    }
  }
}

/**
 * QS_SetEnvIf (hp and logger)
 * @param r
 * @param sconf
 */
static void qos_setenvif(request_rec *r, qos_srv_config *sconf) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->setenvif_t)->elts;
  for(i = 0; i < apr_table_elts(sconf->setenvif_t)->nelts; i++) {
    qos_setenvif_t *setenvif = (qos_setenvif_t *)entry[i].val;
    if((setenvif->variable1[0] == '!') && (setenvif->variable2[0] == '!')) {
      if(!apr_table_get(r->subprocess_env, &setenvif->variable1[1]) &&
         !apr_table_get(r->subprocess_env, &setenvif->variable2[1])) {
        if(setenvif->name[0] == '!') {
          apr_table_unset(r->subprocess_env, &setenvif->name[1]);
        } else {
          apr_table_set(r->subprocess_env, setenvif->name, setenvif->value);
        }
      }
    } else if(setenvif->variable1[0] == '!') {
      if(!apr_table_get(r->subprocess_env, &setenvif->variable1[1]) &&
         apr_table_get(r->subprocess_env, setenvif->variable2)) {
        if(setenvif->name[0] == '!') {
          apr_table_unset(r->subprocess_env, &setenvif->name[1]);
        } else {
          apr_table_set(r->subprocess_env, setenvif->name, setenvif->value);
        }
      }
    } else if(setenvif->variable2[0] == '!') {
      if(apr_table_get(r->subprocess_env, setenvif->variable1) &&
         !apr_table_get(r->subprocess_env, &setenvif->variable2[1])) {
        if(setenvif->name[0] == '!') {
          apr_table_unset(r->subprocess_env, &setenvif->name[1]);
        } else {
          apr_table_set(r->subprocess_env, setenvif->name, setenvif->value);
        }
      }
    } else {
      if(apr_table_get(r->subprocess_env, setenvif->variable1) &&
         apr_table_get(r->subprocess_env, setenvif->variable2)) {
        if(setenvif->name[0] == '!') {
          apr_table_unset(r->subprocess_env, &setenvif->name[1]);
        } else {
          apr_table_set(r->subprocess_env, setenvif->name, setenvif->value);
        }
      }
    }
  }
}

/*
 * QS_RequestHeaderFilter enforcement
 * @param r
 * @param sconf
 * @parm dconf
 * @return
 */
static int qos_hp_header_filter(request_rec *r, qos_srv_config *sconf, qos_dir_config *dconf) {
  qs_headerfilter_mode_e mode = sconf->headerfilter;
  if(dconf->headerfilter > QS_HEADERFILTER_OFF_DEFAULT) {
    // override serve configuration
    mode = dconf->headerfilter;
  }
  if(mode > QS_HEADERFILTER_OFF) {
    apr_status_t rv = qos_header_filter(r, sconf, r->headers_in, "request",
                                        sconf->hfilter_table, mode);
    if(rv != APR_SUCCESS) {
      int rc;
      const char *error_page = sconf->error_page;
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
      if(!sconf->log_only) {
        rc = qos_error_response(r, error_page);
        if((rc == DONE) || (rc == HTTP_MOVED_TEMPORARILY)) {
          return rc;
        }
        return rv;
      }
    }
  }
  return DECLINED;
}

/**
 * Dynamic keep alive.
 * Creates a copy of the server_rec and adjusts the keep-aliva settings for this request.
 *
 * @param r
 * @param sconf
 */
static void qos_keepalive(request_rec *r, qos_srv_config *sconf) {
  if(r->subprocess_env) {
    const char *v = apr_table_get(r->subprocess_env, QS_KEEPALIVE);
    if(v) {
      int ka = atoi(v);
      if(ka == 0 && v[0] != '0') {
        ka = -1;
      }
      if(ka >= 0) {
        qs_req_ctx *rctx = qos_rctx_config_get(r);
        apr_interval_time_t kat = apr_time_from_sec(ka);
        /* copy the server record (I konw, but least this works ...) */
        if(!rctx->evmsg || !strstr(rctx->evmsg, "T;")) {
          /* copy it only once (@hp or @out-filter) */
          if(!sconf->log_only) {
            server_rec *sr = apr_pcalloc(r->connection->pool, sizeof(server_rec));
            server_rec *sc = apr_pcalloc(r->connection->pool, sizeof(server_rec));
            memcpy(sr, r->server, sizeof(server_rec));
            memcpy(sc, r->connection->base_server, sizeof(server_rec));
            r->server = sr;
            r->connection->base_server = sc;
          }
          rctx->evmsg = apr_pstrcat(r->pool, "T;", rctx->evmsg, NULL);
        }
        if(!sconf->log_only) {
          r->server->keep_alive_timeout = kat;
          r->connection->base_server->keep_alive_timeout = kat;
        }
      }
    }
  }
}

/**
 * QS_EventPerSecLimit
 */
static void qos_lg_event_update(request_rec *r, apr_time_t *t) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                &qos_module);
  qs_actable_t *act = sconf->act;
  if(act->has_events && (apr_table_get(r->notes, QS_R012_ALREADY_BLOCKED) == NULL)) {
    apr_time_t now = apr_time_sec(r->request_time);
    qs_acentry_t *e = act->entry;
    *t = now;
    if(e) {
      apr_global_mutex_lock(act->lock);     /* @CRT13 */
      while(e) {
        if(e->event) {
          if(((e->event[0] != '!') && apr_table_get(r->subprocess_env, e->event)) ||
             ((e->event[0] == '!') && !apr_table_get(r->subprocess_env, &e->event[1]))) {
            e->req++;
            e->bytes = e->bytes + r->bytes_sent;
            if(now > (e->interval + QS_BW_SAMPLING_RATE)) {
              if(e->req_per_sec_limit) {
                /* QS_EventPerSecLimit */
                e->req_per_sec = e->req / (now - e->interval);
                e->req = 0;
                e->interval = now;
                qos_cal_req_sec(r, e);
              } else if(e->kbytes_per_sec_limit) {
                /* QS_EventKBytesPerSecLimit */
                e->kbytes_per_sec = e->bytes / (now - e->interval) / 1024;
                e->bytes = 0;
                e->interval = now;
                qos_cal_bytes_sec(r, e);
              }
            }
          }
        }
        e = e->next;
      }
      apr_global_mutex_unlock(act->lock);   /* @CRT13 */
    }
  }
}

/**
 * QS_EventLimitCount, detect and enforce
 */
static int qos_hp_event_limit(request_rec *r, qos_srv_config *sconf) {
  apr_status_t rv = DECLINED;
  qs_actable_t *act = sconf->act;
  if(act->event_entry) {
    apr_time_t now = apr_time_sec(r->request_time);
    int i;
    qos_event_limit_entry_t *entry = act->event_entry;
    apr_global_mutex_lock(act->lock);     /* @CRT41 */
    for(i = 0; i < sconf->event_limit_a->nelts; i++) {
      if(entry->action == QS_EVENT_ACTION_DENY) {
        if(apr_table_get(r->subprocess_env, entry->env_var) != NULL) {
          char *eventLimitId = apr_pstrcat(r->pool, QS_R013_ALREADY_BLOCKED, entry->env_var, NULL);
          apr_table_set(r->notes, eventLimitId, "");
          // reset required (expired)?
          if(entry->limit_time + entry->seconds < now) {
            entry->limit = 0;
            entry->limit_time = 0;
          }
          /* increment limit event */
          entry->limit++;
          if(entry->limit == 1) {
            /* ... and start timer */
            entry->limit_time = now;
          }
          // check limit
          if(entry->limit > entry->max) {
            rv = m_retcode;
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                          QOS_LOG_PFX(013)"access denied, QS_EventLimitCount rule: %s,"
                          " max=%d, current=%d,"
                          " c=%s, id=%s",
                          entry->env_var, entry->max, entry->limit,
                          QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                          qos_unique_id(r, "013"));
          }
        }
        // propagte to environment
        apr_table_set(r->subprocess_env,
                      apr_pstrcat(r->pool, entry->env_var, QS_COUNTER_SUFFIX, NULL),
                      apr_psprintf(r->pool, "%d", entry->limit));
      }
      // next rule
      entry++;
    }
    apr_global_mutex_unlock(act->lock);   /* @CRT41 */
  }
  if(rv != DECLINED) {
    int rc;
    const char *error_page = sconf->error_page;
    qs_req_ctx *rctx = qos_rctx_config_get(r);
    rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
    if(!sconf->log_only) {
      rc = qos_error_response(r, error_page);
      if((rc == DONE) || (rc == HTTP_MOVED_TEMPORARILY)) {
        rv = rc;
      }
    } else {
      return DECLINED;
    }
  }
  return rv;
}

/**
 * QS_EventRequestLimit
 */
static int qos_hp_event_filter(request_rec *r, qos_srv_config *sconf) {
  apr_status_t rv = DECLINED;
  qs_req_ctx *rctx = qos_rctx_config_get(r);
  qs_actable_t *act = sconf->act;
  if(act->has_events) {
    qs_acentry_t *e = act->entry;
    if(e) {
      apr_global_mutex_lock(act->lock);   /* @CRT31 */
      while(e) {
        if(e->event && (e->limit != -1)) {
          const char *var = apr_table_get(r->subprocess_env, e->event);
          if(var) {
            int match = 1;
            if(e->regex_var) {
              if(ap_regexec(e->regex_var, var, 0, NULL, 0) != 0) {
                match = 0;
              }
            }
            if(match) {
              apr_table_addn(rctx->event_entries, e->url, (char *)e);
              e->counter++;
              if(e->counter > e->limit) {
                rv = m_retcode;
                ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                              QOS_LOG_PFX(012)"access denied, QS_EventRequestLimit rule: %s(%d),"
                              " concurrent requests=%d,"
                              " c=%s, id=%s",
                              e->url, e->limit, e->counter,
                              QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                              qos_unique_id(r, "012"));
                apr_table_set(r->notes, QS_R012_ALREADY_BLOCKED, "");
              }
            }
          }
        }
        e = e->next;
      }
      apr_global_mutex_unlock(act->lock); /* @CRT31 */
    }
  }
  if(rv != DECLINED) {
    int rc;
    const char *error_page = sconf->error_page;
    qs_req_ctx *rctx = qos_rctx_config_get(r);
    rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
    if(!sconf->log_only) {
      rc = qos_error_response(r, error_page);
      if((rc == DONE) || (rc == HTTP_MOVED_TEMPORARILY)) {
        rv = rc;
      }
    } else {
      return DECLINED;
    }
  }
  return rv;
}

static qs_conn_base_ctx *qos_create_conn_base_ctx(conn_rec *c, qos_srv_config *sconf) {
  qs_conn_base_ctx *base = apr_pcalloc(c->pool, sizeof(qs_conn_base_ctx));
  base->cconf = NULL;
  base->requests = 0;
  base->c = c;
  base->sconf = sconf;
  ap_set_module_config(c->conn_config, &qos_module, base);
  apr_pool_cleanup_register(c->pool, base, qos_base_cleanup_conn, apr_pool_cleanup_null);
  return base;
}

static qs_conn_base_ctx *qos_get_conn_base_ctx(conn_rec *c) {
  qs_conn_base_ctx *base = (qs_conn_base_ctx*)ap_get_module_config(c->conn_config, &qos_module);
  return base;
}

static qs_conn_ctx *qos_get_cconf(conn_rec *c) {
  qs_conn_ctx *cconf = NULL;
  qs_conn_base_ctx *base = qos_get_conn_base_ctx(c);
  if(base) {
    cconf = base->cconf;
  }
  return cconf;
}

static qs_conn_ctx *qos_create_cconf(conn_rec *c, qos_srv_config *sconf) {
  qs_conn_base_ctx *base = qos_get_conn_base_ctx(c);
  qs_conn_ctx *cconf = apr_pcalloc(c->pool, sizeof(qs_conn_ctx));
  cconf->c = c;
  cconf->evmsg = NULL;
  cconf->sconf = sconf;
  cconf->is_vip = 0;
  cconf->is_vip_by_header = 0;
  cconf->has_lowrate = 0;
  apr_pool_cleanup_register(c->pool, cconf, qos_cleanup_conn, apr_pool_cleanup_null);
  if(base == NULL) {
    base = qos_create_conn_base_ctx(c, sconf);
  }
  base->cconf = cconf;
  return cconf;  
}

/*
 * QS_ClientSerialize
 */
static void qos_hp_cc_serialize(request_rec *r, qos_srv_config *sconf, qs_req_ctx * rctx) {
  qos_user_t *u = qos_get_user_conf(sconf->act->ppool);
  qs_conn_ctx *cconf = qos_get_cconf(r->connection);
  if(!rctx) {
    rctx = qos_rctx_config_get(r);
  }
  if(u && cconf) {
    const char *forwardedForLogIP = QS_CONN_REMOTEIP(cconf->c);
    int loops = 0;
    int locked = 0;
    rctx->cc_serialize_set = 1;
    /* wait until we get a lock */
    while(!locked) {
      qos_s_entry_t **e = NULL;
      qos_s_entry_t searchE;
      searchE.ip6[0] = 0;
      searchE.ip6[1] = 0;
      if(sconf->qos_cc_forwardedfor) {
        const char *forwardedfor = apr_table_get(r->headers_in, sconf->qos_cc_forwardedfor);
        if(forwardedfor) {
          if(qos_ip_str2long(forwardedfor, &searchE.ip6) == 0) {
            if(apr_table_get(r->notes, "QOS_LOG_PFX069") == NULL) {
              ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                            QOS_LOG_PFX(069)"no valid IP header found (@hp):"
                            " invalid header value '%s', fallback to connection's IP %s, id=%s",
                            forwardedfor,
                            QS_CONN_REMOTEIP(r->connection) == NULL ? "-" :
                            QS_CONN_REMOTEIP(r->connection),
                            qos_unique_id(r, "069"));
              apr_table_set(r->notes, "QOS_LOG_PFX069", "log once");
            }
          } else {
            forwardedForLogIP = forwardedfor;
          }
        } else {
          if(apr_table_get(r->notes, "QOS_LOG_PFX069") == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                          QOS_LOG_PFX(069)"no valid IP header found (@hp):"
                          " header '%s' not available, fallback to connection's IP %s, id=%s",
                          sconf->qos_cc_forwardedfor,
                          QS_CONN_REMOTEIP(r->connection) == NULL ? "-" :
                          QS_CONN_REMOTEIP(r->connection),
                          qos_unique_id(r, "069"));
            apr_table_set(r->notes, "QOS_LOG_PFX069", "log once");
          }
        }
      }
      if((searchE.ip6[0] == 0) &&
         (searchE.ip6[1] == 0)) {
        // use real ip from the connection
        searchE.ip6[0] = cconf->ip6[0];
        searchE.ip6[1] = cconf->ip6[1];
      }
      apr_global_mutex_lock(u->qos_cc->lock);          /* @CRT36 */
      e = qos_cc_get0(u->qos_cc, &searchE, apr_time_sec(r->request_time));
      if(!e) {
        e = qos_cc_set(u->qos_cc, &searchE, apr_time_sec(r->request_time));
      }
      /* Which request is getting the lock? We assume all requests comming
         from the same client (no proxy), so it's up to the client how many
         requests are waiting at the same time and every request waits
         the same amount of time (100ms) before re-trying it again. */
      if((*e)->serialize == 0) {
        (*e)->serialize = 1;
        locked = 1;
      }
      apr_global_mutex_unlock(u->qos_cc->lock);        /* @CRT36 */   
      if(!locked) {
        /* sleep 100ms */
        struct timespec delay;
        delay.tv_sec  = 0;
        delay.tv_nsec = 100 * 1000000;
        if(!rctx->evmsg || !strstr(rctx->evmsg, "s;")) {
          rctx->evmsg = apr_pstrcat(r->pool, "s;", rctx->evmsg, NULL);
        }
        if(sconf->log_only) {
          return;
        }
        nanosleep(&delay, NULL);
      }
      // max wait time: 5 minutes
      if(loops >= 3000) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                      QOS_LOG_PFX(068)"QS_ClientSerialize exceeds limit of 5 minutes, "
                      "c=%s, id=%s",
                      forwardedForLogIP == NULL ? "-" : forwardedForLogIP,
                      qos_unique_id(r, "068"));
        break;
      }
      loops++;
    }
  }
}

/*
 * QS_ClientEventRequestLimit
 */
static int qos_hp_cc_event_count(request_rec *r, qos_srv_config *sconf, qs_req_ctx * rctx) {
  qos_user_t *u = qos_get_user_conf(sconf->act->ppool);
  qs_conn_ctx *cconf = qos_get_cconf(r->connection);
  if(!rctx) {
    rctx = qos_rctx_config_get(r);
  }
  if(u && cconf &&
     r->subprocess_env && apr_table_get(r->subprocess_env, "QS_EventRequest")) {
    int vip = 0;
    int count = 0;
    qos_s_entry_t **e = NULL;
    qos_s_entry_t searchE;
    rctx->cc_event_req_set = 1;
    apr_global_mutex_lock(u->qos_cc->lock);            /* @CRT33 */
    searchE.ip6[0] = cconf->ip6[0];
    searchE.ip6[1] = cconf->ip6[1];
    e = qos_cc_get0(u->qos_cc, &searchE, apr_time_sec(r->request_time));
    if(!e) {
      e = qos_cc_set(u->qos_cc, &searchE, apr_time_sec(r->request_time));
    }
    (*e)->event_req++;
    count = (*e)->event_req;
    if((*e)->vip || rctx->is_vip) {
      vip = 1;
    }
    apr_global_mutex_unlock(u->qos_cc->lock);          /* @CRT33 */
    if(vip) {
      apr_table_set(r->subprocess_env, QS_ISVIPREQ, "yes");
    }
    if(count > sconf->qos_cc_event_req) {
      if(vip) {
        rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
      } else {
        int rc;
        const char *error_page = sconf->error_page;
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      QOS_LOG_PFX(065)"access denied, QS_ClientEventBlockCount rule: "
                      "max=%d, current=%d, c=%s, id=%s",
                      sconf->qos_cc_event_req,
                      count,
                      QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : 
                      QS_CONN_REMOTEIP(r->connection),
                      qos_unique_id(r, "065"));
        rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
        if(!sconf->log_only) {
          rc = qos_error_response(r, error_page);
          if((rc == DONE) || (rc == HTTP_MOVED_TEMPORARILY)) {
            return rc;
          }
          return m_retcode;
        }
      }
    }
  }
  return DECLINED;
}

/*
 * QS_EventPerSecLimit/QS_EventKBytesPerSecLimit
 * returns the max req_per_sec_block_rate/kbytes_per_sec_block_rate
 */
static void qos_hp_event_count(request_rec *r, int *req_per_sec_block, int *kbytes_per_sec_block) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                &qos_module);
  qs_actable_t *act = sconf->act;
  *req_per_sec_block = 0;
  *kbytes_per_sec_block = 0;
  if(act->has_events) {
    qs_acentry_t *e = act->entry;
    if(e) {
      apr_global_mutex_lock(act->lock);   /* @CRT12 */
      while(e) {
        if(e->event && (e->limit == -1)) {
          if(((e->event[0] != '!') && apr_table_get(r->subprocess_env, e->event)) ||
             ((e->event[0] == '!') && !apr_table_get(r->subprocess_env, &e->event[1]))) {
            if(e->req_per_sec_limit) {
              /* QS_EventPerSecLimit */
              if(e->req_per_sec_block_rate > *req_per_sec_block) {
                *req_per_sec_block = e->req_per_sec_block_rate;
              }
            } else {
              /* QS_EventKBytesPerSecLimit */
              if(e->kbytes_per_sec_block_rate > *kbytes_per_sec_block) {
                *kbytes_per_sec_block = e->kbytes_per_sec_block_rate;
              }
            }
          }
        }
        e = e->next;
      }
      apr_global_mutex_unlock(act->lock); /* @CRT12 */
    }
  }
  return;
}

static apr_status_t qos_cleanup_inctx(void *p) {
  qos_ifctx_t *inctx = p;
  qos_srv_config *sconf = inctx->sconf;
#if APR_HAS_THREADS
  if(sconf->inctx_t && !sconf->inctx_t->exit) {
    apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT25 */
    inctx->status = QS_CONN_STATE_DESTROY;
    apr_table_unset(sconf->inctx_t->table,
                    QS_INCTX_ID);
    apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT25 */
  }
#endif
  return APR_SUCCESS;
}

/**
 * creates a new connection ctx (remember to set the socket, connection and timeout)
 */
static qos_ifctx_t *qos_create_ifctx(conn_rec *c, qos_srv_config *sconf) {
  char buf[128];
  qos_ifctx_t *inctx = apr_pcalloc(c->pool, sizeof(qos_ifctx_t));
  inctx->client_socket = NULL;
  inctx->status = QS_CONN_STATE_NEW;
  inctx->cl_val = 0;
  inctx->c = c;
  inctx->r = NULL;
  inctx->client_socket = NULL;
  inctx->time = 0;
  inctx->nbytes = 0;
  inctx->shutdown = 0;
  inctx->disabled = 0;
  inctx->lowrate = -1;
  sprintf(buf, "%p", inctx);
  inctx->id = apr_psprintf(c->pool, "%s%.16lx", buf, c->id);
  inctx->sconf = sconf;
  apr_pool_cleanup_register(c->pool, inctx, qos_cleanup_inctx, apr_pool_cleanup_null);
  return inctx;
}

/**
 * returns the context from the r->connection->input_filters
 */
static qos_ifctx_t *qos_get_ifctx(ap_filter_t *f) {
  qos_ifctx_t *inctx = NULL;
  while(f) {
    if(strcmp(f->frec->name, "qos-in-filter") == 0) {
      inctx = f->ctx;
      break;
    }
    f = f->next;
  }
  return inctx;
}

static apr_size_t qos_packet_rate(qos_ifctx_t *inctx, apr_bucket_brigade *bb) {
  apr_bucket *b;
  apr_size_t total = 0;
  for(b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
    if(b->length) {
      total = total + b->length;
    }
  }
  return total;
}

/**
 * start packet rate measure (if filter has not already been inserted)
 */
static void qos_pktrate_pc(conn_rec *c, qos_srv_config *sconf) {
  if(sconf->qos_cc_prefer_limit) {
    qos_ifctx_t *inctx = qos_get_ifctx(c->input_filters);
    if(inctx == NULL) {
      inctx = qos_create_ifctx(c, sconf);
      ap_add_input_filter("qos-in-filter", inctx, NULL, c);
    }
    inctx->lowrate = 0;
  }
}

/**
 * timeout control at process connection handler
 */
static void qos_timeout_pc(conn_rec *c, qos_srv_config *sconf) {
  if(sconf && (sconf->req_rate != -1)) {
    qos_ifctx_t *inctx = qos_get_ifctx(c->input_filters);
    if(inctx) {
      inctx->status = QS_CONN_STATE_HEAD;
      inctx->time = time(NULL);
      inctx->nbytes = 0;
#if APR_HAS_THREADS
      if(sconf->inctx_t && !sconf->inctx_t->exit && sconf->min_rate_off == 0) {
        apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT22 */
        apr_table_setn(sconf->inctx_t->table,
                       QS_INCTX_ID,
                       (char *)inctx);
        apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT22 */
      }
#endif
    }
  }
}

/** determine client behavior */
static int qos_content_type(request_rec *r, qos_srv_config *sconf,
                            qos_s_t *s, qos_s_entry_t *e, int limit) {
  int penalty = 0;
  const char *ct = apr_table_get(r->headers_out, "Content-Type");
  e->events++; // events counts requests and connections
  if(r->status == 304) {
    e->notmodified ++;
    s->notmodified ++;
  }
  if(ct) {
    if(ap_strcasestr(ct, "html")) {
      e->events++; // learn faster if user requests HTML content (main pages)
      e->html++;
      s->html++;
      goto end;
    } else if(ap_strcasestr(ct, "image")) {
      e->img++;
      s->img++;
      goto end;
    } else if(ap_strcasestr(ct, "css")) {
      e->cssjs++;
      s->cssjs++;
      goto end;
    } else if(ap_strcasestr(ct, "javascript")) {
      e->cssjs++;
      s->cssjs++;
      goto end;
    }
  }
  e->other++;
  s->other++;

 end:
  /* compare this client with other clients */
  if(limit &&
     e->events > QOS_CC_BEHAVIOR_THR_SINGLE &&
     ((sconf->static_on == 1) ||
      (s->html > QOS_CC_BEHAVIOR_THR && s->html && s->img && s->cssjs && s->other && s->notmodified))) {
    int i;
    unsigned int server[5];
    unsigned int client[5];
    // note: all e->* variables are initialized by "1" to avaoid FPE
    if(sconf->static_on == 1) {
      /* use predefined value */
      unsigned long e_all = e->html + e->img + e->cssjs + e->other + e->notmodified;
      server[0] = sconf->static_html;
      server[1] = sconf->static_cssjs;
      server[2] = sconf->static_img;
      server[3] = sconf->static_other;
      server[4] = sconf->static_notmodified;
      client[0] = 100 * e->html / e_all;
      client[1] = 100 * e->cssjs / e_all;
      client[2] = 100 * e->img / e_all;
      client[3] = 100 * e->other / e_all;
      client[4] = 100 * e->notmodified / e_all;
    } else {
      /* learn average */
      unsigned long long s_all = s->html + s->img + s->cssjs + s->other + s->notmodified;
      unsigned long e_all = e->html + e->img + e->cssjs + e->other + e->notmodified;
      server[0] = 100 * s->html / s_all;
      server[1] = 100 * s->cssjs / s_all;
      server[2] = 100 * s->img / s_all;
      server[3] = 100 * s->other / s_all;
      server[4] = 100 * s->notmodified / s_all;
      client[0] = 100 * e->html / e_all;
      client[1] = 100 * e->cssjs / e_all;
      client[2] = 100 * e->img / e_all;
      client[3] = 100 * e->other / e_all;
      client[4] = 100 * e->notmodified / e_all;
    }
    for(i = 0; i < 5; i++) {
      if(client[i] > (server[i] + sconf->cc_tolerance)) {
        penalty++;        
      } else {
        if((server[i] > sconf->cc_tolerance) &&
           (client[i] < (server[i] - sconf->cc_tolerance))) {
          penalty++;
        }
      }
    }
  }
  return penalty;
}

//static void qos_error_log(const char *file, int line, int level,
//                          apr_status_t status, const server_rec *s,
//                          const request_rec *r, apr_pool_t *pool,
//                          const char *errstr) {
//  return;
//}

/**
 * QS_EventLimitCount, detect/update only
 */
static void qos_logger_event_limit(request_rec *r, qos_srv_config *sconf) {
  qs_actable_t *act = sconf->act;
  if(act->event_entry) {
    apr_time_t now = apr_time_sec(r->request_time);
    int i;
    qos_event_limit_entry_t *entry = act->event_entry;
    apr_global_mutex_lock(act->lock);     /* @CRT42 */
    for(i = 0; i < sconf->event_limit_a->nelts; i++) {
      if(entry->action == QS_EVENT_ACTION_DENY) {
        if(apr_table_get(r->subprocess_env, entry->env_var) != NULL) {
          // increment only once
          char *eventLimitId = apr_pstrcat(r->pool, QS_R013_ALREADY_BLOCKED, entry->env_var, NULL);
          if(apr_table_get(r->notes, eventLimitId) == NULL) {
            // reset required (expired)?
            if(entry->limit_time + entry->seconds < now) {
              entry->limit = 0;
              entry->limit_time = 0;
            }
            /* increment limit event */
            entry->limit++;
            if(entry->limit == 1) {
              /* ... and start timer */
              entry->limit_time = now;
            }
          }
        }
      }
      // next rule
      entry++;
    }
    apr_global_mutex_unlock(act->lock);   /* @CRT42 */
  }
}

/**
 * client contol rules at log transaction
 */
static void qos_logger_cc(request_rec *r, qos_srv_config *sconf, qs_req_ctx *rctx) {
  if(sconf->has_qos_cc) {
    int lowrate = 0;
    int unusual_bahavior = 0;
    int block_event = !apr_table_get(r->subprocess_env, QS_BLOCK_SEEN) &&
      apr_table_get(r->subprocess_env, QS_BLOCK);
    qs_conn_ctx *cconf = qos_get_cconf(r->connection);
    qos_user_t *u = qos_get_user_conf(sconf->act->ppool);
    apr_time_t now = apr_time_sec(r->request_time);
    qos_s_entry_t **e = NULL;
    qos_s_entry_t **ef = NULL; // client ip entry from header
    qos_s_entry_t searchE;
    qos_s_entry_t searchEFromHeader;
    searchEFromHeader.ip6[0] = 0;
    searchEFromHeader.ip6[1] = 0;

    if(sconf->qos_cc_prefer_limit || (sconf->req_rate != -1)) {
      qos_ifctx_t *inctx = qos_get_ifctx(r->connection->input_filters);
      if(inctx) {
        if(inctx->lowrate > QS_PKT_RATE_TH) {
          lowrate = inctx->lowrate;
        }
        if(inctx->lowrate != -1) {
          inctx->lowrate = 0;
        }
        if(inctx->status > QS_CONN_STATE_NEW) {
          inctx->r = NULL;
          inctx->status = QS_CONN_STATE_KEEP;
        }
        if(inctx->shutdown) {
          lowrate++;
          inctx->shutdown = 0;
        }
      }
    }

    searchE.ip6[0] = cconf->ip6[0];
    searchE.ip6[1] = cconf->ip6[1];
    if(sconf->qos_cc_forwardedfor) {
      const char *forwardedfor = apr_table_get(r->headers_in, sconf->qos_cc_forwardedfor);
      if(forwardedfor == NULL && r->prev) {
        // experimental (internal redirect?)
        forwardedfor = apr_table_get(r->prev->headers_in, sconf->qos_cc_forwardedfor);
      }
      if(forwardedfor == NULL && r->main) {
        // experimental (internal redirect?)
        forwardedfor = apr_table_get(r->main->headers_in, sconf->qos_cc_forwardedfor);
      }
      if(forwardedfor) {
        if(qos_ip_str2long(forwardedfor, &searchEFromHeader.ip6) == 0) {
          if(apr_table_get(r->notes, "QOS_LOG_PFX069") == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                          QOS_LOG_PFX(069)"no valid IP header found (@logger):"
                          " invalid header value '%s', fallback to connection's IP %s, id=%s",
                          forwardedfor,
                          QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : 
                          QS_CONN_REMOTEIP(r->connection),
                          qos_unique_id(r, "069"));
            apr_table_set(r->notes, "QOS_LOG_PFX069", "log once");
          }
        }
      } else {
        if(apr_table_get(r->notes, "QOS_LOG_PFX069") == NULL) {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                        QOS_LOG_PFX(069)"no valid IP header found (@logger):"
                        " header '%s' not available, fallback to connection's IP %s, id=%s",
                        sconf->qos_cc_forwardedfor,
                        QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                        qos_unique_id(r, "069"));
          apr_table_set(r->notes, "QOS_LOG_PFX069", "log once");
        }
      }
    }
    apr_global_mutex_lock(u->qos_cc->lock);            /* @CRT19 */
    e = qos_cc_get0(u->qos_cc, &searchE, apr_time_sec(r->request_time));
    if(!e) {
      e = qos_cc_set(u->qos_cc, &searchE, apr_time_sec(r->request_time));
    }
    if(searchEFromHeader.ip6[0] || searchEFromHeader.ip6[1]) {
      ef = qos_cc_get0(u->qos_cc, &searchEFromHeader, apr_time_sec(r->request_time));
      if(!ef) {
        ef = qos_cc_set(u->qos_cc, &searchEFromHeader, apr_time_sec(r->request_time));
      }
    } else {
      ef = e; // use either ip from header or connection
    }
    if(rctx->cc_event_req_set) {
      /* QS_ClientEventRequestLimit */
      rctx->cc_event_req_set = 0;
      if((*e)->event_req > 0) {
        (*e)->event_req--;
      }
    }
    if(rctx->cc_serialize_set) {
      /* QS_ClientSerialize */
      rctx->cc_serialize_set = 0;
      (*ef)->serialize = 0;
    }
    unusual_bahavior = qos_content_type(r, sconf, u->qos_cc, *e, sconf->qos_cc_prefer_limit);
    if(block_event || lowrate || unusual_bahavior) {
      if(((*e)->block_time + sconf->qos_cc_block_time) < now) {
        /* reset expired events */
        if((*e)->blockMsg > QS_LOG_REPEAT) {
          // write remaining log lines
          ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->connection->base_server,
                       QOS_LOG_PFX(060)"access denied (previously), "
                       "QS_ClientEventBlockCount rule: "
                       "max=%d, current=%d, "
                       "message repeated %d times, "
                       "c=%s",
                       sconf->qos_cc_block,
                       (*e)->block,
                       (*e)->blockMsg % QS_LOG_REPEAT,
                       QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : 
                       QS_CONN_REMOTEIP(r->connection));
          (*e)->blockMsg = 0;
        }
        (*e)->block = 0;
        (*e)->block_time = 0;
      }
      /* mark lowpkt client */
      if(lowrate || unusual_bahavior) {
        qs_req_ctx *rctx = qos_rctx_config_get(r);
        (*e)->lowrate = apr_time_sec(r->request_time);
        rctx->evmsg = apr_pstrcat(r->pool, "r;", rctx->evmsg, NULL);
      }
      if(block_event) {
        /* increment block event */
        (*e)->block++;
        if((*e)->block == 1) {
          /* ... and start timer */
          (*e)->block_time = now;
        }
      }
    } else if((*e)->lowrate) {
      /* reset low prio client after 24h */
      if(((*e)->lowrate + 86400) < now) {
        (*e)->lowrate = 0;
      }
    }

    /* QS_Limit* */
    if(u->qos_cc->limitTable) {
      int limitTableIndex;
      apr_table_entry_t *limitTableEntry = (apr_table_entry_t *)apr_table_elts(u->qos_cc->limitTable)->elts;
      for(limitTableIndex = 0; 
          limitTableIndex < apr_table_elts(u->qos_cc->limitTable)->nelts;
          limitTableIndex++) {
        const char *eventSet = NULL;
        const char *eventName = limitTableEntry[limitTableIndex].key;
        qos_s_entry_limit_conf_t *eventLimitConf = (qos_s_entry_limit_conf_t *)limitTableEntry[limitTableIndex].val;
        const char *clearEvent = apr_table_get(r->subprocess_env, eventLimitConf->eventClearStr);

        /*
         * reset expired events
         */
        if(clearEvent ||
           (((*ef)->limit[limitTableIndex].limit_time + eventLimitConf->limit_time) < now)) {
          (*ef)->limit[limitTableIndex].limit = 0;
          (*ef)->limit[limitTableIndex].limit_time = 0;
        }
        /*
         * check for new events
         */
        eventSet = apr_table_get(r->subprocess_env, eventName);
        if(eventSet) {
          char *seenEvent;
          if(strcasecmp(eventName, QS_LIMIT_DEFAULT) == 0) {
            // backward compat/event forwarding
            seenEvent = apr_pstrcat(r->pool, QS_LIMIT_SEEN, NULL);
          } else {
            seenEvent = apr_pstrcat(r->pool, QS_LIMIT_SEEN, eventName, NULL);
          }
          if(apr_table_get(r->subprocess_env, seenEvent) == NULL) {
            /* only once per request */
            apr_table_set(r->subprocess_env, seenEvent, "");
            /* increment limit event */
            (*ef)->limit[limitTableIndex].limit++;
            if((*ef)->limit[limitTableIndex].limit == 1) {
              /* ... and start timer */
              (*ef)->limit[limitTableIndex].limit_time = now;
            }
          }
        }
      }
    }
    apr_global_mutex_unlock(u->qos_cc->lock);          /* @CRT19 */
    if(block_event) {
      /* only once per request */
      apr_table_set(r->subprocess_env, QS_BLOCK_SEEN, "");
      apr_table_set(r->connection->notes, QS_BLOCK_SEEN, "");
    }
  }
}

/**
 * client contol rules at header parser
 */
static int qos_hp_cc(request_rec *r, qos_srv_config *sconf, char **msg, char **uid) {
  int ret = DECLINED;
  if(sconf->has_qos_cc) {
    int req_per_sec_block_rate = 0;
    qos_s_entry_t **e = NULL;
    qos_s_entry_t **ef = NULL;
    qos_s_entry_t searchE;
    qos_s_entry_t searchEFromHeader;
    qs_conn_ctx *cconf = qos_get_cconf(r->connection);
    const char *forwardedForLogIP = QS_CONN_REMOTEIP(cconf->c);
    qos_user_t *u = qos_get_user_conf(sconf->act->ppool);
    searchE.ip6[0] = cconf->ip6[0];
    searchE.ip6[1] = cconf->ip6[1];
    searchEFromHeader.ip6[0] = 0;
    searchEFromHeader.ip6[1] = 0;

    if(sconf->qos_cc_forwardedfor) {
      const char *forwardedfor = apr_table_get(r->headers_in, sconf->qos_cc_forwardedfor);
      if(forwardedfor) {
        if(qos_ip_str2long(forwardedfor, &searchEFromHeader.ip6) == 0) {
          if(apr_table_get(r->notes, "QOS_LOG_PFX069") == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                          QOS_LOG_PFX(069)"no valid IP header found (@hp):"
                          " invalid header value '%s', fallback to connection's IP %s, id=%s",
                          forwardedfor,
                          QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : 
                          QS_CONN_REMOTEIP(r->connection),
                          qos_unique_id(r, "069"));
            apr_table_set(r->notes, "QOS_LOG_PFX069", "log once");
          }
        } else {
          forwardedForLogIP = forwardedfor;
        }
      } else {
        if(apr_table_get(r->notes, "QOS_LOG_PFX069") == NULL) {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                        QOS_LOG_PFX(069)"no valid IP header found (@hp):"
                        " header '%s' not available, fallback to connection's IP %s, id=%s",
                        sconf->qos_cc_forwardedfor,
                        QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : 
                        QS_CONN_REMOTEIP(r->connection),
                        qos_unique_id(r, "069"));
          apr_table_set(r->notes, "QOS_LOG_PFX069", "log once");
        }
      }
    }
    apr_global_mutex_lock(u->qos_cc->lock);            /* @CRT17 */
    e = qos_cc_get0(u->qos_cc, &searchE, apr_time_sec(r->request_time));
    if(!e) {
      e = qos_cc_set(u->qos_cc, &searchE, apr_time_sec(r->request_time));
    } else {
      /* update time */
      (*e)->time = apr_time_sec(r->request_time);
    }
    if(searchEFromHeader.ip6[0] || searchEFromHeader.ip6[1]) {
      ef = qos_cc_get0(u->qos_cc, &searchEFromHeader, apr_time_sec(r->request_time));
      if(!ef) {
        ef = qos_cc_set(u->qos_cc, &searchEFromHeader, apr_time_sec(r->request_time));
      } else {
        /* update time */
        (*ef)->time = apr_time_sec(r->request_time);
      }
    } else {
      ef = e; // use either ip from header or connection
    }
    if(sconf->qos_cc_event) {
      apr_time_t now = apr_time_sec(r->request_time);
      const char *v = apr_table_get(r->subprocess_env, QS_EVENT);
      if(v) {
        (*e)->req++;
        if(now > (*e)->interval + QS_BW_SAMPLING_RATE) {
          /* calc req/sec */
          (*e)->req_per_sec = (*e)->req / (now - (*e)->interval);
          (*e)->req = 0;
          (*e)->interval = now;
          /* calc block rate */
          if((*e)->req_per_sec > sconf->qos_cc_event) {
            int factor = (((*e)->req_per_sec * 100) / sconf->qos_cc_event) - 100;
            (*e)->req_per_sec_block_rate = (*e)->req_per_sec_block_rate + factor;
            if((*e)->req_per_sec_block_rate > QS_MAX_DELAY) {
              (*e)->req_per_sec_block_rate = QS_MAX_DELAY;
            }
            /* QS_ClientEventPerSecLimit */
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_WARNING, 0, r,
                          QOS_LOG_PFX(061)"request rate limit,"
                          " rule: "QS_EVENT"(%d), req/sec=%ld,"
                          " delay=%dms%s",
                          sconf->qos_cc_event,
                          (*e)->req_per_sec, (*e)->req_per_sec_block_rate,
                          (*e)->req_per_sec_block_rate == QS_MAX_DELAY ? " (max)" : "");
          } else if((*e)->req_per_sec_block_rate > 0) {
            if((*e)->req_per_sec_block_rate < 50) {
              (*e)->req_per_sec_block_rate = 0;
            } else {
              int factor = (*e)->req_per_sec_block_rate / 4;
              (*e)->req_per_sec_block_rate = (*e)->req_per_sec_block_rate - factor;
            }
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                          QOS_LOG_PFX(062)"request rate limit, rule: "QS_EVENT"(%d), req/sec=%ld,"
                          " delay=%dms",
                          sconf->qos_cc_event,
                          (*e)->req_per_sec, (*e)->req_per_sec_block_rate);
          }
        }
        req_per_sec_block_rate = (*e)->req_per_sec_block_rate;
      }
    }
    if(sconf->qos_cc_block) {
      apr_time_t now = apr_time_sec(r->request_time);
      const char *block_event_str = apr_table_get(r->subprocess_env, QS_BLOCK);
      if(((*e)->block_time + sconf->qos_cc_block_time) < now) {
        /* reset expired events */
        if((*e)->blockMsg > QS_LOG_REPEAT) {
          // write remaining log lines
          ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r->connection->base_server,
                       QOS_LOG_PFX(060)"access denied (previously), "
                       "QS_ClientEventBlockCount rule: "
                       "max=%d, current=%d, "
                       "message repeated %d times, "
                       "c=%s",
                       sconf->qos_cc_block,
                       (*e)->block,
                       (*e)->blockMsg % QS_LOG_REPEAT,
                       QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : 
                       QS_CONN_REMOTEIP(r->connection));
          (*e)->blockMsg = 0;
        }
        (*e)->block = 0;
        (*e)->block_time = 0;
      }
      if(block_event_str) {
        /* increment block event */
        (*e)->block++;
        if((*e)->block == 1) {
          /* ... and start timer */
          (*e)->block_time = now;
        }
        /* only once per request */
        apr_table_set(r->subprocess_env, QS_BLOCK_SEEN, "");
        apr_table_set(r->connection->notes, QS_BLOCK_SEEN, "");
      }
      if((*e)->block >= sconf->qos_cc_block) {
        *uid = apr_pstrdup(cconf->c->pool, "060");
        *msg = apr_psprintf(cconf->c->pool, 
                            QOS_LOG_PFX(060)"access denied, QS_ClientEventBlockCount rule: "
                            "max=%d, current=%d, c=%s",
                            cconf->sconf->qos_cc_block,
                            (*e)->block,
                            QS_CONN_REMOTEIP(cconf->c) == NULL ? "-" : 
                            QS_CONN_REMOTEIP(cconf->c));
        ret = m_retcode;
        (*e)->lowrate = apr_time_sec(r->request_time);
      }
    }
    if(u->qos_cc->limitTable) {
      apr_time_t now = apr_time_sec(r->request_time);
      int limitTableIndex;
      apr_table_entry_t *limitTableEntry = (apr_table_entry_t *)apr_table_elts(u->qos_cc->limitTable)->elts;
      for(limitTableIndex = 0; 
          limitTableIndex < apr_table_elts(u->qos_cc->limitTable)->nelts;
          limitTableIndex++) {
        const char *eventSet = NULL;
        const char *eventName = limitTableEntry[limitTableIndex].key;
        qos_s_entry_limit_conf_t *eventLimitConf = (qos_s_entry_limit_conf_t *)limitTableEntry[limitTableIndex].val;
        const char *clearEvent = apr_table_get(r->subprocess_env, eventLimitConf->eventClearStr);

        /*
         * reset expired events
         */
        if(clearEvent ||
           (((*ef)->limit[limitTableIndex].limit_time + eventLimitConf->limit_time) < now)) {
          (*ef)->limit[limitTableIndex].limit = 0;
          (*ef)->limit[limitTableIndex].limit_time = 0;
        }

        /*
         * check for new events
         */
        eventSet = apr_table_get(r->subprocess_env, eventName);
        if(eventSet) {
          char *seenEvent;
          if(strcasecmp(eventName, QS_LIMIT_DEFAULT) == 0) {
            // backward compat/event forwarding
            seenEvent = apr_pstrcat(r->pool, QS_LIMIT_SEEN, NULL);
          } else {
            seenEvent = apr_pstrcat(r->pool, QS_LIMIT_SEEN, eventName, NULL);
          }
          if(apr_table_get(r->subprocess_env, seenEvent) == NULL) {
            // first occurance
            apr_table_set(r->subprocess_env, seenEvent, "");
            /* increment limit event */
            (*ef)->limit[limitTableIndex].limit++;
            if((*ef)->limit[limitTableIndex].limit == 1) {
              /* ... and start timer */
              (*ef)->limit[limitTableIndex].limit_time = now;
            }
          }
        }

        /*
         * propagate to env
         */
        apr_table_set(r->subprocess_env,
                      apr_pstrcat(r->pool, eventName, QS_COUNTER_SUFFIX, NULL),
                      apr_psprintf(r->pool, "%d", (*ef)->limit[limitTableIndex].limit));

        /*
         * enforce limit
         */
        if((*ef)->limit[limitTableIndex].limit >= eventLimitConf->limit) {
          int block = 1;
          char *conditional = "";
          if(eventLimitConf->condStr != NULL) {
            // conditional enforcement...
            const char *condition = apr_table_get(r->subprocess_env, QS_COND);
            conditional = apr_pstrdup(r->pool, "Cond");
            if(condition == NULL) {
              block = 0; // variable not set
            } else {
              if(ap_regexec(eventLimitConf->preg, condition, 0, NULL, 0) != 0) {
                block = 0; // pattern does not match
              }
            }
          }
          if(block) {
            if(ret == DECLINED || ef != e) {
              /* log only one error (either block or limit) */
              *uid = apr_pstrdup(cconf->c->pool, "067");
              *msg = apr_psprintf(cconf->c->pool, 
                                  QOS_LOG_PFX(067)"access denied, QS_%sClientEventLimitCount rule: "
                                  "event=%s, "
                                  "max=%d, current=%d, c=%s",
                                  conditional,
                                  eventName,
                                  eventLimitConf->limit,
                                  (*ef)->limit[limitTableIndex].limit,
                                  forwardedForLogIP == NULL ? "-" : forwardedForLogIP);
              ret = m_retcode;
            }
          }
          (*ef)->lowrate = apr_time_sec(r->request_time);
        }
      }
    }

    apr_global_mutex_unlock(u->qos_cc->lock);          /* @CRT17 */
    if(!sconf->log_only) {
      if(req_per_sec_block_rate) {
        qs_req_ctx *rctx = qos_rctx_config_get(r);
        int sec = req_per_sec_block_rate / 1000;
        int nsec = req_per_sec_block_rate % 1000;
        struct timespec delay;
        rctx->evmsg = apr_pstrcat(r->pool, "L;", rctx->evmsg, NULL);
        delay.tv_sec  = sec;
        delay.tv_nsec = nsec * 1000000;
        nanosleep(&delay,NULL);
      }
    }
  }
  return ret;
}

// checks if connection counting is enabled (any host)
static int qos_count_connections(qos_srv_config *sconf) {
  server_rec *s = sconf->base_server;
  qos_srv_config *bsconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
  if(QS_COUNT_CONNECTIONS(bsconf)) {
    return 1;
  }
  s = s->next;
  while(s) {
    qos_srv_config *sc = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
    if(QS_COUNT_CONNECTIONS(sc)) {
      return 1;
    }
    s = s->next;
  }
  return 0;
}

// total (server/all hosts) conections
static int qos_server_connections(qos_srv_config *sconf) {
  server_rec *s = sconf->base_server;
  qos_srv_config *bsconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
  int connections = bsconf->act->conn->connections;
  s = s->next;
  while(s) {
    qos_srv_config *sc = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
    if(sc != bsconf) {
      connections += sc->act->conn->connections;
    }
    s = s->next;
  }
  return connections;
  /*
  int i, j;
  worker_score *ws_record;
  process_score *ps_record;
  for(i = 0; i < sconf->server_limit; ++i) {
    ps_record = ap_get_scoreboard_process(i);
    for(j = 0; j < sconf->thread_limit; ++j) {
      ws_record = ap_get_scoreboard_worker(i, j);
      if(!ps_record->quiescing && ps_record->pid) {
        if(ws_record->status == SERVER_READY && ps_record->generation == qos_my_generation) {
          ready++;
        }
      }
    }
  }
  */ 
}

/**
 * client control rules at process connection handler
 */
static int qos_cc_pc_filter(conn_rec *c, qs_conn_ctx *cconf, qos_user_t *u, char **msg) {
  int ret = DECLINED;
  if(cconf->sconf->has_qos_cc) {
    qos_s_entry_t **e = NULL;
    qos_s_entry_t searchE;
    searchE.ip6[0] = cconf->ip6[0];
    searchE.ip6[1] = cconf->ip6[1];
    apr_global_mutex_lock(u->qos_cc->lock);            /* @CRT14 */
    e = qos_cc_get0(u->qos_cc, &searchE, 0);
    if(!e) {
      e = qos_cc_set(u->qos_cc, &searchE, time(NULL));
    }
    /* early vip detection */
    if((*e)->vip) {
      cconf->is_vip = 1;
    }
    /* max connections */
    if(cconf->sconf->has_qos_cc && cconf->sconf->qos_cc_prefer) {
      u->qos_cc->connections++;
      if((*e)->lowrate) {
        if(c->notes) {
          apr_table_set(c->notes, "QS_ClientLowPrio", "1");
        }
      }
      if(u->qos_cc->connections > cconf->sconf->qos_cc_prefer_limit) {
        /* allow all vip addresses */
        if(!(*e)->vip) {
          /* step 1 - deny slow clients  */
          if((*e)->lowrate) {
            if(c->notes) {
              apr_table_set(c->notes, "QS_ClientLowPrio", "1");
            }
            if(u->qos_cc->connections > cconf->sconf->qos_cc_prefer_limit) {
              *msg = apr_psprintf(cconf->c->pool, 
                                  QOS_LOG_PFX(064)"access denied, "
                                  "QS_ClientPrefer rule (low prio): "
                                  "max=%d, concurrent connections=%d, c=%s",
                                  cconf->sconf->qos_cc_prefer_limit, u->qos_cc->connections,
                                  QS_CONN_REMOTEIP(cconf->c) == NULL ? "-" : 
                                  QS_CONN_REMOTEIP(cconf->c));
              ret = m_retcode;
            }
          } else {
            /* step 2 - deny also normal clients (they are not vip) */
            int more = (cconf->sconf->max_clients - cconf->sconf->qos_cc_prefer_limit) / 2;
            if(u->qos_cc->connections > (cconf->sconf->qos_cc_prefer_limit + more)) {
              *msg = apr_psprintf(cconf->c->pool, 
                                  QOS_LOG_PFX(063)"access denied, "
                                  "QS_ClientPrefer rule (not vip): "
                                  "max=%d(+%d), concurrent connections=%d, c=%s",
                                  cconf->sconf->qos_cc_prefer_limit, more, 
                                  u->qos_cc->connections,
                                  QS_CONN_REMOTEIP(cconf->c) == NULL ? "-" : 
                                  QS_CONN_REMOTEIP(cconf->c));
              ret = m_retcode;
            }
          }
        }
      }
    }

//    /* blocked by event (block only, no limit) - moderate*/
//    if(cconf->sconf->qos_cc_block) {
//      if((*e)->block >= cconf->sconf->qos_cc_block) {
//        apr_time_t now = time(NULL);
//        if(((*e)->block_time + cconf->sconf->qos_cc_block_time) > now) {
//          /* still blocking */
//          *msg = apr_psprintf(cconf->c->pool, 
//                              QOS_LOG_PFX(060)"access denied, QS_ClientEventBlockCount rule: "
//                              "max=%d, current=%d, c=%s",
//                              cconf->sconf->qos_cc_block,
//                              (*e)->block,
//                              QS_CONN_REMOTEIP(cconf->c) == NULL ? "-" : QS_CONN_REMOTEIP(cconf->c));
//          ret = m_retcode;
//        } else {
//          /* release */
//          (*e)->block = 0;
//          (*e)->block_time = 0;
//        }
//      }
//    }
    apr_global_mutex_unlock(u->qos_cc->lock);          /* @CRT14 */
  }
  return ret;
}

/**
 * calculates the current minimal up/download bandwith
 */
static int qos_req_rate_calc(qos_srv_config *sconf, int *current) {
  int req_rate = sconf->req_rate;
  if(sconf->min_rate_max != -1) {
    server_rec *s = sconf->base_server;
    qos_srv_config *bsconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
    int connections = bsconf->act->conn->connections;
    s = s->next;
    while(s) {
      qos_srv_config *sc = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
      if(sc != bsconf) {
        connections = connections + sc->act->conn->connections;
      }
      s = s->next;
    }
    if(connections > sconf->req_rate_start) {
      /* keep the minimal rate until reaching the min connections */
      req_rate = req_rate + ((sconf->min_rate_max / sconf->max_clients) * connections);
      if(connections > sconf->max_clients) {
        // limit the max rate if we have more connections then expected
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, sconf->base_server, 
                     QOS_LOG_PFX(036)"QS_SrvMinDataRate: unexpected connection status!"
                     " connections=%d,"
                     " cal. request rate=%d,"
                     " max. limit=%d."
                     " Check log for unclean child exit and consider"
                     " to do a graceful server restart.",
                     connections, req_rate, sconf->min_rate_max);
        req_rate = sconf->min_rate_max;
      }
    }
    *current = connections;
  }
  return req_rate;
}

static qos_s_entry_limit_conf_t *qos_getQSLimitEvent(qos_user_t *u, const char *event,
                                                     int *limitTableIndex) {
  int i = 0;
  apr_table_entry_t *limitTableEntry = (apr_table_entry_t *)apr_table_elts(u->qos_cc->limitTable)->elts;
  for(i = 0; i < apr_table_elts(u->qos_cc->limitTable)->nelts; i++) {
    const char *eventName = limitTableEntry[i].key;
    if(strcasecmp(eventName, event) == 0) {
      *limitTableIndex = i;
      return (qos_s_entry_limit_conf_t *)limitTableEntry[i].val;
    }
  }
  return NULL;
}

/************************************************************************
 * "public"
 ***********************************************************************/

/**
 * short status viewer
 */
static void qos_ext_status_short(request_rec *r, apr_table_t *qt) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                &qos_module);
  server_rec *s = sconf->base_server;
  qos_srv_config *bsconf = (qos_srv_config*)ap_get_module_config(s->module_config,
                                                                 &qos_module);
  const char *option = apr_table_get(qt, "option");
  const char *all_connections = apr_table_get(r->subprocess_env, "QS_AllConn");
  apr_time_t now = apr_time_sec(r->request_time);

  while(s) {
    char *sn = apr_psprintf(r->pool, "%s"QOS_DELIM"%s"QOS_DELIM"%d",
                            s->is_virtual ? "v" : "b",
                            s->server_hostname == NULL ? "-" :
                            ap_escape_html(r->pool, s->server_hostname),
                            s->addrs->host_port);
    sconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
    if(all_connections && !s->is_virtual) {
      ap_rprintf(r, "%s"QOS_DELIM"QS_AllConn: %s\n", sn, all_connections);
    }
    if((s->is_virtual && (sconf != bsconf)) || !s->is_virtual) {
      qs_acentry_t *e;
      if(!s->is_virtual && sconf->has_qos_cc && sconf->qos_cc_prefer_limit) {
        qos_user_t *u = qos_get_user_conf(sconf->act->ppool);
        int hc = u->qos_cc->connections; /* not synchronized ... */
        ap_rprintf(r, "%s"QOS_DELIM"QS_ClientPrefer"QOS_DELIM"%d[]: %d\n", sn,
                   sconf->qos_cc_prefer_limit, hc);
      }
      /* request level */
      e = sconf->act->entry;
      while(e) {
        if((e->limit > 0) && !e->condition && !e->event) {
          ap_rprintf(r, "%s"QOS_DELIM"QS_LocRequestLimit%s"QOS_DELIM"%d[%s]: %d\n", sn,
                     e->regex == NULL ? "" : "Match", 
                     e->limit,
                     e->url, 
                     e->counter);
        }
        if((e->req_per_sec_limit > 0) && !e->event) {
          ap_rprintf(r, "%s"QOS_DELIM"QS_LocRequestPerSecLimit%s"QOS_DELIM"%ld[%s]: %ld\n", sn,
                     e->regex == NULL ? "" : "Match", 
                     e->req_per_sec_limit,
                     e->url,
                     e->req_per_sec);
        }
        if((e->kbytes_per_sec_limit > 0) && !e->event) {
          ap_rprintf(r, "%s"QOS_DELIM"QS_LocKBytesPerSecLimit%s"QOS_DELIM"%ld[%s]: %ld\n", sn,
                     e->regex == NULL ? "" : "Match",
                     e->kbytes_per_sec_limit,
                     e->url, 
                     e->kbytes_per_sec);
        }
        if(e->condition && !e->event) {
          ap_rprintf(r, "%s"QOS_DELIM"QS_CondLocRequestLimitMatch"QOS_DELIM"%d[%s]: %d\n", sn,
                     e->limit,
                     e->url, 
                     e->counter);
        }
        if(e->event && (e->limit != -1)) {
          ap_rprintf(r, "%s"QOS_DELIM"QS_EventRequestLimit"QOS_DELIM"%d[%s]: %d\n", sn,
                     e->limit,
                     e->url, 
                     e->counter);
        }
        if(e->event && (e->kbytes_per_sec_limit != 0)) {
          ap_rprintf(r, "%s"QOS_DELIM"QS_EventKBytesPerSecLimit"QOS_DELIM"%ld[%s]: %ld\n", sn,
                     e->kbytes_per_sec_limit,
                     e->url, 
                     now > (e->interval + (QS_BW_SAMPLING_RATE*10)) ? 0 : e->kbytes_per_sec);
        }
        if(e->event && (e->req_per_sec_limit > 0)) {
          ap_rprintf(r, "%s"QOS_DELIM"QS_EventPerSecLimit"QOS_DELIM"%ld[%s]: %ld\n", sn,
                     e->req_per_sec_limit,
                     e->url, 
                     now > (e->interval + (QS_BW_SAMPLING_RATE*3)) ? 0 : e->req_per_sec);
        }
        e = e->next;
      }
      /* event limit */
      if(sconf->event_limit_a->nelts > 0) {
        int ie = 0;
        qos_event_limit_entry_t *event_limit = sconf->act->event_entry;
        for(ie = 0; ie < sconf->event_limit_a->nelts; ie++) {
          int elimit = event_limit->limit;
          if(event_limit->limit_time + event_limit->seconds <= now) {
            elimit = 0;
          }
          if(event_limit->action == QS_EVENT_ACTION_DENY) {
            ap_rprintf(r, "%s"QOS_DELIM"QS_EventLimitCount"QOS_DELIM"%d/%d[%s]: %d\n", sn,
                       event_limit->max,
                       event_limit->seconds,
                       event_limit->env_var,
                       elimit);
          }
          event_limit++;
        }
      }
      if(sconf->max_conn != -1) {
        ap_rprintf(r, "%s"QOS_DELIM"QS_SrvMaxConn"QOS_DELIM"%d[]: %d\n", sn,
                   sconf->max_conn,
                   sconf->act->conn->connections);
      }
      if(sconf->max_conn_close != -1) {
        ap_rprintf(r, "%s"QOS_DELIM"QS_SrvMaxConnClose"QOS_DELIM"%d[]: %d\n", sn,
                   sconf->max_conn_close,
                   sconf->act->conn->connections);
      }
      if(option && ap_strstr_c(option, "ip")) {
        if(sconf->act->conn->connections) {
          apr_table_t *entries = apr_table_make(r->pool, 100);
          int j;
          apr_table_entry_t *entry;
          qos_collect_ip(r, sconf, entries, sconf->max_conn_per_ip, 0);
          entry = (apr_table_entry_t *)apr_table_elts(entries)->elts;
          for(j = 0; j < apr_table_elts(entries)->nelts; j++) {
            ap_rprintf(r, "%s"QOS_DELIM"QS_SrvMaxConnPerIP"QOS_DELIM"%s: %s\n",
                       sn,
                       entry[j].key, entry[j].val);
          }
        }
      }
    }
    s = s->next;
  }
}

/**
 * Comperator for bsearch function
 */
static int qos_geo_comp(const void *_pA, const void *_pB) {
  unsigned long *pA = (unsigned long *)_pA;
  qos_geo_t *pB = (qos_geo_t *)_pB;
  unsigned long search = *pA;
  if((search >= pB->start) && (search <= pB->end)) return 0;
  if(search > pB->start) return 1;
  if(search < pB->start) return -1;
  return -1; // error
}

/**
 * Translates an IP address (from geo csv) to a numeric value.
 *
 * @param pool To dup the string whike parsing.
 * @param ip
 * @return
 */
static unsigned long qos_geo_str2long(apr_pool_t *pool, const char *ip) {
  char *p;
  char *i = apr_pstrdup(pool, ip);
  unsigned long addr = 0;

  p = strchr(i, '.');
  if(!p) return 0;
  p[0] = '\0';
  if(!qos_is_num(i)) return 0;
  addr += (atol(i) * 16777216);
  i = p;
  i++;

  p = strchr(i, '.');
  if(!p) return 0;
  p[0] = '\0';
  if(!qos_is_num(i)) return 0;
  addr += (atol(i) * 65536);
  i = p;
  i++;

  p = strchr(i, '.');
  if(!p) return 0;
  p[0] = '\0';
  if(!qos_is_num(i)) return 0;
  addr += (atol(i) * 256);
  i = p;
  i++;

  if(!qos_is_num(i)) return 0;
  addr += (atol(i));

  return addr;
}

/**
 * Viewer settings about ip address information.
 */
static void qos_show_ip(request_rec *r, qos_srv_config *sconf, apr_table_t *qt) {
  int max_conn_per_ip = 0;
  server_rec *s = sconf->base_server;
  while(s) {
    // enable per client connection search if any server has enabled QS_SrvMaxConnPerIP
    qos_srv_config *conf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
    if(conf->max_conn_per_ip != -1) {
      max_conn_per_ip = 1;
      break;
    }
    s = s->next;
  }
  if(sconf->has_qos_cc || max_conn_per_ip) {
    const char *option = apr_table_get(qt, "option");
    if(strcmp(r->handler, "qos-viewer") == 0) {
      ap_rputs("<table class=\"btable\"><tbody>\n", r);
      ap_rputs(" <tr class=\"row\"><td>\n", r);
    } else {
      ap_rputs("<table border=\"1\"><tbody>\n", r);
      ap_rputs(" <tr><td>\n", r);
    }
    if(strcmp(r->handler, "qos-viewer") == 0) {
      ap_rputs("  <table border=\"0\" cellpadding=\"2\" "
               "cellspacing=\"2\" style=\"width: 100%\"><tbody>\n",r);
    } else {
      ap_rputs("  <table border=\"1\" cellpadding=\"2\" "
               "cellspacing=\"2\" style=\"width: 100%\"><tbody>\n",r);
    }
    ap_rputs("    <tr class=\"rowe\">\n", r);
    ap_rputs("      <td colspan=\"9\">viewer settings</td>\n", r);
    ap_rputs("    </tr>\n", r);
    /* show ip addresses and their connections */
    ap_rputs("    <tr class=\"rows\">\n"
             "      <td colspan=\"1\">client ip connections</td>\n", r);
    ap_rputs("      <td colspan=\"8\">\n", r);
    ap_rprintf(r, "        <form action=\"%s\" method=\"get\">\n",
               ap_escape_html(r->pool, r->parsed_uri.path ? r->parsed_uri.path : ""));
    if(!option || (option && !ap_strstr_c(option, "ip")) ) {
      ap_rprintf(r, "          <input name=\"option\" value=\"ip\" type=\"hidden\">\n");
      ap_rprintf(r, "          <input name=\"action\" value=\"enable\" type=\"submit\">\n");
    } else {
      ap_rprintf(r, "          <input name=\"option\" value=\"no\" type=\"hidden\">\n");
      ap_rprintf(r, "          <input name=\"action\" value=\"disable\" type=\"submit\">\n");
    }
    ap_rputs("        </form>\n", r);
    ap_rputs("      </td>\n", r);
    ap_rputs("    </tr>\n", r);
  
    if(sconf->has_qos_cc) {
      const char *address = apr_table_get(qt, "address");
      if(address) {
        int escerr = 0;
        char *ta = apr_pstrdup(r->pool, address);
        qos_unescaping(ta, QOS_DEC_MODE_FLAGS_URL, &escerr);
        address = ta;
      }
      ap_rputs("    <tr class=\"rows\">\n"
               "      <td colspan=\"1\">search a client ip entry</td>\n", r); 
      ap_rputs("      <td colspan=\"8\">\n", r);
      ap_rprintf(r, "        <form action=\"%s\" method=\"get\">\n",
                 ap_escape_html(r->pool, r->parsed_uri.path ? r->parsed_uri.path : ""));
      if(option && ap_strstr_c(option, "ip")) {
        ap_rprintf(r, "          <input name=\"option\" value=\"ip\" type=\"hidden\">\n");
      }
      ap_rprintf(r, "          <input name=\"address\" value=\"%s\" type=\"text\">\n",
                 address ? ap_escape_html(r->pool, address) : "0.0.0.0");
      ap_rprintf(r, "          <input name=\"action\" value=\"search\" type=\"submit\">\n");
      ap_rputs("          </form>\n", r);
      ap_rputs("      </td>\n", r);
      ap_rputs("    </tr>\n", r);
      if(address) {
        apr_uint64_t ip[2];
        qos_user_t *u = qos_get_user_conf(sconf->act->ppool);
        if(qos_ip_str2long(address, &ip)) {
          unsigned long html;
          unsigned long cssjs;
          unsigned long img;
          unsigned long other;
          unsigned long notmodified;
          qos_s_entry_t **e = NULL;
          qos_s_entry_t searchE;
          int found = 0;
          apr_global_mutex_lock(u->qos_cc->lock);            /* @CRT20 */
          html = u->qos_cc->html;
          cssjs = u->qos_cc->cssjs;
          img = u->qos_cc->img;
          other = u->qos_cc->other;
          notmodified = u->qos_cc->notmodified;
          searchE.ip6[0] = ip[0];
          searchE.ip6[1] = ip[1];
          e = qos_cc_get0(u->qos_cc, &searchE, 0);
          if(e) {
            found = 1;
            searchE.vip = (*e)->vip;
            searchE.lowrate = (*e)->lowrate;
            searchE.time = (*e)->time;
            searchE.block = (*e)->block;
            searchE.block_time = (*e)->block_time;
            searchE.limit = (*e)->limit;
            searchE.req_per_sec = (*e)->req_per_sec;
            searchE.req_per_sec_block_rate = (*e)->req_per_sec_block_rate;
            searchE.other = (*e)->other - 1;
            searchE.html = (*e)->html - 1;
            searchE.cssjs = (*e)->cssjs - 1;
            searchE.img = (*e)->img - 1;
            searchE.notmodified = (*e)->notmodified - 1;
            searchE.event_req = (*e)->event_req;
          }
          apr_global_mutex_unlock(u->qos_cc->lock);            /* @CRT20 */
          ap_rputs("    <tr class=\"rowt\">\n", r);
          ap_rputs("      <td colspan=\"1\">IP</td>\n", r);
          ap_rputs("      <td colspan=\"2\">last request</td>\n", r);
          ap_rputs("      <td colspan=\"1\">"
                   "<div title=\"QS_VipHeaderName|QS_VipIPHeaderName\">vip</div></td>\n", r);
          ap_rputs("      <td colspan=\"1\">"
                   "<div title=\"QS_ClientEventBlockCount\">blocked</div></td>\n", r);
          ap_rputs("      <td colspan=\"1\">"
                   "<div title=\"QS_ClientEventLimitCount (QS_Limit)\">limited</div></td>\n", r);
          ap_rputs("      <td colspan=\"2\">"
                   "<div title=\"QS_ClientEventPerSecLimit\">events/sec</div></td>\n", r);
          ap_rputs("      <td colspan=\"1\">"
                   "<div title=\"QS_ClientPrefer\">low prio</div></td>\n", r);
          ap_rputs("    </tr>\n", r);
          ap_rprintf(r, "    <tr class=\"rows\">"
                     "<td colspan=\"1\">%s</td>", ap_escape_html(r->pool, address));
          if(!found) {
            ap_rputs("<td colspan=\"8\"><i>not found</i></td>\n", r);
          } else {
            char buf[1024];
            struct tm *ptr = localtime(&searchE.time);
            strftime(buf, sizeof(buf), "%d.%m.%Y %H:%M:%S", ptr);
            ap_rprintf(r, "<td colspan=\"2\">%s</td>", buf);
            ap_rprintf(r, "<td colspan=\"1\">%s</td>", searchE.vip ? "yes" : "no");
            if(sconf->qos_cc_block_time > (time(NULL) - searchE.block_time)) {
              ap_rprintf(r, "<td colspan=\"1\">%d, %ld&nbsp;sec</td>",
                         searchE.block, time(NULL) - searchE.block_time);
            } else {
              ap_rprintf(r, "<td colspan=\"1\">no</td>");
            }
            
            if(u->qos_cc->limitTable) {
              int limitTableIndex;
              qos_s_entry_limit_conf_t *eventLimitConf = qos_getQSLimitEvent(u, QS_LIMIT_DEFAULT, &limitTableIndex);
              if(eventLimitConf) {
                if(eventLimitConf->limit_time > (time(NULL) - searchE.limit[limitTableIndex].limit_time)) {
                  ap_rprintf(r, "<td colspan=\"1\">%d, %ld&nbsp;sec</td>",
                             searchE.limit[limitTableIndex].limit, time(NULL) - searchE.limit[limitTableIndex].limit_time);
                } else {
                  ap_rprintf(r, "<td colspan=\"1\">no</td>");
                }
              } else {
                ap_rprintf(r, "<td colspan=\"1\">off</td>");
              }
            } else {
              ap_rprintf(r, "<td colspan=\"1\">off</td>");
            }
            ap_rprintf(r, "<td colspan=\"1\">%ld</td>", searchE.req_per_sec);
            ap_rprintf(r, "<td colspan=\"1\">%d&nbsp;ms</td>", searchE.req_per_sec_block_rate);
            ap_rprintf(r, "<td colspan=\"1\">%s</td>\n", searchE.lowrate > 0 ? "yes" : "no");

            ap_rputs("</tr>\n", r);
            ap_rprintf(r, "<tr class=\"rows\">"
                       "<td colspan=\"6\">&nbsp;</td>"
                       "<td>"
                       "<div title=\"QS_ClientEventRequestLimit\">events:</div></td>"
                       "<td style=\"width:9%%\">%s</td>"
                       "<td colspan=\"1\"></td>"
                       "</tr>", (sconf->qos_cc_event_req == -1 ? "off" : apr_psprintf(r->pool, "%d", searchE.event_req)));
          }
          ap_rprintf(r, "<tr class=\"rowt\">"
                     "<td colspan=\"4\"></td>"
                     "<td style=\"width:9%%\">html</td>"
                     "<td style=\"width:9%%\">css/js</td>"
                     "<td style=\"width:9%%\">images</td>"
                     "<td style=\"width:9%%\">other</td>"
                     "<td style=\"width:9%%\">304</td>"
                     "</tr>");
          if(found) {
            ap_rprintf(r, "<tr class=\"rows\">"
                       "<td colspan=\"4\"></td>"
                       "<td style=\"width:9%%\">%u</td>"
                       "<td style=\"width:9%%\">%u</td>"
                       "<td style=\"width:9%%\">%u</td>"
                       "<td style=\"width:9%%\">%u</td>"
                       "<td style=\"width:9%%\">%u</td>"
                       "</tr>", searchE.html,
                       searchE.cssjs,
                       searchE.img,
                       searchE.other,
                       searchE.notmodified);
          }
          ap_rprintf(r, "<tr class=\"rows\">"
                     "<td colspan=\"3\"></td>"
                     "<td style=\"width:9%%\">all clients</td>"
                     "<td style=\"width:9%%\">%lu</td>"
                     "<td style=\"width:9%%\">%lu</td>"
                     "<td style=\"width:9%%\">%lu</td>"
                     "<td style=\"width:9%%\">%lu</td>"
                     "<td style=\"width:9%%\">%lu</td>"
                     "</tr>", html, cssjs, img, other, notmodified);
          if(sconf->static_on == 1) {
            unsigned long shtml = sconf->static_html;
            unsigned long scssjs = sconf->static_cssjs;
            unsigned long simg = sconf->static_img;
            unsigned long sother = sconf->static_other;
            unsigned long snotmodified = sconf->static_notmodified;
            ap_rprintf(r, "<tr class=\"rows\">"
                       "<td colspan=\"3\"></td>"
                       "<td style=\"width:9%%\">configured (global)</td>"
                       "<td style=\"width:9%%\">%lu</td>"
                       "<td style=\"width:9%%\">%lu</td>"
                       "<td style=\"width:9%%\">%lu</td>"
                       "<td style=\"width:9%%\">%lu</td>"
                       "<td style=\"width:9%%\">%lu</td>"
                       "</tr>", shtml, scssjs,
                       simg, sother, snotmodified);
          }
        }
      }
    }
    ap_rprintf(r, "<tr class=\"row\">"
               "<td style=\"width:28%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "</tr>");
    ap_rputs(" </tbody></table>\n", r);
    ap_rputs(" </tr></td>\n", r);
    ap_rputs("</tbody></table>\n", r);
  }
}

/**
 * Daws the load/connection bars at the top of the status page
 *
 * @param r
 * @param bs
 */
static void qos_bars(request_rec *r, server_rec *bs) {
  server_rec *s = bs;
  qos_srv_config *bsconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
  if(bsconf->act && bsconf->act->conn) {
    int connections = -1;
    double av[1];
    int load;
    getloadavg(av, 1);
    load = av[0];

    ap_rputs("<table class=\"btable\"><tbody>\n", r);
    ap_rputs(" <tr class=\"row\"><td>\n", r);

    ap_rputs("<table border=\"0\" cellpadding=\"2\" "
             "cellspacing=\"2\" style=\"width: 100%\"><tbody>\n",r);
    ap_rputs("<tr class=\"rowe\">\n", r);
    ap_rputs("<td colspan=\"2\">overview</td>", r);
    ap_rputs("</tr>\n", r);

    if(bsconf->log_only) {
      ap_rputs("<tr class=\"rowt\">\n", r);
      ap_rputs("<td colspan=\"2\">running in 'log only' mode - rules are NOT enforced</td>", r);
      ap_rputs("</tr>\n", r);
    }
    if(qos_count_connections(bsconf)) {
      connections = qos_server_connections(bsconf);
    }
    if(connections != -1) {
      ap_rprintf(r, "<tr class=\"rowt\">"
                 "<td colspan=\"1\">connections: %d</td>"
                 "<td colspan=\"1\">load: %.2f</td>"
                 "</tr>\n", connections, av[0]);
    } else {
      ap_rprintf(r, "<tr class=\"rowt\">"
                 "<td colspan=\"1\">connections: n/a</td>"
                 "<td colspan=\"1\">load: %.2f</td>"
                 "</tr>\n", av[0]);
    }
    ap_rprintf(r, "<tr class=\"rows\">");
    ap_rprintf(r, "<td>");
    if(connections != -1) {
      ap_rprintf(r, "<div class=\"prog-border\">"
                 "<div class=\"prog-bar\" style=\"width: %d%%;\"></div></div>",
                 100 * connections / bsconf->max_clients);
      ap_rprintf(r, "</td>");
    } else {
      ap_rprintf(r, "&nbsp;");
    }      
    ap_rprintf(r, "<td>");
    ap_rprintf(r, "<div class=\"prog-border\">"
               "<div class=\"prog-bar\" style=\"width: %d%%;\"></div></div>",
               load > 20 ? 100 : 100 * load / 20);
    ap_rprintf(r, "</td>");
    ap_rprintf(r, "</tr>\n");

    ap_rputs("</tbody></table>\n", r);

    ap_rputs(" </tr></td>\n", r);
    ap_rputs("</tbody></table>\n", r);
  }
}

/**
 * (Extendet-)Status viewer, used by internal and mod_status handler.
 */
static int qos_ext_status_hook(request_rec *r, int flags) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                &qos_module);
  server_rec *s = sconf->base_server;
  int i = 0;
  apr_time_t now = apr_time_sec(r->request_time);
  qos_srv_config *bsconf = (qos_srv_config*)ap_get_module_config(s->module_config,
                                                                 &qos_module);
  apr_table_t *qt = qos_get_query_table(r);
  const char *option = apr_table_get(qt, "option");
  if(sconf->disable_handler == 1) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOS_LOG_PFX(072)"handler has been disabled for this host");
    return OK;
  }
  if (flags & AP_STATUS_SHORT) {
    qos_ext_status_short(r, qt);
    return OK;
  }
  if(qt && (apr_table_get(qt, "auto") != NULL)) {
    qos_ext_status_short(r, qt);
    return OK;
  }
  if(strcmp(r->handler, "qos-viewer") != 0) {
    ap_rputs("<hr>\n", r);
    ap_rputs("<table style=\"width:400px\" cellspacing=0 cellpadding=0>\n", r);
    ap_rputs(" <tr><td bgcolor=\"#000000\">\n", r);
    ap_rputs(" <b><font color=\"#ffffff\" face=\"Arial,Helvetica\">", r);
    ap_rprintf(r, "mod_qos&nbsp;%s", ap_escape_html(r->pool, qos_revision(r->pool)));
    ap_rputs(" </font></b>\r", r);
    ap_rputs(" </td></tr>\n", r);
    ap_rputs("</table>\n", r);
    if(sconf->log_only) {
      ap_rputs("<p>running in 'log only' mode - rules are NOT enforced</p>\n", r);
    }      
  }
#ifdef QS_INTERNAL_TEST
  {
    apr_uint64_t remoteip[2];
    qos_ip_str2long(QS_CONN_REMOTEIP(r->connection), &remoteip);
    qs_conn_ctx *cconf = qos_get_cconf(r->connection);
    if(cconf) {
      remoteip[0] = cconf->ip6[0];
      remoteip[1] = cconf->ip6[1];
    }
    ap_rputs("<p>TEST BINARY, NOT FOR PRODUCTIVE USE<br>\n", r);
    ap_rprintf(r, "client ip=%s</p>\n", qos_ip_long2str(r->pool, remoteip));
  }
#endif
  if(strcmp(r->handler, "qos-viewer") == 0) {
    qos_bars(r, s);
  }
  qos_show_ip(r, bsconf, qt);
  if(strcmp(r->handler, "qos-viewer") == 0) {
    ap_rputs("<table class=\"btable\"><tbody>\n", r);
    ap_rputs(" <tr class=\"row\"><td>\n", r);
  } else {
    ap_rputs("<table border=\"1\"><tbody>\n", r);
    ap_rputs(" <tr><td>\n", r);
  }
  while(s) {
    qs_acentry_t *e;
    if(strcmp(r->handler, "qos-viewer") == 0) {
      ap_rputs("  <table border=\"0\" cellpadding=\"2\" "
               "cellspacing=\"2\" style=\"width: 100%\"><tbody>\n",r);
    } else {
      ap_rputs("  <table border=\"1\" cellpadding=\"2\" "
               "cellspacing=\"2\" style=\"width: 100%\"><tbody>\n",r);
    }
    ap_rputs("    <tr class=\"rowe\">\n", r);
    ap_rprintf(r, "      <td colspan=\"9\">%s:%d (%s)</td>\n",
               s->server_hostname == NULL ? "-" : ap_escape_html(r->pool, s->server_hostname),
               s->addrs->host_port,
               s->is_virtual ? "virtual" : "base");
    ap_rputs("    </tr>\n", r);
    sconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);

    if((sconf == bsconf) && s->is_virtual) {
      ap_rputs("    <tr class=\"rows\">\n"
               "     <td colspan=\"9\"><i>uses base server settings</i></td>\n    </tr>\n", r);
    } else {
      if(!s->is_virtual && sconf->has_qos_cc) {
        qos_user_t *u = qos_get_user_conf(sconf->act->ppool);
        int num = 0;
        int max = 0;
        int hc = -1;
        apr_global_mutex_lock(u->qos_cc->lock);           /* @CRT16 */
        hc = u->qos_cc->connections;
        num = u->qos_cc->num;
        max = u->qos_cc->max;
        apr_global_mutex_unlock(u->qos_cc->lock);         /* @CRT16 */
        ap_rputs("<tr class=\"rowt\">"
                 "<td colspan=\"6\">client control</td>"
                 "<td >max</td>"
                 "<td >limit&nbsp;</td>"
                 "<td >current&nbsp;</td>", r);
        ap_rputs("</tr>\n", r);
        ap_rprintf(r, "<tr class=\"rows\">");
        ap_rprintf(r, "<td colspan=\"6\"><div title=\"QS_ClientEntries\">clients in memory</div></td>");
        ap_rprintf(r, "<td >%d</td>", max);
        ap_rprintf(r, "<td >-</td>");
        ap_rprintf(r, "<td >%d</td>", num);
        ap_rputs("</tr>\n", r);
        if(sconf->qos_cc_prefer) {
          ap_rprintf(r, "<tr class=\"rows\">");
          ap_rprintf(r, "<td colspan=\"6\"><div title=\"QS_ClientPrefer\">connections</div></td>");
          ap_rprintf(r, "<td >%d</td>", sconf->qos_cc_prefer);
          ap_rprintf(r, "<td >%d</td>", sconf->qos_cc_prefer_limit);
          ap_rprintf(r, "<td >%d</td>", hc);
          ap_rputs("</tr>\n", r);
        }
        /*
        if(sconf->qos_cc_block) {
          ap_rprintf(r, "<tr class=\"rows\">");
          ap_rprintf(r, "<td colspan=\"6\">block event</td>");
          ap_rprintf(r, "<td >%d</td>", sconf->qos_cc_block);
          ap_rprintf(r, "<td >&nbsp</td>");
          ap_rprintf(r, "<td >%d</td>", blocked);
          ap_rputs("</tr>\n", r);
        }
        */
      }
      /* request level */
      e = sconf->act->entry;
      if(e) {
        ap_rputs("<tr class=\"rowt\">"
                 "<td colspan=\"1\">rule</td>"
                 "<td colspan=\"2\">"
                 "<div title=\"QS_LocRequestLimitMatch|QS_LocRequestLimit"
                 "|QS_CondLocRequestLimitMatch|QS_EventRequestLimit\">"
                 "concurrent requests</div></td>"
                 "<td colspan=\"3\">"
                 "<div title=\"QS_LocRequestPerSecLimitMatch|"
                 "QS_LocRequestPerSecLimit|QS_EventPerSecLimit\">"
                 "requests/second</div></td>"
                 "<td colspan=\"3\">"
                 "<div title=\"QS_LocKBytesPerSecLimitMatch|QS_LocKBytesPerSecLimit\">"
                 "kbytes/second</div></td>", r);
        ap_rputs("</tr>\n", r);
        ap_rputs("<tr class=\"rowt\">"
                 "<td >&nbsp;</td>"
                 "<td >limit</td>"
                 "<td >current</td>"
                   "<td >wait rate</td>"
                 "<td >limit</td>"
                 "<td >current</td>"
                 "<td >wait rate</td>"
                 "<td >limit</td>"
                 "<td >current</td>", r);
          ap_rputs("</tr>\n", r);
      }
      while(e) {
        char *red = "style=\"background-color: rgb(240,153,155);\"";
        ap_rputs("<tr class=\"rows\">", r);
        ap_rprintf(r, "<!--%d--><td>%s%s</a></td>", i,
                   ap_escape_html(r->pool, qos_crline(r, e->url)),
                   e->condition == NULL ? "" : " <small>(conditional)</small>");
        if((e->limit == 0) || (e->limit == -1)) {
          ap_rprintf(r, "<td>-</td>");
          ap_rprintf(r, "<td>-</td>");
        } else {
          ap_rprintf(r, "<td>%d</td>", e->limit);
          ap_rprintf(r, "<td %s>%d</td>",
                     ((e->counter * 100) / e->limit) > 90 ? red : "",
                     e->counter);
        }
        if(e->req_per_sec_limit == 0) {
          ap_rprintf(r, "<td>-</td>");
          ap_rprintf(r, "<td>-</td>");
          ap_rprintf(r, "<td>-</td>");
          } else {
          ap_rprintf(r, "<td %s>%d&nbsp;ms</td>",
                     e->req_per_sec_block_rate ? red : "",
                     e->req_per_sec_block_rate);
          ap_rprintf(r, "<td>%ld</td>", e->req_per_sec_limit);
          ap_rprintf(r, "<td %s>%ld</td>",
                     ((e->req_per_sec * 100) / e->req_per_sec_limit) > 90 ? red : "",
                     now > (e->interval + (QS_BW_SAMPLING_RATE*3)) ? 0 : e->req_per_sec);
        }
        if(e->kbytes_per_sec_limit == 0) {
            ap_rprintf(r, "<td>-</td>");
            ap_rprintf(r, "<td>-</td>");
            ap_rprintf(r, "<td>-</td>");
        } else {
          ap_rprintf(r, "<td %s>%d&nbsp;ms</td>",
                     e->kbytes_per_sec_block_rate ? red : "",
                     e->kbytes_per_sec_block_rate);
          ap_rprintf(r, "<td>%ld</td>", e->kbytes_per_sec_limit);
          ap_rprintf(r, "<td %s>%ld</td>",
                     ((e->kbytes_per_sec * 100) / e->kbytes_per_sec_limit) > 90 ? red : "",
                     now > (e->interval + (QS_BW_SAMPLING_RATE*10)) ? 0 : e->kbytes_per_sec);
        }
        ap_rputs("</tr>\n", r);
        e = e->next;
      }
      /* event limit */
      if(sconf->event_limit_a->nelts > 0) {
        char *red = "style=\"background-color: rgb(240,153,155);\"";
        int ie = 0;
        qos_event_limit_entry_t *event_limit = sconf->act->event_entry;
        ap_rputs("<tr class=\"rowt\">"
                 "<td colspan=\"5\"><div title=\"QS_EventLimitCount\">events</div></td>"
                 "<td colspan=\"1\">limit</td>"
                 "<td colspan=\"1\">seconds</td>"
                 "<td colspan=\"2\">current</td>", r);
        ap_rputs("</tr>\n", r);
        for(ie = 0; ie < sconf->event_limit_a->nelts; ie++) {
          int edelta = event_limit->limit_time + event_limit->seconds - now;
          int elimit = event_limit->limit;
          if(event_limit->limit_time + event_limit->seconds <= now) {
            elimit = 0;
            edelta = 0;
          }
          if(event_limit->action == QS_EVENT_ACTION_DENY) {
            ap_rprintf(r, "<tr class=\"rows\">"
                       "<td colspan=\"5\">%s</td>"
                       "<td>%d</td><td>%ds</td><td %s>%d</td><td>%ds</td>"
                       "</tr>\n",
                       event_limit->env_var,
                       event_limit->max,
                       event_limit->seconds,
                       elimit >= event_limit->max ? red : "",
                       elimit,
                       edelta);
          }
          event_limit++;
        }
      }
      /* connection level */
      if(sconf) {
        char *red = "style=\"background-color: rgb(240,153,155);\"";
        int c = qos_count_free_ip(sconf);
        ap_rputs("<tr class=\"rowt\">"
                 "<td colspan=\"9\">connections</td>", r);
        ap_rputs("</tr>\n", r);
        ap_rprintf(r, "<tr class=\"rows\">"
                   "<!--%d--><td colspan=\"6\">"
                   "<div title=\"QS_SrvMaxConnPerIP\">free ip entries</div></td>"
                   "<td colspan=\"3\">%d</td></tr>\n", i, c);
        ap_rprintf(r, "<tr class=\"rows\">"
                   "<!--%d--><td colspan=\"6\">"
                   "<div title=\"QS_SrvMaxConn|QS_SrvMaxConnClose\">current connections</div></td>"
                   "<td %s colspan=\"3\">%d</td></tr>\n", i,
                   ( ( (sconf->max_conn_close != -1) &&
                       (sconf->act->conn->connections >= sconf->max_conn_close) )  ||
                     ( (sconf->max_conn != -1) &&
                       (sconf->act->conn->connections >= sconf->max_conn) ) ) ? red : "",
                   sconf->act->conn->connections);

        if(!s->is_virtual) {
          ap_rprintf(r, "<tr class=\"rows\">"
                     "<!--base--><td colspan=\"6\">"
                     "<div>total connections</div></td>"
                     "<td colspan=\"3\">%d</td></tr>\n",
                     qos_server_connections(sconf));
        }

        if(option && ap_strstr_c(option, "ip")) {
          apr_table_t *entries = apr_table_make(r->pool, 100);
          int j;
          apr_table_entry_t *entry;
          ap_rputs("<tr class=\"rowt\">"
                   "<td colspan=\"6\">"
                   "<div title=\"QS_SrvMaxConnPerIP\">client ip connections</div></td>"
                   "<td colspan=\"3\">current&nbsp;</td>", r);
          ap_rputs("</tr>\n", r);
          qos_collect_ip(r, sconf, entries, sconf->max_conn_per_ip, 1);
          entry = (apr_table_entry_t *)apr_table_elts(entries)->elts;
          for(j = 0; j < apr_table_elts(entries)->nelts; j++) {
            ap_rputs("<tr class=\"rows\">", r);
            ap_rputs("<td colspan=\"6\">", r);
            ap_rprintf(r, "%s</td></tr>\n", entry[j].key);
          }
        }

        ap_rputs("<tr class=\"rowt\">"
                 "<td colspan=\"9\">connection settings</td>", r);
        ap_rputs("</tr>\n", r);
        ap_rprintf(r, "<tr class=\"rows\">"
                   "<td colspan=\"6\">"
                   "<div title=\"QS_SrvMaxConn\">max connections</div></td>");
        if(sconf->max_conn == -1) {
          ap_rprintf(r, "<td colspan=\"3\">-</td></tr>\n");
        } else {
          ap_rprintf(r, "<td colspan=\"3\">%d</td></tr>\n", sconf->max_conn);
        }
        ap_rprintf(r, "<tr class=\"rows\">"
                   "<td colspan=\"6\">"
                   "<div title=\"QS_SrvMaxConnClose\">max connections with keep-alive</div></td>");
        if(sconf->max_conn_close == -1) {
          ap_rprintf(r, "<td colspan=\"3\">-</td></tr>\n");
        } else {
          ap_rprintf(r, "<td colspan=\"3\">%d</td></tr>\n", sconf->max_conn_close);
        }
        ap_rprintf(r, "<tr class=\"rows\">"
                   "<td colspan=\"6\">"
                   "<div title=\"QS_SrvMaxConnPerIP\">max connections per client ip</div></td>");
        if(sconf->max_conn_per_ip == -1) {
          ap_rprintf(r, "<td colspan=\"3\">-</td></tr>\n");
        } else {
          ap_rprintf(r, "<td colspan=\"3\">%d</td></tr>\n", sconf->max_conn_per_ip);
        }
        ap_rprintf(r, "<tr class=\"rows\">"
                   "<td colspan=\"6\">"
                   "<div title=\"QS_SrvMinDataRate|QS_SrvRequestRate\">"
                   "min. data rate (bytes/sec) (min/max/current)</div></td>");
        if(sconf->req_rate == -1) {
          ap_rprintf(r, "<td colspan=\"3\">-</td></tr>\n");
        } else {
          int connections;
          int rt = qos_req_rate_calc(sconf, &connections);
          ap_rprintf(r, "<td colspan=\"3\">%d/%d/%d</td></tr>\n",
                     sconf->req_rate,
                     sconf->min_rate_max == -1 ? sconf->req_rate : sconf->min_rate_max,
                     rt);
        }
      }
    }
    ap_rprintf(r, "<tr class=\"row\">"
               "<td style=\"width:28%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "<td style=\"width:9%%\"></td>"
               "</tr>");
    i++;
    s = s->next;
    ap_rputs("</tbody></table>\n", r);
  }
  ap_rputs(" </td></tr>\n", r);
  ap_rputs("</tbody></table>\n", r);
  return OK;
}

/**
 * Disables request rate enforcements for all child processes (at start/fork) if
 * init has failed.
 *
 * @param bs Base server_rec to iterate through all client configurations
 * @param msg Error message to log (reason what has failed @init).
 */
static void qos_disable_req_rate(server_rec *bs, const char *msg) {
  server_rec *s = bs->next;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(bs->module_config, &qos_module);
  ap_log_error(APLOG_MARK, APLOG_ERR, 0, bs,
               QOS_LOG_PFX(008)"could not create supervisor thread (%s),"
               " disable request rate enforcement", msg);
  sconf->req_rate = -1;
  while(s) {
    sconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
    sconf->req_rate = -1;
    s = s->next;
  }
}

/** 
 * stores the IP of the connection into the array and
 * increments the array pointer (for QS_Block for connection errors)
 */
static apr_uint64_t *qos_inc_block(conn_rec *c, qos_srv_config *sconf,
                                   qs_conn_ctx *cconf, apr_uint64_t *ip) {
  if(sconf->qos_cc_block &&
     apr_table_get(sconf->setenvstatus_t, QS_CLOSE) &&
     !apr_table_get(c->notes, QS_BLOCK_SEEN)) {
    apr_table_set(c->notes, QS_BLOCK_SEEN, "");
    *ip = cconf->ip6[0];
    ip++;
    *ip = cconf->ip6[1];
    ip++;
  }
  return ip;
}

#if APR_HAS_THREADS
/**
 * Supervisior thread monitoring the bandith of registered connections.
 *
 * Connections are closed by a apr_socket_close/shutdown which must be
 * detected by the thread processing the connection in order to 
 * de-register the connection and to terminate the pending request in
 * order to free resources (thread).
 *
 * @param thread
 * @param selfv Base server_rec
 */
static void *qos_req_rate_thread(apr_thread_t *thread, void *selfv) {
  server_rec *bs = selfv;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(bs->module_config, &qos_module);
  // list of ip addr. for whose we shall inc. block count
  apr_uint64_t *ips = calloc(1, sconf->max_clients * sizeof(apr_uint64_t) * 2);
  while(!sconf->inctx_t->exit) {
    apr_uint64_t *ip = ips;
    int currentcon = 0;
    int req_rate = qos_req_rate_calc(sconf, &currentcon);
    apr_time_t now = apr_time_sec(apr_time_now());
    apr_time_t interval = now - sconf->qs_req_rate_tm;
    int i;
    apr_table_entry_t *entry;
    sleep(1);
    if(sconf->inctx_t->exit) {
      break;
    }
    apr_thread_mutex_lock(sconf->inctx_t->lock);   /* @CRT21 */
    entry = (apr_table_entry_t *)apr_table_elts(sconf->inctx_t->table)->elts;
    for(i = 0; i < apr_table_elts(sconf->inctx_t->table)->nelts; i++) {
      qos_ifctx_t *inctx = (qos_ifctx_t *)entry[i].val;
      if(inctx->status == QS_CONN_STATE_KEEP) {
        /* enforce keep alive */
        apr_interval_time_t current_timeout = 0;
        apr_socket_timeout_get(inctx->client_socket, &current_timeout);
        /* add 5sec tolerance to receive the request line or let Apache close the connection */
        if(now > (apr_time_sec(current_timeout) + 5 + inctx->time)) {
          qs_conn_ctx *cconf = qos_get_cconf(inctx->c);
          int level = APLOG_ERR;
          /* disabled by vip priv */
          if(cconf && cconf->is_vip) {
            level = APLOG_DEBUG;
            cconf->has_lowrate = 1; /* mark connection low rate */
          }
          /* disabled for this request/connection */
          if(inctx->disabled) {
            level = APLOG_DEBUG;
            cconf->has_lowrate = 1; /* mark connection low rate */
          }
          /* enable only if min. num of connection reached */
          if(currentcon <= sconf->req_rate_start) {
            level = APLOG_DEBUG;
            cconf->has_lowrate = 1; /* mark connection low rate */
          }
          ip = qos_inc_block(inctx->c, sconf, cconf, ip);
          ap_log_error(APLOG_MARK, APLOG_NOERRNO|level, 0, inctx->c->base_server,
                       QOS_LOG_PFX(034)"%s, QS_SrvMinDataRate rule (enforce keep-alive),"
                       " c=%s",
                       level == APLOG_DEBUG ? 
                       "log only (allowed)" 
                       : "access denied",
                       QS_CONN_REMOTEIP(inctx->c) == NULL ? "-" : QS_CONN_REMOTEIP(inctx->c));
          if(level == APLOG_DEBUG) {
            inctx->time = now;
            inctx->nbytes = 0;
          } else {
            if(!sconf->log_only) {
              apr_socket_shutdown(inctx->client_socket, APR_SHUTDOWN_READ);
            }
          }
          /* mark slow clients (QS_ClientPrefer) even they are VIP */
          inctx->shutdown = 1;
        }
      } else {
        if(interval > inctx->time) {
          int rate = inctx->nbytes / sconf->qs_req_rate_tm;
          if(rate < req_rate) {
            if(inctx->client_socket) {
              qs_conn_ctx *cconf = qos_get_cconf(inctx->c);
              int level = APLOG_ERR;
              /* disabled by vip priv */
              if(cconf && cconf->is_vip) {
                level = APLOG_DEBUG;
                cconf->has_lowrate = 1; /* mark connection low rate */
              }
              /* disabled for this request/connection */
              if(inctx->disabled) {
                level = APLOG_DEBUG;
                cconf->has_lowrate = 1; /* mark connection low rate */
              }
              /* enable only if min. num of connection reached */
              if(currentcon <= sconf->req_rate_start) {
                level = APLOG_DEBUG;
                cconf->has_lowrate = 1; /* mark connection low rate */
              }
              ip = qos_inc_block(inctx->c, sconf, cconf, ip);
              ap_log_error(APLOG_MARK, APLOG_NOERRNO|level, 0, inctx->c->base_server,
                           QOS_LOG_PFX(034)"%s, QS_SrvMinDataRate rule (%s): min=%d,"
                           " this connection=%d,"
                           " c=%s",
                           level == APLOG_DEBUG ? 
                           "log only (allowed)" 
                           : "access denied",
                           inctx->status == QS_CONN_STATE_RESPONSE ? "out" : "in",
                           req_rate,
                           rate,
                           QS_CONN_REMOTEIP(inctx->c) == NULL ? "-" : QS_CONN_REMOTEIP(inctx->c));
              if(level == APLOG_DEBUG) {
                inctx->time = interval + sconf->qs_req_rate_tm;
                inctx->nbytes = 0;
              } else {
                if(!sconf->log_only) {
                  if(inctx->status == QS_CONN_STATE_RESPONSE) {
                    apr_socket_shutdown(inctx->client_socket, APR_SHUTDOWN_WRITE);
                    /* close out socket (the hard way) */
                    apr_socket_close(inctx->client_socket);
                  } else {
                    apr_socket_shutdown(inctx->client_socket, APR_SHUTDOWN_READ);
                  }
                }
              }
              /* mark slow clients (QS_ClientPrefer) even they are VIP */
              inctx->shutdown = 1;
            }
          } else {
            inctx->time = interval + sconf->qs_req_rate_tm;
            inctx->nbytes = 0;
          }
        }
      }
    }
    apr_thread_mutex_unlock(sconf->inctx_t->lock); /* @CRT21 */
    /* QS_Block for connection errors */
    while(ip != ips) {
      qos_user_t *u = qos_get_user_conf(sconf->act->ppool);    
      qos_s_entry_t **e = NULL;
      qos_s_entry_t searchE;
      apr_global_mutex_lock(u->qos_cc->lock);          /* @CRT38 */
      ip--;
      searchE.ip6[1] = *ip;
      ip--;
      searchE.ip6[0] = *ip;
      e = qos_cc_get0(u->qos_cc, &searchE, 0);
      if(!e) {
        e = qos_cc_set(u->qos_cc, &searchE, time(NULL));
      }
      /* increment block event */
      (*e)->block++;
      if((*e)->block == 1) {
        /* ... and start timer */
        (*e)->block_time = apr_time_sec(apr_time_now());
      }
      apr_global_mutex_unlock(u->qos_cc->lock);        /* @CRT38 */
    }
  }
  // apr_thread_mutex_lock(sconf->inctx_t->lock);
  // apr_thread_mutex_unlock(sconf->inctx_t->lock);
  // called via apr_pool_cleanup_register():
  // apr_thread_mutex_destroy(sconf->inctx_t->lock);
  free(ips);
  if(m_worker_mpm) {
    apr_thread_exit(thread, APR_SUCCESS);
  }
  return NULL;
}

/**
 * Terminates the connection supervisor thread.
 * (works for mpm_worker only)
 *
 * @param selfv The base server_rec
 * @return APR_SUCCESS
 */
static apr_status_t qos_cleanup_req_rate_thread(void *selfv) {
  server_rec *bs = selfv;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(bs->module_config, &qos_module);
  sconf->inctx_t->exit = 1;
  /* may long up to one second */
  if(m_worker_mpm) {
    apr_status_t status;
    apr_thread_join(&status, sconf->inctx_t->thread);
  }
  return APR_SUCCESS;
}
#endif

/**
 * Writes the query/body to the env variables which may be used
 * for the qsfilter* audit log.
 *
 * @param r
 * @param dconf
 */
static void qos_audit(request_rec *r, qos_dir_config *dconf) {
  const char *q = NULL;
  const char *u = apr_table_get(r->notes, QS_PARP_PATH);
  if(dconf->bodyfilter_p == 1 || dconf->bodyfilter_d == 1) {
    q = apr_table_get(r->notes, QS_PARP_QUERY);
  }
  if(u == NULL) {
    if(r->parsed_uri.path) {
      u = apr_pstrdup(r->pool, r->parsed_uri.path);
    } else {
      u = apr_pstrdup(r->pool, "");
    }
    apr_table_setn(r->notes, apr_pstrdup(r->pool, QS_PARP_PATH), u);
  }
  if(q == NULL) {
    if(r->parsed_uri.query) {
      q = apr_pstrcat(r->pool, "?", r->parsed_uri.query, NULL);
    } else {
      q = apr_pstrdup(r->pool, "");
    }
    apr_table_setn(r->notes, apr_pstrdup(r->pool, QS_PARP_QUERY), q);
  }
  apr_table_setn(r->notes, apr_pstrdup(r->pool, QS_PARP_LOC), dconf->path);
  if(r->next) {
    apr_table_setn(r->next->notes, apr_pstrdup(r->pool, QS_PARP_PATH), u);
    apr_table_setn(r->next->notes, apr_pstrdup(r->pool, QS_PARP_QUERY), q);
    apr_table_setn(r->next->notes, apr_pstrdup(r->pool, QS_PARP_LOC), dconf->path);
  }
}

/**
 * Adds the configured (QS_Delay env var) delay to the request
 *
 * @param r
 * @param sconf Do set log-only mode
 */
static void qos_delay(request_rec *r, qos_srv_config *sconf) {
  const char *d = apr_table_get(r->subprocess_env, "QS_Delay");
  if(d) {
    apr_off_t s;
#ifdef ap_http_scheme
    /* Apache 2.2 */
    char *errp = NULL;
    if((APR_SUCCESS == apr_strtoff(&s, d, &errp, 10)) && s > 0)
#else
    if((s = apr_atoi64(d)) > 0)
#endif
      {
        if(!sconf->log_only) {
          qs_req_ctx *rctx = qos_rctx_config_get(r);
          int sec = s / 1000;
          int nsec = s % 1000;
          struct timespec delay;
          rctx->evmsg = apr_pstrcat(r->pool, "L;", rctx->evmsg, NULL);
          delay.tv_sec  = sec;
          delay.tv_nsec = nsec * 1000000;
          nanosleep(&delay,NULL);     
        } 
    }
  }
}

/** 
 * Enables mod_deflate
 * QS_DeflateReqBody (if parp has been enabled)
 *
 * @param r
 */
static void qos_deflate(request_rec *r) {
  if(apr_table_get(r->subprocess_env, "QS_DeflateReqBody") && 
     apr_table_get(r->subprocess_env, "parp")) {
    ap_add_input_filter("DEFLATE", NULL, r, r->connection);
  }
}

/**
 * Adjusts the content-length header
 *
 * @param r
 */
static void qos_deflate_contentlength(request_rec *r) {
  if(apr_table_get(r->subprocess_env, "QS_DeflateReqBody") && 
     apr_table_get(r->subprocess_env, "parp")) {
    const char *PARPContentLength = apr_table_get(r->subprocess_env, "PARPContentLength");
    const char *contentLength = apr_table_get(r->headers_in, "Content-Length");
    if(PARPContentLength && contentLength) {
      apr_table_set(r->headers_in, "Content-Length", PARPContentLength);
    }
  }
}

/**
 * Returns the configured server name supporting ServerAlias directive.
 *
 * @param r
 * @param server_hostname
 * @return hostname
 */
static char *qos_server_alias(request_rec *r, const char *server_hostname) {
  char *server = apr_pstrdup(r->pool, r->server->server_hostname);
  char *p;
  if(server_hostname) {
    if(strcasecmp(server_hostname, r->server->server_hostname) == 0) {
      /* match ServerName */
      server = apr_pstrdup(r->pool, r->server->server_hostname);
    } else if(r->server->names) {
      int i;
      apr_array_header_t *names = r->server->names;
      char **name = (char **)names->elts;
      for(i = 0; i < names->nelts; ++i) {
        if(!name[i]) continue;
        if(strcasecmp(server_hostname, name[i]) == 0) {
          /* match ServerAlias */
          server = apr_pstrdup(r->pool, name[i]);
        }
      }
    } else if(r->server->wild_names) {
      int i;
      apr_array_header_t *names = r->server->wild_names;
      char **name = (char **)names->elts;
      for(i = 0; i < names->nelts; ++i) {
        if(!name[i]) continue;
        if(!ap_strcasecmp_match(server_hostname, name[i]))
          /* match ServerAlias using wildcards */
          server = apr_pstrdup(r->pool, server_hostname);
      }
    }
  }
  p = strchr(server, ':');
  if(p) {
    p[0] = '\0';
  }
  return server;
}

/** 
 * Returns the url to this server, e.g. https://server1 or http://server1:8080
 * used for redirects.
 *
 * @param r
 * @return schema/hostname
 */
static char *qos_this_host(request_rec *r) {
  const char *orig_hostport= apr_table_get(r->headers_in, "Host");
  char *hostport;
  int port = 0;
  int ssl = 0;
  int default_port;
  const char *server_hostname = r->server->server_hostname;
  if(qos_is_https) {
    ssl = qos_is_https(r->connection);
  }
  if(orig_hostport) {
    char *p;
    hostport = apr_pstrdup(r->pool, orig_hostport);
    if((p = ap_strchr(hostport, ':')) != NULL) {
      server_hostname = qos_server_alias(r, hostport);
      p[0] = '\0';
      p++;
      port = atoi(p);
    } else {
      server_hostname = qos_server_alias(r, hostport);
    }
  }
  if(port == 0) {
    // pref. vhost
    port = r->server->addrs->host_port;
  }
  if(port == 0) {
    // main srv
    port = r->server->port;
  }
  default_port = ssl ? 443 : 80;
  if(port == default_port) {
    return apr_psprintf(r->pool, "%s%s",
                        ssl ? "https://" : "http://",
                        server_hostname);
  }
  return apr_psprintf(r->pool, "%s%s:%d",
                      ssl ? "https://" : "http://",
                      server_hostname,
                      port);
}

/**
 * Verifies Apache and MPM version and writes error message (notice)
 * for incompatibel version/type.
 *
 * Apache 2.2 MPM worker binaries is the only configuration which
 * has been tested (as mentioned in the documentation, see index.html).
 *
 * - old MPM Apache prefork versions do not unload the DSO properly
 *   or child exit may cause a segfault (pool cleanup)
 * - Apache 2.4 is experimental only and some directives are not available
 *   (see CHANGES.txt for more informaton)
 * - Apache 2.0 does not support all directives (e.g. QS_ClientPrefer) and
 *   we do no longer test against this version (the module does probably
 *   not even compile with version 2.0)
 *
 */
static void qos_version_check(server_rec *bs) {
  ap_version_t version;

  if(strcasecmp(ap_show_mpm(), "worker") != 0) {
    m_worker_mpm = 0; // disable child cleanup
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, bs, 
                 QOS_LOG_PFX(009)"loaded MPM is '%s'"
                 " but mod_qos should be used with MPM 'Worker' only.",
                 ap_show_mpm());
  }

  ap_get_server_revision(&version);
  if(version.major != 2 || version.minor != 2) {
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, bs, 
                 QOS_LOG_PFX(009)"server version is %d.%d"
                 " but mod_qos should be used with Apache 2.2 only.",
                 version.major, version.minor);
  }
}

/**
 * enforces the QS_RedirectIf varibale
 * @param r
 * @param sconf
 * @param rules Rules array
 * @retrun HTTP_MOVED_TEMPORARILY or DECLINED
 */
static int qos_redirectif(request_rec *r, qos_srv_config *sconf, apr_array_header_t *rules) {
#ifdef AP_REGEX_H
  ap_regmatch_t regm[AP_MAX_REG_MATCH];
#else
  regmatch_t regm[AP_MAX_REG_MATCH];
#endif
  int i;
  qos_redirectif_entry_t *entries = (qos_redirectif_entry_t *)rules->elts;
  for(i = 0; i < rules->nelts; ++i) {
    qos_redirectif_entry_t *entry = &entries[i];
    const char *val = apr_table_get(r->subprocess_env, entry->name);
    if(val) {
      if(ap_regexec(entry->preg, val, AP_MAX_REG_MATCH, regm, 0) == 0) {
        int severity = sconf->log_only ? APLOG_WARNING : APLOG_ERR;
        char *replaced = ap_pregsub(r->pool, entry->url, val, AP_MAX_REG_MATCH, regm);
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|severity, 0, r,
                      QOS_LOG_PFX(049)"redirect to %s,"
                      " var=%s,"
                      " action=%s, c=%s, id=%s",
                      replaced,
                      entry->name,
                      sconf->log_only ? "log only" : "redirect",
                      QS_CONN_REMOTEIP(r->connection) == NULL ? "-" :
                      QS_CONN_REMOTEIP(r->connection),
                      qos_unique_id(r, "049"));
        if(!sconf->log_only) {
          apr_table_set(r->headers_out, "Location", replaced);
          return HTTP_MOVED_TEMPORARILY;
        }
      }
    }
  }
  return DECLINED;
}

static void qos_init_unique_id(apr_pool_t *p, server_rec *bs) {
  char str[APRMAXHOSTLEN + 1];
  apr_sockaddr_t *sockaddr;
  str[APRMAXHOSTLEN] = '\0';
  m_unique_id.in_addr = 0;
  if(apr_gethostname(str, sizeof(str) - 1, p) == APR_SUCCESS) {
    if(apr_sockaddr_info_get(&sockaddr, str, AF_INET, 0, 0, p) == APR_SUCCESS) {
      m_unique_id.in_addr = sockaddr->sa.sin.sin_addr.s_addr;
    }
  }
  m_unique_id.pid = getpid();
  if(m_unique_id.in_addr == 0) {
    m_unique_id.in_addr = m_unique_id.pid;
  }
  m_unique_id.unique_id_counter = time(NULL);
}

/************************************************************************
 * handlers
 ***********************************************************************/

/**
 * Destructor for connections which does not have been established
 * successfully.
 *
 * Increments block counter.
 *
 * @param p Connection base context
 * @return APR_SUCCESS
 */
static apr_status_t qos_base_cleanup_conn(void *p) {
  qs_conn_base_ctx *base = p;
  if(base->sconf->has_qos_cc || base->sconf->qos_cc_prefer) {
    int norequests = 0;
    if(base->requests == 0 &&
       apr_table_get(base->sconf->setenvstatus_t, QS_EMPTY_CON) && 
       !apr_table_get(base->c->notes, QS_BLOCK_SEEN)) {
      norequests = 1;
      apr_table_set(base->c->notes, QS_BLOCK_SEEN, "");
    }
    if(norequests) {
      qos_user_t *u = qos_get_user_conf(base->sconf->act->ppool);
      qos_s_entry_t **e = NULL;
      qos_s_entry_t searchE;
      qos_ip_str2long(QS_CONN_REMOTEIP(base->c), &searchE.ip6); // no ip simulation here
      apr_global_mutex_lock(u->qos_cc->lock);           /* @CRT40 */
      e = qos_cc_get0(u->qos_cc, &searchE, 0);
      if(!e) {
        e = qos_cc_set(u->qos_cc, &searchE, time(NULL));
      }
      /* increment block event */
      (*e)->block++;
      if((*e)->block == 1) {
        /* ... and start timer */
        (*e)->block_time = apr_time_sec(apr_time_now());
      }
      apr_global_mutex_unlock(u->qos_cc->lock);         /* @CRT40 */
      if(QS_ISDEBUG(base->c->base_server)) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, base->c->base_server, 
                     QOS_LOGD_PFX"QS_ClientEventBlockCount rule: "
                     QS_EMPTY_CON " event detected "
                     "c=%s",
                     QS_CONN_REMOTEIP(base->c) == NULL ? "-" : QS_CONN_REMOTEIP(base->c));
      }
    }
  }
  return APR_SUCCESS;
}

/**
 * Connection destructor.
 *
 * Updates per IP events and connection counter.
 *
 * @param p Connection context
 * @return APR_SUCCESS
 */
static apr_status_t qos_cleanup_conn(void *p) {
  qs_conn_ctx *cconf = p;
  if(cconf->sconf->has_qos_cc || cconf->sconf->qos_cc_prefer) {
    qos_user_t *u = qos_get_user_conf(cconf->sconf->act->ppool);
    qos_s_entry_t **e = NULL;
    qos_s_entry_t searchE;
    searchE.ip6[0] = cconf->ip6[0];
    searchE.ip6[1] = cconf->ip6[1];
    apr_global_mutex_lock(u->qos_cc->lock);           /* @CRT15 */
    if(m_generation == u->generation && u->qos_cc->connections > 0) {
      u->qos_cc->connections--;
    }
    e = qos_cc_get0(u->qos_cc, &searchE, 0);
    if(!e) {
      e = qos_cc_set(u->qos_cc, &searchE, time(NULL));
    }
    (*e)->events++; // update event activity even there is no valid request (logger)
    if(cconf->is_vip_by_header) {
      (*e)->vip = 1;
    }
    if(cconf->has_lowrate) {
      (*e)->lowrate = time(NULL);
    }
    apr_global_mutex_unlock(u->qos_cc->lock);         /* @CRT15 */
  }
  /* QS_SrvMaxConn or Geo */
  if(qos_count_connections(cconf->sconf)) {
    apr_global_mutex_lock(cconf->sconf->act->lock);   /* @CRT3 */
    if(cconf->sconf->act->conn && cconf->sconf->act->conn->connections > 0) {
      cconf->sconf->act->conn->connections--;
    }
    apr_global_mutex_unlock(cconf->sconf->act->lock); /* @CRT3 */
  }
  if(cconf->sconf->max_conn_per_ip != -1) {
    qos_dec_ip(cconf);
  }
  return APR_SUCCESS;
}

/**
 * Connection constructor. Rules that are applied to established connections.
 *
 * @param c
 * @return
 */
static int qos_process_connection(conn_rec *c) {
  qs_conn_ctx *cconf = qos_get_cconf(c);
  int vip = 0;
  if(cconf == NULL) {
    int client_control = DECLINED;
    int connections = 0;
    int all_connections = 0;
    int current = 0;
    qs_ip_entry_t *e = NULL;
    char *msg = NULL;
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(c->base_server->module_config,
                                                                  &qos_module);
    qos_user_t *u = qos_get_user_conf(sconf->act->ppool);
    cconf = qos_create_cconf(c, sconf);

    /* control timeout */
    qos_timeout_pc(c, sconf);

    /* packet rate */
    if(sconf->qos_cc_prefer_limit) {
      qos_pktrate_pc(c, sconf);
    }

    /* evaluates client ip */
    if((sconf->max_conn_per_ip != -1) ||
       sconf->has_qos_cc) {
      qos_ip_str2long(QS_CONN_REMOTEIP(c), &cconf->ip6);
#ifdef QS_INTERNAL_TEST
      /* use one of the predefined ip addresses */
      if(cconf->sconf->enable_testip) {
        char *testid = apr_psprintf(c->pool, "%d", rand()%(QS_SIM_IP_LEN-1));
        const char *testip = apr_table_get(cconf->sconf->testip, testid);
        qos_ip_str2long(testip, &cconf->ip6);
      }
#endif
    }

    /* ------------------------------------------------------------
     * update data
     */
    /* client control */
    client_control = qos_cc_pc_filter(c, cconf, u, &msg);
    /* QS_SrvMaxConn: vhost connections or Geo */
    if(qos_count_connections(sconf)) {
      apr_global_mutex_lock(cconf->sconf->act->lock);    /* @CRT4 */
      if(cconf->sconf->act->conn) {
        cconf->sconf->act->conn->connections++;
        all_connections = qos_server_connections(sconf);
        connections = cconf->sconf->act->conn->connections; /* @CRT4 */
        apr_table_set(c->notes, "QS_SrvConn", apr_psprintf(c->pool, "%d", connections));
        apr_table_set(c->notes, "QS_AllConn", apr_psprintf(c->pool, "%d", all_connections));
      }
      apr_global_mutex_unlock(cconf->sconf->act->lock);
    }

    /* single source ip */
    if(sconf->max_conn_per_ip != -1) {
      current = qos_inc_ip(sconf, cconf, &e);
      apr_table_set(c->notes, "QS_IPConn", apr_psprintf(c->pool, "%d", current));
    }
    /* Check for vip (by ip) */
    if(apr_table_elts(sconf->exclude_ip)->nelts > 0) {
      int i;
      apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->exclude_ip)->elts;
      for(i = 0; i < apr_table_elts(sconf->exclude_ip)->nelts; i++) {
        if(entry[i].val[0] == 'r') {
          if(strncmp(entry[i].key, QS_CONN_REMOTEIP(cconf->c), strlen(entry[i].key)) == 0) {
            vip = 1;
            /* propagate vip to connection */
            cconf->is_vip = vip;
            if(!cconf->evmsg || !strstr(cconf->evmsg, "S;")) {
              cconf->evmsg = apr_pstrcat(c->pool, "S;", cconf->evmsg, NULL);
            }
          }
        } else {
          if(strcmp(entry[i].key, QS_CONN_REMOTEIP(cconf->c)) == 0) {
            vip = 1;
            /* propagate vip to connection */
            cconf->is_vip = vip;
            if(!cconf->evmsg || !strstr(cconf->evmsg, "S;")) {
              cconf->evmsg = apr_pstrcat(c->pool, "S;", cconf->evmsg, NULL);
            }
          }
        }
      }
    }

    /* ------------------------------------------------------------
     * enforce rules
     */
    /* client control */
    if((client_control != DECLINED) && !vip) {
      ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                   "%s",
                   msg == NULL ? "-" : msg);
      if(!sconf->log_only) {
        c->keepalive = AP_CONN_CLOSE;
        return qos_return_error(c);
      }
    }
    /* Geo */
    if(sconf->geodb) {
      unsigned long ip = qos_geo_str2long(c->pool, QS_CONN_REMOTEIP(c));
      qos_geo_t *pB = bsearch(&ip,
                              sconf->geodb,
                              sconf->geodb_size,
                              sizeof(qos_geo_t),
                              qos_geo_comp);
      if(pB) {
        apr_table_set(c->notes, QS_COUNTRY, pB->country);
      }
      if(sconf->geo_limit != -1) {
        if(all_connections >= sconf->geo_limit) {
          if(pB == NULL || apr_table_get(sconf->geo_priv, pB->country) == NULL) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                         QOS_LOG_PFX(101)"access denied, QS_ClientGeoCountryPriv rule: max=%d,"
                         " concurrent connections=%d,"
                         " c=%s"
                         " country=%s",
                         sconf->geo_limit,
                         all_connections,
                         QS_CONN_REMOTEIP(c),
                         pB != NULL ? pB->country : "--");
            if(!sconf->log_only) {
              c->keepalive = AP_CONN_CLOSE;
              return qos_return_error(c);
            }
          }
        }
      }
    }
    /* QS_SrvMaxConn: vhost connections */
    if((sconf->max_conn != -1) && !vip) {
      if(connections > sconf->max_conn) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                     QOS_LOG_PFX(030)"access denied, QS_SrvMaxConn rule: max=%d,"
                     " concurrent connections=%d,"
                     " c=%s",
                     sconf->max_conn, connections,
                     QS_CONN_REMOTEIP(c) == NULL ? "-" : QS_CONN_REMOTEIP(c));
        if(!sconf->log_only) {
          c->keepalive = AP_CONN_CLOSE;
          return qos_return_error(c);
        }
      }
    }
    /* single source ip */
    if((sconf->max_conn_per_ip != -1) && !vip) {
      if((current > sconf->max_conn_per_ip) &&
         (all_connections >= sconf->max_conn_per_ip_connections)) {
        e->error++;
        /* only print the first 20 messages for this client */
        if(e->error <= QS_LOG_REPEAT) {
          ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                       QOS_LOG_PFX(031)"access denied, QS_SrvMaxConnPerIP rule: max=%d,"
                       " concurrent connections=%d,"
                       " c=%s",
                       sconf->max_conn_per_ip, current,
                       QS_CONN_REMOTEIP(c) == NULL ? "-" : QS_CONN_REMOTEIP(c));
        } else {
          if((e->error % QS_LOG_REPEAT) == 0) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                         QOS_LOG_PFX(031)"access denied, QS_SrvMaxConnPerIP rule: max=%d,"
                         " concurrent connections=%d,"
                         " message repeated %d times,"
                           " c=%s",
                         sconf->max_conn_per_ip, current,
                         QS_LOG_REPEAT,
                         QS_CONN_REMOTEIP(c) == NULL ? "-" : QS_CONN_REMOTEIP(c));
          }
        }
        if(!sconf->log_only) {
          c->keepalive = AP_CONN_CLOSE;
          return qos_return_error(c);
        }
      } else {
        if(e) {
          if(e->error > QS_LOG_REPEAT) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                         QOS_LOG_PFX(031)"access denied (previously), QS_SrvMaxConnPerIP rule: max=%d,"
                         " concurrent connections=%d,"
                         " message repeated %d times,"
                         " c=%s",
                         sconf->max_conn_per_ip, current,
                         e->error % QS_LOG_REPEAT,
                         QS_CONN_REMOTEIP(c) == NULL ? "-" : QS_CONN_REMOTEIP(c));
          }
          e->error = 0;
        }
      }
    }
  }
  return DECLINED;
}

/**
 * Pre connection
 * - constructs the connection ctx (stores socket ref)
 * - enforces block counter (as early as possible)
 */
static int qos_pre_connection(conn_rec *c, void *skt) {
  int ret = DECLINED;
  qos_srv_config *sconf;
  qs_conn_base_ctx *base;
  if(c->sbh == NULL) {
    // proxy connections do NOT have any relation to the score board, don't handle them
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server, 
                 QOS_LOGD_PFX"skip processing of outgoing connection %s<->%s",
                 QS_CONN_REMOTEIP(c) ? QS_CONN_REMOTEIP(c) : "UNKNOWN", c->local_ip ? c->local_ip : "UNKNOWN");
    return ret;
  }
  sconf = (qos_srv_config*)ap_get_module_config(c->base_server->module_config, &qos_module);
  base = qos_get_conn_base_ctx(c);
  if(base == NULL) {
    base = qos_create_conn_base_ctx(c, sconf);
  }

  if(sconf && (sconf->req_rate != -1)) {
    qos_ifctx_t *inctx = qos_create_ifctx(c, sconf);
    inctx->client_socket = skt;
    ap_add_input_filter("qos-in-filter", inctx, NULL, c);
  }

  /* blocked by event (block only, no limit) - very aggressive */
  if(sconf->qos_cc_block) {
    qos_user_t *u = qos_get_user_conf(sconf->act->ppool);
    qos_s_entry_t **e = NULL;
    qos_s_entry_t searchE;
    qos_ip_str2long(QS_CONN_REMOTEIP(c), &searchE.ip6); // no ip simulation here
    apr_global_mutex_lock(u->qos_cc->lock);           /* @CRT39 */
    e = qos_cc_get0(u->qos_cc, &searchE, 0);
    if(!e) {
      e = qos_cc_set(u->qos_cc, &searchE, time(NULL));
    }
    if((*e)->block >= sconf->qos_cc_block) {
      apr_time_t now = time(NULL);
      if(((*e)->block_time + sconf->qos_cc_block_time) > now) {
        (*e)->blockMsg++;;
        // stop logging every event if we have logged it many times
        if((*e)->blockMsg > QS_LOG_REPEAT) {
          if(((*e)->blockMsg % QS_LOG_REPEAT) == 0) {
            ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                         QOS_LOG_PFX(060)"access denied, QS_ClientEventBlockCount rule: "
                         "max=%d, current=%d, "
                         "message repeated %d times, "
                         "c=%s",
                         sconf->qos_cc_block,
                         (*e)->block,
                         QS_LOG_REPEAT,
                         QS_CONN_REMOTEIP(c) == NULL ? "-" : QS_CONN_REMOTEIP(c));
          }
        } else {
          ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                       QOS_LOG_PFX(060)"access denied, QS_ClientEventBlockCount rule: "
                       "max=%d, current=%d, c=%s",
                       sconf->qos_cc_block,
                       (*e)->block,
                       QS_CONN_REMOTEIP(c) == NULL ? "-" : QS_CONN_REMOTEIP(c));
        }
        if(!sconf->log_only) {
          apr_table_set(c->notes, QS_BLOCK_SEEN, ""); // supress NullConnection messages
          c->keepalive = AP_CONN_CLOSE;
          ret = m_retcode;
        }
      } else {
        /* release */
        if((*e)->blockMsg > QS_LOG_REPEAT) {
          // write remaining log lines
          ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, c->base_server,
                       QOS_LOG_PFX(060)"access denied (previously), QS_ClientEventBlockCount rule: "
                       "max=%d, current=%d, "
                       "message repeated %d times, "
                       "c=%s",
                       sconf->qos_cc_block,
                       (*e)->block,
                       (*e)->blockMsg % QS_LOG_REPEAT,
                       QS_CONN_REMOTEIP(c) == NULL ? "-" : QS_CONN_REMOTEIP(c));          
          (*e)->blockMsg = 0;
        }
        (*e)->block = 0;
        (*e)->block_time = 0;
      }
    }
    apr_global_mutex_unlock(u->qos_cc->lock);         /* @CRT39 */
  }

  return ret;
}

/**
 * Process user tracking cookie
 *
 * @param r
 * @return DECLINED or 302
 */
static int qos_post_read_request_later(request_rec *r) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                &qos_module);
  if(ap_is_initial_req(r)) {
    /* QS_UserTrackingCookieName */
    if(sconf && sconf->user_tracking_cookie) {
      char *value = qos_get_remove_cookie(r, sconf->user_tracking_cookie);
      qos_get_create_user_tracking(r, sconf, value);
      if(sconf->user_tracking_cookie_force) {
        const char *ignore = apr_table_get(r->subprocess_env, "DISABLE_UTC_ENFORCEMENT");
        if(!ignore) {
          if(strcmp(sconf->user_tracking_cookie_force, r->parsed_uri.path) == 0) {
            /* access to check url */
            if(apr_table_get(r->subprocess_env, QOS_USER_TRACKING_NEW) == NULL) {
              if(r->parsed_uri.query && (strncmp(r->parsed_uri.query, "r=", 2) == 0)) {
                /* client has send a cookie, redirect to original url */
                char *redirect_page;
                int buf_len = 0;
                unsigned char *buf;
                char *q = r->parsed_uri.query;
                buf_len = qos_decrypt(r, sconf, &buf, &q[2]);
                if(buf_len > 0) {
                  redirect_page = apr_psprintf(r->pool, "%s%.*s",
                                               qos_this_host(r),
                                               buf_len, buf);
                  apr_table_set(r->headers_out, "Location", redirect_page);
                  return HTTP_MOVED_TEMPORARILY;
                }
              }
            } /* else, "grant access" to the error page */
          } else if(apr_table_get(r->subprocess_env, QOS_USER_TRACKING_NEW) != NULL) {
            if(r->method_number == M_GET) {
              /* no valid cookie in request, redirect to check page */
              char *redirect_page = apr_pstrcat(r->pool, qos_this_host(r),
                                                sconf->user_tracking_cookie_force,
                                                "?r=",
                                                qos_encrypt(r, sconf,
                                                            (unsigned char *)r->unparsed_uri,
                                                            strlen(r->unparsed_uri)),
                                                NULL);
              apr_table_set(r->headers_out, "Location", redirect_page);
              qos_send_user_tracking_cookie(r, sconf, HTTP_MOVED_TEMPORARILY);
              return HTTP_MOVED_TEMPORARILY;
            }
          }
        }
      }
    }
  }
  return DECLINED;
}

/**
 * All headers has been read. End/updates connection level filters and propagtes
 * per connection events to the request_rec.
 *
 * @param r
 * @return DECLINED
 */
static int qos_post_read_request(request_rec *r) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                &qos_module);
  qos_ifctx_t *inctx = NULL;

  /* propagate connection env vars to req, geo data and QS_SrvMaxConn */
  const char *country = apr_table_get(r->connection->notes, QS_COUNTRY);
  const char *connections = apr_table_get(r->connection->notes, "QS_SrvConn");
  const char *all_connections = apr_table_get(r->connection->notes, "QS_AllConn");
  const char *fromCurrentIp = apr_table_get(r->connection->notes, "QS_IPConn");
  const char *connectionid = apr_table_get(r->connection->notes, QS_CONNID);
  if(country) {
    if(sconf->qos_cc_forwardedfor) {
      const char *forwardedfor = apr_table_get(r->headers_in, sconf->qos_cc_forwardedfor);
      if(forwardedfor) {
        unsigned long ip = qos_geo_str2long(r->pool, forwardedfor);
        if(ip) {
          qos_geo_t *pB = bsearch(&ip,
                                  sconf->geodb,
                                  sconf->geodb_size,
                                  sizeof(qos_geo_t),
                                  qos_geo_comp);
          if(pB) {
            country = apr_pstrdup(r->pool, pB->country);
          }
        } else {
          if(apr_table_get(r->notes, "QOS_LOG_PFX069") == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                          QOS_LOG_PFX(069)"no valid IP header found (@prr):"
                          " invalid header value '%s', fallback to connection's IP %s, id=%s",
                          forwardedfor,
                          QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                          qos_unique_id(r, "069"));
            apr_table_set(r->notes, "QOS_LOG_PFX069", "log once");
          }
        }
      } else {
        if(apr_table_get(r->notes, "QOS_LOG_PFX069") == NULL) {
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                        QOS_LOG_PFX(069)"no valid IP header found (@prr):"
                        " header '%s' not available, fallback to connection's IP %s, id=%s",
                        sconf->qos_cc_forwardedfor,
                        QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                        qos_unique_id(r, "069"));
          apr_table_set(r->notes, "QOS_LOG_PFX069", "log once");
        }
      }
    }
    apr_table_set(r->subprocess_env, QS_COUNTRY, country);
  }
  if(connections) {
    apr_table_set(r->subprocess_env, "QS_SrvConn", connections);
  }
  if(fromCurrentIp) {
    apr_table_set(r->subprocess_env, "QS_IPConn", fromCurrentIp);
  }
  if(all_connections) {
    apr_table_set(r->subprocess_env, "QS_AllConn", all_connections);
  }
  if(connectionid == NULL) {
    connectionid = apr_psprintf(r->pool, "%"APR_TIME_T_FMT"%.2ld%.5"APR_PID_T_FMT,
                                r->request_time,
                                r->connection->id % 100,
                                getpid());
    apr_table_set(r->connection->notes, QS_CONNID, connectionid);
  }
  apr_table_set(r->subprocess_env, QS_CONNID, connectionid);

  /* QS_ClientPrefer: propagate connection env vars to req*/
  if(apr_table_get(r->connection->notes, "QS_ClientLowPrio")) {
    apr_table_set(r->subprocess_env, "QS_ClientLowPrio", "1");
  }
  if(qos_request_check(r, sconf) != APR_SUCCESS) {
    return HTTP_BAD_REQUEST;
  }
  qos_parp_prr(r, sconf);
  if(sconf && (sconf->req_rate != -1)) {
    inctx = qos_get_ifctx(r->connection->input_filters);
    if(inctx) {
      const char *te = apr_table_get(r->headers_in, "Transfer-Encoding");
      inctx->r = r;
      if(r->read_chunked || (te && (strcasecmp(te, "chunked") == 0))) {
        ap_add_input_filter("qos-in-filter2", inctx, r, r->connection);
        inctx->status = QS_CONN_STATE_CHUNKED;
      } else {
        const char *cl = apr_table_get(r->headers_in, "Content-Length");
        if(cl == NULL) {
          inctx->status = QS_CONN_STATE_END;
#if APR_HAS_THREADS
          if(!sconf->inctx_t->exit) {
            apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT26 */
            apr_table_unset(sconf->inctx_t->table,
                            QS_INCTX_ID);
            apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT26 */
          }
#endif
        } else {
#ifdef ap_http_scheme
          /* Apache 2.2 */
          if(APR_SUCCESS == apr_strtoff(&inctx->cl_val, cl, NULL, 0))
#else
          if((inctx->cl_val = apr_atoi64(cl)) >= 0)
#endif
            {
            ap_add_input_filter("qos-in-filter2", inctx, r, r->connection);
            inctx->status = QS_CONN_STATE_BODY;
          } else {
            /* header filter should block this request */
          }
        }
      }
    }
  }
  return DECLINED;
}

/**
 * QS_LimitRequestBody, if content-length header is available.
 *
 * @param r
 * @param sconf Either server or dir config is used (or env var)
 * @param dconf Either server or dir config is used (or env var)
 * @return HTTP_REQUEST_ENTITY_TOO_LARGE if not allowed
 */
static apr_status_t qos_limitrequestbody_ctl(request_rec *r, qos_srv_config *sconf,
                                             qos_dir_config *dconf) {
  apr_off_t maxpost = qos_maxpost(r, sconf, dconf);
  if(maxpost != -1) {
    const char *l = apr_table_get(r->headers_in, "Content-Length");
    if(l != NULL) {
      apr_off_t s;
#ifdef ap_http_scheme
      /* Apache 2.2 */
      char *errp = NULL;
      if((APR_SUCCESS != apr_strtoff(&s, l, &errp, 10)) || (s < 0))
#else
      if(((s = apr_atoi64(l)) < 0) || (s < 0))
#endif
        {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      QOS_LOG_PFX(044)"access denied, QS_LimitRequestBody:"
                      " invalid content-length header, c=%s, id=%s",
                      QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                      qos_unique_id(r, "044"));
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
      }
      if(s > maxpost) {
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      QOS_LOG_PFX(044)"access denied, QS_LimitRequestBody:"
                      " max=%"APR_OFF_T_FMT" this=%"APR_OFF_T_FMT", c=%s, id=%s",
                      maxpost, s,
                      QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                      qos_unique_id(r, "044"));
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
      }
    } else {
      ap_add_input_filter("qos-in-filter3", NULL, r, r->connection);
    }
  }
  return APR_SUCCESS;
}

/**
 * Header parser (executed after mod_setenvif but before mod_parp).
 * Implements content-length based request body size limit and activates
 * content-length adijustmen for compressed request body.
 *
 * @param r
 * @return
 */
static int qos_header_parser1(request_rec * r) {
  if(ap_is_initial_req(r)) {
    apr_status_t rv;
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                  &qos_module);
    qos_dir_config *dconf = (qos_dir_config*)ap_get_module_config(r->per_dir_config,
                                                                  &qos_module);

    qos_deflate(r);
   
    /** QS_LimitRequestBody */
    rv = qos_limitrequestbody_ctl(r, sconf, dconf);
    if(rv != APR_SUCCESS) {
      int rc;
      const char *error_page = sconf->error_page;
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
      if(!sconf->log_only) {
        rc = qos_error_response(r, error_page);
        if((rc == DONE) || (rc == HTTP_MOVED_TEMPORARILY)) {
          return rc;
        }
        return rv;
      }
    }
  }
  return DECLINED;
}

/**
 * Header parser (executed before mod_setenvif or mod_parp).
 * Enables mod_parp if request body processing (filter) has been enabled
 * and limits the request header filter.
 *
 * @param r
 * @return
 */
static int qos_header_parser0(request_rec * r) {
  if(ap_is_initial_req(r)) {
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                  &qos_module);
    qos_dir_config *dconf = (qos_dir_config*)ap_get_module_config(r->per_dir_config,
                                                                  &qos_module);

    /** QS_DenyBody */
    if(dconf && (dconf->bodyfilter_p == 1 || dconf->bodyfilter_d == 1)) {
      qos_enable_parp(r);
    }

    /*
     * QS_RequestHeaderFilter enforcement
     */
    return qos_hp_header_filter(r, sconf, dconf);
  }
  return DECLINED;
}

/**
 * Header parser implements restrictions on a per location (url) basis.
 *
 * @param r
 * @return
 */
static int qos_header_parser(request_rec * r) {
  /* apply rules only to main request (avoid filtering of error documents) */
  if(ap_is_initial_req(r)) {
    char *msg = NULL;
    char *uid = NULL;
    int req_per_sec_block = 0;
    int kbytes_per_sec_block = 0;
    int status;
    qs_acentry_t *e = NULL;
    qs_acentry_t *e_cond = NULL;
    qs_acentry_t *ex = NULL; // either e or e_cond (used for locking)
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                  &qos_module);
    qos_dir_config *dconf = (qos_dir_config*)ap_get_module_config(r->per_dir_config,
                                                                  &qos_module);
    qs_req_ctx *rctx = NULL;
    const char *error_page = sconf->error_page;

    qos_deflate_contentlength(r);

    /* QS_SetEnvIfResBody */
    if(dconf && dconf->response_pattern) {
      ap_add_output_filter("qos-out-filter-body", NULL, r, r->connection);
    }

    /* 
     * QS_Permit* / QS_Deny* enforcement (but not QS_DenyEvent)
     */
    status = qos_hp_filter(r, sconf, dconf);
    /* prepare audit log */
    if(m_enable_audit && dconf) {
      qos_audit(r, dconf);
    }
    if(status != DECLINED) {
      return status;
    }

    /* 
     * Dynamic keep alive
     */
    if(!sconf->log_only) {
      qos_keepalive(r, sconf);
    }

    /*
     * VIP control
     */
    if(sconf->header_name || sconf->vip_user) {
      rctx = qos_rctx_config_get(r);
      rctx->is_vip = qos_is_vip(r, sconf);
      if(rctx->is_vip) {
        qs_conn_ctx *cconf = qos_get_cconf(r->connection);
        if(cconf) {
          cconf->is_vip = 1;
        }
      }
    }

    /*
     * additional variables
     */
    qos_parp_hp(r, sconf);
    qos_parp_hp_body(r, sconf);
    qos_setenvifquery(r, sconf);
    qos_setenvif(r, sconf);
    qos_setenv(r, sconf);
    qos_setreqheader(r, sconf->setreqheader_t);

    /*
     * QS_DenyEvent
     */
    status = qos_hp_event_deny_filter(r, sconf, dconf);
    if(status != DECLINED) {
      return status;
    }

    /*
     * QS_EventLimitCount
     */
    status = qos_hp_event_limit(r, sconf);
    if(status != DECLINED) {
      return status;
    }

    /*
     * QS_EventRequestLimit
     */
    if(sconf->has_event_filter) {
      status = qos_hp_event_filter(r, sconf);
      if(status != DECLINED) {
        return status;
      }
    }

    /*
     * QS_EventPerSecLimit
     */
    if(sconf->has_event_limit) {
      qos_hp_event_count(r, &req_per_sec_block, &kbytes_per_sec_block);
    }

    /*
     * QS_ClientEventRequestLimit
     */
    if(sconf->qos_cc_event_req >= 0) {
      status = qos_hp_cc_event_count(r, sconf, rctx);
      if(status != DECLINED) {
        return status;
      }
    }

    /*
     * QS_ClientSerialize
     */
    if(sconf->qos_cc_serialize && apr_table_get(r->subprocess_env, QS_SERIALIZE)) {
      qos_hp_cc_serialize(r, sconf, rctx);
    }

    /*
     * client control
     */
    if(qos_hp_cc(r, sconf, &msg, &uid) != DECLINED) {
      int rc;
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    "%s, id=%s", msg == NULL ? "-" : msg,
                    qos_unique_id(r, uid));
      if(!rctx) {
        rctx = qos_rctx_config_get(r);
      }
      rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
      if(!sconf->log_only) {
        rc = qos_error_response(r, error_page);
        if((rc == DONE) || (rc == HTTP_MOVED_TEMPORARILY)) {
          return rc;
        }
        return m_retcode;
      }
    }
    
    /* 
     * Request level control
     * get rule with conditional enforcement
     */
    e_cond = qos_getcondrule_byregex(r, sconf);
    /* 1st prio has "Match" rule */
    e = qos_getrule_byregex(r, sconf);
    /* 2th prio has "URL" rule */
    if(!e) e = qos_getrule_bylocation(r, sconf);
    if(e) {
      ex = e;
    } else if(e_cond) {
      ex = e_cond;
    }

    if(!rctx) {
      rctx = qos_rctx_config_get(r);
    }
    // optimistic locking (write only)
    if(ex) {
      rctx->entry_cond = e_cond;
      rctx->entry = e;
      
      apr_global_mutex_lock(ex->lock);   /* @CRT5 */

      if(e_cond) {
        e_cond->counter++;
      }

      if(e) {
        e->counter++;
        if(e->req_per_sec_block_rate > req_per_sec_block) {
          /* update req_per_sec_block if event restriction has returned worse block rate */
          req_per_sec_block = e->req_per_sec_block_rate;
        }
      }

      apr_global_mutex_unlock(ex->lock); /* @CRT5 */

    }

    if(e) {
      /*
       * QS_LocRequestLimitMatch/QS_LocRequestLimit/QS_LocRequestLimitDefault enforcement
       */
      if(e->limit && (e->counter > e->limit)) {
        /* vip session has no limitation */
        if(rctx->is_vip) {
          rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
        } else {
          /* std user */
          int rc;
          ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                        QOS_LOG_PFX(010)"access denied, QS_LocRequestLimit* rule: %s(%d),"
                        " concurrent requests=%d,"
                        " c=%s, id=%s",
                        e->url, e->limit, e->counter,
                        QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                        qos_unique_id(r, "010"));
          rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
          // request has already been blocked, don't cont this request for req/sec violations!
          apr_table_set(r->notes, QS_R010_ALREADY_BLOCKED, "");
          if(!sconf->log_only) {
            rc = qos_error_response(r, error_page);
            if((rc == DONE) || (rc == HTTP_MOVED_TEMPORARILY)) {
              return rc;
            }
            return m_retcode;
          }
        }
      }
      /*
       * QS_LocRequestPerSecLimit/QS_EventPerSecLimit enforcement
       */
      if(req_per_sec_block) {
        if(rctx->is_vip) {
          rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
        } else {
          int sec = req_per_sec_block / 1000;
          int nsec = req_per_sec_block % 1000;
          struct timespec delay;
          rctx->evmsg = apr_pstrcat(r->pool, "L;", rctx->evmsg, NULL);
          delay.tv_sec  = sec;
          delay.tv_nsec = nsec * 1000000;
          if(!sconf->log_only) {
            nanosleep(&delay,NULL);
          }
          /* don't wait more than once */
          req_per_sec_block = 0;
        }
      }
    
      /*
       * QS_LocKBytesPerSecLimit enforcement
       */
      if(e->kbytes_per_sec_block_rate) {
        if(rctx->is_vip) {
          rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
        } else {
          rctx->evmsg = apr_pstrcat(r->pool, "L;", rctx->evmsg, NULL);
          ap_add_output_filter("qos-out-filter-delay", NULL, r, r->connection);
        }
      }
    }
    
    /* QS_EventNewKBytesPerSecLimit */
    {
      qs_actable_t *act = sconf->act;
      qs_acentry_t *e = act->entry;
      while (e) {
        if (e->hard_kbytes_per_sec_limit
            && e->event) {
          if ((e->event[0] == '!'
               && apr_table_get(r->subprocess_env, &e->event[1]) == NULL)
              || apr_table_get(r->subprocess_env, e->event)) {
            if (rctx->is_vip) {
              rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
            }
            else {
              rctx->evmsg = apr_pstrcat(r->pool, "L;", rctx->evmsg, NULL);
              ap_add_output_filter("qos-out-filter-bandwidth", NULL, r, r->connection);
              rctx->hard_limit_e = e;
            }
            break;
          }
        }
        e = e->next;
      }
    }

    /*
     * QS_EventKBytesPerSecLimit
     */
    if(kbytes_per_sec_block) {
      if(rctx->is_vip) {
        rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
      } else {
        rctx->evmsg = apr_pstrcat(r->pool, "L;", rctx->evmsg, NULL);
        rctx->event_kbytes_per_sec_block_rate = kbytes_per_sec_block;
        ap_add_output_filter("qos-out-filter-delay", NULL, r, r->connection);
      }
    }
    
    if(e_cond) {
      /*
       * QS_CondLocRequestLimitMatch
       */
      if(e_cond->limit && (e_cond->counter > e_cond->limit)) {
        /* check condition */
        const char *condition = apr_table_get(r->subprocess_env, QS_COND);
        if(condition) {
          if(ap_regexec(e_cond->condition, condition, 0, NULL, 0) == 0) {
            /* vip session has no limitation */
            if(rctx->is_vip) {
              rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
            } else {
              /* std user */
              int rc;
              ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                            QOS_LOG_PFX(011)"access denied, QS_CondLocRequestLimitMatch"
                            " rule: %s(%d),"
                            " concurrent requests=%d,"
                            " c=%s, id=%s",
                            e_cond->url, e_cond->limit, e_cond->counter,
                            QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                            qos_unique_id(r, "011"));
              rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
              if(!sconf->log_only) {
                rc = qos_error_response(r, error_page);
                if((rc == DONE) || (rc == HTTP_MOVED_TEMPORARILY)) {
                  return rc;
                }
                return m_retcode;
              }
            }
          }
        }
      }
    }
  
    /*
     * QS_EventPerSecLimit
     */
    if(req_per_sec_block) {
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      int sec = req_per_sec_block / 1000;
      int nsec = req_per_sec_block % 1000;
      struct timespec delay;
      rctx->evmsg = apr_pstrcat(r->pool, "L;", rctx->evmsg, NULL);
      delay.tv_sec  = sec;
      delay.tv_nsec = nsec * 1000000;
      if(!sconf->log_only) {
        nanosleep(&delay,NULL);
      }
    }

    /*
     * QS_Delay
     */
    qos_delay(r, sconf);

  }
  return DECLINED;
}

/**
 * QS_LimitRequestBody
 * Input filter limiting request body size for chunked encoded requests.
 *
 * @param f
 * @param bb
 * @param mode
 * @param block
 * @param nbytes
 * @return
 */
static apr_status_t qos_in_filter3(ap_filter_t *f, apr_bucket_brigade *bb,
                                  ap_input_mode_t mode, apr_read_type_e block,
                                  apr_off_t nbytes) {
  apr_status_t rv = ap_get_brigade(f->next, bb, mode, block, nbytes);
  request_rec *r = f->r;
  if(rv != APR_SUCCESS) {
    return rv;
  }
  if(!ap_is_initial_req(r) || !r->read_chunked) {
    ap_remove_input_filter(f);
    return APR_SUCCESS;
  } else {
    qos_srv_config *sconf = ap_get_module_config(r->server->module_config, &qos_module);
    qos_dir_config *dconf = ap_get_module_config(r->per_dir_config, &qos_module);
    apr_off_t maxpost = qos_maxpost(r, sconf, dconf);
    if(maxpost != -1) {
      apr_size_t bytes = 0;
      apr_bucket *b;
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      for(b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
        bytes = bytes + b->length;
      }
      rctx->maxpostcount += bytes;
      if(rctx->maxpostcount > maxpost) {
        int rc;
        const char *error_page = sconf->error_page;
        qs_req_ctx *rctx = qos_rctx_config_get(r);
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      QOS_LOG_PFX(044)"access denied, QS_LimitRequestBody:"
                      " max=%"APR_OFF_T_FMT" this=%"APR_OFF_T_FMT", c=%s, id=%s",
                      maxpost, rctx->maxpostcount,
                      QS_CONN_REMOTEIP(r->connection) == NULL ? "-" : QS_CONN_REMOTEIP(r->connection),
                      qos_unique_id(r, "044"));
        rctx->evmsg = apr_pstrcat(r->pool, "D;", rctx->evmsg, NULL);
        if(!sconf->log_only) {
          rc = qos_error_response(r, error_page);
          if((rc == DONE) || (rc == HTTP_MOVED_TEMPORARILY)) {
            return rc;
          }
          return HTTP_REQUEST_ENTITY_TOO_LARGE;
        }
      }
    }
  }
  return APR_SUCCESS;
}

/**
 * Input filter removes connection from sconf->inctx_t->table
 * when reading EOS.
 *
 * @param f
 * @param bb
 * @param mode
 * @param block
 * @param nbytes
 * @return
 */
static apr_status_t qos_in_filter2(ap_filter_t *f, apr_bucket_brigade *bb,
                                  ap_input_mode_t mode, apr_read_type_e block,
                                  apr_off_t nbytes) {
  qos_ifctx_t *inctx = f->ctx;
  apr_status_t rv = ap_get_brigade(f->next, bb, mode, block, nbytes);
  if((rv == APR_SUCCESS) && APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(inctx->c->base_server->module_config,
                                                                  &qos_module);
    ap_remove_input_filter(f);
#if APR_HAS_THREADS
    if(!sconf->inctx_t->exit) {
      apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT28 */
      apr_table_unset(sconf->inctx_t->table,
                      QS_INCTX_ID);
      apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT28 */
    }
#endif
  }
  return rv;
}

/**
 * Input filter, used to log timeout event, mark slow clients,
 * and to calculate packet rate.
 *
 * Adds/removes the connection from the sconf->inctx_t->table
 * dapending of the request state (read head/body, keepalive, ...).
 *
 * @param f
 * @param bb
 * @param mode
 * @param block
 * @param nbytes
 * @return
 */
static apr_status_t qos_in_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                                  ap_input_mode_t mode, apr_read_type_e block,
                                  apr_off_t nbytes) {
  apr_status_t rv;
  qos_ifctx_t *inctx = f->ctx;
  apr_size_t bytes = 0;
  int crs = inctx->status;
  rv = ap_get_brigade(f->next, bb, mode, block, nbytes);
  if(rv == APR_SUCCESS) {
    if(inctx->lowrate != -1) {
      bytes = qos_packet_rate(inctx, bb);
    }
  }
  if(inctx->status == QS_CONN_STATE_KEEP) {
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(inctx->c->base_server->module_config,
                                                                  &qos_module);
    inctx->time = time(NULL);
    inctx->nbytes = 0;
    inctx->status = QS_CONN_STATE_HEAD;
#if APR_HAS_THREADS
    if(sconf->inctx_t && !sconf->inctx_t->exit && sconf->min_rate_off == 0) {
      apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT23 */
      apr_table_setn(sconf->inctx_t->table,
                     QS_INCTX_ID,
                     (char *)inctx);
      apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT23 */
    }
#endif
  }
  if(rv != APR_SUCCESS) {
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(inctx->c->base_server->module_config,
                                                                  &qos_module);
    inctx->status = QS_CONN_STATE_END;
    inctx->time = 0;
    inctx->nbytes = 0;
#if APR_HAS_THREADS
    if(sconf->inctx_t && !sconf->inctx_t->exit) {
      apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT24 */
      apr_table_unset(sconf->inctx_t->table,
                      QS_INCTX_ID);
      apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT24 */
    }
#endif
  }
  if(inctx->status > QS_CONN_STATE_NEW) {
    if(rv == APR_SUCCESS) {
      if(bytes == 0) {
        apr_bucket *b;
        for(b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
          bytes = bytes + b->length;
        }
      }
      inctx->nbytes = inctx->nbytes + bytes;
      if(inctx->status == QS_CONN_STATE_BODY) {
        if(inctx->cl_val >= bytes) {
          inctx->cl_val = inctx->cl_val - bytes;
        }
        if(inctx->cl_val == 0) {
          qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(inctx->c->base_server->module_config,
                                                                        &qos_module);
#if APR_HAS_THREADS
          if(!sconf->inctx_t->exit) {
            apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT27 */
            apr_table_unset(sconf->inctx_t->table,
                            QS_INCTX_ID);
            apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT27 */
          }
#endif
        }
      }
    }
    if((rv == APR_TIMEUP) &&
       (crs != QS_CONN_STATE_END) && 
       (crs != QS_CONN_STATE_KEEP)) {
      qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(inctx->c->base_server->module_config,
                                                                    &qos_module);
      /* mark clients causing a timeout */
      if(sconf && sconf->has_qos_cc) {
        qos_user_t *u = qos_get_user_conf(sconf->act->ppool);
        qos_s_entry_t **e = NULL;
        qos_s_entry_t searchE;
        apr_global_mutex_lock(u->qos_cc->lock);            /* @CRT18 */
        qos_ip_str2long(QS_CONN_REMOTEIP(inctx->c), &searchE.ip6);
        e = qos_cc_get0(u->qos_cc, &searchE, 0);
        if(!e) {
          e = qos_cc_set(u->qos_cc, &searchE, time(NULL));
        }
        (*e)->lowrate = time(NULL);
        apr_global_mutex_unlock(u->qos_cc->lock);          /* @CRT18 */
      }
      inctx->lowrate = QS_PKT_RATE_TH + 1;
    }
  }
  return rv;
}

/**
 * QS_SetEnvIfResBody 
 *
 * Searches the response body for the pattern defined by the QS_SetEnvIfResBody
 * directive (supports only one search pattern (literal string)).
 *
 * @param f
 * @param bb
 * @return
 */
static apr_status_t qos_out_filter_body(ap_filter_t *f, apr_bucket_brigade *bb) {
  request_rec *r = f->r;
  qos_dir_config *dconf = ap_get_module_config(r->per_dir_config, &qos_module);
  if((dconf == NULL) || (dconf->response_pattern == NULL)) {
    ap_remove_output_filter(f);
  } else {
    int len = strlen(dconf->response_pattern);
    apr_bucket *b;
    qs_req_ctx *rctx = qos_rctx_config_get(r);
    for(b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
      if(APR_BUCKET_IS_EOS(b)) {
        /* If we ever see an EOS, make sure to FLUSH. */
        apr_bucket *flush = apr_bucket_flush_create(f->c->bucket_alloc);
        APR_BUCKET_INSERT_BEFORE(b, flush);
      }
      if(!(APR_BUCKET_IS_METADATA(b))) {
        const char *buf;
        apr_size_t nbytes;
        if(apr_bucket_read(b, &buf, &nbytes, APR_BLOCK_READ) == APR_SUCCESS) {
          if(nbytes > 0) {
            int blen = nbytes > len ? len : nbytes - 1;
            /* 1. overlap: this buffer avoids that we miss a string if it is cut apart
               within two buckets 
               e.g., [Logi][n Page] instaed of [Login Page] when searching for "Login Page" */
            if(rctx->body_window == NULL) {
              // first call, create a window buffer
              rctx->body_window = apr_pcalloc(r->pool, (len*2)+1);
              rctx->body_window[0] = '\0';
            } else {
              // subsequent call, searches within the window too
              int wlen = strlen(rctx->body_window);
              strncpy(&rctx->body_window[wlen], buf, blen);
              rctx->body_window[wlen+blen+1] = '\0';
              if(strstr(rctx->body_window, dconf->response_pattern)) {
                /* found pattern */
                apr_table_set(r->subprocess_env, dconf->response_pattern_var, dconf->response_pattern);
                ap_remove_output_filter(f);
              }
            }
            /* 2. new buffer (don't want to copy the data) */
            if(qos_strnstr(buf, dconf->response_pattern, nbytes)) {
              /* found pattern */
              apr_table_set(r->subprocess_env, dconf->response_pattern_var, dconf->response_pattern);
              ap_remove_output_filter(f);
            }
            /* 3. store the end (for next loop) */
            strncpy(rctx->body_window, &buf[nbytes - blen], blen);
            rctx->body_window[blen] = '\0';
          }
        }
      }
    }
  }
  return ap_pass_brigade(f->next, bb);
}

static apr_status_t qos_out_filter_bandwidth(ap_filter_t *f, apr_bucket_brigade *bb) {
  request_rec *r = f->r;
  qs_req_ctx *rctx = qos_rctx_config_get(r);
  qs_acentry_t *e = rctx->hard_limit_e;
  apr_off_t length;
  apr_status_t rv;
  apr_uint32_t concurrency;
  /* smoother, perhaps better network utilization down to client if we send
   * smaller amounts more frequently, so try to send multiple times per second
   *
   * also, by checking concurrency relatively often we are fairly accurate
   * without implementing any complex resource reservation scheme to deal with
   * concurrency increasing while we sleep and/or implementing error correction
   * over time (which would then require more blocking)
   */
  double time_quanta_per_sec = 4.0;
  apr_interval_time_t normal_sleep =
    (double)apr_time_from_sec(1) / time_quanta_per_sec;
  apr_off_t our_share_per_time_quantum = 0;

  concurrency = 1 + apr_atomic_inc32(&e->hard_limit_concurrency);

  while (!APR_BRIGADE_EMPTY(bb)) {
    apr_bucket *b, *first, *next;
    apr_bucket_brigade *tmp_bb;

    /* How long do we sleep after sending?
     * Calculate the number of requests going through here.
     * We get to use hard_kbytes_per_sec_limit / concurrency.
     * Send up to our fair share per time quantum, then sleep.
     * Repeat until we worked through the brigade.
     */

    our_share_per_time_quantum =
      (int)(1024.0 * (double)e->hard_kbytes_per_sec_limit / (double)concurrency /time_quanta_per_sec);

    rv = apr_brigade_partition(bb, our_share_per_time_quantum, &next);
    if (rv != APR_SUCCESS && rv != APR_INCOMPLETE) {
      apr_atomic_dec32(&e->hard_limit_concurrency);
      return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rv == APR_INCOMPLETE) { /* no split needed */
      break;
    }

    first = APR_BRIGADE_FIRST(bb);
    APR_BUCKET_REMOVE(first);
        
    tmp_bb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(tmp_bb, first);

    /* A flush bucket is required when passing down small pieces,
     * else we have really poor utilization of the pipeline
     * (i.e., we'll use much less than the configured bandwidth).
     * It isn't so important when passing down big pieces since
     * most will be sent, but there's no use leaving the last
     * fragment buffered until after we sleep again.
     */
    b = apr_bucket_flush_create(f->c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(tmp_bb, b);

    rv = ap_pass_brigade(f->next, tmp_bb);
    if (rv != APR_SUCCESS) {
      apr_atomic_dec32(&e->hard_limit_concurrency);
      return rv;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "Sleeping, concurrency %u, our rate %"
                  APR_OFF_T_FMT "per quantum",
                  concurrency, our_share_per_time_quantum);
    apr_sleep(normal_sleep);
    /* probably changed during slumber */
    concurrency = e->hard_limit_concurrency;
  }

  if (our_share_per_time_quantum) {
    rv = apr_brigade_length(bb, 1, &length);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, r,
                  "Sleeping, concurrency %u, our rate %"
                  APR_OFF_T_FMT " per quantum (have %"
                  APR_OFF_T_FMT ")",
                  concurrency, our_share_per_time_quantum,
                  rv == APR_SUCCESS ? length : 0);
    /* don't sleep full quantum, since this is the remainder */
    if (rv == APR_SUCCESS) {
      apr_sleep(normal_sleep * length / our_share_per_time_quantum);
    }
  }

  apr_atomic_dec32(&e->hard_limit_concurrency);

  return ap_pass_brigade(f->next, bb); 
}

/**
 * Output filter adds response delay.
 *
 * @param f
 * @param bb
 * @return
 */
static apr_status_t qos_out_filter_delay(ap_filter_t *f, apr_bucket_brigade *bb) {
  request_rec *r = f->r;
  qs_req_ctx *rctx = qos_rctx_config_get(r);
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);
  if(rctx->entry && rctx->entry->kbytes_per_sec_block_rate) {
    if(rctx->is_vip) {
      rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
    } else if(!sconf->log_only) {
      /*
       * QS_LocKBytesPerSecLimit enforcement
       */
      int kbytes_per_sec_block = rctx->entry->kbytes_per_sec_block_rate;
      int sec = kbytes_per_sec_block / 1000;
      int nsec = kbytes_per_sec_block % 1000;
      struct timespec delay;
      delay.tv_sec  = sec;
      delay.tv_nsec = nsec * 1000000;
      nanosleep(&delay,NULL);
    }
  } else if(rctx->event_kbytes_per_sec_block_rate) {
    if(rctx->is_vip) {
      rctx->evmsg = apr_pstrcat(r->pool, "S;", rctx->evmsg, NULL);
    } else if(!sconf->log_only) {
      /*
       * QS_EventKBytesPerSecLimit enforcement
       */
      int kbytes_per_sec_block = rctx->event_kbytes_per_sec_block_rate;
      int sec = kbytes_per_sec_block / 1000;
      int nsec = kbytes_per_sec_block % 1000;
      struct timespec delay;
      delay.tv_sec  = sec;
      delay.tv_nsec = nsec * 1000000;
      nanosleep(&delay,NULL);
    }
  }
  return ap_pass_brigade(f->next, bb); 
}

/**
 * Out filter measuring the minimal download bandwith.
 *
 * @param f
 * @param bb
 * @return
 */
static apr_status_t qos_out_filter_min(ap_filter_t *f, apr_bucket_brigade *bb) {
  request_rec *r = f->r;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);
  qos_ifctx_t *inctx = qos_get_ifctx(r->connection->input_filters);
  if(APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
    if(!sconf->inctx_t->exit) {
      apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT30 */
      apr_table_unset(sconf->inctx_t->table,
                      QS_INCTX_ID);
      apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT30 */
    }
    inctx->status = QS_CONN_STATE_END;
    ap_remove_output_filter(f);
  } else {
    apr_size_t total = 0;
    apr_bucket *b;
    for(b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
      total = total + b->length;
    }
    inctx->nbytes = inctx->nbytes + total;
  }
  return ap_pass_brigade(f->next, bb); 
}

/**
 * Merges two  rule tables. Entires whose key/name begin with a "+" are added
 * while those with a "-" prefix are removed.
 *
 * @param p Pool to allocate new table from.
 * @param b_rfilter_table Base rule table (parent)
 * @param o_rfilter_table Over rule table (child)
 * @return Merged table
 */
static apr_table_t *qos_table_merge_create(apr_pool_t *p, apr_table_t *b_rfilter_table,
                                           apr_table_t *o_rfilter_table) {
  int i;
  apr_table_t *rfilter_table = apr_table_make(p, apr_table_elts(b_rfilter_table)->nelts +
                                              apr_table_elts(o_rfilter_table)->nelts);
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(b_rfilter_table)->elts;
  // add additional (+) entries from the base/parent table
  for(i = 0; i < apr_table_elts(b_rfilter_table)->nelts; ++i) {
    if(entry[i].key[0] == '+') {
      apr_table_setn(rfilter_table, entry[i].key, entry[i].val);
    }
  }
  // add additional (+) entries from the over/child table
  entry = (apr_table_entry_t *)apr_table_elts(o_rfilter_table)->elts;
  for(i = 0; i < apr_table_elts(o_rfilter_table)->nelts; ++i) {
    if(entry[i].key[0] == '+') {
      apr_table_setn(rfilter_table, entry[i].key, entry[i].val);
    }
  }
  // remove the "-" entries
  for(i = 0; i < apr_table_elts(o_rfilter_table)->nelts; ++i) {
    if(entry[i].key[0] == '-') {
      char *id = apr_psprintf(p, "+%s", &entry[i].key[1]);
      apr_table_unset(rfilter_table, id);
    }
  }
  return rfilter_table;
}

/* QS_SrvMinDataRateOffEvent */
#if APR_HAS_THREADS
static void qos_disable_rate(request_rec *r, qos_srv_config *sconf,
                             qos_dir_config *dconf) {
  if(dconf && sconf && (sconf->req_rate != -1) && (sconf->min_rate != -1)) {
    apr_table_t *disable_reqrate_events = dconf->disable_reqrate_events;
    if(apr_table_elts(sconf->disable_reqrate_events)->nelts > 0) {
      disable_reqrate_events = qos_table_merge_create(r->pool, sconf->disable_reqrate_events,
                                                      dconf->disable_reqrate_events);
    }
    if(apr_table_elts(disable_reqrate_events)->nelts > 0) {
      qos_ifctx_t *inctx = qos_get_ifctx(r->connection->input_filters);
      if(inctx) {
        apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(disable_reqrate_events)->elts;
        int i;
        for(i = 0; i < apr_table_elts(disable_reqrate_events)->nelts; i++) {
          char *v = entry[i].key;
          if(apr_table_get(r->subprocess_env, &v[1])) {
            inctx->disabled = 1;
            break;
          }
        }
      }
    }
  }
}
#endif

static void qos_start_res_rate(request_rec *r, qos_srv_config *sconf) {
  if(sconf && (sconf->req_rate != -1) && (sconf->min_rate != -1)) {
    qos_ifctx_t *inctx = qos_get_ifctx(r->connection->input_filters);
    if(inctx) {
      inctx->status = QS_CONN_STATE_RESPONSE;
      inctx->time = time(NULL);
      inctx->nbytes = 0;
#if APR_HAS_THREADS
      if(sconf->inctx_t && !sconf->inctx_t->exit && sconf->min_rate_off == 0) {
        apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT29 */
        apr_table_setn(sconf->inctx_t->table,
                       QS_INCTX_ID,
                       (char *)inctx);
        apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT29 */
      }
      ap_add_output_filter("qos-out-filter-min", NULL, r, r->connection);
#endif
    }
  }
}

static void qos_propagate_events(request_rec *r) {
  request_rec *mr = NULL;
  const char **var;
  if(r->prev) {
    mr = r->prev;
  } else if(r->main) {
    mr = r->main;
  } else if(r->next) {
    mr = r->next;
  }
  var = m_env_variables;
  while(*var) {
    int propagated = 0;
    if(mr) {
      const char *p = apr_table_get(mr->subprocess_env, *var);
      if(p) {
        propagated = 1;
        apr_table_set(r->subprocess_env, *var, p);
      }
      if(!propagated) {
        p = apr_table_get(r->subprocess_env, *var);
        if(p) {
          propagated = 1;
          apr_table_set(mr->subprocess_env, *var, p);
        }
      }
    }
    var++;
  }
}

/** ensure that every request record has the error notes to log */
static void qos_propagate_notes(request_rec *r) {
  request_rec *mr = NULL;
  const char **var;
  if(r->prev) {
    mr = r->prev;
  } else if(r->main) {
    mr = r->main;
  } else if(r->next) {
    mr = r->next;
  }
  var = m_note_variables;
  while(*var) {
    int propagated = 0;
    if(mr) {
      const char *p = apr_table_get(mr->notes, *var);
      if(p) {
        propagated = 1;
        apr_table_setn(r->notes, *var, p);
      }
      if(!propagated) {
        p = apr_table_get(r->notes, *var);
        if(p) {
          propagated = 1;
          apr_table_setn(mr->notes, *var, p);
        }
      }
    }
    var++;
  }
}

/* QS_UnsetResHeader */
static void qos_unset_header(request_rec *r, qos_srv_config *sconf) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->unsetresheader_t)->elts;
  for(i = 0; i < apr_table_elts(sconf->unsetresheader_t)->nelts; i++) {
    apr_table_unset(r->headers_out, entry[i].key);
    apr_table_unset(r->err_headers_out, entry[i].key);
  }
  return;
}

static void qos_end_res_rate(request_rec *r, qos_srv_config *sconf) {
  if(sconf && (sconf->req_rate != -1) && (sconf->min_rate != -1)) {
    qos_ifctx_t *inctx = qos_get_ifctx(r->connection->input_filters);
    if(inctx) {
      inctx->time = time(NULL);
      inctx->nbytes = 0;
      if(r->connection->keepalive == AP_CONN_CLOSE) {
        if(!sconf->inctx_t->exit) {
          apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT30 */
          inctx->status = QS_CONN_STATE_END;
          apr_table_unset(sconf->inctx_t->table,
                         QS_INCTX_ID);
          apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT30 */
        }
      } else {
        if(!sconf->inctx_t->exit) {
          apr_thread_mutex_lock(sconf->inctx_t->lock);     /* @CRT30 */
          if(inctx->status != QS_CONN_STATE_DESTROY) {
            inctx->status = QS_CONN_STATE_KEEP;
            apr_table_setn(sconf->inctx_t->table,
                           QS_INCTX_ID, (char *)inctx);
          }
          apr_thread_mutex_unlock(sconf->inctx_t->lock);   /* @CRT30 */
        }
      }
    }
  }
}

/**
 * process response:
 * - start min data measure
 * - setenvif header
 * - detects vip header and create session
 * - header filter
 */
static apr_status_t qos_out_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
  request_rec *r = f->r;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);
  qos_dir_config *dconf = ap_get_module_config(r->per_dir_config, &qos_module);
  qs_headerfilter_mode_e mode;

  qos_start_res_rate(r, sconf);
  qos_setenvstatus(r, sconf, dconf);
  qos_setenvresheader(r, sconf);
  qos_setenvres(r, sconf);
  if(sconf && sconf->user_tracking_cookie) {
    qos_send_user_tracking_cookie(r, sconf, r->status);
  }
  if(sconf && sconf->milestones) {
    qos_update_milestone(r, sconf);
  }
  if(sconf->ip_header_name) {
    const char *ctrl_h = apr_table_get(r->headers_out, sconf->ip_header_name);
    if(ctrl_h) {
      int match = 1;
      if(sconf->ip_header_name_regex) {
        if(ap_regexec(sconf->ip_header_name_regex, ctrl_h, 0, NULL, 0) != 0) {
          match = 0;
        }
      }
      if(match) {
        qs_conn_ctx *cconf = qos_get_cconf(r->connection);
        if(cconf) {
          cconf->is_vip = 1;
          cconf->is_vip_by_header = 1;
          apr_table_set(r->subprocess_env, QS_ISVIPREQ, "yes");
        }
      }
      if(sconf->ip_header_name_drop) {
        apr_table_unset(r->headers_out, sconf->ip_header_name);
      }
    }
  }
  if(sconf->header_name) {
    /* got a vip header: create new session (if non exists) */
    const char *ctrl_h = apr_table_get(r->headers_out, sconf->header_name);
    if(ctrl_h && !apr_table_get(r->notes, QS_REC_COOKIE)) {
      int match = 1;
      if(sconf->header_name_regex) {
        if(ap_regexec(sconf->header_name_regex, ctrl_h, 0, NULL, 0) != 0) {
          match = 0;
        }
      }
      if(match) {
        qs_conn_ctx *cconf = qos_get_cconf(r->connection);
        qs_req_ctx *rctx = qos_rctx_config_get(r);
        qos_set_session(r, sconf);
        if(!rctx->evmsg || !strstr(rctx->evmsg, "V;")) {
          rctx->evmsg = apr_pstrcat(r->pool, "V;", rctx->evmsg, NULL);
        }
        if(cconf) {
          cconf->is_vip = 1;
          cconf->is_vip_by_header = 1;
          apr_table_set(r->subprocess_env, QS_ISVIPREQ, "yes");
        }
        apr_table_set(r->notes, QS_REC_COOKIE, "");
      }
      if(sconf->header_name_drop) {
        apr_table_unset(r->headers_out, sconf->header_name);
      }
    }
  }
  if(sconf->vip_user && r->user) {
    if(!apr_table_get(r->notes, QS_REC_COOKIE)) {
      qs_conn_ctx *cconf = qos_get_cconf(r->connection);
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      qos_set_session(r, sconf);
      if(!rctx->evmsg || !strstr(rctx->evmsg, "V;")) {
        rctx->evmsg = apr_pstrcat(r->pool, "V;", rctx->evmsg, NULL);
      }
      if(cconf) {
        cconf->is_vip = 1;
        cconf->is_vip_by_header = 1;
        apr_table_set(r->subprocess_env, QS_ISVIPREQ, "yes");
      }
      apr_table_set(r->notes, QS_REC_COOKIE, "");
    }
  }
  if(sconf->vip_ip_user && r->user) {
    qs_conn_ctx *cconf = qos_get_cconf(r->connection);
    if(cconf) {
      cconf->is_vip = 1;
      cconf->is_vip_by_header = 1;
      apr_table_set(r->subprocess_env, QS_ISVIPREQ, "yes");
    }
  }
  qos_unset_header(r, sconf);
  /* don't handle response status since response header filter use "drop" action only */
  mode = sconf->resheaderfilter;
  if(dconf->resheaderfilter > QS_HEADERFILTER_OFF_DEFAULT) {
    // override server configuration
    mode = dconf->resheaderfilter;
  }
  if(mode > QS_HEADERFILTER_OFF) {
    qos_header_filter(r, sconf, r->headers_out, "response",
                      sconf->reshfilter_table, mode);
  }
  qos_keepalive(r, sconf);
  if(sconf->max_conn_close != -1) {
    if(sconf->act->conn->connections > sconf->max_conn_close) {
      qs_req_ctx *rctx = qos_rctx_config_get(r);
      rctx->evmsg = apr_pstrcat(r->pool, "K;", rctx->evmsg, NULL);
      r->connection->keepalive = AP_CONN_CLOSE;
    }
  }
  /* disable request rate for certain connections */
#if APR_HAS_THREADS
  qos_disable_rate(r, sconf, dconf);
#endif
  ap_remove_output_filter(f);
  return ap_pass_brigade(f->next, bb);
}

static apr_status_t qos_out_err_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
  request_rec *r = f->r;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);

  if(sconf) {
    qos_dir_config *dconf = ap_get_module_config(r->per_dir_config, &qos_module);
    qos_setenvstatus(r, sconf, dconf);
    qos_setenvresheader(r, sconf);
    qos_setenvres(r, sconf);
  }
  ap_remove_output_filter(f);
  return ap_pass_brigade(f->next, bb);
}

/**
 * QS_EventRequestLimit
 * reset event counter
 */
static void qos_event_reset(qos_srv_config *sconf, qs_req_ctx *rctx) {
  int i;
  apr_table_entry_t *entry;
  apr_global_mutex_lock(sconf->act->lock);   /* @CRT32 */
  entry = (apr_table_entry_t *)apr_table_elts(rctx->event_entries)->elts;
  for(i = 0; i < apr_table_elts(rctx->event_entries)->nelts; i++) {
    qs_acentry_t *e = (qs_acentry_t *)entry[i].val;
    if(e->counter > 0) {
      e->counter--;
    }
  }
  apr_global_mutex_unlock(sconf->act->lock); /* @CRT32 */
}

static int qos_fixup(request_rec * r) {
  int rc = 0;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                &qos_module);
  qos_dir_config *dconf = (qos_dir_config*)ap_get_module_config(r->per_dir_config,
                                                                &qos_module);
  /* QS_VipUser/QS_VipIpUser */
  if(sconf && (sconf->vip_user || sconf->vip_ip_user) && r->user) {
    /* check r->user early (final status is update is implemented in output-filter) */
    qs_conn_ctx *cconf = qos_get_cconf(r->connection);
    if(cconf) {
      cconf->is_vip = 1;
      cconf->is_vip_by_header = 1;
      apr_table_set(r->subprocess_env, QS_ISVIPREQ, "yes");
    }
  }
#if APR_HAS_THREADS
  qos_disable_rate(r, sconf, dconf);
#endif

  qos_setreqheader(r, sconf->setreqheaderlate_t);

  rc = qos_redirectif(r, sconf, sconf->redirectif);
  if(rc == HTTP_MOVED_TEMPORARILY) {
    return HTTP_MOVED_TEMPORARILY;
  }
  rc = qos_redirectif(r, sconf, dconf->redirectif);
  if(rc == HTTP_MOVED_TEMPORARILY) {
    return HTTP_MOVED_TEMPORARILY;
  }

  return DECLINED;
}

/**
 * "free resources" and update stats
 */
static int qos_logger(request_rec *r) {
  qs_req_ctx *rctx = qos_rctx_config_get(r);
  qs_acentry_t *e = rctx->entry;
  qs_acentry_t *e_cond = rctx->entry_cond;
  qs_acentry_t *ex = e;
  qs_conn_base_ctx *base = qos_get_conn_base_ctx(r->connection);
  qs_conn_ctx *cconf = qos_get_cconf(r->connection);
  apr_time_t now = 0;
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);
  qos_dir_config *dconf = ap_get_module_config(r->per_dir_config, &qos_module);
  if(ex == NULL) {
    ex = e_cond;
  }
  qos_propagate_notes(r);
  qos_propagate_events(r);
  qos_end_res_rate(r, sconf);
  qos_setenvif(r, sconf);
  qos_logger_cc(r, sconf, rctx);
  qos_logger_event_limit(r, sconf);
  if(base) {
    base->requests++;
  }
  if(cconf) {
    if(cconf->evmsg) {
      rctx->evmsg = apr_pstrcat(r->pool, cconf->evmsg, rctx->evmsg, NULL);
    }
  }
  if(sconf->has_event_filter) {
    qos_event_reset(sconf, rctx);
  }
  if(sconf->has_event_limit) {
    qos_lg_event_update(r, &now);
  }
  if(ex) {
    char *h;
    if(!now) {
      now = apr_time_sec(r->request_time);
    }
    apr_global_mutex_lock(ex->lock);   /* @CRT6 */
    h = apr_psprintf(r->pool, "%d", ex->counter);
    if(e_cond) {
      if(e_cond->counter > 0) {
        e_cond->counter--;
      }
    }
    if(e) {
      if(e->counter > 0) {
        e->counter--;
      }
      if(apr_table_get(r->notes, QS_R010_ALREADY_BLOCKED) == NULL) {
        e->req++;
        e->bytes = e->bytes + r->bytes_sent;
        if(now > (e->interval + QS_BW_SAMPLING_RATE)) {
          e->req_per_sec = e->req / (now - e->interval);
          e->req = 0;
          e->kbytes_per_sec = e->bytes / (now - e->interval) / 1024;
          e->bytes = 0;
          e->interval = now;
          if(e->req_per_sec_limit) {
            qos_cal_req_sec(r, e);
          }
          if(e->kbytes_per_sec_limit) {
            qos_cal_bytes_sec(r, e);
          }
        }
      }
    }
    apr_global_mutex_unlock(ex->lock); /* @CRT6 */
    /* allow logging of the current location usage */
    apr_table_set(r->subprocess_env, "mod_qos_cr", h);
    if(r->next) {
      apr_table_set(r->next->subprocess_env, "mod_qos_cr", h);
    }
    /* decrement only once */
    ap_set_module_config(r->request_config, &qos_module, NULL);
  }
  if(cconf && (cconf->sconf->max_conn != -1)) {
    char *cc = apr_psprintf(r->pool, "%d", cconf->sconf->act->conn->connections);
    apr_table_set(r->subprocess_env, "mod_qos_con", cc);
    if(r->next) {
      apr_table_set(r->next->subprocess_env, "mod_qos_con", cc);
    }
  }
  if(rctx->evmsg) {
    apr_table_set(r->subprocess_env, "mod_qos_ev", rctx->evmsg);
    if(r->next) {
      apr_table_set(r->next->subprocess_env, "mod_qos_ev", rctx->evmsg);
    }
  }
#if APR_HAS_THREADS
  qos_disable_rate(r, sconf, dconf);
#endif
  return DECLINED;
}

static void qos_audit_check(ap_directive_t * node) {
  ap_directive_t *pdir;
  for(pdir = node; pdir != NULL; pdir = pdir->next) {
    if(pdir->args && 
       ap_strstr_c(pdir->args, "%{"QS_PARP_PATH"}n") &&
       ap_strstr_c(pdir->args, "%{"QS_PARP_QUERY"}n")) {
      m_enable_audit = 1;
    }
    if(pdir->first_child != NULL) {
      qos_audit_check(pdir->first_child);
    }
  }
}

static int qos_module_check(const char *m) {
  module *modp = NULL;
  for(modp = ap_top_module; modp; modp = modp->next) {
    if(strcmp(modp->name, m) == 0) {
      return APR_SUCCESS;
    }
  }
  return DECLINED;
}

static int qos_chroot(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *bs) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(bs->module_config, &qos_module);
#ifndef QS_HAS_APACHE_PATH
  qos_user_t *u = qos_get_user_conf(bs->process->pool);
  if(u->server_start == 2) {
#endif
    if(sconf->chroot) {
      int rc = 0;
      ap_log_error(APLOG_MARK, APLOG_INFO, 0, bs, 
                   QOS_LOG_PFX(000)"change root to %s", sconf->chroot);
      if((rc = chroot(sconf->chroot)) < 0) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, bs, 
                     QOS_LOG_PFX(000)"chroot failed: %s", strerror(errno));
        return !DECLINED;
      }
      if((rc = chdir("/")) < 0) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, bs, 
                     QOS_LOG_PFX(000)"chroot failed (chdir /): %s", strerror(errno));
        return !DECLINED;
      }
    }
#ifndef QS_HAS_APACHE_PATH
  }
#endif
  return DECLINED;
}

/**
 * inits each child
 */
static void qos_child_init(apr_pool_t *p, server_rec *bs) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(bs->module_config, &qos_module);
  qos_user_t *u = qos_get_user_conf(sconf->act->ppool);
  qos_ifctx_list_t *inctx_t = NULL;
#ifdef QS_INTERNAL_TEST
#ifdef PREFORK_MPM
  int seed = getpid() + time(NULL) + apr_os_thread_current();
  srand(seed);
#endif
#endif
  qos_init_unique_id(p, bs);
  m_generation = u->generation;
#if APR_HAS_THREADS
  if(sconf->req_rate != -1) {
    inctx_t = apr_pcalloc(p, sizeof(qos_ifctx_list_t));
    inctx_t->exit = 0;
    inctx_t->table = apr_table_make(p, 64);
    sconf->inctx_t = inctx_t;
    if(apr_thread_mutex_create(&sconf->inctx_t->lock, APR_THREAD_MUTEX_DEFAULT, p) != APR_SUCCESS) {
      qos_disable_req_rate(bs, "create mutex");
    } else {
      apr_threadattr_t *tattr;
      if(apr_threadattr_create(&tattr, p) != APR_SUCCESS) {
        qos_disable_req_rate(bs, "create thread attr");
      } else {
        if(apr_thread_create(&sconf->inctx_t->thread, tattr,
                             qos_req_rate_thread, bs, p) != APR_SUCCESS) {
          qos_disable_req_rate(bs, "create thread");
        } else {
          server_rec *sn = bs->next;
          apr_pool_cleanup_register(p, bs, qos_cleanup_req_rate_thread, apr_pool_cleanup_null);
          while(sn) {
            qos_srv_config *sc = (qos_srv_config*)ap_get_module_config(sn->module_config, &qos_module);
            sc->inctx_t = inctx_t;
            sn = sn->next;
          }
        }
      }
    }
  }
#endif
  if(sconf->has_qos_cc) {
    apr_global_mutex_child_init(&u->qos_cc->lock, u->qos_cc->lock_file, p);
  }
  if(!sconf->act->child_init) {
    sconf->act->child_init = 1;
    /* propagate mutex to child process (required for certaing platforms) */
    apr_global_mutex_child_init(&sconf->act->lock, sconf->act->lock_file, p);
  }
}

/*
static const char *qos_search_docroot(apr_pool_t *pconf, server_rec *bs,
                                      ap_directive_t *node) {
  ap_directive_t *pdir;
  for(pdir = node; pdir != NULL; pdir = pdir->next) {
    if(strcasecmp(pdir->directive, "DocumentRoot") == 0) {
      return pdir->args;
    }
    if(pdir->first_child != NULL) {
      const char *docroot = qos_search_docroot(pconf, bs, pdir->first_child);
      if(docroot != NULL) {
        return docroot;
      }
    }
  }
  return NULL;
}
*/

static const char *detectErrorPage(apr_pool_t *ptemp, server_rec *bs, ap_directive_t *pdir) {
  const qos_errelt_t *e = m_error_pages;
  apr_finfo_t finfo;
  /*
  const char *docroot = qos_search_docroot(ptemp, bs, pdir);
  if(docroot) {
    docroot = ap_server_root_relative(ptemp, docroot);
  }
  */
  while(e->path != NULL) {
    char *path = ap_server_root_relative(ptemp, e->path);
    if(apr_stat(&finfo, path, APR_FINFO_TYPE, ptemp) == APR_SUCCESS) {
      return e->url;
    }
    /*
    if(docroot) {
      path = apr_pstrcat(ptemp, docroot, "/", e->path, NULL);
      if(apr_stat(&finfo, path, APR_FINFO_TYPE, ptemp) == APR_SUCCESS) {
        return e->url;
      }
    }
    */
    e++;
  }
  return NULL;
}

/**
 * inits the server configuration
 */
static int qos_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *bs) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(bs->module_config, &qos_module);
  char *rev = qos_revision(ptemp);
  qos_user_t *u;
  int net_prefer = 0;
  int cc_net_prefer_limit = 0;
  apr_status_t rv;
  ap_directive_t *pdir = ap_conftree;
  const char *error_page = detectErrorPage(ptemp, bs, pdir);
  int auto_error_page = 0;

  if(sconf->ip_type == QS_IP_V4) {
    m_ip_type = QS_IP_V4;
  } else {
    m_ip_type = QS_IP_V6;
  }

  qos_hostcode(ptemp, bs);
  QOS_MY_GENERATION(sconf->act->generation);
  for (pdir = ap_conftree; pdir != NULL; pdir = pdir->next) {
    if(strcasecmp(pdir->directive, "MaxClients") == 0 ||
       strcasecmp(pdir->directive, "MaxRequestWorkers") == 0) {
      net_prefer = atoi(pdir->args);
      sconf->max_clients = net_prefer;
    }
  }
  if(sconf->log_only) {
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, bs, 
                 QOS_LOG_PFX(009)"running in 'log only' mode - rules are NOT enforced!");
  }
  if(sconf->geo_limit != -1 && !sconf->geodb) {
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, bs, 
                 QOS_LOG_PFX(100)"QS_ClientGeoCountryDB has not been configured");
  }
  if(net_prefer <= 1) {
    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, bs, 
                 QOS_LOG_PFX(007)"could not determine MaxClients/MaxRequestWorkers!"
                 " You MUST set this directive within the Apache configuration file.");
  }

  // verify if this Apache version is supported/mod_qos has been tested for
  qos_version_check(bs);

  if(sconf->max_conn_close_percent) {
    sconf->max_conn_close = net_prefer * sconf->max_conn_close_percent / 100;
  }
  cc_net_prefer_limit = net_prefer * sconf->qos_cc_prefer / 100;
  if(sconf->qos_cc_prefer && net_prefer) {
    sconf->qos_cc_prefer = net_prefer;
    sconf->qos_cc_prefer_limit = cc_net_prefer_limit;
  } else {
    sconf->qos_cc_prefer = 0;
    sconf->qos_cc_prefer_limit = 0;
  }
  u = qos_get_user_conf(bs->process->pool);
  if(u == NULL) return !OK;
  u->server_start++;
  /* mutex init */
  if(sconf->act->lock_file == NULL) {
    sconf->act->lock_file = apr_psprintf(sconf->act->pool, "%s.mod_qos",
                                         qos_tmpnam(sconf->act->pool, bs));
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, bs, 
                 QOS_LOGD_PFX"create mutex (ACT)(%s)",
                 sconf->act->lock_file);
    rv = apr_global_mutex_create(&sconf->act->lock, sconf->act->lock_file,
                                 APR_LOCK_DEFAULT, sconf->act->pool);
    if (rv != APR_SUCCESS) {
      char buf[MAX_STRING_LEN];
      apr_strerror(rv, buf, sizeof(buf));
      ap_log_error(APLOG_MARK, APLOG_EMERG, 0, bs, 
                   QOS_LOG_PFX(004)"failed to create mutex (ACT)(%s): %s",
                   sconf->act->lock_file, buf);
      exit(1);
    }
#ifdef AP_NEED_SET_MUTEX_PERMS
    qos_unixd_set_global_mutex_perms(sconf->act->lock);
#endif
  }
  sconf->base_server = bs;
  sconf->act->timeout = apr_time_sec(bs->timeout);
  if(sconf->act->timeout == 0) sconf->act->timeout = 300;
  if(qos_init_shm(bs, sconf, sconf->act, sconf->location_t, net_prefer) != APR_SUCCESS) {
    return !OK;
  }
  apr_pool_cleanup_register(sconf->pool, sconf->act,
                            qos_cleanup_shm, apr_pool_cleanup_null);

  if((qos_module_check("mod_unique_id.c") != APR_SUCCESS) &&
     (qos_module_check("mod_navajo.cpp") != APR_SUCCESS)) {
    ap_log_error(APLOG_MARK, APLOG_WARNING, 0, bs, 
                 QOS_LOG_PFX(009)"mod_unique_id not available (mod_qos generates simple"
                 " request id if required)");
  }
  qos_audit_check(ap_conftree);
  qos_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
  if(m_requires_parp) {
    if(qos_module_check("mod_parp.c") != APR_SUCCESS) {
      qos_parp_hp_table_fn = NULL;
      ap_log_error(APLOG_MARK, APLOG_EMERG, 0, bs, 
                   QOS_LOG_PFX(009)"mod_parp not available"
                   " (required by some directives)");
    } else {
      qos_parp_hp_table_fn = APR_RETRIEVE_OPTIONAL_FN(parp_hp_table);
      parp_appl_body_data_fn = APR_RETRIEVE_OPTIONAL_FN(parp_body_data);
    }
  }
  if(u->server_start == 2) {
    int i;
    apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(sconf->hfilter_table)->elts;
    for(i = 0; i < apr_table_elts(sconf->hfilter_table)->nelts; i++) {
      qos_fhlt_r_t *he = (qos_fhlt_r_t *)entry[i].val;
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, bs, 
                   QOS_LOGD_PFX"request header filter rule (%s) %s: %s max=%d",
                   he->action == QS_FLT_ACTION_DROP ? "drop" : "deny", entry[i].key,
                   he->text, he->size);
    }
    entry = (apr_table_entry_t *)apr_table_elts(sconf->reshfilter_table)->elts;
    for(i = 0; i < apr_table_elts(sconf->reshfilter_table)->nelts; i++) {
      qos_fhlt_r_t *he = (qos_fhlt_r_t *)entry[i].val;
      ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, bs, 
                   QOS_LOGD_PFX"response header filter rule (%s) %s: %s max=%d",
                   he->action == QS_FLT_ACTION_DROP ? "drop" : "deny", entry[i].key,
                   he->text, he->size);
    }
  }
  if(sconf->has_qos_cc) {
    if(!u->qos_cc) {
      u->qos_cc = qos_cc_new(bs->process->pool, bs, sconf->qos_cc_size, sconf->qos_cc_limitTable);
      if(u->qos_cc == NULL) {
        return !OK;
      }
    } else {
      int configOk = 1;
      int limitTableSize = apr_table_elts(sconf->qos_cc_limitTable)->nelts;
      if(u->qos_cc->limitTable) {
        int i;
        apr_table_entry_t *te = (apr_table_entry_t *)apr_table_elts(sconf->qos_cc_limitTable)->elts;
        for(i = 0; i < limitTableSize; i++) {
          const char *name = te[i].key;
          qos_s_entry_limit_conf_t *newentry = (qos_s_entry_limit_conf_t *)te[i].val;
          qos_s_entry_limit_conf_t *entryConf = (qos_s_entry_limit_conf_t *)apr_table_get(u->qos_cc->limitTable, name);
          if(entryConf) {
            entryConf->limit = newentry->limit;
            entryConf->limit_time = newentry->limit_time;
            entryConf->condStr = NULL;
            entryConf->preg = NULL;
            if(newentry->condStr) {
              entryConf->condStr = apr_pstrdup(bs->process->pool, newentry->condStr);
#ifdef AP_REGEX_H
              entryConf->preg = ap_pregcomp(bs->process->pool, newentry->condStr, AP_REG_EXTENDED);
#else
              entryConf->preg = ap_pregcomp(bs->process->pool, newentry->condStr, REG_EXTENDED);
#endif
            }
          } else {
            // new variable
            configOk = 0;
          }
          if(apr_table_elts(u->qos_cc->limitTable)->nelts != limitTableSize) {
            // removed variable
            configOk = 0;
          }
        }
      } else {
        if(limitTableSize > 0) {
          // enabled after graceful restart
          configOk = 0;
        }
      }
      if(!configOk) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, bs, 
                     QOS_LOG_PFX(001)"QS_ClientEventLimitCount directives"
                     " can't be added/removed by graceful restart. A server"
                     " restart is required to apply the new configuration!");
      }
    }
  }
  if(sconf->error_page == NULL && error_page != NULL) {
    sconf->error_page = error_page;
    auto_error_page = 1;
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, bs, 
                 QOS_LOGD_PFX"QS_ErrorPage: use %s for server %s:%d (global)",
                 error_page,
                 bs->server_hostname == NULL ? "-" : bs->server_hostname,
                 bs->addrs->host_port);
  }
  {
    server_rec *s = bs->next;
    while(s) {
      qos_srv_config *ssconf = (qos_srv_config*)ap_get_module_config(s->module_config, &qos_module);
      QOS_MY_GENERATION(ssconf->act->generation);
      /* mutex init */
      if(ssconf->act->lock_file == NULL) {
        ssconf->act->lock_file = sconf->act->lock_file;
        ssconf->act->lock = sconf->act->lock;
      }
      ssconf->base_server = bs;
      ssconf->act->timeout = apr_time_sec(s->timeout);
      ssconf->qos_cc_prefer = sconf->qos_cc_prefer;
      ssconf->qos_cc_prefer_limit = sconf->qos_cc_prefer_limit;
      ssconf->max_clients = sconf->max_clients;
      if(ssconf->max_conn_close_percent) {
        ssconf->max_conn_close = net_prefer * ssconf->max_conn_close_percent / 100;
      }
      if(ssconf->act->timeout == 0) {
        ssconf->act->timeout = 300;
      }
      if(ssconf->is_virtual) {
        if(qos_init_shm(s, ssconf, ssconf->act, ssconf->location_t, net_prefer) != APR_SUCCESS) {
          return !OK;
        }
        apr_pool_cleanup_register(ssconf->pool, ssconf->act,
                                  qos_cleanup_shm, apr_pool_cleanup_null);
      }
      if(ssconf->error_page == NULL && error_page != NULL) {
        ssconf->error_page = error_page;
        auto_error_page |= 2;
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, bs, 
                     QOS_LOGD_PFX"QS_ErrorPage: use %s for server %s:%d",
                     error_page,
                     s->server_hostname == NULL ? "-" : s->server_hostname,
                     s->addrs->host_port);
      }
      s = s->next;
    }
  }
  if(auto_error_page) {
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, bs, 
                 QOS_LOG_PFX(009)"found default error document '%s'. Use the QS_ErrorPage"
                 " directive to override this default page.",
                 error_page);
  }
  ap_add_version_component(pconf, apr_psprintf(pconf, "mod_qos/%s", rev));
               
#ifdef QS_INTERNAL_TEST
  fprintf(stdout, "\033[1mmod_qos TEST BINARY, NOT FOR PRODUCTIVE USE\033[0m\n");
  fflush(stdout);
#endif
#ifndef QS_NO_STATUS_HOOK
  APR_OPTIONAL_HOOK(ap, status_hook, qos_ext_status_hook, NULL, NULL, APR_HOOK_MIDDLE);
#endif

  return DECLINED;
}

/**
 * mod_qos
 */
static int qos_favicon(request_rec *r) {
  int i;
  unsigned const char ico[] = {
    0x00,0x00,0x01,0x00,0x01,0x00,0x10,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x68,0x05,
    0x00,0x00,0x16,0x00,0x00,0x00,0x28,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x20,0x00,
    0x00,0x00,0x01,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x0f,0x29,0x21,0x00,0x11,0x29,0x21,0x00,0x9c,0x9d,0x9c,0x00,0x8d,0x8e,
    0x8d,0x00,0x65,0x65,0x65,0x00,0x73,0xaf,0x9d,0x00,0xf1,0xf3,0xf2,0x00,0x04,0x0e,
    0x0b,0x00,0x05,0x0e,0x0b,0x00,0x1b,0x3b,0x31,0x00,0x26,0x60,0x4d,0x00,0x45,0x45,
    0x45,0x00,0x9c,0xc8,0xb9,0x00,0x38,0x89,0x6e,0x00,0x35,0x7d,0x67,0x00,0x7d,0x7d,
    0x7d,0x00,0x6f,0x27,0x80,0x00,0x3d,0x28,0x3d,0x00,0x0c,0x10,0x0f,0x00,0x04,0x05,
    0x05,0x00,0x5f,0x64,0x62,0x00,0x20,0x50,0x42,0x00,0x85,0xca,0xb6,0x00,0x61,0x22,
    0x98,0x00,0x76,0xb4,0xa2,0x00,0x69,0x6a,0x6a,0x00,0x02,0x03,0x03,0x00,0xaa,0xda,
    0xca,0x00,0x25,0x5c,0x4a,0x00,0xfc,0xfc,0xfc,0x00,0x87,0xae,0xa2,0x00,0xaa,0xcc,
    0xc0,0x00,0x01,0x01,0x01,0x00,0x6a,0xa0,0x91,0x00,0x31,0x75,0x5f,0x00,0x44,0xa5,
    0x85,0x00,0xe6,0xe5,0xec,0x00,0x31,0x7a,0x62,0x00,0x0b,0x1d,0x16,0x00,0xc2,0xcb,
    0xdc,0x00,0x2e,0x6c,0x58,0x00,0x22,0x53,0x44,0x00,0xa5,0xd4,0xc4,0x00,0x3e,0x42,
    0x41,0x00,0x68,0x85,0x7b,0x00,0x31,0x5a,0x51,0x00,0x55,0x4e,0xd5,0x00,0x8b,0x8b,
    0x8a,0x00,0x02,0x06,0x05,0x00,0x04,0x06,0x05,0x00,0x48,0x62,0x5b,0x00,0x0c,0x1d,
    0x17,0x00,0x01,0x04,0x03,0x00,0x03,0x04,0x03,0x00,0x2f,0x3d,0x38,0x00,0x65,0x81,
    0x77,0x00,0xef,0xf1,0xf5,0x00,0x57,0x25,0x51,0x00,0xc1,0xbd,0xc3,0x00,0x34,0x81,
    0x69,0x00,0x39,0x5d,0x52,0x00,0xff,0xff,0xff,0x00,0x2f,0x31,0x31,0x00,0x79,0x7d,
    0xd5,0x00,0x1b,0x46,0x39,0x00,0x4d,0x46,0xdd,0x00,0x13,0x13,0x13,0x00,0x5a,0x40,
    0x71,0x00,0xb4,0xb4,0xb4,0x00,0x71,0x74,0x73,0x00,0x4c,0x59,0x55,0x00,0x02,0x02,
    0x02,0x00,0xec,0xec,0xec,0x00,0x6f,0x72,0x71,0x00,0x67,0x67,0x67,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3e,0x3e,
    0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,
    0x3e,0x3e,0x3e,0x4a,0x26,0x26,0x15,0x3e,0x3e,0x3e,0x3e,0x1e,0x28,0x39,0x3e,0x3f,
    0x3e,0x24,0x24,0x24,0x24,0x24,0x24,0x24,0x20,0x2f,0x11,0x18,0x25,0x3e,0x3e,0x3e,
    0x00,0x24,0x08,0x00,0x05,0x4b,0x21,0x42,0x3a,0x0f,0x40,0x3e,0x3e,0x3e,0x3e,0x17,
    0x2e,0x00,0x0c,0x45,0x00,0x00,0x44,0x12,0x24,0x09,0x3c,0x3e,0x3e,0x3e,0x3c,0x3c,
    0x00,0x3c,0x00,0x00,0x0d,0x2b,0x24,0x24,0x00,0x00,0x3c,0x46,0x3e,0x3e,0x3c,0x3c,
    0x30,0x43,0x24,0x31,0x1c,0x1c,0x0e,0x00,0x48,0x3b,0x3c,0x3c,0x3e,0x3e,0x3c,0x06,
    0x3e,0x00,0x23,0x1c,0x1c,0x1c,0x1c,0x00,0x36,0x3e,0x16,0x3c,0x3e,0x3e,0x3c,0x22,
    0x3e,0x00,0x33,0x1c,0x37,0x1f,0x1c,0x3d,0x14,0x3e,0x41,0x3c,0x3e,0x3e,0x3c,0x3c,
    0x49,0x00,0x00,0x32,0x1c,0x1c,0x2a,0x24,0x00,0x3e,0x3c,0x3c,0x3e,0x3e,0x47,0x3c,
    0x00,0x00,0x27,0x24,0x29,0x13,0x00,0x02,0x24,0x00,0x3c,0x0a,0x3e,0x3e,0x3e,0x3c,
    0x19,0x34,0x24,0x21,0x48,0x1b,0x00,0x00,0x01,0x0b,0x3c,0x3e,0x3e,0x3e,0x3e,0x3e,
    0x1d,0x3c,0x00,0x1a,0x3e,0x3e,0x10,0x00,0x3c,0x35,0x3e,0x3e,0x3e,0x3e,0x3e,0x2c,
    0x3e,0x3c,0x3c,0x3c,0x2d,0x38,0x3c,0x3c,0x3c,0x07,0x3f,0x3e,0x3e,0x3e,0x3e,0x3e,
    0x3e,0x3e,0x03,0x3c,0x3c,0x3c,0x3c,0x04,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,
    0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x3e,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
  ap_set_content_type(r, "image/x-icon");
  for(i=0; i < sizeof(ico); i++) {
    ap_rputc(ico[i], r);
  }
  return OK;
}

static int qos_console_dump(request_rec * r, const char *event) {
  qos_srv_config *sconf = sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config,
                                                                        &qos_module);
  if(sconf && sconf->has_qos_cc) {
    int i = 0;
    qos_user_t *u = qos_get_user_conf(sconf->act->ppool);
    qos_s_entry_t **e = NULL;
    /* table requires heap (100'000 ~ 4MB) but we avaoid io with drawn lock */
    apr_table_t *iptable = apr_table_make(r->pool, u->qos_cc->max);
    apr_table_entry_t *entry;
    ap_set_content_type(r, "text/plain");
    apr_global_mutex_lock(u->qos_cc->lock);            /* @CRT35 */
    e = u->qos_cc->ipd;
    for(i = 0; i < u->qos_cc->max; i++) {
      if((e[i]->ip6[0] != 0) ||
         (e[i]->ip6[1] != 0)) {
        char *k;
        int limit = 0;
        time_t limit_time = 0;
        if(u->qos_cc->limitTable) {
          int limitTableIndex;
          qos_s_entry_limit_conf_t *eventLimitConf = qos_getQSLimitEvent(u, event, &limitTableIndex);
          if(eventLimitConf) {
            limit = e[i]->limit[limitTableIndex].limit;
            limit_time = (eventLimitConf->limit_time >= (time(NULL) - e[i]->limit[limitTableIndex].limit_time)) ? 
              (eventLimitConf->limit_time - (time(NULL) - e[i]->limit[limitTableIndex].limit_time)) : 0;
          }
        }
        k = apr_psprintf(r->pool,
                         "%010d %s vip=%s lowprio=%s block=%d/%ld limit=%d/%ld",
                         i,
                         qos_ip_long2str(r->pool, e[i]->ip6),
                         e[i]->vip ? "yes" : "no",
                         e[i]->lowrate ? "yes" : "no",
                         e[i]->block,
                         (sconf->qos_cc_block_time >= (time(NULL) - e[i]->block_time)) ? 
                         (sconf->qos_cc_block_time - (time(NULL) - e[i]->block_time)) : 0,
                         limit,
                         limit_time);
        apr_table_addn(iptable, k, NULL);
      }
    }
    apr_global_mutex_unlock(u->qos_cc->lock);          /* @CRT35 */
    entry = (apr_table_entry_t *)apr_table_elts(iptable)->elts;
    for(i = 0; i < apr_table_elts(iptable)->nelts; ++i) {
      ap_rprintf(r, "%s\n", entry[i].key);
    }
    return OK;
  }
  ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                QOS_LOG_PFX(070)"console, not acceptable, qos client control has not been activated");
  return HTTP_NOT_ACCEPTABLE;
}

static int qos_handler_console(request_rec * r) {
  apr_table_t *qt;
  const char *ip;
  const char *cmd;
  const char *event;
  apr_uint64_t addr[2];
  qos_srv_config *sconf;
  int status = HTTP_NOT_ACCEPTABLE;;
  if (strcmp(r->handler, "qos-console") != 0) {
    return DECLINED;
  }
  sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);
  if(sconf->disable_handler == 1) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOS_LOG_PFX(072)"handler has been disabled for this host");
    return DECLINED;
  }
  apr_table_add(r->err_headers_out, "Cache-Control", "no-cache");
  qt = qos_get_query_table(r);
  ip = apr_table_get(qt, "address");
  cmd = apr_table_get(qt, "action");
  event = apr_table_get(qt, "event");
  if(event == NULL) {
    event = apr_pstrdup(r->pool, QS_LIMIT_DEFAULT);
  }
  if(!cmd || !ip) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOS_LOG_PFX(070)"console, not acceptable,"
                  " missing request query (action/address)");
    return HTTP_NOT_ACCEPTABLE;
  }
  if(ip) {
    int escerr = 0;
    char *ta = apr_pstrdup(r->pool, ip);
    qos_unescaping(ta, QOS_DEC_MODE_FLAGS_URL, &escerr);
    ip = ta;
  }
  if(!sconf->has_qos_cc) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOS_LOG_PFX(070)"console, not acceptable,"
                  " client data store has not been enabled");
    return HTTP_NOT_ACCEPTABLE;
  }
  if((strcasecmp(cmd, "search") == 0) && (strcmp(ip, "*") == 0)) {
    return qos_console_dump(r, event);
  }
  if(qos_ip_str2long(ip, &addr) == 0) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOS_LOG_PFX(070)"console, not acceptable,"
                  " invalid ip/wrong format");
    return HTTP_NOT_ACCEPTABLE;
  }
  if(sconf->has_qos_cc) {
    char *msg = "not available";
    qos_user_t *u = qos_get_user_conf(sconf->act->ppool);
    qos_s_entry_t **e = NULL;
    qos_s_entry_t new;
    int limitTableIndex = 0;
    qos_s_entry_limit_conf_t *eventLimitConf = NULL;
    int limit = 0;
    time_t limit_time = 0;
    apr_global_mutex_lock(u->qos_cc->lock);            /* @CRT34 */
    new.ip6[0] = addr[0];
    new.ip6[1] = addr[1];
    e = qos_cc_get0(u->qos_cc, &new, apr_time_sec(r->request_time));
    if(!e) {
      if(strcasecmp(cmd, "search") != 0) {
        e = qos_cc_set(u->qos_cc, &new, time(NULL));
        ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                      QOS_LOG_PFX(071)"console, add new client ip entry '%s'", ip);
      }
    }
    status = OK;
    if(u->qos_cc->limitTable) {
      eventLimitConf = qos_getQSLimitEvent(u, event, &limitTableIndex);
    }
    if(strcasecmp(cmd, "setvip") == 0) {
      (*e)->vip = 1;
    } else if(strcasecmp(cmd, "unsetvip") == 0) {
      (*e)->vip = 0;
    } else if(strcasecmp(cmd, "setlowprio") == 0) {
      (*e)->lowrate = time(NULL);
    } else if(strcasecmp(cmd, "unsetlowprio") == 0) {
      (*e)->lowrate = 0;
    } else if(strcasecmp(cmd, "unblock") == 0) {
      (*e)->block_time = 0;
      (*e)->block = 0;
    } else if(strcasecmp(cmd, "block") == 0) {
      (*e)->block_time = time(NULL);
      (*e)->block = sconf->qos_cc_block + 1000;
    } else if(strcasecmp(cmd, "unlimit") == 0) {
      if(eventLimitConf) {
        (*e)->limit[limitTableIndex].limit_time = 0;
        (*e)->limit[limitTableIndex].limit = 0;
      }
    } else if(strcasecmp(cmd, "limit") == 0) {
      if(eventLimitConf) {
        (*e)->limit[limitTableIndex].limit_time = time(NULL);
        (*e)->limit[limitTableIndex].limit = eventLimitConf->limit + 1000;
      }
    } else if(strcasecmp(cmd, "search") == 0) {
      /* nothing to do here */
    } else {
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                    QOS_LOG_PFX(070)"console, not acceptable, unknown action '%s'", cmd);
      status = HTTP_NOT_ACCEPTABLE;
    }
    if(e) {
      if(eventLimitConf) {
        limit = (*e)->limit[limitTableIndex].limit;
        limit_time = (eventLimitConf->limit_time >= (time(NULL) - (*e)->limit[limitTableIndex].limit_time)) ? 
          (eventLimitConf->limit_time - (time(NULL) - (*e)->limit[limitTableIndex].limit_time)) : 0;
      }
      msg = apr_psprintf(r->pool, "%s vip=%s lowprio=%s block=%d/%ld limit=%d/%ld", ip,
                         (*e)->vip ? "yes" : "no",
                         (*e)->lowrate ? "yes" : "no",
                         (*e)->block,
                         (sconf->qos_cc_block_time >= (time(NULL) - (*e)->block_time)) ? 
                         (sconf->qos_cc_block_time - (time(NULL) - (*e)->block_time)) : 0,
                         limit,
                         limit_time);
    }
    apr_global_mutex_unlock(u->qos_cc->lock);          /* @CRT34 */
    if(status == OK) {
      ap_set_content_type(r, "text/plain");
      ap_rprintf(r, "%s\n", msg);
      ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_INFO, 0, r,
                    QOS_LOG_PFX(071)"console, action '%s' applied to client ip entry '%s'",
                    cmd, ip);
    }
  } else {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOS_LOG_PFX(070)"console, not acceptable,"
                  " qos client control has not been activated");
    status = HTTP_NOT_ACCEPTABLE;
  }
  return status;
}

/**
 * viewer which may be used as an alternative to mod_status
 */
static int qos_handler_view(request_rec * r) {
  qos_srv_config *sconf;
  apr_table_t *qt;
  if (strcmp(r->handler, "qos-viewer") != 0) {
    return DECLINED;
  }
  sconf = (qos_srv_config*)ap_get_module_config(r->server->module_config, &qos_module);
  if(sconf->disable_handler == 1) {
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                  QOS_LOG_PFX(072)"handler has been disabled for this host");
    return DECLINED;
  }
  if(r->parsed_uri.path && (strstr(r->parsed_uri.path, "favicon.ico") != NULL)) {
    return qos_favicon(r);
  }
  apr_table_add(r->err_headers_out, "Cache-Control", "no-cache");
  qt = qos_get_query_table(r);
  if(qt && (apr_table_get(qt, "refresh") != NULL)) {
  apr_table_add(r->err_headers_out, "Refresh", "10");
  }
  if(qt && (apr_table_get(qt, "auto") != NULL)) {
    ap_set_content_type(r, "text/plain");
    qos_ext_status_short(r, qt);
    return OK;
  }
  ap_set_content_type(r, "text/html");
  if(!r->header_only) {
    ap_rputs("<html><head><title>mod_qos</title>\n", r);
    ap_rprintf(r,"<link rel=\"shortcut icon\" href=\"%s/favicon.ico\"/>\n",
               r->parsed_uri.path ? r->parsed_uri.path : "");
    ap_rputs("<meta http-equiv=\"content-type\" content=\"text/html; charset=ISO-8859-1\">\n", r);
    ap_rputs("<meta name=\"author\" content=\"Pascal Buchbinder\">\n", r);
    ap_rputs("<meta http-equiv=\"Pragma\" content=\"no-cache\">\n", r);
    ap_rputs("<style TYPE=\"text/css\">\n", r);
    ap_rputs("<!--", r);
    ap_rputs("  body {\n\
          background-color: rgb(248,250,246);\n\
          color: black;\n\
          font-family: arial, helvetica, verdana, sans-serif;\n\
   }\n\
  .btable{\n\
          background-color: white;\n\
          border: 1px solid; padding: 0px;\n\
          margin: 6px; width: 920px;\n\
          font-weight: normal;\n\
          border-collapse: collapse;\n\
  }\n\
  .rowts {\n\
          background-color: rgb(150,165,158);\n\
          vertical-align: top;\n\
          border: 1px solid;\n\
          border-color: black;\n\
          font-weight: normal;\n\
          padding: 0px;\n\
          margin: 0px;\n\
  }\n\
  .rowt {\n\
          background-color: rgb(210,220,215);\n\
          vertical-align: top;\n\
          border: 1px solid;\n\
          border-color: black;\n\
          font-weight: normal;\n\
          padding: 0px;\n\
          margin: 0px;\n\
  }\n\
  .rows {\n\
          background-color: rgb(228,235,230);\n\
          vertical-align: top;\n\
          border: 1px solid;\n\
          border-color: black;\n\
          font-weight: normal;\n\
          padding: 0px;\n\
          margin: 0px;\n\
  }\n\
  .row  {\n\
          background-color: white;\n\
          vertical-align: top;\n\
          border: 1px solid;\n\
          border-color: black;\n\
          font-weight: normal;\n\
          padding: 0px;\n\
          margin: 0px;\n\
  }\n\
  .rowe {\n\
          background-color: rgb(186,200,190);\n\
          vertical-align: top;\n\
          border: 1px solid;\n\
          border-color: black;\n\
          font-weight: normal;\n\
          padding: 0px;\n\
          margin: 0px;\n\
  }\n\
  .small {\n\
          font-size: 0.75em;\n\
          font-family: courier;\n\
  }\n\
  .prog-border {\n\
          height: 10px;\n\
          width: 150px;\n\
          background: #eee;\n\
          border: 1px solid #000;\n\
          padding: 2px;\n\
          font-family: arial, helvetica, verdana, sans-serif; font-size: 10px; color: #000;\n\
  }\n\
          .prog-bar {\n\
          height: 10px;\n\
          padding: 0;\n\
          background: #339900;\n\
          font-family: arial, helvetica, verdana, sans-serif; font-size: 10px; color: #000;\n\
  }\n\
  form      { display: inline; }\n", r);
    ap_rputs("-->\n", r);
    ap_rputs("</style>\n", r);
    ap_rputs("</head><body>\n", r);
    qos_ext_status_hook(r, 0);
    {
      apr_time_t nowtime = apr_time_now();
      ap_rvputs(r, "<div class=\"small\">",
                ap_ht_time(r->pool, nowtime, QS_ERR_TIME_FORMAT, 0), NULL);
      ap_rprintf(r, ", mod_qos %s\n", ap_escape_html(r->pool, qos_revision(r->pool)));

    }
    ap_rputs("</body></html>", r);
  }
  return OK;
}

static int qos_handler(request_rec * r) {
  int status = qos_handler_view(r);
  if(status != DECLINED) {
    return status;
  }
  status = qos_handler_console(r);
  if(status != DECLINED) {
    return status;
  }
  return DECLINED;
}

/**
 * insert response filter
 */
static void qos_insert_filter(request_rec *r) {
  ap_add_output_filter("qos-out-filter", NULL, r, r->connection);
}
static void qos_insert_err_filter(request_rec *r) {
  ap_add_output_filter("qos-out-err-filter", NULL, r, r->connection);
}

/************************************************************************
 * directiv handlers 
 ***********************************************************************/
static void qos_table_merge(apr_table_t *o, apr_table_t *b) {
  int i;
  apr_table_entry_t *entry = (apr_table_entry_t *)apr_table_elts(b)->elts;
  for(i = 0; i < apr_table_elts(b)->nelts; ++i) {
    if(apr_table_get(o, entry[i].key) == NULL) {
      // copy the pointer only!!!
      apr_table_setn(o, entry[i].key, entry[i].val);
    }
  }
}

static void *qos_dir_config_create(apr_pool_t *p, char *d) {
  qos_dir_config *dconf = apr_pcalloc(p, sizeof(qos_dir_config));
  dconf->path = d;
  dconf->rfilter_table = apr_table_make(p, 1);
  dconf->inheritoff = 0;
  dconf->headerfilter = QS_HEADERFILTER_OFF_DEFAULT;
  dconf->resheaderfilter = QS_HEADERFILTER_OFF_DEFAULT;
  dconf->bodyfilter_p = -1;
  dconf->bodyfilter_d = -1;
  dconf->dec_mode = QOS_DEC_MODE_FLAGS_URL;
  dconf->maxpost = -1;
  dconf->urldecoding = QS_OFF_DEFAULT;
  dconf->response_pattern = NULL;
  dconf->response_pattern_var = NULL;
  dconf->redirectif = apr_array_make(p, 20, sizeof(qos_redirectif_entry_t));
  dconf->disable_reqrate_events = apr_table_make(p, 1);
  dconf->setenvstatus_t = apr_table_make(p, 5);
  return dconf;
}

/**
 * merges dir config, inheritoff disables merge of rfilter_table.
 */
static void *qos_dir_config_merge(apr_pool_t *p, void *basev, void *addv) {
  qos_dir_config *b = (qos_dir_config *)basev;
  qos_dir_config *o = (qos_dir_config *)addv;
  qos_dir_config *dconf = apr_pcalloc(p, sizeof(qos_dir_config));
  dconf->path = o->path;
  if(o->headerfilter != QS_HEADERFILTER_OFF_DEFAULT) {
    dconf->headerfilter = o->headerfilter;
  } else {
    dconf->headerfilter = b->headerfilter;
  }
  if(o->resheaderfilter != QS_HEADERFILTER_OFF_DEFAULT) {
    dconf->resheaderfilter = o->resheaderfilter;
  } else {
    dconf->resheaderfilter = b->resheaderfilter;
  }
  if(o->bodyfilter_p != -1) {
    dconf->bodyfilter_p = o->bodyfilter_p;
  } else {
    dconf->bodyfilter_p = b->bodyfilter_p;
  }
  if(o->bodyfilter_d != -1) {
    dconf->bodyfilter_d = o->bodyfilter_d;
  } else {
    dconf->bodyfilter_d = b->bodyfilter_d;
  }
  if((o->dec_mode != QOS_DEC_MODE_FLAGS_URL) ||
     (o->inheritoff)) {
    dconf->dec_mode = o->dec_mode;
  } else {
    dconf->dec_mode = b->dec_mode;
  }
  if(o->inheritoff) {
    dconf->rfilter_table = o->rfilter_table;
  } else {
    dconf->rfilter_table = qos_table_merge_create(p, b->rfilter_table, o->rfilter_table);
  }
  if(o->maxpost != -1) {
    dconf->maxpost = o->maxpost;
  } else {
    dconf->maxpost = b->maxpost;
  }
  if(o->urldecoding == QS_OFF_DEFAULT) {
    dconf->urldecoding = b->urldecoding;
  } else {
    dconf->urldecoding = o->urldecoding;
  }
  if(o->response_pattern) {
    dconf->response_pattern = o->response_pattern;
    dconf->response_pattern_var = o->response_pattern_var;
  } else {
    dconf->response_pattern = b->response_pattern;
    dconf->response_pattern_var = b->response_pattern_var;
  }
  dconf->disable_reqrate_events = qos_table_merge_create(p, b->disable_reqrate_events,
                                                         o->disable_reqrate_events);
  dconf->redirectif = apr_array_append(p, b->redirectif, o->redirectif);
  dconf->setenvstatus_t = apr_table_copy(p, b->setenvstatus_t);
  qos_table_merge(dconf->setenvstatus_t, o->setenvstatus_t);
  return dconf;
}

static void *qos_srv_config_create(apr_pool_t *p, server_rec *s) {
  qos_srv_config *sconf;
  apr_pool_t *act_pool;
  apr_pool_create(&act_pool, NULL);
  sconf =(qos_srv_config *)apr_pcalloc(p, sizeof(qos_srv_config));
  sconf->pool = p;
  sconf->chroot = NULL;
  sconf->location_t = apr_table_make(sconf->pool, 2);
  sconf->setenvif_t = apr_table_make(sconf->pool, 1);
  sconf->setenv_t = apr_table_make(sconf->pool, 1);
  sconf->setreqheader_t = apr_table_make(sconf->pool, 5);
  sconf->setreqheaderlate_t = apr_table_make(sconf->pool, 5);
  sconf->unsetresheader_t = apr_table_make(sconf->pool, 5);
  sconf->setenvifquery_t = apr_table_make(sconf->pool, 1);
  sconf->setenvifparp_t = apr_table_make(sconf->pool, 1);
  sconf->setenvifparpbody_t = apr_table_make(sconf->pool, 1);
  sconf->setenvstatus_t = apr_table_make(sconf->pool, 5);
  sconf->setenvresheader_t = apr_table_make(sconf->pool, 1);
  sconf->setenvresheadermatch_t = apr_table_make(sconf->pool, 1);
  sconf->setenvres_t = apr_table_make(sconf->pool, 1);
  sconf->headerfilter = QS_HEADERFILTER_OFF_DEFAULT;
  sconf->resheaderfilter = QS_HEADERFILTER_OFF_DEFAULT;
  sconf->redirectif = apr_array_make(p, 20, sizeof(qos_redirectif_entry_t));
  sconf->error_page = NULL;
  sconf->req_rate = -1;
  sconf->req_rate_start = 0;
  sconf->min_rate = -1;
  sconf->min_rate_max = -1;
  sconf->min_rate_off = 0;
  sconf->max_clients = 1024;
  sconf->has_event_filter = 0;
  sconf->has_event_limit = 0;
  sconf->event_limit_a = apr_array_make(p, 2, sizeof(qos_event_limit_entry_t));
  sconf->mfile = NULL;
  sconf->act = (qs_actable_t *)apr_pcalloc(act_pool, sizeof(qs_actable_t));
  sconf->act->pool = act_pool;
  sconf->act->ppool = s->process->pool;
  sconf->act->generation = -1;
  // QOS_MY_GENERATION(sconf->act->generation);
  sconf->act->child_init = 0;
  sconf->act->timeout = apr_time_sec(s->timeout);
  sconf->act->has_events = 0;
  sconf->act->lock_file = NULL;
  sconf->is_virtual = s->is_virtual;
  sconf->cookie_name = apr_pstrdup(sconf->pool, QOS_COOKIE_NAME);
  sconf->cookie_path = apr_pstrdup(sconf->pool, "/");
  sconf->user_tracking_cookie = NULL;
  sconf->max_age = atoi(QOS_MAX_AGE);
  sconf->header_name = NULL;
  sconf->header_name_drop = 0;
  sconf->header_name_regex = NULL;
  sconf->ip_header_name = NULL;
  sconf->ip_header_name_drop = 0;
  sconf->ip_header_name_regex = NULL;
  sconf->vip_user = 0;
  sconf->vip_ip_user = 0;
  sconf->max_conn = -1;
  sconf->max_conn_close = -1;
  sconf->max_conn_per_ip = -1;
  sconf->max_conn_per_ip_connections = -1;
  sconf->exclude_ip = apr_table_make(sconf->pool, 2);
  sconf->hfilter_table = apr_table_make(p, 5);
  sconf->reshfilter_table = apr_table_make(p, 5);
  sconf->disable_reqrate_events = apr_table_make(p, 1);
  sconf->log_only = 0;
  sconf->has_qos_cc = 0;
  sconf->qos_cc_size = 50000;
  sconf->qos_cc_prefer = 0;
  sconf->qos_cc_prefer_limit = 0;
  sconf->qos_cc_event = 0;
  sconf->qos_cc_event_req = -1;
  sconf->qos_cc_block = 0;
  sconf->qos_cc_serialize = 0;
  sconf->cc_tolerance = atoi(QOS_CC_BEHAVIOR_TOLERANCE_STR);
  sconf->qs_req_rate_tm = QS_REQ_RATE_TM;
  sconf->geodb = NULL;
  sconf->geodb_size = 0;
  sconf->geo_limit = -1;
  sconf->geo_priv = apr_table_make(p, 20);
  sconf->ip_type = QS_IP_V6_DEFAULT;
  sconf->qos_cc_block_time = 600;
  sconf->qos_cc_limitTable = apr_table_make(p, 5);
  sconf->qos_cc_forwardedfor = NULL;
  sconf->disable_handler = -1;
  sconf->maxpost = -1;
  sconf->milestones = NULL;
  sconf->milestone_timeout = QOS_MILESTONE_TIMEOUT;
  sconf->static_on = -1;
  sconf->static_html = 0;
  sconf->static_cssjs = 0;
  sconf->static_img = 0;
  sconf->static_other = 0;
  sconf->static_notmodified = 0;
  if(!s->is_virtual) {
    char *msg = qos_load_headerfilter(p, sconf->hfilter_table, qs_header_rules);
    if(msg) {
      ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, 
                   QOS_LOG_PFX(006)"could not compile request header filter rules: %s", msg);
      exit(1);
    }
    msg = qos_load_headerfilter(p, sconf->reshfilter_table, qs_res_header_rules);
    if(msg) {
      ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s, 
                   QOS_LOG_PFX(006)"could not compile response header filter rules: %s", msg);
      exit(1);
    }
  }

  {
    int len = EVP_MAX_KEY_LENGTH;
    unsigned char *rand = apr_pcalloc(p, len);
    RAND_bytes(rand, len);
    EVP_BytesToKey(EVP_des_ede3_cbc(), EVP_sha1(), NULL, rand, len, 1, sconf->key, NULL);
    sconf->keyset = 0;
  }
#ifdef QS_INTERNAL_TEST
  {
    int i;
    sconf->testip = apr_table_make(sconf->pool, QS_SIM_IP_LEN);
    sconf->enable_testip = 1;
    for(i = 0; i < QS_SIM_IP_LEN; i++) {
      char *qsmi = apr_psprintf(p, "%d.%d.%d.%d", rand()%255, rand()%255, rand()%255, rand()%255);
      apr_table_add(sconf->testip, apr_psprintf(p, "%d", i), qsmi);
    }
  }
#endif
  return sconf;
}

/**
 * "merges" server configuration: virtual host overwrites global settings (if
 * any rule has been specified)
 * but: global settings such as header filter table and connection timeouts
 * are always used from the base server
 */
static void *qos_srv_config_merge(apr_pool_t *p, void *basev, void *addv) {
  qos_srv_config *b = (qos_srv_config *)basev;
  qos_srv_config *o = (qos_srv_config *)addv;
  /* GLOBAL ONLY directives: */
  o->chroot = b->chroot;
  o->hfilter_table = b->hfilter_table;
  o->reshfilter_table = b->reshfilter_table;
  o->log_only = b->log_only;
  o->has_qos_cc = b->has_qos_cc;
  o->qos_cc_size = b->qos_cc_size;
  o->qos_cc_prefer = b->qos_cc_prefer;
  o->qos_cc_prefer_limit = b->qos_cc_prefer_limit;
  o->qos_cc_event = b->qos_cc_event;
  o->qos_cc_event_req = b->qos_cc_event_req;
  o->qos_cc_block = b->qos_cc_block;
  o->qos_cc_block_time = b->qos_cc_block_time;
  o->qos_cc_limitTable = b->qos_cc_limitTable;
  o->qos_cc_forwardedfor = b->qos_cc_forwardedfor;
  o->qos_cc_serialize = b->qos_cc_serialize;
  o->cc_tolerance = b->cc_tolerance;
  o->qs_req_rate_tm = b->qs_req_rate_tm;
  o->geodb = b->geodb;
  o->geodb_size = b->geodb_size;
  o->geo_limit = b->geo_limit;
  o->geo_priv = b->geo_priv;
  o->ip_type = b->ip_type;
  o->req_rate = b->req_rate;
  o->req_rate_start = b->req_rate_start;
  o->min_rate = b->min_rate;
  o->min_rate_max = b->min_rate_max;
  o->event_limit_a = apr_array_append(p, b->event_limit_a, o->event_limit_a);
  /* end GLOBAL ONLY directives */
  if(o->disable_handler == -1) {
    o->disable_handler = b->disable_handler;
  }
#ifdef QS_INTERNAL_TEST
  o->enable_testip = b->enable_testip;
#endif
  if(o->error_page == NULL) {
    o->error_page = b->error_page;
  }
  qos_table_merge(o->location_t, b->location_t);
  qos_table_merge(o->setenvif_t, b->setenvif_t);
  qos_table_merge(o->setenv_t, b->setenv_t);
  qos_table_merge(o->setreqheader_t, b->setreqheader_t);
  qos_table_merge(o->setreqheaderlate_t, b->setreqheaderlate_t);
  qos_table_merge(o->unsetresheader_t, b->unsetresheader_t);
  qos_table_merge(o->setenvifquery_t, b->setenvifquery_t);
  qos_table_merge(o->setenvifparp_t, b->setenvifparp_t);
  qos_table_merge(o->setenvifparpbody_t, b->setenvifparpbody_t);
  qos_table_merge(o->setenvstatus_t, b->setenvstatus_t);
  qos_table_merge(o->setenvresheader_t, b->setenvresheader_t);
  qos_table_merge(o->setenvresheadermatch_t, b->setenvresheadermatch_t);
  qos_table_merge(o->setenvres_t, b->setenvres_t);
  qos_table_merge(o->exclude_ip, b->exclude_ip);
  o->disable_reqrate_events = qos_table_merge_create(p, b->disable_reqrate_events,
                                                     o->disable_reqrate_events);
  if(o->headerfilter == QS_HEADERFILTER_OFF_DEFAULT) {
    o->headerfilter = b->headerfilter;
  }
  if(o->resheaderfilter == QS_HEADERFILTER_OFF_DEFAULT) {
    o->resheaderfilter = b->resheaderfilter;
  }
  o->redirectif = apr_array_append(p, b->redirectif, o->redirectif);
  if(o->mfile == NULL) {
    o->mfile = b->mfile;
  }
  if(strcmp(o->cookie_name, QOS_COOKIE_NAME) == 0) {
    o->cookie_name = b->cookie_name;
  }
  if(strcmp(o->cookie_path, "/") == 0) {
    o->cookie_path = b->cookie_path;
  }
  if(o->max_age == atoi(QOS_MAX_AGE)) {
    o->max_age = b->max_age;
  }
  if(o->user_tracking_cookie == NULL) {
    o->user_tracking_cookie = b->user_tracking_cookie;
    o->user_tracking_cookie_force = b->user_tracking_cookie_force;
  }
  if(o->keyset == 0) {
    memcpy(o->key, b->key, sizeof(o->key));
  }
  if(o->header_name == NULL) {
    o->header_name = b->header_name;
    o->header_name_drop = b->header_name_drop;
    o->header_name_regex = b->header_name_regex;
  }
  if(o->ip_header_name == NULL) {
    o->ip_header_name = b->ip_header_name;
    o->ip_header_name_drop = b->ip_header_name_drop;
    o->ip_header_name_regex = b->ip_header_name_regex;
  }
  if(o->vip_user == 0) {
    o->vip_user = b->vip_user;
  }
  if(o->vip_ip_user == 0) {
    o->vip_ip_user = b->vip_ip_user;
  }
  if(o->max_conn == -1) {
    o->max_conn = b->max_conn;
  }
  if(o->max_conn_close == -1) {
    o->max_conn_close = b->max_conn_close;
    o->max_conn_close_percent = b->max_conn_close_percent;
  }
  if(o->max_conn_per_ip == -1) {
    o->max_conn_per_ip = b->max_conn_per_ip;
  }
  if(o->max_conn_per_ip_connections == -1) {
    o->max_conn_per_ip_connections = b->max_conn_per_ip_connections;
  }
  if(o->has_event_filter == 0) {
    o->has_event_filter = b->has_event_filter;
  }
  if(o->has_event_limit == 0) {
    o->has_event_limit = b->has_event_limit;
  }
  if(o->maxpost == -1) {
    o->maxpost = b->maxpost;
  }
  if(o->milestones == NULL) {
    o->milestones = b->milestones;
    o->milestone_timeout = b->milestone_timeout;
  }
  if(o->static_on == -1) {
    /* use base settings if not configured per vhost */
    o->static_on = b->static_on;
    o->static_html = b->static_html;
    o->static_cssjs = b->static_cssjs;
    o->static_img = b->static_img;
    o->static_other = b->static_other;
    o->static_notmodified = b->static_notmodified;
  }
  return o;
}

static const char *qos_logonly_cmd(cmd_parms *cmd, void *dcfg, int flag) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->log_only = flag;
  return NULL;
}

static const char *qos_mfile_cmd(cmd_parms *cmd, void *dcfg, const char *path) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  apr_finfo_t finfo;
  apr_status_t rc;
  if(!path[0]) {
    return apr_psprintf(cmd->pool, "%s: invalid path",
                        cmd->directive->directive);
  }
  if((rc = apr_stat(&finfo, path, APR_FINFO_TYPE, cmd->pool)) != APR_SUCCESS) {
    char *p = apr_pstrdup(cmd->pool, path);
    /* file? */
    if(p[strlen(p)-1] == '/') {
      return apr_psprintf(cmd->pool, "%s: path does not exist",
                          cmd->directive->directive);
    } else {
      char *e = strrchr(p, '/');
      if(e) {
        e[0] = '\0';
      }
      if(((rc = apr_stat(&finfo, p, APR_FINFO_TYPE, cmd->pool)) != APR_SUCCESS) ||
         (finfo.filetype != APR_DIR)){
        return apr_psprintf(cmd->pool, "%s: path does not exist",
                            cmd->directive->directive);
      }
    }
  }
  sconf->mfile = apr_pstrdup(cmd->pool, path);
  return NULL;
}

/**
 * command to define the concurrent request limitation for a location
 */
static const char *qos_loc_con_cmd(cmd_parms *cmd, void *dcfg, const char *loc, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_table_get(sconf->location_t, loc);
  if(rule == NULL) {
    rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
    rule->url = apr_pstrdup(cmd->pool, loc);
  }
  rule->limit = atoi(limit);
  if((rule->limit < 0) || ((rule->limit == 0) && limit && (strcmp(limit, "0") != 0))) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >=0", 
                        cmd->directive->directive);
  }
  rule->event = NULL;
  rule->regex = NULL;
  rule->condition = NULL;
  apr_table_setn(sconf->location_t, apr_pstrdup(cmd->pool, loc), (char *)rule);
  return NULL;
}

/**
 * QS_LocRequestPerSecLimit: command to define the req/sec limitation for a location
 */
static const char *qos_loc_rs_cmd(cmd_parms *cmd, void *dcfg, const char *loc, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_table_get(sconf->location_t, loc);
  if(rule == NULL) {
    rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
    rule->url = apr_pstrdup(cmd->pool, loc);
  }
  rule->req_per_sec_limit = atol(limit);
  if(rule->req_per_sec_limit == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  rule->event = NULL;
  rule->regex = NULL;
  rule->condition = NULL;
  apr_table_setn(sconf->location_t, apr_pstrdup(cmd->pool, loc), (char *)rule);
  return NULL;
}

/**
 * QS_LocKBytesPerSecLimit: command to define the kbytes/sec limitation for a location
 */
static const char *qos_loc_bs_cmd(cmd_parms *cmd, void *dcfg, const char *loc, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_table_get(sconf->location_t, loc);
  if(rule == NULL) {
    rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
    rule->url = apr_pstrdup(cmd->pool, loc);
  }
  rule->kbytes_per_sec_limit = atol(limit);
  if(rule->kbytes_per_sec_limit == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  rule->event = NULL;
  rule->regex = NULL;
  rule->condition = NULL;
  apr_table_setn(sconf->location_t, apr_pstrdup(cmd->pool, loc), (char *)rule);
  return NULL;
}

/**
 * QS_LocRequestLimitMatch: defines the maximum of concurrent requests matching the specified
 * request line pattern
 */
static const char *qos_match_con_cmd(cmd_parms *cmd, void *dcfg, const char *match, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_table_get(sconf->location_t, match);
  if(rule == NULL) {
    rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
    rule->url = apr_pstrdup(cmd->pool, match);
  }
  rule->limit = atoi(limit);
  if((rule->limit < 0) || ((rule->limit == 0) && limit && (strcmp(limit, "0") != 0))) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >=0", 
                        cmd->directive->directive);
  }
#ifdef AP_REGEX_H
  rule->regex = ap_pregcomp(cmd->pool, match, AP_REG_EXTENDED);
#else
  rule->regex = ap_pregcomp(cmd->pool, match, REG_EXTENDED);
#endif
  if(rule->regex == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to compile regular expession (%s)",
                       cmd->directive->directive, match);
  }
  rule->event = NULL;
  rule->condition = NULL;
  apr_table_setn(sconf->location_t, apr_pstrdup(cmd->pool, match), (char *)rule);
  return NULL;
}

/**
 * QS_CondLocRequestLimitMatch: defines the maximum of concurrent requests
 * matching the specified request line pattern
 */
static const char *qos_cond_match_con_cmd(cmd_parms *cmd, void *dcfg, const char *match,
                                   const char *limit, const char *pattern) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
  rule->url = apr_pstrdup(cmd->pool, match);
  rule->limit = atoi(limit);
  if((rule->limit < 0) || ((rule->limit == 0) && limit && (strcmp(limit, "0") != 0))) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >=0", 
                        cmd->directive->directive);
  }
#ifdef AP_REGEX_H
  rule->regex = ap_pregcomp(cmd->pool, match, AP_REG_EXTENDED);
  rule->condition = ap_pregcomp(cmd->pool, pattern, AP_REG_EXTENDED);
#else
  rule->regex = ap_pregcomp(cmd->pool, match, REG_EXTENDED);
  rule->condition = ap_pregcomp(cmd->pool, pattern, REG_EXTENDED);
#endif
  if(rule->regex == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to compile regular expession (%s)",
                       cmd->directive->directive, match);
  }
  if(rule->condition == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to compile regular expession (%s)",
                       cmd->directive->directive, pattern);
  }
  rule->event = NULL;
  apr_table_setn(sconf->location_t, apr_pstrcat(cmd->pool, match, "##conditional##", NULL), (char *)rule);
  return NULL;
}

/**
 * QS_LocRequestPerSecLimitMatch: defines the maximum requests/sec for
 * the matching request line pattern
 */
static const char *qos_match_rs_cmd(cmd_parms *cmd, void *dcfg, const char *match, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_table_get(sconf->location_t, match);
  if(rule == NULL) {
    rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
    rule->url = apr_pstrdup(cmd->pool, match);
  }
  rule->req_per_sec_limit = atol(limit);
  if(rule->req_per_sec_limit == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
#ifdef AP_REGEX_H
  rule->regex = ap_pregcomp(cmd->pool, match, AP_REG_EXTENDED);
#else
  rule->regex = ap_pregcomp(cmd->pool, match, REG_EXTENDED);
#endif
  if(rule->regex == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to compile regular expession (%s)",
                       cmd->directive->directive, match);
  }
  rule->event = NULL;
  rule->condition = NULL;
  apr_table_setn(sconf->location_t, apr_pstrdup(cmd->pool, match), (char *)rule);
  return NULL;
}

/**
 * QS_LocKBytesPerSecLimitMatch: defines the maximum kbytes/sec for
 * the matching request line pattern
 */
static const char *qos_match_bs_cmd(cmd_parms *cmd, void *dcfg, const char *match, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule = (qs_rule_ctx_t *)apr_table_get(sconf->location_t, match);
  if(rule == NULL) {
    rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
    rule->url = apr_pstrdup(cmd->pool, match);
  }
  rule->kbytes_per_sec_limit = atol(limit);
  if(rule->kbytes_per_sec_limit == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
#ifdef AP_REGEX_H
  rule->regex = ap_pregcomp(cmd->pool, match, AP_REG_EXTENDED);
#else
  rule->regex = ap_pregcomp(cmd->pool, match, REG_EXTENDED);
#endif
  if(rule->regex == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to compile regular expession (%s)",
                       cmd->directive->directive, match);
  }
  rule->event = NULL;
  rule->condition = NULL;
  apr_table_setn(sconf->location_t, apr_pstrdup(cmd->pool, match), (char *)rule);
  return NULL;
}

/**
 * sets the default limitation of cuncurrent requests
 */
static const char *qos_loc_con_def_cmd(cmd_parms *cmd, void *dcfg, const char *limit) {
  return qos_loc_con_cmd(cmd, dcfg, "/", limit);
}

/**
 * QS_EventRequestLimit: defines the number of concurrent events
 */
static const char *qos_event_req_cmd(cmd_parms *cmd, void *dcfg, const char *event, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
  const char *p = ap_strchr_c(event, '=');
  rule->url = apr_pstrcat(cmd->pool, "var=(", event, ")", NULL);
  rule->limit = atoi(limit);
  rule->req_per_sec_limit = 0;
  rule->req_per_sec_limit = 0;
  if((rule->limit < 0) || ((rule->limit == 0) && limit && (strcmp(limit, "0") != 0))) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >=0", 
                        cmd->directive->directive);
  }
  sconf->has_event_filter = 1;
  if(p) {
    p++;
#ifdef AP_REGEX_H
    rule->regex_var = ap_pregcomp(cmd->pool, p, AP_REG_EXTENDED);
#else
    rule->regex_var = ap_pregcomp(cmd->pool, p, REG_EXTENDED);
#endif
    if(rule->regex_var == NULL) {
      return apr_psprintf(cmd->pool, "%s: failed to compile regex (%s)",
                          cmd->directive->directive, p);
    }
    rule->event = apr_pstrndup(cmd->pool, event, p - event - 1);
  } else {
    rule->regex_var = NULL;
    rule->event = apr_pstrdup(cmd->pool, event);
  }
  rule->regex = NULL;
  rule->condition = NULL;
  apr_table_setn(sconf->location_t, rule->url, (char *)rule);
  return NULL;
}

/**
 * QS_EventPerSecLimit: defines the maximum requests/sec for the matching variable.
 */
static const char *qos_event_rs_cmd(cmd_parms *cmd, void *dcfg, const char *event, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
  rule->url = apr_pstrcat(cmd->pool, "var=[", event, "]", NULL);
  rule->req_per_sec_limit = atol(limit);
  rule->kbytes_per_sec_limit = 0;
  if(rule->req_per_sec_limit == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  sconf->has_event_limit = 1;
  rule->event = apr_pstrdup(cmd->pool, event);
  rule->regex = NULL;
  rule->condition = NULL;
  rule->limit = -1;
  apr_table_setn(sconf->location_t, rule->url, (char *)rule);
  return NULL;
}

static const char *qos_event_hard_bandwidth_cmd(cmd_parms *cmd, void *dcfg, const char *event,
                                                const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
  long tmp_limit;
  char *endptr;
  errno = 0;
  tmp_limit = strtol(limit, &endptr, 10);
  if (*endptr != '\0' || errno) {
    return apr_pstrcat(cmd->pool, "Bad bandwidth limit: ", limit, NULL);
  }
  rule->hard_kbytes_per_sec_limit = tmp_limit;
  rule->url = apr_pstrcat(cmd->pool, "var={", event, "}", NULL);
  sconf->has_event_limit = 1;
  rule->event = apr_pstrdup(cmd->pool, event);
  rule->regex = NULL;
  rule->condition = NULL;
  rule->limit = -1;
  apr_table_setn(sconf->location_t, rule->url, (char *)rule);
  return NULL;
}

/**
 * QS_EventKBytesPerSecLimit: maximum download per event
 */
static const char *qos_event_bps_cmd(cmd_parms *cmd, void *dcfg, const char *event, const char *limit) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qs_rule_ctx_t *rule =  (qs_rule_ctx_t *)apr_pcalloc(cmd->pool, sizeof(qs_rule_ctx_t));
  rule->url = apr_pstrcat(cmd->pool, "var={", event, "}", NULL);
  rule->kbytes_per_sec_limit = atol(limit);
  rule->req_per_sec_limit = 0;
  if(rule->kbytes_per_sec_limit == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  sconf->has_event_limit = 1;
  rule->event = apr_pstrdup(cmd->pool, event);
  rule->regex = NULL;
  rule->condition = NULL;
  rule->limit = -1;
  apr_table_setn(sconf->location_t, rule->url, (char *)rule);
  return NULL;
}

static const char *qos_event_limit_cmd(cmd_parms *cmd, void *dcfg, const char *event,
                                       const char *number, const char *seconds) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qos_event_limit_entry_t *new = apr_array_push(sconf->event_limit_a);
  new->env_var = apr_pstrdup(cmd->pool, event);
  new->max = atoi(number);
  new->seconds = atoi(seconds);
  new->action = QS_EVENT_ACTION_DENY;
  if(new->max == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  if(new->seconds == 0) {
    return apr_psprintf(cmd->pool, "%s: seconds must be numeric value >0", 
                        cmd->directive->directive);
  }
  return NULL;
}

static const char *qos_event_setenvstatus_cmd(cmd_parms *cmd, void *dcfg, const char *rc, const char *var) {
  apr_table_t *setenvstatus_t;
  if(cmd->path) {
    qos_dir_config *dconf = (qos_dir_config*)dcfg;
    setenvstatus_t = dconf->setenvstatus_t;
  } else {
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                  &qos_module);
    setenvstatus_t = sconf->setenvstatus_t;
  }

  if(strcasecmp(rc, QS_CLOSE) == 0) {
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if(err != NULL) {
      return apr_psprintf(cmd->pool, "%s: "QS_CLOSE" may only be defined globally",
                          cmd->directive->directive);
    }
    if(strcasecmp(var, QS_BLOCK) != 0) {
      return apr_psprintf(cmd->pool, "%s: "QS_CLOSE" may only be defined for the event "QS_BLOCK,
                          cmd->directive->directive);
    }
  } else if(strcasecmp(rc, QS_EMPTY_CON) == 0) {
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if(err != NULL) {
      return apr_psprintf(cmd->pool, "%s: "QS_EMPTY_CON" may only be defined globally",
                          cmd->directive->directive);
    }
    if(strcasecmp(var, QS_BLOCK) != 0) {
      return apr_psprintf(cmd->pool, "%s: "QS_EMPTY_CON" may only be defined for the event "QS_BLOCK,
                          cmd->directive->directive);
    }
  } else {
    int code = atoi(rc);
    if(code <= 0) {
      return apr_psprintf(cmd->pool, "%s: invalid HTTP status code",
                          cmd->directive->directive);    
    }
  }
  apr_table_set(setenvstatus_t, rc, var);
  return NULL;
}

/** QS_SetEnvIfResBody */
static const char *qos_event_setenvresbody_cmd(cmd_parms *cmd, void *dcfg, const char *pattern,
                                               const char *var) {
  qos_dir_config *dconf = (qos_dir_config*)dcfg;
  if(dconf->response_pattern) {
    return apr_psprintf(cmd->pool, "%s: only one pattern must be configured for a location",
                        cmd->directive->directive);
  }
  dconf->response_pattern = apr_pstrdup(cmd->pool, pattern);
  dconf->response_pattern_var = apr_pstrdup(cmd->pool, var);
  return NULL;
}

/* QS_SetEnv */
static const char *qos_setenv_cmd(cmd_parms *cmd, void *dcfg, const char *variable,
                                  const char *value) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  if(!variable[0] || !value[0]) {
    return apr_psprintf(cmd->pool, "%s: invalid parameter",
                        cmd->directive->directive);
  }
  if(ap_strchr_c(variable, '=')) {
    return apr_psprintf(cmd->pool, "%s: variable must not contain a '='",
                        cmd->directive->directive);
  }
  apr_table_set(sconf->setenv_t, apr_pstrcat(cmd->pool, variable, "=", value, NULL), variable);
  return NULL;
}

/* QS_SetReqHeader */
static const char *qos_setreqheader_cmd(cmd_parms *cmd, void *dcfg, const char *header,
                                        const char *variable, const char *late) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);

  if(!variable[0] || !header[0]) {
    return apr_psprintf(cmd->pool, "%s: invalid parameter",
                        cmd->directive->directive);
  }
  if(ap_strchr_c(header, '=')) {
    return apr_psprintf(cmd->pool, "%s: header name must not contain a '='",
                        cmd->directive->directive);
  }
  if(late != NULL) {
    if(strcasecmp(late, "late") != 0) {
      return apr_psprintf(cmd->pool, "%s: third parameter can only be 'late'",
                          cmd->directive->directive);
    }
    apr_table_set(sconf->setreqheaderlate_t, 
                  apr_pstrcat(cmd->pool, header, "=", variable, NULL), header);
  } else {
    apr_table_set(sconf->setreqheader_t, 
                  apr_pstrcat(cmd->pool, header, "=", variable, NULL), header);
  }
  return NULL;
}

/* QS_UnsetResHeader */
static const char *qos_unsetresheader_cmd(cmd_parms *cmd, void *dcfg, const char *header) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  apr_table_set(sconf->unsetresheader_t, header, "");
  return NULL;
}

static const char *qos_event_setenvresheader_cmd(cmd_parms *cmd, void *dcfg, const char *hdr,
                                                 const char *action) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  apr_table_set(sconf->setenvresheader_t, hdr, action == NULL ? "" : action);
  return NULL;
}

static const char *qos_event_setenvresheadermatch_cmd(cmd_parms *cmd, void *dcfg, const char *hdr,
                                                      const char *pcres) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *errptr = NULL;
  int erroffset;
  pcre *pr = pcre_compile(pcres, PCRE_DOTALL | PCRE_CASELESS, &errptr, &erroffset, NULL);
  if(pr == NULL) {
    return apr_psprintf(cmd->pool, "%s: could not compile pcre at position %d,"
                        " reason: %s", 
                        cmd->directive->directive,
                        erroffset, errptr);
  }
  apr_pool_cleanup_register(cmd->pool, pr, (int(*)(void*))pcre_free, apr_pool_cleanup_null);
  apr_table_setn(sconf->setenvresheadermatch_t, apr_pstrdup(cmd->pool, hdr), (char *)pr);
  return NULL;
}

static const char *qos_redirectif_cmd(cmd_parms *cmd, void *dcfg, const char *var,
                                      const char *pattern, const char *url) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qos_dir_config *dconf = (qos_dir_config*)dcfg;
  qos_redirectif_entry_t *new;
  if(cmd->path) {
    new = apr_array_push(dconf->redirectif);
  } else {
    new = apr_array_push(sconf->redirectif);
  }
  new->name = apr_pstrdup(cmd->pool, var);
#ifdef AP_REGEX_H
  new->preg = ap_pregcomp(cmd->pool, pattern, (AP_REG_EXTENDED | AP_REG_ICASE));
#else
  new->preg = ap_pregcomp(cmd->pool, pattern, (REG_EXTENDED | REG_ICASE));
#endif
  if(new->preg == NULL) {
    return apr_psprintf(cmd->pool, "%s: could not compile regex %s",
                        cmd->directive->directive, pattern);
  }
  new->url = apr_pstrdup(cmd->pool, url);
  return NULL;
}

static const char *qos_setenvres_cmd(cmd_parms *cmd, void *dcfg, const char *var,
                                     const char *pattern, const char *var2) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qos_pregval_t *pregval = apr_pcalloc(cmd->pool, sizeof(qos_pregval_t));
  pregval->name = apr_pstrdup(cmd->pool, var2);
  pregval->value = strchr(pregval->name, '=');
  if(pregval->value) {
    pregval->value[0] = '\0';
    pregval->value++;
  }
#ifdef AP_REGEX_H
  pregval->preg = ap_pregcomp(cmd->pool, pattern, AP_REG_EXTENDED);
#else
  pregval->preg = ap_pregcomp(cmd->pool, pattern, REG_EXTENDED);
#endif
  if(pregval->preg == NULL) {
    return apr_psprintf(cmd->pool, "%s: could not compile regex %s",
                        cmd->directive->directive, pattern);
  }
  apr_table_addn(sconf->setenvres_t, apr_pstrdup(cmd->pool, var), (char *)pregval);
  return NULL;
}

static const char *qos_event_setenvif_cmd(cmd_parms *cmd, void *dcfg, const char *v1, const char *v2,
                                          const char *a3) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qos_setenvif_t *setenvif = apr_pcalloc(cmd->pool, sizeof(qos_setenvif_t));
  setenvif->variable1 = apr_pstrdup(cmd->pool, v1);
  setenvif->variable2 = apr_pstrdup(cmd->pool, v2);
  setenvif->name = apr_pstrdup(cmd->pool, a3);
  setenvif->value = strchr(setenvif->name, '=');
  if(setenvif->value == NULL) {
    if(setenvif->name[0] == '!') {
      setenvif->value = apr_pstrdup(cmd->pool, "");
    } else {
      return apr_psprintf(cmd->pool, "%s: new variable must have the format <name>=<value>",
                          cmd->directive->directive);
    }
  } else {
    setenvif->value[0] = '\0';
    setenvif->value++;
  }
  apr_table_setn(sconf->setenvif_t, apr_pstrcat(cmd->pool, v1, v2, a3, NULL), (char *)setenvif);
  return NULL;
}

static const char *qos_event_setenvifquery_cmd(cmd_parms *cmd, void *dcfg, const char *rx, const char *v) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qos_setenvifquery_t *setenvif = apr_pcalloc(cmd->pool, sizeof(qos_setenvifquery_t));
  char *p;
#ifdef AP_REGEX_H
  setenvif->preg = ap_pregcomp(cmd->pool, rx, AP_REG_EXTENDED);
#else
  setenvif->preg = ap_pregcomp(cmd->pool, rx, REG_EXTENDED);
#endif
  if(setenvif->preg == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to compile regex (%s)",
                        cmd->directive->directive, rx);
  }
  if(strlen(v) < 2) {
    return apr_psprintf(cmd->pool, "%s: variable name is too short (%s)",
                        cmd->directive->directive, v);
  }
  setenvif->name = apr_pstrdup(cmd->pool, v);
  p = strchr(setenvif->name, '=');
  if(p == NULL) {
    setenvif->value = apr_pstrdup(cmd->pool, "");
  } else {
    p[0] = '\0';
    p++;
    setenvif->value = p;
  }
  apr_table_setn(sconf->setenvifquery_t, apr_pstrdup(cmd->pool, rx), (char *)setenvif);
  return NULL;
}

static const char *qos_event_setenvifparpbody_cmd(cmd_parms *cmd, void *dcfg,
                                                  const char *rx, const char *v) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qos_setenvifparpbody_t *setenvif = apr_pcalloc(cmd->pool, sizeof(qos_setenvifparpbody_t));
  char *p;
  const char *errptr = NULL;
  int erroffset;
#ifdef AP_REGEX_H
  setenvif->pregx = ap_pregcomp(cmd->pool, rx, AP_REG_EXTENDED);
#else
  setenvif->pregx = ap_pregcomp(cmd->pool, rx, REG_EXTENDED);
#endif
  setenvif->preg = pcre_compile(rx, PCRE_DOTALL | PCRE_CASELESS, &errptr, &erroffset, NULL);
  if(setenvif->preg == NULL) {
    return apr_psprintf(cmd->pool, "%s: could not compile pcre at position %d,"
                        " reason: %s", 
                        cmd->directive->directive,
                        erroffset, errptr);
  }
  setenvif->extra = qos_pcre_study(cmd->pool, setenvif->preg);
  apr_pool_cleanup_register(cmd->pool, setenvif->preg, (int(*)(void*))pcre_free, apr_pool_cleanup_null);
  if(setenvif->pregx == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to compile regex (%s)",
                        cmd->directive->directive, rx);
  }
  setenvif->name = apr_pstrdup(cmd->pool, v);
  p = strchr(setenvif->name, '=');
  if(p == NULL) {
    setenvif->value = apr_pstrdup(cmd->pool, "");
  } else {
    p[0] = '\0';
    p++;
    setenvif->value = p;
  }
  m_requires_parp = 1;
  apr_table_setn(sconf->setenvifparpbody_t, apr_pstrdup(cmd->pool, rx), (char *)setenvif);
  return NULL;
}

static const char *qos_event_setenvifparp_cmd(cmd_parms *cmd, void *dcfg, const char *rx, const char *v) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  qos_setenvifquery_t *setenvif = apr_pcalloc(cmd->pool, sizeof(qos_setenvifquery_t));
  char *p;
#ifdef AP_REGEX_H
  setenvif->preg = ap_pregcomp(cmd->pool, rx, AP_REG_EXTENDED);
#else
  setenvif->preg = ap_pregcomp(cmd->pool, rx, REG_EXTENDED);
#endif
  if(setenvif->preg == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to compile regex (%s)",
                        cmd->directive->directive, rx);
  }
  if(strlen(v) < 2) {
    return apr_psprintf(cmd->pool, "%s: variable name is too short (%s)",
                        cmd->directive->directive, v);
  }
  setenvif->name = apr_pstrdup(cmd->pool, v);
  p = strchr(setenvif->name, '=');
  if(p == NULL) {
    setenvif->value = apr_pstrdup(cmd->pool, "");
  } else {
    p[0] = '\0';
    p++;
    setenvif->value = p;
  }
  m_requires_parp = 1;
  apr_table_setn(sconf->setenvifparp_t, apr_pstrdup(cmd->pool, rx), (char *)setenvif);
  return NULL;
}

/**
 * defines custom error page
 */
static const char *qos_error_page_cmd(cmd_parms *cmd, void *dcfg, const char *path) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->error_page = apr_pstrdup(cmd->pool, path);
  if((sconf->error_page[0] != '/') &&
     (strncmp(sconf->error_page, "http", 4) != 0)) {
    return apr_psprintf(cmd->pool, "%s: requires absolute path (%s)", 
                        cmd->directive->directive, sconf->error_page);
  }
  return NULL;
}

/**
 * path to chrooted jail
 */
static const char *qos_chroot_cmd(cmd_parms *cmd, void *dcfg, const char *arg) {
  char cwd[2048] = "";
  qos_srv_config *sconf = ap_get_module_config(cmd->server->module_config, &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->chroot = apr_pstrdup(cmd->pool, arg);
  if(getcwd(cwd, sizeof(cwd)) == NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to examine current working directory",
                        cmd->directive->directive);
  }
  if(chdir(sconf->chroot) < 0) {
    return apr_psprintf(cmd->pool, "%s: change dir to %s failed",
                        cmd->directive->directive, sconf->chroot);
  }
  if(chdir(cwd) < 0) {
    return apr_psprintf(cmd->pool, "%s: change dir to %s failed",
                        cmd->directive->directive, cwd);
  }
 
  return NULL;
}

/**
 * global error code setting
 */
static const char *qos_error_code_cmd(cmd_parms *cmd, void *dcfg, const char *arg) {
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  int idx500 = ap_index_of_response(HTTP_INTERNAL_SERVER_ERROR);
  if (err != NULL) {
    return err;
  }
  m_retcode = atoi(arg);
  if((m_retcode < 400) || (m_retcode > 599)) {
    return apr_psprintf(cmd->pool, "%s: HTTP response code code must be a"
                        " numeric value between 400 and 599", 
                        cmd->directive->directive);
  }
  if(m_retcode != 500) {
    if(ap_index_of_response(m_retcode) == idx500) {
      return apr_psprintf(cmd->pool, "%s: unsupported HTTP response code", 
                          cmd->directive->directive);
    }
  }
  return NULL;
}

/** QS_UserTrackingCookieName */
static const char *qos_user_tracking_cookie_cmd(cmd_parms *cmd, void *dcfg, const char *name,
                                                const char *force) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->user_tracking_cookie = apr_pstrdup(cmd->pool, name);
  sconf->user_tracking_cookie_force = NULL;
  if(force) {
    if(force[0] != '/') {
      return apr_psprintf(cmd->pool, "%s: invalid path '%s'", 
                          cmd->directive->directive, force);
    }
    sconf->user_tracking_cookie_force = apr_pstrdup(cmd->pool, force);
  }
  return NULL;
}

/**
 * session definitions: cookie name and path, expiration/max-age
 */
static const char *qos_cookie_name_cmd(cmd_parms *cmd, void *dcfg, const char *name) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->cookie_name = apr_pstrdup(cmd->pool, name);
  return NULL;
}

static const char *qos_cookie_path_cmd(cmd_parms *cmd, void *dcfg, const char *path) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->cookie_path = apr_pstrdup(cmd->pool, path);
  return NULL;
}

static const char *qos_timeout_cmd(cmd_parms *cmd, void *dcfg, const char *sec) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->max_age = atoi(sec);
  if(sconf->max_age == 0) {
    return apr_psprintf(cmd->pool, "%s: timeout must be numeric value >0", 
                        cmd->directive->directive);
  }
  return NULL;
}

static const char *qos_key_cmd(cmd_parms *cmd, void *dcfg, const char *seed) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  EVP_BytesToKey(EVP_des_ede3_cbc(), EVP_sha1(), NULL,
                 (const unsigned char *)seed, strlen(seed), 1, sconf->key, NULL);
  sconf->keyset = 1;
  return NULL;
}

/**
 * name of the http header to mark a vip
 */
static const char *qos_header_name_cmd(cmd_parms *cmd, void *dcfg, const char *n, const char *drop) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  char *name = apr_pstrdup(cmd->pool, n);
  char *p = strchr(name, '=');
  if(p) {
    p[0] = '\0';
    p++;
#ifdef AP_REGEX_H
    sconf->header_name_regex = ap_pregcomp(cmd->pool, p, AP_REG_EXTENDED);
#else
    sconf->header_name_regex = ap_pregcomp(cmd->pool, p, REG_EXTENDED);
#endif
    if(sconf->header_name_regex == NULL) {
      return apr_psprintf(cmd->pool, "%s: failed to compile regex (%s)",
                          cmd->directive->directive, p);
    }
  } else {
    sconf->header_name_regex = NULL;
  }
  if(drop && (strcasecmp(drop, "drop") == 0)) {
    sconf->header_name_drop = 1;
  } else {
    sconf->header_name_drop = 0;
  }
  sconf->header_name = name;
  return NULL;
}

static const char *qos_ip_header_name_cmd(cmd_parms *cmd, void *dcfg, const char *n, const char *drop) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  char *name = apr_pstrdup(cmd->pool, n);
  char *p = strchr(name, '=');
  if(p) {
    p[0] = '\0';
    p++;
#ifdef AP_REGEX_H
    sconf->ip_header_name_regex = ap_pregcomp(cmd->pool, p, AP_REG_EXTENDED);
#else
    sconf->ip_header_name_regex = ap_pregcomp(cmd->pool, p, REG_EXTENDED);
#endif
    if(sconf->ip_header_name_regex == NULL) {
      return apr_psprintf(cmd->pool, "%s: failed to compile regex (%s)",
                          cmd->directive->directive, p);
    }
  } else {
    sconf->ip_header_name_regex = NULL;
  }
  if(drop && (strcasecmp(drop, "drop") == 0)) {
    sconf->ip_header_name_drop = 1;
  } else {
    sconf->ip_header_name_drop = 0;
  }
  sconf->ip_header_name = name;
  return NULL;
}

static const char *qos_vip_u_cmd(cmd_parms *cmd, void *dcfg) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->vip_user = 1;
  return NULL;
}

static const char *qos_vip_ip_u_cmd(cmd_parms *cmd, void *dcfg) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->vip_ip_user = 1;
  return NULL;
}

/**
 * max concurrent connections per server
 */
static const char *qos_max_conn_cmd(cmd_parms *cmd, void *dcfg, const char *number) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->max_conn = atoi(number);
  if(sconf->max_conn == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  return NULL;
}

/**
 * QS_SrvMaxConnClose, disable keep-alive
 */
static const char *qos_max_conn_close_cmd(cmd_parms *cmd, void *dcfg, const char *number) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  char *n = apr_pstrdup(cmd->temp_pool, number);
  if((strlen(n) > 1) &&
     (n[strlen(n)-1] == '%')) {
    n[strlen(n)-1] = '\0';
    sconf->max_conn_close = atoi(n);
    sconf->max_conn_close_percent = sconf->max_conn_close;
    if(sconf->max_conn_close > 99) {
      return apr_psprintf(cmd->pool, "%s: number must be a percentage <99", 
                          cmd->directive->directive);
    }
  } else {
    sconf->max_conn_close = atoi(n);
    sconf->max_conn_close_percent = 0;
  }
  if(sconf->max_conn_close == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  return NULL;
}

/**
 * max concurrent connections per client ip
 */
static const char *qos_max_conn_ip_cmd(cmd_parms *cmd, void *dcfg, const char *number,
                                       const char *connections) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->max_conn_per_ip = atoi(number);
  if(sconf->max_conn_per_ip == 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                        cmd->directive->directive);
  }
  if(connections) {
    sconf->max_conn_per_ip_connections = atoi(connections);
    if((sconf->max_conn_per_ip_connections == 0) &&
       (strcmp(connections, "0") != 0)) {
      return apr_psprintf(cmd->pool, "%s: number must be numeric value >0", 
                          cmd->directive->directive);
    }
  }
  return NULL;
}

/**
 * ip address without any limitation
 */
static const char *qos_max_conn_ex_cmd(cmd_parms *cmd, void *dcfg, const char *addr) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  if(addr[strlen(addr)-1] == '.') {
    /* address range */
    apr_table_add(sconf->exclude_ip, addr, "r");
  } else {
    /* single ip */
    apr_table_add(sconf->exclude_ip, addr, "s");
  }
  return NULL;
}
#ifdef UNUSED
static const char *qos_req_rate_off_cmd(cmd_parms *cmd, void *dcfg) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->min_rate_off = 1;
  return NULL;
}

/** verify, that the platform supports "%p" in sprintf */
static int qos_sprintfcheck() {
  char buf[128];
  char buf2[128];
  sprintf(buf, "%p", buf);
  sprintf(buf2, "%p", buf2);
  if((strcmp(buf, buf2) == 0) || (strlen(buf) < 4)) {
    /* not okay */
    return 0;
  }
  return 1;
}

static const char *qos_req_rate_cmd(cmd_parms *cmd, void *dcfg, const char *sec, const char *secmax) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  if(!qos_sprintfcheck()) {
    return apr_psprintf(cmd->pool, "%s: directive can't be used on this platform",
                        cmd->directive->directive);
  }
  if(sconf->req_rate != -1) {
    return apr_psprintf(cmd->pool, "%s: directive can't be used together with QS_SrvMinDataRate", 
                        cmd->directive->directive);
  }
  sconf->req_rate = atoi(sec);
  if(sconf->req_rate <= 0) {
    return apr_psprintf(cmd->pool, "%s: request rate must be a numeric value >0", 
                        cmd->directive->directive);
  }
  if(secmax) {
    sconf->min_rate_max = atoi(secmax);
    if(sconf->min_rate_max <= sconf->min_rate) {
      return apr_psprintf(cmd->pool, "%s: max. data rate must be a greater than min. value", 
                          cmd->directive->directive);
    }
  }
  return NULL;
}

/* QS_SrvMinDataRateOffEvent */
static const char *qos_min_rate_off_cmd(cmd_parms *cmd, void *dcfg, const char *var) {
  apr_table_t *disable_reqrate_events;
  if(cmd->path) {
    qos_dir_config *dconf = (qos_dir_config*)dcfg;
    disable_reqrate_events = dconf->disable_reqrate_events;
  } else {
    qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                  &qos_module);
    disable_reqrate_events = sconf->disable_reqrate_events; 
  }
  if(((var[0] != '+') && (var[0] != '-')) || (strlen(var) < 2)) {
    return apr_psprintf(cmd->pool, "%s: invalid variable (requires +/- prefix)", 
                        cmd->directive->directive);
  }
  apr_table_set(disable_reqrate_events, var, "");
  return NULL;
}

#ifdef AP_TAKE_ARGV
static const char *qos_min_rate_cmd(cmd_parms *cmd, void *dcfg, int argc, char *const argv[])
#else
static const char *qos_min_rate_cmd(cmd_parms *cmd, void *dcfg, const char *_sec, const char *_secmax)
#endif
{
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  const char *sec = NULL;
  const char *secmax = NULL;
  const char *connections = NULL;
#ifdef AP_TAKE_ARGV
  if(argc == 0) {
    return apr_psprintf(cmd->pool, "%s: takes 1 to 3 arguments",
                        cmd->directive->directive);
  }
  sec = argv[0];
  if(argc > 1) {
    secmax = argv[1];
  }
  if(argc > 2) {
    connections = argv[2];
  }
#else
  sec = _sec;
  secmax = _secmax;
#endif
  if (err != NULL) {
    return err;
  }
  if(!qos_sprintfcheck()) {
    return apr_psprintf(cmd->pool, "%s: directive can't be used on this platform",
                        cmd->directive->directive);
  }
  if(sconf->req_rate != -1) {
    return apr_psprintf(cmd->pool, "%s: directive can't be used together with QS_SrvRequestRate", 
                        cmd->directive->directive);
  }
  sconf->req_rate = atoi(sec);
  sconf->min_rate = sconf->req_rate;
  if(connections) {
    sconf->req_rate_start = atoi(connections);
    if(sconf->req_rate_start <= 0) {
      return apr_psprintf(cmd->pool, "%s: number of connections must be a numeric value >0", 
                          cmd->directive->directive);
    }
  }
  if(sconf->req_rate <= 0) {
    return apr_psprintf(cmd->pool, "%s: minimal data rate must be a numeric value >0", 
                        cmd->directive->directive);
  }
  if(secmax) {
    sconf->min_rate_max = atoi(secmax);
    if(sconf->min_rate_max <= sconf->min_rate) {
      return apr_psprintf(cmd->pool, "%s: max. data rate must be a greater than min. value", 
                          cmd->directive->directive);
    }
  }
  return NULL;
}
#endif

/**
 * generic filter command
 */
static const char *qos_deny_cmd(cmd_parms *cmd, void *dcfg,
                                const char *id, const char *action, const char *pcres,
                                qs_rfilter_type_e type, int options) {
  qos_dir_config *dconf = (qos_dir_config*)dcfg;
  qos_rfilter_t *flt = apr_pcalloc(cmd->pool, sizeof(qos_rfilter_t));
  const char *errptr = NULL;
  int erroffset;
  flt->type = type;
  if(((id[0] != '+') && (id[0] != '-')) || (strlen(id) < 2)) {
    return apr_psprintf(cmd->pool, "%s: invalid rule id", 
                        cmd->directive->directive);
  }
  flt->id = apr_pstrdup(cmd->pool, &id[1]);
  if(strcasecmp(action, "log") == 0) {
    flt->action = QS_LOG;
  } else if(strcasecmp(action, "deny") == 0) {
    flt->action = QS_DENY;
  } else {
    return apr_psprintf(cmd->pool, "%s: invalid action", 
                        cmd->directive->directive);
  }
  if(flt->type != QS_DENY_EVENT) {
    flt->pr = pcre_compile(pcres, PCRE_DOTALL | options, &errptr, &erroffset, NULL);
    if(flt->pr == NULL) {
      return apr_psprintf(cmd->pool, "%s: could not compile pcre at position %d,"
                          " reason: %s", 
                          cmd->directive->directive,
                          erroffset, errptr);
    }
    flt->extra = qos_pcre_study(cmd->pool, flt->pr);
    apr_pool_cleanup_register(cmd->pool, flt->pr, (int(*)(void*))pcre_free, apr_pool_cleanup_null);
  }
  flt->text = apr_pstrdup(cmd->pool, pcres);
  apr_table_setn(dconf->rfilter_table, apr_pstrdup(cmd->pool, id), (char *)flt);
  return NULL;
}
static const char *qos_deny_rql_cmd(cmd_parms *cmd, void *dcfg,
                                    const char *id, const char *action, const char *pcres) {
  return qos_deny_cmd(cmd, dcfg, id, action, pcres, QS_DENY_REQUEST_LINE, PCRE_CASELESS);
}
static const char *qos_deny_path_cmd(cmd_parms *cmd, void *dcfg,
                                     const char *id, const char *action, const char *pcres) {
  return qos_deny_cmd(cmd, dcfg, id, action, pcres, QS_DENY_PATH, PCRE_CASELESS);
}
static const char *qos_deny_query_cmd(cmd_parms *cmd, void *dcfg,
                                      const char *id, const char *action, const char *pcres) {
  return qos_deny_cmd(cmd, dcfg, id, action, pcres, QS_DENY_QUERY, PCRE_CASELESS);
}
static const char *qos_deny_event_cmd(cmd_parms *cmd, void *dcfg,
                                      const char *id, const char *action, const char *event) {
  return qos_deny_cmd(cmd, dcfg, id, action, event, QS_DENY_EVENT, 0);
}
static const char *qos_permit_uri_cmd(cmd_parms *cmd, void *dcfg,
                                      const char *id, const char *action, const char *pcres) {
  return qos_deny_cmd(cmd, dcfg, id, action, pcres, QS_PERMIT_URI, 0);
}
static const char *qos_deny_urlenc_cmd(cmd_parms *cmd, void *dcfg, const char *mode) {
  qos_dir_config *dconf = (qos_dir_config*)dcfg;
  if(strcasecmp(mode, "log") == 0) {
    dconf->urldecoding = QS_LOG;
  } else if(strcasecmp(mode, "deny") == 0) {
    dconf->urldecoding = QS_DENY;
  } else if(strcasecmp(mode, "off") == 0) {
    dconf->urldecoding = QS_OFF;
  } else {
    return apr_psprintf(cmd->pool, "%s: invalid action", 
                        cmd->directive->directive);
  }
  return NULL;
}

static const char *qos_milestone_tmo_cmd(cmd_parms *cmd, void *dcfg, const char *sec) {
  qos_srv_config *sconf = ap_get_module_config(cmd->server->module_config, &qos_module);
  sconf->milestone_timeout = atoi(sec);
  if(sconf->milestone_timeout <= 0) {
    return apr_psprintf(cmd->pool, "%s: timeout must be numeric value >0",
                        cmd->directive->directive);
  }
  return NULL;
}

static const char *qos_milestone_cmd(cmd_parms *cmd, void *dcfg, const char *action,
                                     const char *pattern) {
  qos_srv_config *sconf = ap_get_module_config(cmd->server->module_config, &qos_module);
  const char *errptr = NULL;
  int erroffset;
  qos_milestone_t *ms = apr_pcalloc(cmd->pool, sizeof(qos_milestone_t));
  if(sconf->milestones == NULL) {
    sconf->milestones = apr_table_make(cmd->pool, 100);
  }
  ms->preg = pcre_compile(pattern, PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(ms->preg == NULL) {
    return apr_psprintf(cmd->pool, "%s: could not compile pcre %s at position %d,"
                        " reason: %s", 
                        cmd->directive->directive,
                        pattern,
                        erroffset, errptr);
  }
  apr_pool_cleanup_register(cmd->pool, ms->preg, (int(*)(void*))pcre_free, apr_pool_cleanup_null);
  ms->extra = qos_pcre_study(cmd->pool, ms->preg);
  ms->pattern = apr_pstrdup(cmd->pool, pattern);
  if(strcasecmp(action, "deny") == 0) {
    ms->action = QS_DENY;
  } else if(strcasecmp(action, "log") == 0) {
    ms->action = QS_LOG;
  } else {
    return apr_psprintf(cmd->pool, "%s: invalid action %s",
                        cmd->directive->directive, action);
  }
  apr_table_setn(sconf->milestones,
                 apr_psprintf(cmd->pool, "%d", apr_table_elts(sconf->milestones)->nelts),
                 (char *)ms);
  return NULL;
}

static const char *qos_maxpost_cmd(cmd_parms *cmd, void *dcfg, const char *bytes) {
  apr_off_t s;
  char *errp = NULL;
#ifdef ap_http_scheme
  /* Apache 2.2 */
  if(APR_SUCCESS != apr_strtoff(&s, bytes, &errp, 10))
#else
  if((s = apr_atoi64(bytes)) < 0)
#endif
    {
    return "QS_LimitRequestBody argument is not parsable";
  }
  if(s < 0) {
    return "QS_LimitRequestBody requires a non-negative integer";
  }
  if(cmd->path == NULL) {
    /* server */
    qos_srv_config *sconf = ap_get_module_config(cmd->server->module_config, &qos_module);
    sconf->maxpost = s;
  } else {
    /* location */
    qos_dir_config *dconf = (qos_dir_config*)dcfg;
    dconf->maxpost = s;
  }
  return NULL;
}

/* QS_Decoding */
static const char *qos_dec_cmd(cmd_parms *cmd, void *dcfg, const char *arg) {
  qos_dir_config *dconf = (qos_dir_config*)dcfg;
//  if(strcasecmp(arg, "html") == 0) {
//    dconf->dec_mode |= QOS_DEC_MODE_FLAGS_HTML;
//  } else 
  if(strcasecmp(arg, "uni") == 0) {
    dconf->dec_mode |= QOS_DEC_MODE_FLAGS_UNI;
//  } if(strcasecmp(arg, "ansi") == 0) {
//    dconf->dec_mode |= QOS_DEC_MODE_FLAGS_ANSI;
  } else {
    return apr_psprintf(cmd->pool, "%s: unknown decoding '%s'",
                        cmd->directive->directive, arg);
  }
  return NULL;
}

static const char *qos_denyinheritoff_cmd(cmd_parms *cmd, void *dcfg) {
  qos_dir_config *dconf = (qos_dir_config*)dcfg;
  dconf->inheritoff = 1;
  return NULL;
}

static const char *qos_denybody_cmd(cmd_parms *cmd, void *dcfg, int flag) {
  qos_dir_config *dconf = (qos_dir_config*)dcfg;
  dconf->bodyfilter_p = flag;
  dconf->bodyfilter_d = flag;
  if(flag) {
    m_requires_parp = 1;
  }
  return NULL;
}

static const char *qos_denybody_d_cmd(cmd_parms *cmd, void *dcfg, int flag) {
  qos_dir_config *dconf = (qos_dir_config*)dcfg;
  dconf->bodyfilter_d = flag;
  if(flag) {
    m_requires_parp = 1;
  }
  return NULL;
}

static const char *qos_denybody_p_cmd(cmd_parms *cmd, void *dcfg, int flag) {
  qos_dir_config *dconf = (qos_dir_config*)dcfg;
  dconf->bodyfilter_p = flag;
  if(flag) {
    m_requires_parp = 1;
  }
  return NULL;
}

/* QS_RequestHeaderFilter enables/disables header filter */
static const char *qos_headerfilter_cmd(cmd_parms *cmd, void *dcfg, const char *flag) {
  qs_headerfilter_mode_e headerfilter;
  if(strcasecmp(flag, "on") == 0) {
    headerfilter = QS_HEADERFILTER_ON;
  } else if(strcasecmp(flag, "off") == 0) {
    headerfilter = QS_HEADERFILTER_OFF;
  } else if(strcasecmp(flag, "size") == 0) {
    headerfilter = QS_HEADERFILTER_SIZE_ONLY;
  } else {
    return apr_psprintf(cmd->pool, "%s: invalid argument",
                        cmd->directive->directive);
  }
  if(cmd->path) {
    qos_dir_config *dconf = (qos_dir_config*)dcfg;
    dconf->headerfilter = headerfilter;
  } else {
    qos_srv_config *sconf = ap_get_module_config(cmd->server->module_config, &qos_module);
    sconf->headerfilter = headerfilter;
  }
  return NULL;
}

/* QS_ResponseHeaderFilter */
static const char *qos_resheaderfilter_cmd(cmd_parms *cmd, void *dcfg, const char *flag) {
  qos_dir_config *dconf = (qos_dir_config*)dcfg;
  if(strcasecmp(flag, "on") == 0) {
    dconf->resheaderfilter = QS_HEADERFILTER_ON;
  } else if(strcasecmp(flag, "off") == 0) {
    dconf->resheaderfilter = QS_HEADERFILTER_OFF;
  } else if(strcasecmp(flag, "silent") == 0) {
    dconf->resheaderfilter = QS_HEADERFILTER_SILENT;
  } else {
    return apr_psprintf(cmd->pool, "%s: invalid argument",
                        cmd->directive->directive);
  }
  return NULL;
}

/* QS_RequestHeaderFilterRule: set custom header rules (global only)
   name, action, pcre, size */
#ifdef AP_TAKE_ARGV
static const char *qos_headerfilter_rule_cmd(cmd_parms *cmd, void *dcfg, int argc, char *const argv[])
#else
static const char *qos_headerfilter_rule_cmd(cmd_parms *cmd, void *dcfg, 
                                             const char *header, const char *action,
                                             const char *rule)
#endif
  {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *errptr = NULL;
  int erroffset;
  qos_fhlt_r_t *he;
#ifdef AP_TAKE_ARGV
  const char *header;
  const char *rule;
  const char *action;
#endif
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
#ifdef AP_TAKE_ARGV
  if(argc != 4) {
    return apr_psprintf(cmd->pool, "%s: takes 4 arguments",
                        cmd->directive->directive);
  }
#endif
  he = apr_pcalloc(cmd->pool, sizeof(qos_fhlt_r_t));
#ifdef AP_TAKE_ARGV
  header = argv[0];
  action = argv[1];
  rule = argv[2];
  he->size = atoi(argv[3]);
#else
  he->size = 9000;
#endif
  he->text = apr_pstrdup(cmd->pool, rule);
  he->pcre = pcre_compile(rule, PCRE_DOTALL, &errptr, &erroffset, NULL);
  if(strcasecmp(action, "deny") == 0) {
    he->action = QS_FLT_ACTION_DENY;
  } else if(strcasecmp(action, "drop") == 0) {
    he->action = QS_FLT_ACTION_DROP;
  } else {
    return apr_psprintf(cmd->pool, "%s: invalid action %s",
                        cmd->directive->directive, action);
  }
  if(he->pcre == NULL) {
    return apr_psprintf(cmd->pool, "%s: could not compile pcre %s at position %d,"
                        " reason: %s", 
                        cmd->directive->directive,
                        rule,
                        erroffset, errptr);
  }
  he->extra = qos_pcre_study(cmd->pool, he->pcre);
  if(he->size <= 0) {
    return apr_psprintf(cmd->pool, "%s: size must be numeric value >0",
                        cmd->directive->directive);
  }
  apr_table_setn(sconf->hfilter_table, apr_pstrdup(cmd->pool, header), (char *)he);
  apr_pool_cleanup_register(cmd->pool, he->pcre, (int(*)(void*))pcre_free, apr_pool_cleanup_null);
  return NULL;
}

static const char *qos_resheaderfilter_rule_cmd(cmd_parms *cmd, void *dcfg, 
                                                const char *header,
                                                const char *rule, const char *size) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *errptr = NULL;
  int erroffset;
  qos_fhlt_r_t *he;
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  he = apr_pcalloc(cmd->pool, sizeof(qos_fhlt_r_t));
  he->size = atoi(size);
  he->text = apr_pstrdup(cmd->pool, rule);
  he->pcre = pcre_compile(rule, PCRE_DOTALL, &errptr, &erroffset, NULL);
  he->action = QS_FLT_ACTION_DROP;
  if(he->pcre == NULL) {
    return apr_psprintf(cmd->pool, "%s: could not compile pcre %s at position %d,"
                        " reason: %s", 
                        cmd->directive->directive,
                        rule,
                        erroffset, errptr);
  }
  he->extra = qos_pcre_study(cmd->pool, he->pcre);
  if(he->size <= 0) {
    return apr_psprintf(cmd->pool, "%s: size must be numeric value >0",
                        cmd->directive->directive);
  }
  apr_table_setn(sconf->reshfilter_table, apr_pstrdup(cmd->pool, header), (char *)he);
  apr_pool_cleanup_register(cmd->pool, he->pcre, (int(*)(void*))pcre_free, apr_pool_cleanup_null);
  return NULL;  
}

static const char *qos_geodb_cmd(cmd_parms *cmd, void *dcfg, const char *arg1) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  char *msg = NULL;
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->geodb = qos_loadgeo(cmd->pool, ap_server_root_relative(cmd->pool, arg1), &sconf->geodb_size, &msg);
  if(sconf->geodb == NULL || msg != NULL) {
    return apr_psprintf(cmd->pool, "%s: failed to load the database: %s",
                        cmd->directive->directive,
                        msg ? msg : "-");
  }
  return NULL;
}

static const char *qos_geopriv_cmd(cmd_parms *cmd, void *dcfg, const char *list, const char *con) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  char *next = apr_pstrdup(cmd->pool, list);
  int geo_limit;
  char *name;
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  name = apr_strtok(next, ",", &next);
  if(name == NULL) {
    return apr_psprintf(cmd->pool, "%s: empty list",
                        cmd->directive->directive);
  }
  while(name) {
    apr_table_set(sconf->geo_priv, name, "");
    name = apr_strtok(NULL, ",", &next);
  }
  geo_limit = atoi(con);
  if(geo_limit <= 0 && con[0] != '0' && con[1] != '\0') {
    return apr_psprintf(cmd->pool, "%s: invalid connection number",
                        cmd->directive->directive);
  }
  if(sconf->geo_limit != -1 && sconf->geo_limit != geo_limit) {
    return apr_psprintf(cmd->pool, "%s: already configured with a different limitation",
                        cmd->directive->directive);
  }
  sconf->geo_limit = geo_limit;
  return NULL;
}

static const char *qos_enable_ipv6_cmd(cmd_parms *cmd, void *dcfg, int flag) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  if(flag) {
    sconf->ip_type = QS_IP_V6;
  } else {
    sconf->ip_type = QS_IP_V4;
  }
  return NULL;
}

static const char *qos_client_cmd(cmd_parms *cmd, void *dcfg, const char *arg1) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->qos_cc_size = atoi(arg1);
  sconf->qos_cc_size = sconf->qos_cc_size / 100 * 100 ;
  if(sconf->qos_cc_size < 50000) {
    m_qos_cc_partition = 2;
  }
  if(sconf->qos_cc_size >= 100000) {
    m_qos_cc_partition = 8;
  }
  if(sconf->qos_cc_size >= 500000) {
    m_qos_cc_partition = 16;
  }
  if(sconf->qos_cc_size >= 1000000) {
    m_qos_cc_partition = 32;
  }
  if(sconf->qos_cc_size <= 0) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >=100", 
                        cmd->directive->directive);
  }
  return NULL;
}

#ifdef AP_TAKE_ARGV
static const char *qos_client_pref_cmd(cmd_parms *cmd, void *dcfg, int argc, char *const argv[])
#else
static const char *qos_client_pref_cmd(cmd_parms *cmd, void *dcfg)
#endif
  {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->has_qos_cc = 1;
  sconf->qos_cc_prefer = 80;
#ifdef AP_TAKE_ARGV
  if(argc) {
    sconf->qos_cc_prefer = atoi(argv[0]);
  }
#endif
  if((sconf->qos_cc_prefer == 0) || (sconf->qos_cc_prefer > 99)) {
    return apr_psprintf(cmd->pool, "%s: percentage must be numeric value between 1 and 99",
                        cmd->directive->directive);
  }
#ifdef AP_TAKE_ARGV
  if(argc > 1) {
    return apr_psprintf(cmd->pool, "%s: command takes not more than one argument",
                        cmd->directive->directive);
  }
#endif
  return NULL;
}

static const char *qos_client_block_cmd(cmd_parms *cmd, void *dcfg, const char *arg1,
                                        const char *arg2) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->has_qos_cc = 1;
  sconf->qos_cc_block = atoi(arg1);
  if((sconf->qos_cc_block < 0) || ((sconf->qos_cc_block == 0) && (strcmp(arg1, "0") != 0))) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >=0", 
                        cmd->directive->directive);
  }
  if(arg2) {
    sconf->qos_cc_block_time = atoi(arg2);
  }
  if(sconf->qos_cc_block_time == 0) {
    return apr_psprintf(cmd->pool, "%s: time must be numeric value >0", 
                        cmd->directive->directive);
  }
  return NULL;
}

static const char *qos_client_limit_int_cmd(cmd_parms *cmd, void *dcfg, const char *arg_number,
                                            const char *arg_sec, const char *arg_varname,
                                            const char *arg_condition) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  char *limit_name = QS_LIMIT_DEFAULT;
  int limit;
  time_t limit_time = 600;
  qos_s_entry_limit_conf_t *entry = apr_pcalloc(cmd->pool, sizeof(qos_s_entry_limit_conf_t));
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->has_qos_cc = 1;
  limit = atoi(arg_number);
  if((limit < 0) || ((limit == 0) && (strcmp(arg_number, "0") != 0))) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >=0", 
                        cmd->directive->directive);
  }
  if(arg_sec) {
    limit_time = atoi(arg_sec);
  }
  if(limit_time == 0) {
    return apr_psprintf(cmd->pool, "%s: time must be numeric value >0", 
                        cmd->directive->directive);
  }
  if(arg_varname) {
    limit_name = apr_pstrdup(cmd->pool, arg_varname);
  }
  entry->limit = limit;
  entry->limit_time = limit_time;
  entry->condStr = NULL;
  entry->preg = NULL;
  if(arg_condition) {
    entry->condStr = apr_pstrdup(cmd->pool, arg_condition);
#ifdef AP_REGEX_H
    entry->preg = ap_pregcomp(cmd->pool, entry->condStr, AP_REG_EXTENDED);
#else
    entry->preg = ap_pregcomp(cmd->pool, entry->condStr, REG_EXTENDED);
#endif
    if(entry->preg == NULL) {
      return apr_psprintf(cmd->pool, "%s: failed to compile regex (%s)",
                          cmd->directive->directive, entry->condStr);
    }
  }
  if(apr_table_get(sconf->qos_cc_limitTable, limit_name) != NULL) {
      return apr_psprintf(cmd->pool, "%s: variable %s has already been used by"
                          " another QS_[Cond]ClientEventLimitCount directive",
                          cmd->directive->directive, limit_name);    
  }
  apr_table_setn(sconf->qos_cc_limitTable, limit_name, (char *)entry);
  return NULL;
}

/* QS_ClientEventLimitCount <number> <seconds> <variable> */
static const char *qos_client_limit_cmd(cmd_parms *cmd, void *dcfg, const char *arg_number,
                                        const char *arg_sec, const char *arg_varname) {
  return qos_client_limit_int_cmd(cmd, dcfg, arg_number, arg_sec, arg_varname, NULL);
}

#ifdef AP_TAKE_ARGV
/* QS_CondClientEventLimitCount <number> <seconds> <variable> <pattern> */
static const char *qos_cond_client_limit_cmd(cmd_parms *cmd, void *dcfg, int argc, char *const argv[]) {
  if(argc != 4) {
    return apr_psprintf(cmd->pool, "%s: takes 4 arguments",
                        cmd->directive->directive);
  }
  return qos_client_limit_int_cmd(cmd, dcfg, argv[0], argv[1], argv[2], argv[3]);
}
#endif

static const char *qos_client_forwardedfor_cmd(cmd_parms *cmd, void *dcfg, const char *header) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->qos_cc_forwardedfor = apr_pstrdup(cmd->pool, header);
  return NULL;
}

static const char *qos_client_serial_cmd(cmd_parms *cmd, void *dcfg) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->has_qos_cc = 1;
  sconf->qos_cc_serialize = 1;
  return NULL;
}

#ifdef UNUSED
static const char *qos_req_rate_tm_cmd(cmd_parms *cmd, void *dcfg, const char *arg1) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->qs_req_rate_tm= atoi(arg1);
  if(sconf->qs_req_rate_tm <= 0) {
    return apr_psprintf(cmd->pool, "%s: must be numeric value between >0",
                        cmd->directive->directive);
  }
  return NULL;
}
#endif

static const char *qos_client_tolerance_cmd(cmd_parms *cmd, void *dcfg, const char *arg1) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->cc_tolerance = atoi(arg1);
  if(sconf->cc_tolerance < 5 || sconf->cc_tolerance > 80) {
    return apr_psprintf(cmd->pool, "%s: must be numeric value between 5 and 80",
                        cmd->directive->directive);
  }
  return NULL;
}

#ifdef AP_TAKE_ARGV
static const char *qos_client_contenttype(cmd_parms *cmd, void *dcfg, int argc, char *const argv[]) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  if(argc != 5) {
    return apr_psprintf(cmd->pool, "%s: requires five arguments",
                        cmd->directive->directive);
  }
  sconf->static_on = 1;
  sconf->static_html = atol(argv[0]);
  sconf->static_cssjs = atol(argv[1]);
  sconf->static_img = atol(argv[2]);
  sconf->static_other = atol(argv[3]);
  sconf->static_notmodified = atol(argv[4]);
  if(sconf->static_html == 0 ||
     sconf->static_cssjs == 0 ||
     sconf->static_img == 0 ||
     sconf->static_other == 0 ||
     sconf->static_notmodified == 0) {
    return apr_psprintf(cmd->pool, "%s: requires numeric values greater than 0",
                        cmd->directive->directive);
  } else {
    unsigned long long s_all = sconf->static_html + sconf->static_img + sconf->static_cssjs + 
      sconf->static_other + sconf->static_notmodified;
    unsigned long long s_2html = 100 * sconf->static_html / s_all;
    unsigned long long s_2cssjs = 100 * sconf->static_cssjs / s_all;
    unsigned long long s_2img = 100 * sconf->static_img / s_all;
    unsigned long long s_2other = 100 * sconf->static_other / s_all;
    unsigned long long s_2notmodified = 100 * sconf->static_notmodified / s_all;
    sconf->static_html = s_2html;
    sconf->static_cssjs = s_2cssjs;
    sconf->static_img = s_2img;
    sconf->static_other = s_2other;
    sconf->static_notmodified = s_2notmodified;
  }
  return NULL;
}
#endif

static const char *qos_client_event_cmd(cmd_parms *cmd, void *dcfg, const char *arg1) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->has_qos_cc = 1;
  sconf->qos_cc_event = atoi(arg1);
  if((sconf->qos_cc_event < 0) || ((sconf->qos_cc_event == 0) && (strcmp(arg1, "0") != 0))) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >=0", 
                        cmd->directive->directive);
  }
  return NULL;
}

static const char *qos_client_event_req_cmd(cmd_parms *cmd, void *dcfg, const char *arg1) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
  if (err != NULL) {
    return err;
  }
  sconf->has_qos_cc = 1;
  sconf->qos_cc_event_req = atoi(arg1);
  if((sconf->qos_cc_event_req < 0) || ((sconf->qos_cc_event_req == 0) && (strcmp(arg1, "0") != 0))) {
    return apr_psprintf(cmd->pool, "%s: number must be numeric value >=0", 
                        cmd->directive->directive);
  }
  return NULL;
}

static const char *qos_disable_handler_cmd(cmd_parms *cmd, void *dcfg, int flag) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->disable_handler = flag;
  return NULL;
}

#ifdef QS_INTERNAL_TEST
static const char *qos_disable_int_ip_cmd(cmd_parms *cmd, void *dcfg, int flag) {
  qos_srv_config *sconf = (qos_srv_config*)ap_get_module_config(cmd->server->module_config,
                                                                &qos_module);
  sconf->enable_testip = flag;
  return NULL;
}
#endif

static const command_rec qos_config_cmds[] = {
  AP_INIT_FLAG("QS_LogOnly", qos_logonly_cmd, NULL,
               RSRC_CONF,
               "QS_LogOnly 'on'|'off', enabled log only mode where no limitations are"
               " enforced. Default is off."),
  AP_INIT_TAKE1("QS_SemMemFile", qos_mfile_cmd, NULL,
                RSRC_CONF,
                "QS_SemMemFile <path>, optional path to a directory or file"
                " which shall be used for file based samaphores/shared memory"
                " usage."
                " Default is "QS_MFILE"."),
  /* request limitation per location */
  AP_INIT_TAKE2("QS_LocRequestLimit", qos_loc_con_cmd, NULL,
                RSRC_CONF,
                "QS_LocRequestLimit <location> <number>, defines the maximum number of"
                " concurrent requests allowed to access the specified location. Default is defined by the"
                " QS_LocRequestLimitDefault directive."),
  AP_INIT_TAKE1("QS_LocRequestLimitDefault", qos_loc_con_def_cmd, NULL,
                RSRC_CONF,
                "QS_LocRequestLimitDefault <number>, defines the default for the"
                " QS_LocRequestLimit and QS_LocRequestLimitMatch directive."),
  AP_INIT_TAKE2("QS_LocRequestPerSecLimit", qos_loc_rs_cmd, NULL,
                RSRC_CONF,
                "QS_LocRequestPerSecLimit <location> <number>, defines the allowed"
                " number of requests per second to a location. Requests are limited"
                " by adding a delay to each requests. This directive should be used"
                " in conjunction with QS_LocRequestLimit only."),
  AP_INIT_TAKE2("QS_LocKBytesPerSecLimit", qos_loc_bs_cmd, NULL,
                RSRC_CONF,
                "QS_LocKBytesPerSecLimit <location> <kbytes>, defines the allowed"
                " download bandwidth to the defined kbytes per second. Responses are"
                "slowed by adding a delay to each response (non-linear, bigger files"
                " get longer delay than smaller ones). This directive should be used"
                " in conjunction with QS_LocRequestLimit only."),
  AP_INIT_TAKE2("QS_LocRequestLimitMatch", qos_match_con_cmd, NULL,
                RSRC_CONF,
                "QS_LocRequestLimitMatch <regex> <number>, defines the number of"
                " concurrent requests to the uri (path and query) pattern."
                " Default is defined by the QS_LocRequestLimitDefault directive."),

  AP_INIT_TAKE3("QS_CondLocRequestLimitMatch", qos_cond_match_con_cmd, NULL,
                RSRC_CONF,
                "QS_CondLocRequestLimitMatch <regex> <number> <pattern>, defines the number of"
                " concurrent requests to the uri (path and query) regex."
                " Rule is only enforced of the "QS_COND" variable matches the specified"
                " pattern (regex)."),
  AP_INIT_TAKE2("QS_LocRequestPerSecLimitMatch", qos_match_rs_cmd, NULL,
                RSRC_CONF,
                "QS_LocRequestPerSecLimitMatch <regex> <number>, defines the allowed"
                " number of requests per second to the uri (path and query) pattern."
                " Requests are limited by adding a delay to each requests."
                " This directive should be used in conjunction with"
                " QS_LocRequestLimitMatch only."),
  AP_INIT_TAKE2("QS_LocKBytesPerSecLimitMatch", qos_match_bs_cmd, NULL,
                RSRC_CONF,
                "QS_LocKBytesPerSecLimitMatch <regex> <kbytes>, defines the allowed"
                " download bandwidth to the location matching the defined URL (path"
                " and query) pattern. Responses are slowed down"
                " by adding a delay to each response (non-linear, bigger files"
                " get longer delay than smaller ones). This directive should be used"
                " in conjunction with QS_LocRequestLimitMatch only."),
  /* error document */
  AP_INIT_TAKE1("QS_ErrorPage", qos_error_page_cmd, NULL,
                RSRC_CONF,
                "QS_ErrorPage <url>, defines a custom error page."),
  AP_INIT_TAKE1("QS_Chroot", qos_chroot_cmd, NULL,
                RSRC_CONF,
                "QS_Chroot <path>, change root directory."),
  AP_INIT_TAKE1("QS_ErrorResponseCode", qos_error_code_cmd, NULL,
                RSRC_CONF,
                "QS_ErrorResponseCode <code>, defines the HTTP response code which"
                " is used when a request is denied, default is 500."),
  AP_INIT_TAKE12("QS_UserTrackingCookieName", qos_user_tracking_cookie_cmd, NULL,
                 RSRC_CONF,
                 "QS_UserTrackingCookieName <name> [<path>], enables the user tracking cookie by"
                 " defining a cookie name. User tracking requires mod_unique_id."
                 " This feature is disabled by default. Ignores QS_LogOnly."),
  /* vip session */
  AP_INIT_TAKE1("QS_SessionCookieName", qos_cookie_name_cmd, NULL,
                RSRC_CONF,
                "QS_SessionCookieName <name>, defines a custom session cookie name,"
                " default is "QOS_COOKIE_NAME"."),
  AP_INIT_TAKE1("QS_SessionCookiePath", qos_cookie_path_cmd, NULL,
                RSRC_CONF,
                "QS_SessionCookiePath <path>, defines the cookie path, default is \"/\"."),
  AP_INIT_TAKE1("QS_SessionTimeout", qos_timeout_cmd, NULL,
                RSRC_CONF,
                "QS_SessionTimeout <seconds>, defines the session life time for a VIP."
                " It is only used for session based (cookie) VIP identification (not"
                " for IP based). Default is "QOS_MAX_AGE" seconds."),
  AP_INIT_TAKE1("QS_SessionKey", qos_key_cmd, NULL,
                RSRC_CONF,
                "QS_SessionKey <string>, secret key used for cookie encryption."
                " Used when using the same session cookie for multiple web servers"
                " (load balancing) or sessions should survive a server restart."
                " By default, a random key is used which changes every server restart."),
  AP_INIT_TAKE12("QS_VipHeaderName", qos_header_name_cmd, NULL,
                 RSRC_CONF,
                 "QS_VipHeaderName <name>[=<regex>] [drop], defines an HTTP response"
                 " header which marks a user as a VIP. mod_qos creates"
                 " a session for this user by setting a cookie, e.g., after successful"
                 " user authentication. Tests optionally its value against the provided"
                 " regular expression. Specify the action 'drop' if you want mod_qos"
                 " to remove this control header from the HTTP response."),
  AP_INIT_TAKE12("QS_VipIPHeaderName", qos_ip_header_name_cmd, NULL,
                 RSRC_CONF,
                 "QS_VipIPHeaderName <name>[=<regex>] [drop], defines an HTTP"
                 " response header which marks a client source IP address as a VIP."
                 " Tests optionally its value against the provided regular expression."
                 " Specify the action 'drop' if you want mod_qos to remove this"
                 " control header from the HTTP response."),
  AP_INIT_NO_ARGS("QS_VipUser", qos_vip_u_cmd, NULL,
                  RSRC_CONF,
                  "QS_VipUser, creates a VIP session for users which have been"
                  " authenticated by the Apache server, e.g., by the standard"
                  " mod_auth* modules. It works similar to the QS_VipHeaderName"
                  " directive."),
  AP_INIT_NO_ARGS("QS_VipIpUser", qos_vip_ip_u_cmd, NULL,
                  RSRC_CONF,
                  "QS_VipIpUser, marks a source IP address as a VIP if the"
                  " user has been authenticated by the Apache server, e.g."
                  " by the standard mod_auth* modules. It works similar to"
                  " the QS_VipIPHeaderName directive."),
  AP_INIT_TAKE1("QS_SrvMaxConn", qos_max_conn_cmd, NULL,
                RSRC_CONF,
                "QS_SrvMaxConn <number>, defines the maximum number of concurrent"
                " TCP connections for this server (virtual host)."),
  AP_INIT_TAKE1("QS_SrvMaxConnClose", qos_max_conn_close_cmd, NULL,
                RSRC_CONF,
                "QS_SrvMaxConnClose <number>, defines the maximum number of"
                " concurrent TCP connections until the server disables"
                " keep-alive for this server (closes the connection after"
                " each requests. You may specify the number of connections"
                " as a percentage of MaxClients if adding the suffix '%'"
                " to the specified value."),
  AP_INIT_TAKE12("QS_SrvMaxConnPerIP", qos_max_conn_ip_cmd, NULL,
                 RSRC_CONF,
                 "QS_SrvMaxConnPerIP <number> [<connections>], defines the maximum number"
                 " of connections per source IP address for this server (virtual host)."
                 " 'connections' defines the number of busy connections of the server"
                 " (all virtual hosts) to enable this limitation, default is 0."),
  AP_INIT_TAKE1("QS_SrvMaxConnExcludeIP", qos_max_conn_ex_cmd, NULL,
                RSRC_CONF,
                "QS_SrvMaxConnExcludeIP <addr>, excludes an ip address or"
                " address range from beeing limited."),
#if QS_APACHE_22
#if APR_HAS_THREADS
  AP_INIT_NO_ARGS("QS_SrvDataRateOff", qos_req_rate_off_cmd, NULL,
                  RSRC_CONF,
                  "QS_SrvDataRateOff,"
                  " disables the QS_SrvRequestRate and QS_SrvMinDataRate enforcement for"
                  " a virtual host (only port/address based but not for name based"
                  " virtual hosts)."),
  AP_INIT_TAKE1("QS_SrvSampleRate", qos_req_rate_tm_cmd, NULL,
                RSRC_CONF,
                "QS_SrvSampleRate <seconds>"),
  AP_INIT_TAKE12("QS_SrvRequestRate", qos_req_rate_cmd, NULL,
                 RSRC_CONF,
                 "QS_SrvRequestRate <bytes per seconds> [<max bytes per second>],"
                 " defines the minumum upload"
                 " throughput a client must generate. See also QS_SrvMinDataRate."),
#ifdef AP_TAKE_ARGV
  AP_INIT_TAKE_ARGV("QS_SrvMinDataRate", qos_min_rate_cmd, NULL,
                    RSRC_CONF,
                    "QS_SrvMinDataRate <bytes per seconds> [<max bytes per second> [<connections>]],"
                    " defines the minumum upload/download"
                    " throughput a client must generate (the bytes send/received by the client"
                    " per seconds). This bandwidth is measured while transmitting the data"
                    " (request line, header fields, request body, or response data). The"
                    " client connection get closed if the client does not fulfill the"
                    " required data rate and the IP address of the causing client get marked"
                    " in order to be handled with low priority (see the QS_ClientPrefer"
                    " directive)."
                    " The \"max bytes per second\" activates dynamic"
                    " minimum throughput control: The required minimal throughput"
                    " is increased in parallel to the number of concurrent clients"
                    " sending/receiving data. The \"max bytes per second\""
                    " setting is reached when the number of sending/receiving"
                    " clients is equal to the MaxClients setting."
                    " The \"connections\" argument is used to specify the"
                    " number of busy TCP connections a server must have to"
                    " enable this feature (0 by default)."
                    " No limitation is set by default."),
#else
  AP_INIT_TAKE2("QS_SrvMinDataRate", qos_min_rate_cmd, NULL,
                    RSRC_CONF,
                    "QS_SrvMinDataRate <bytes per seconds> [<max bytes per second>],"
                    " defines the minumum upload/download"
                    " throughput a client must generate (the bytes send/received by the client"
                    " per seconds). This bandwidth is measured while transmitting the data"
                    " (request line, header fields, request body, or response data). The"
                    " client connection get closed if the client does not fulfill the"
                    " required data rate and the IP address of the causing client get marked"
                    " in order to be handled with low priority (see the QS_ClientPrefer"
                    " directive)."
                    " The \"max bytes per second\" activates dynamic"
                    " minimum throughput control: The required minimal throughput"
                    " is increased in parallel to the number of concurrent clients"
                    " sending/receiving data. The \"max bytes per second\""
                    " setting is reached when the number of sending/receiving"
                    " clients is equal to the MaxClients setting."
                    " No limitation is set by default."),
#endif // ARGV
  AP_INIT_TAKE1("QS_SrvMinDataRateOffEvent", qos_min_rate_off_cmd, NULL,
                RSRC_CONF|ACCESS_CONF,
                "QS_SrvMinDataRateOffEvent  '+'|'-'<env-variable>,"
                " disables the minimal data rate enfocement (QS_SrvMinDataRate)"
                " for a certain connection if the defined environment variable"
                " has been set. The '+' prefix is used to add a variable"
                " to the configuration while the '-' prefix is used"
                " to remove a variable."),
#endif // has threads
#endif // QS_APACHE_22
  /* event */
  AP_INIT_TAKE2("QS_EventRequestLimit", qos_event_req_cmd, NULL,
                RSRC_CONF,
                "QS_EventRequestLimit <variable>[=<regex>] <number>, defines the"
                " number of concurrent events. Directive works similar to"
                " QS_LocRequestLimit, but counts the requests having the same"
                " environment variable (and optionally matching its value, too)"
                " rather than those that have the same URL pattern."),
  AP_INIT_TAKE2("QS_EventPerSecLimit", qos_event_rs_cmd, NULL,
                RSRC_CONF,
                "QS_EventPerSecLimit [!]<variable> <number>, defines how"
                " often requests may have the defined environment variable"
                " (literal string) set. It measures the occurrences of the defined"
                " environment variable on a request per seconds level and tries to"
                " limit this occurrence to the defined number. It works similar to"
                " as QS_LocRequestPerSecLimit, but counts only the requests with the"
                " specified variable (or without it if the variable name is"
                " prefixed by a '!'). If a request matches multiple events, the"
                " rule with the lowest bandwidth is applied. Events are limited"
                " by adding a delay to each request causing an  event."),
  AP_INIT_TAKE2("QS_EventKBytesPerSecLimit", qos_event_bps_cmd, NULL,
                RSRC_CONF,
                "QS_EventKBytesPerSecLimit [!]<variable> <kbytes>, throttles the"
                " download bandwidth of all requests having the defined"
                " variable set to the defined kbytes per second. Responses are slowed"
                " by adding a delay to each response (non-linear, bigger files get"
                " longer delay than smaller ones). By default, no limitation is active."
                " This directive should be used in conjunction with QS_EventRequestLimit"
                " only (you must use the same variable name for both directives)."),
  AP_INIT_TAKE2("QS_EventNewKbytesPerSecLimit", qos_event_hard_bandwidth_cmd, NULL,
                RSRC_CONF, "proposed reimplementation of bandwidth use per event"),
  AP_INIT_TAKE3("QS_EventLimitCount", qos_event_limit_cmd, NULL,
                RSRC_CONF,
                "QS_EventLimitCount <env-variable> <number> <seconds>,"
                " defines the maximum number of events allowed within the defined"
                " time. Requests are denied when reaching this limitation for the"
                " specified time (blocked at request level)."),
  AP_INIT_TAKE3("QS_SetEnvIf", qos_event_setenvif_cmd, NULL,
                RSRC_CONF,
                "QS_SetEnvIf [!]<variable1> [!]<variable1> [!]<variable=value>,"
                " sets (or unsets) the 'variable=value' (literal string) if variable1"
                " (literal string) AND variable2 (literal string) are set in the"
                " request environment variable list (not case sensitive)."
                " This is used to combine multiple variables to a new event type."),
  AP_INIT_TAKE2("QS_SetEnvIfQuery", qos_event_setenvifquery_cmd, NULL,
                RSRC_CONF,
                "QS_SetEnvIfQuery <regex> [!]<variable>[=value],"
                " directive works quite similar to the SetEnvIf directive"
                " of the Apache module mod_setenvif, but the specified regex is"
                " applied against the query string portion of the request line."
                " The directive recognizes the occurrences of $1..$9 within"
                " value and replaces them by the sub-expressions of the defined"
                " regex pattern."),
  AP_INIT_TAKE2("QS_SetEnvIfParp", qos_event_setenvifparp_cmd, NULL,
                RSRC_CONF,
                "QS_SetEnvIfParp <regex> [!]<variable>[=value],"
                " directive parsing the request payload using the Apache module"
                " mod_parp. It matches the request URL query and the HTTP"
                " request message body data as well ('application/x-www-form-urlencoded'," 
                " 'multipart/form-data', and 'multipart/mixed') and sets the defined"
                " process variable (quite similar to the QS_SetEnvIfQuery directive)."
                " The directive recognizes the occurrences of $1..$9 within value"
                " and replaces them by the sub-expressions of the defined regex"
                " pattern. This directive activates mod_parp for every request to"
                " the virtual host. You may deactivate mod_parp for selected requests"
                " using the SetEnvIf directive: unset the variable 'parp' to do so."
                " Important: request message body processing requires that the server"
                " loads the whole request into its memory (at least twice the length"
                " of the message). You should limit the allowed size of the HTTP"
                " request message body using the QS_LimitRequestBody directive"
                " when using QS_SetEnvIfParp!"),
  AP_INIT_TAKE2("QS_SetEnvIfBody", qos_event_setenvifparpbody_cmd, NULL,
                RSRC_CONF,
                "QS_SetEnvIfBody <regex> [!]<variable>[=value],"
                " parses the request body using the Apache module mod_parp."
                " Specify the content types to process using the mod_parp"
                " directive PARP_BodyData and ensure that mod_parp is enabled"
                " using the SetEnvIf directive of the Apache module mod_setenvif." 
                " You should limit the allowed size of HTTP requests message body"
                " using the QS_LimitRequestBody directive when using mod_parp."
                " The directive recognizes the occurrence of $1 within the variable"
                " value and replaces it by the sub-expressions of the defined regex"
                " pattern."),
  AP_INIT_TAKE2("QS_SetEnvStatus", qos_event_setenvstatus_cmd, NULL,
                RSRC_CONF|ACCESS_CONF,
                "QS_SetEnvStatus (deprecated, use QS_SetEnvIfStatus)"),
  AP_INIT_TAKE2("QS_SetEnvIfStatus", qos_event_setenvstatus_cmd, NULL,
                RSRC_CONF|ACCESS_CONF,
                "QS_SetEnvIfStatus <status code> <variable>, adds the defined"
                " request environment variable if the HTTP status code matches the"
                " defined value. The value '"QS_CLOSE"' may be used as a special"
                " status code to set a "QS_BLOCK" event in order to handle"
                " connection close events caused by "QS_CLOSE" rules while"
                " the status '"QS_EMPTY_CON"' may be used to mark connections"
                " which are closed before any HTTP request has ever been received."),
  AP_INIT_TAKE2("QS_SetEnvResBody", qos_event_setenvresbody_cmd, NULL,
                ACCESS_CONF,
                "QS_SetEnvResBody (deprecated, use QS_SetEnvIfResBody)"),
  AP_INIT_TAKE2("QS_SetEnvIfResBody", qos_event_setenvresbody_cmd, NULL,
                ACCESS_CONF,
                "QS_SetEnvIfResBody <string> <variable>, adds the defined"
                " request environment variable (e.g. "QS_BLOCK") if the HTTP"
                " response body contains the defined literal string."
                " Supports only one pattern per location."),
  AP_INIT_TAKE2("QS_SetEnv", qos_setenv_cmd, NULL,
                RSRC_CONF,
                "QS_SetEnv <variable> <value>, sets the defined variable"
                " with the value where the value string may contain" 
                " other environment variables surrounded by \"${\" and \"}\"."
                " The variable is only set if all defined variables within"
                " the value can be resolved."),
  AP_INIT_TAKE23("QS_SetReqHeader", qos_setreqheader_cmd, NULL,
                RSRC_CONF,
                "QS_SetReqHeader <header name> <variable> ['late'], sets the defined"
                " HTTP request header to the request if the specified"
                " environment variable is set."),
  AP_INIT_TAKE1("QS_UnsetResHeader", qos_unsetresheader_cmd, NULL,
                RSRC_CONF,
                "QS_UnsetResHeader <header name>, Removes the specified response header."),
  AP_INIT_TAKE12("QS_SetEnvResHeader", qos_event_setenvresheader_cmd, NULL,
                 RSRC_CONF,
                 "QS_SetEnvResHeader <header name> [drop], sets the defined"
                 " HTTP response header to the request environment variables."
                 " Deletes the header if the action 'drop' has been specified."),
  AP_INIT_TAKE2("QS_SetEnvResHeaderMatch", qos_event_setenvresheadermatch_cmd, NULL,
                RSRC_CONF,
                "QS_SetEnvResHeaderMatch <header name> <regex>, sets the defined"
                " HTTP response header to the request environment variables"
                " if the specified regular expression (pcre) matches the header value."),
  AP_INIT_TAKE3("QS_SetEnvRes", qos_setenvres_cmd, NULL,
                RSRC_CONF,
                "QS_SetEnvRes <variable> <regex> <variable2>[=<value>], sets the environmet"
                " variable2 if the regular expression matches against the value of"
                " the environment variable. Occurrences of $1..$9 within the value"
                " and replace them by parenthesized subexpressions of the regular expression."),
  AP_INIT_TAKE3("QS_RedirectIf", qos_redirectif_cmd, NULL,
                RSRC_CONF|ACCESS_CONF,
                "QS_RedirectIf <variable> <regex> <url>, redirects the client to the"
                " configured url if the regular expression matches the value of the"
                " the environment variable."),
  /* generic request filter */
  AP_INIT_TAKE3("QS_DenyRequestLine", qos_deny_rql_cmd, NULL,
                ACCESS_CONF,
                "QS_DenyRequestLine '+'|'-'<id> 'log'|'deny' <pcre>, generic"
                " request line (method, path, query and protocol) filter used"
                " to deny access for requests matching the defined expression (pcre)."
                " '+' adds a new rule while '-' removes a rule for a location."
                " The action is either 'log' (access is granted but rule"
                " match is logged) or 'deny' (access is denied)."),
  AP_INIT_TAKE3("QS_DenyPath", qos_deny_path_cmd, NULL,
                ACCESS_CONF,
                "QS_DenyPath, same as QS_DenyRequestLine but applied to the"
                " path only."),
  AP_INIT_TAKE3("QS_DenyQuery", qos_deny_query_cmd, NULL,
                ACCESS_CONF,
                "QS_DenyQuery, same as QS_DenyRequestLine but applied to the"
                " query only."),
  AP_INIT_TAKE1("QS_InvalidUrlEncoding", qos_deny_urlenc_cmd, NULL,
                ACCESS_CONF,
                "QS_InvalidUrlEncoding 'log'|'deny'|'off',"
                " enforces correct URL decoding in conjunction with the"
                " QS_DenyRequestLine, QS_DenyPath, and QS_DenyQuery"
                " directives. Default is \"off\"."),
  AP_INIT_TAKE3("QS_DenyEvent", qos_deny_event_cmd, NULL,
                ACCESS_CONF,
                "QS_DenyEvent '+'|'-'<id> 'log'|'deny' [!]<variable>, matches"
                " requests having the defined process"
                " environment variable set (or NOT set if prefixed by a '!')."
                " The action taken for matching rules"
                " is either 'log' (access is granted but the rule match is"
                " logged) or 'deny' (access is denied)."),
  AP_INIT_TAKE3("QS_PermitUri", qos_permit_uri_cmd, NULL,
                ACCESS_CONF,
                "QS_PermitUri, '+'|'-'<id> 'log'|'deny' <pcre>, generic"
                " request filter applied to the request uri (path and query)."
                " Only requests matching at least one QS_PermitUri pattern are"
                " allowed. If a QS_PermitUri pattern has been defined an the"
                " request does not match any rule, the request is denied albeit of"
                " any server resource availability (white list). All rules"
                " must define the same action. pcre is case sensitve."),
  AP_INIT_TAKE1("QS_LimitRequestBody", qos_maxpost_cmd, NULL,
                ACCESS_CONF|RSRC_CONF,
                "QS_LimitRequestBody <bytes>, limits the allowed size"
                " of an HTTP request message body."),
  AP_INIT_TAKE2("QS_MileStone", qos_milestone_cmd, NULL,
                RSRC_CONF,
                "QS_MileStone 'log'|'deny' <pattern>, defines request line patterns"
                " a client must access in the defined order as they are defined in the"
                " configuration file."),
  AP_INIT_TAKE1("QS_MileStoneTimeout", qos_milestone_tmo_cmd, NULL,
                RSRC_CONF,
                "QS_MileStoneTimeout <seconds>, defines the time in seconds"
                " within a client must reach the next milestone."
                " Default are 3600 seconds."),
  AP_INIT_ITERATE("QS_Decoding", qos_dec_cmd, NULL,
                  ACCESS_CONF,
                  "QS_DenyDecoding 'uni', enabled additional string decoding"
                  " functions which are applied before"
                  " matching QS_Deny* and QS_Permit* directives."
                  " Default is URL decoding (%xx, \\xHH, '+')."),
  AP_INIT_NO_ARGS("QS_DenyInheritanceOff", qos_denyinheritoff_cmd, NULL,
                  ACCESS_CONF,
                  "QS_DenyInheritanceOff, disable inheritance of QS_Deny* and QS_Permit*"
                  " directives to a location."),
  AP_INIT_TAKE1("QS_RequestHeaderFilter", qos_headerfilter_cmd, NULL,
                RSRC_CONF|ACCESS_CONF,
                "QS_RequestHeaderFilter 'on'|'off'|'size', filters request headers by allowing"
                " only these headers which match the request header rules defined by"
                " mod_qos. Request headers which do not conform these definitions"
                " are either dropped or the whole request is denied. Custom"
                " request headers may be added by the QS_RequestHeaderFilterRule"
                " directive. Using the 'size' option, the header field max. size"
                " is verified only (similar to LimitRequestFieldsize but using"
                " individual values for each header type) while the pattern is ignored."),
  AP_INIT_TAKE1("QS_ResponseHeaderFilter", qos_resheaderfilter_cmd, NULL,
                ACCESS_CONF,
                "QS_ResponseHeaderFilter 'on'|'off', filters response headers by allowing"
                " only these headers which match the request header rules defined by"
                " mod_qos. Request headers which do not conform these definitions"
                " are dropped."),
#ifdef AP_TAKE_ARGV
  AP_INIT_TAKE_ARGV("QS_RequestHeaderFilterRule", qos_headerfilter_rule_cmd, NULL,
                    RSRC_CONF,
                    "QS_RequestHeaderFilterRule <header name> 'drop'|'deny' <pcre>  <size>, used"
                    " to add custom request header filter rules which override the internal"
                    " filter rules of mod_qos."
                    " Directive is allowed in global server context only."),
#else
  AP_INIT_TAKE3("QS_RequestHeaderFilterRule", qos_headerfilter_rule_cmd, NULL,
                    RSRC_CONF,
                    "QS_RequestHeaderFilterRule <header name> 'drop'|'deny' <pcre>, used"
                    " to add custom request header filter rules which override the internal"
                    " filter rules of mod_qos."
                    " Directive is allowed in global server context only."),
#endif
  AP_INIT_TAKE3("QS_ResponseHeaderFilterRule", qos_resheaderfilter_rule_cmd, NULL,
                RSRC_CONF,
                "QS_ResponseHeaderFilterRule <header name> <pcre> <size>, used"
                " to add custom response header filter rules which override the internal"
                " filter rules of mod_qos."
                " Directive is allowed in global server context only."),
  AP_INIT_FLAG("QS_DenyBody", qos_denybody_cmd, NULL,
               ACCESS_CONF,
               "QS_DenyBody 'on'|'off', enabled body data filter (obsolete)."),
  AP_INIT_FLAG("QS_DenyQueryBody", qos_denybody_d_cmd, NULL,
               ACCESS_CONF,
               "QS_DenyQueryBody 'on'|'off', enabled body data filter for QS_DenyQuery."),
  AP_INIT_FLAG("QS_PermitUriBody", qos_denybody_p_cmd, NULL,
               ACCESS_CONF,
               "QS_PermitUriBody 'on'|'off', enabled body data filter for QS_PermitUriBody."),
  /* client control */
  AP_INIT_TAKE1("QS_ClientGeoCountryDB", qos_geodb_cmd, NULL,
                RSRC_CONF,
                "QS_ClientGeoCountryDB <path>, path to the geograpical database file."),
  AP_INIT_TAKE2("QS_ClientGeoCountryPriv", qos_geopriv_cmd, NULL,
                RSRC_CONF,
                "QS_ClientGeoCountryPriv <list> <connections>, defines a comma separated list of"
                " country codes for origin client IP address which are allowed to"
                " access the server if the number of busy TCP connections reaches"
                " the defined number of connections."),
  AP_INIT_TAKE1("QS_ClientEntries", qos_client_cmd, NULL,
                RSRC_CONF,
                "QS_ClientEntries <number>, defines the number of individual"
                " clients managed by mod_qos. Default is 50000."
                " Directive is allowed in global server context only."),
  AP_INIT_FLAG("QS_SupportIPv6", qos_enable_ipv6_cmd, NULL,
               RSRC_CONF,
               "QS_SupportIPv6 'on'|'off', enables IPv6 address support."
               " Default is on."),
#ifdef AP_TAKE_ARGV
  AP_INIT_TAKE_ARGV("QS_ClientPrefer", qos_client_pref_cmd, NULL,
                    RSRC_CONF,
                    "QS_ClientPrefer [<percent>], prefers known VIP clients"
                    " when server has"
                    " less than 80% of free TCP connections. Preferred clients"
                    " are VIP clients only, see QS_VipHeaderName directive."
                    " Directive is allowed in global server context only."
                    ""),
#else
  AP_INIT_NO_ARGS("QS_ClientPrefer", qos_client_pref_cmd, NULL,
                  RSRC_CONF,
                  "QS_ClientPrefer [<percent>], prefers known VIP clients"
                  " when server has"
                  " less than 80% of free TCP connections. Preferred clients"
                  " are VIP clients only, see QS_VipHeaderName directive."
                  " Directive is allowed in global server context only."
                  ""),
#endif
  AP_INIT_TAKE1("QS_ClientTolerance", qos_client_tolerance_cmd, NULL,
                RSRC_CONF,
                "QS_ClientTolerance <number>, defines the allowed tolerance (variation)"
                " from a \"normal\" client (average) in percent. Default is "QOS_CC_BEHAVIOR_TOLERANCE_STR"%."
                " Directive is allowed in global server context only."),
#ifdef AP_TAKE_ARGV
  AP_INIT_TAKE_ARGV("QS_ClientContentTypes", qos_client_contenttype, NULL,
                    RSRC_CONF,
                    "QS_ClientContentTypes <html> <css/js> <images> <other> <304>,"
                    " defines the distribution of HTTP response content types a client normaly"
                    " receives when accessing the server. mod_qos normally learns the average"
                    " behavior automatically by default but you may specify a static configuration"
                    " in order to avoid influences by a high number of abnormal clients."),
#endif
  AP_INIT_TAKE12("QS_ClientEventBlockCount", qos_client_block_cmd, NULL,
                 RSRC_CONF,
                 "QS_ClientEventBlockCount <number> [<seconds>], defines the maximum number"
                 " of "QS_BLOCK" allowed within the defined time (default are 10 minutes)."
                 " Directive is allowed in global server context only."),
  AP_INIT_TAKE123("QS_ClientEventLimitCount", qos_client_limit_cmd, NULL,
                  RSRC_CONF,
                  "QS_ClientEventLimitCount <number> [<seconds> [<variable>]],"
                  " defines the maximum number"
                  " of the specified environment variable ("QS_LIMIT_DEFAULT" by default)"
                  " allowed within the defined time (default are 10 minutes)."
                  " Directive is allowed in global server context only."),
#ifdef AP_TAKE_ARGV
  AP_INIT_TAKE_ARGV("QS_CondClientEventLimitCount", qos_cond_client_limit_cmd, NULL,
                    RSRC_CONF,
                    "QS_CondClientEventLimitCount <number> <seconds> <variable> <pattern>,"
                    " defines the maximum number"
                    " of the specified environment variable"
                    " allowed within the defined time."
                    " Directive works similar as QS_ClientEventLimitCount but"
                    " requests are only blocked if the "QS_COND" variable matches"
                    " the defined pattern (regex)."
                    " Directive is allowed in global server context only."),
#endif
  AP_INIT_TAKE1("QS_ClientIpFromHeader", qos_client_forwardedfor_cmd, NULL,
                RSRC_CONF,
                "QS_ClientIpFromHeader <header>, defines a HTTP request header to read"
                " the client's source IP address from (instead of taking the IP address"
                " of the client opening the TCP connection). This may be used for the"
                " QS_ClientEventLimitCount directive and QS_Country variable."),
  AP_INIT_NO_ARGS("QS_ClientSerialize", qos_client_serial_cmd, NULL,
                  RSRC_CONF,
                  "QS_ClientSerialize, serializes requests having the "QS_SERIALIZE" variable"
                  " set if they are comming from the same IP address."),
  AP_INIT_TAKE1("QS_ClientEventPerSecLimit", qos_client_event_cmd, NULL,
                RSRC_CONF,
                "QS_ClientEventPerSecLimit <number>, defines the number"
                " events pro seconds on a per client (source IP) basis."
                " Events are identified by requests having the"
                " "QS_EVENT" variable set."
                " Directive is allowed in global server context only."),
  AP_INIT_TAKE1("QS_ClientEventRequestLimit", qos_client_event_req_cmd, NULL,
                RSRC_CONF,
                "QS_ClientEventRequestLimit <number>, defines the allowed"
                " number of concurrent requests comming from the same client"
                " source IP address"
                " having the QS_EventRequest variable set."
                " Directive is allowed in global server context only."),
  AP_INIT_FLAG("QS_DisableHandler", qos_disable_handler_cmd, NULL,
               RSRC_CONF,
               ""),
#ifdef QS_INTERNAL_TEST
  AP_INIT_FLAG("QS_EnableInternalIPSimulation", qos_disable_int_ip_cmd, NULL,
               RSRC_CONF,
               ""),
#endif
  { NULL }
};


/************************************************************************
 * apache register 
 ***********************************************************************/
static void qos_register_hooks(apr_pool_t * p) {
  static const char *pre[] = { "mod_setenvif.c", "mod_setenvifplus.c", "mod_parp.c", NULL };
  static const char *preuid[] = { "mod_setenvif.c", "mod_setenvifplus.c", "mod_parp.c", "mod_unique_id.c", NULL };
  static const char *pressl[] = { "mod_ssl.c", NULL };
  static const char *preconf[] = { "mod_setenvif.c", "mod_setenvifplus.c", "mod_parp.c", "mod_ssl.c", NULL };
  static const char *post[] = { "mod_setenvif.c", "mod_setenvifplus.c", NULL };
  static const char *parp[] = { "mod_parp.c", NULL };
  static const char *prelast[] = { "mod_setenvif.c", "mod_setenvifplus.c", "mod_ssl.c", NULL };
  ap_hook_post_config(qos_post_config, preconf, NULL, APR_HOOK_MIDDLE);
#ifndef QS_HAS_APACHE_PATH
  /* use post config hook only for non-patched Apache server (worker.c/prefork.c) */
  ap_hook_post_config(qos_chroot, prelast, NULL, APR_HOOK_REALLY_LAST);
#endif
  ap_hook_child_init(qos_child_init, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_pre_connection(qos_pre_connection, NULL, pressl, APR_HOOK_FIRST);
  ap_hook_process_connection(qos_process_connection, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_post_read_request(qos_post_read_request, NULL, post, APR_HOOK_MIDDLE);
  ap_hook_post_read_request(qos_post_read_request_later, preuid, NULL, APR_HOOK_MIDDLE);
  ap_hook_header_parser(qos_header_parser0, NULL, post, APR_HOOK_FIRST);
  ap_hook_header_parser(qos_header_parser1, post, parp, APR_HOOK_FIRST);
  ap_hook_header_parser(qos_header_parser, pre, NULL, APR_HOOK_MIDDLE);
  ap_hook_fixups(qos_fixup, pre, NULL, APR_HOOK_MIDDLE);
  ap_hook_handler(qos_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_log_transaction(qos_logger, NULL, NULL, APR_HOOK_FIRST);
  //ap_hook_error_log(qos_error_log, NULL, NULL, APR_HOOK_LAST);

  ap_register_input_filter("qos-in-filter", qos_in_filter, NULL, AP_FTYPE_CONNECTION);
  ap_register_input_filter("qos-in-filter2", qos_in_filter2, NULL, AP_FTYPE_RESOURCE);
  ap_register_input_filter("qos-in-filter3", qos_in_filter3, NULL, AP_FTYPE_CONTENT_SET);
  /* AP_FTYPE_RESOURCE+1 ensures the filter are executed after mod_setenvifplus */
  ap_register_output_filter("qos-out-filter", qos_out_filter, NULL, AP_FTYPE_RESOURCE+1);
  ap_register_output_filter("qos-out-filter-min", qos_out_filter_min, NULL, AP_FTYPE_RESOURCE+1);
  ap_register_output_filter("qos-out-filter-delay", qos_out_filter_delay, NULL, AP_FTYPE_RESOURCE+1);
  ap_register_output_filter("qos-out-filter-body", qos_out_filter_body, NULL, AP_FTYPE_RESOURCE+1);
  ap_register_output_filter("qos-out-err-filter", qos_out_err_filter, NULL, AP_FTYPE_RESOURCE+1);
  ap_register_output_filter("qos-out-filter-bandwidth", qos_out_filter_bandwidth, NULL, AP_FTYPE_RESOURCE+1);
  ap_hook_insert_filter(qos_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_insert_error_filter(qos_insert_err_filter, NULL, NULL, APR_HOOK_MIDDLE);

}

/************************************************************************
 * apache module definition 
 ***********************************************************************/
module AP_MODULE_DECLARE_DATA qos_module ={ 
  STANDARD20_MODULE_STUFF,
  qos_dir_config_create,                    /**< dir config creater */
  qos_dir_config_merge,                     /**< dir merger */
  qos_srv_config_create,                    /**< server config */
  qos_srv_config_merge,                     /**< server merger */
  qos_config_cmds,                          /**< command table */
  qos_register_hooks,                       /**< hook registery */
};
