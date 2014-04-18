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

#ifndef __MOD_QOS_H__
#define __MOD_QOS_H__

/**************************************************************************
 * Hooks 
 **************************************************************************/
#if !defined(WIN32)
#define QOS_DECLARE(type)            type
#define QOS_DECLARE_NONSTD(type)     type
#define QOS_DECLARE_DATA
#elif defined(QOS_DECLARE_STATIC)
#define QOS_DECLARE(type)            type __stdcall
#define QOS_DECLARE_NONSTD(type)     type
#define QOS_DECLARE_DATA
#elif defined(QOS_DECLARE_EXPORT)
#define QOS_DECLARE(type)            __declspec(dllexport) type __stdcall
#define QOS_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define QOS_DECLARE_DATA             __declspec(dllexport)
#else
#define QOS_DECLARE(type)            __declspec(dllimport) type __stdcall
#define QOS_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define QOS_DECLARE_DATA             __declspec(dllimport)
#endif

#define QOS_OPTIONAL_HOOK(name,fn,pre,succ,order) \
        APR_OPTIONAL_HOOK(qos,name,fn,pre,succ,order)

/**
 * mod_qos.h header file defining hooks for path/query
 * decoding (used by QS_Deny* and QS_Permit* rules).
 *
 * Define QS_MOD_EXT_HOOKS in order to enable these hooks
 * within mod_qos.c.
 */

/* hook to decode/unescape the path portion of the request uri */
APR_DECLARE_EXTERNAL_HOOK(qos, QOS, apr_status_t, path_decode_hook,
                          (request_rec *r, char **path, int *len))
/* hook to decode/unescape the query portion of the request uri */
APR_DECLARE_EXTERNAL_HOOK(qos, QOS, apr_status_t, query_decode_hook,
                          (request_rec *r, char **query, int *len))

#endif /* __MOD_QOS_H__ */
