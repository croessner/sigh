/*! \file milter.h
 *
 * \brief Some helper macros and function declarations for the main application
 *
 * \author Christian Rößner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
  * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#ifndef SRC_MILTER_H_
#define SRC_MILTER_H_

#include <libmilter/mfapi.h>

#include <string>

// Callbacks
sfsistat mlfi_connect(SMFICTX *ctx, char *, struct sockaddr *);

#if defined _CB_HELO
sfsistat mlfi_helo(SMFICTX *, char *);
#endif  // defined _CB_HELO

#if defined _CB_ENVFROM
sfsistat mlfi_envfrom(SMFICTX *, char **);
#endif  // defined _CB_ENVFROM

#if defined _CB_ENVRCPT
sfsistat mlfi_envrcpt(SMFICTX *, char **);
#endif  // defined _CB_ENVFROM

#if defined _CB_DATA
sfsistat mlfi_data(SMFICTX *);
#endif  // defined _CB_DATA

#if defined _CB_UNKNOWN
sfsistat mlfi_unknown(SMFICTX *, const char *);
#endif  // defined _CB_UNKNOWN

#if defined _CB_HEADER
sfsistat mlfi_header(SMFICTX *, char *, char *);
#endif  // defined _CB_HEADER

#if defined _CB_EOH
sfsistat mlfi_eoh(SMFICTX *);
#endif  // defined _CB_EOH

#if defined _CB_BODY
sfsistat mlfi_body(SMFICTX *, u_char *, size_t);
#endif  // defined _CB_BODY

#if defined _CB_EOM
sfsistat mlfi_eom(SMFICTX *);
#endif  // defined _CB_EOM

#if defined _CB_ABORT
sfsistat mlfi_abort(SMFICTX *);
#endif  // defined _CB_ABORT

sfsistat mlfi_close(SMFICTX *);

sfsistat mlfi_negotiate(
        SMFICTX *,
        u_long, u_long, u_long, u_long,
        u_long *, u_long  *, u_long *, u_long *);

// Other functions
static void initMilter(const std::string&);
static void signalHandler(int);

#endif  // SRC_MILTER_H_
