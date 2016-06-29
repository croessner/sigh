/*! \file util.h
 *
 * \brief Helper functions
 *
 * \author Christian Rößner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
  * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#ifndef SRC_UTIL_H_
#define SRC_UTIL_H_

#include <string>
#include <libmilter/mfapi.h>

#include "client.h"

//! \brief Header field name for this milter
const char mlt_header_name[] = "X-Sigh";

//! \brief RFC2822, 2.1.1 Maximum header length per line
const u_int32_t max_header_length = 998 + 2;  // Data, CR+LF

namespace util {
    /*!
     * \brief Shortcut for const char pointer
     * \param x A string literal
     * \return A pointer to char
     */
    auto ccp = [](const std::string &str) {
        return const_cast<char *> (str.c_str());
    };

    /*!
     * \brief Data structure for each client connection
     */
    auto mlfipriv = [](SMFICTX *ctx) {
        return static_cast<mlt::Client *> (smfi_getpriv(ctx));
    };
}  // namespace util

#endif  // SRC_UTIL_H_