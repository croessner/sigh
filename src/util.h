/*! \file util.h
 *
 * \brief Helper functions
 *
 * \author Christian Rößner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
  * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#include <string>
#include <libmilter/mfapi.h>

#include "client.h"

namespace util {
    /*!
     * \brief Shortcut for const char pointer
     * \param x A string literal
     * \return A pointer to char
     */
    static auto ccp = [](const std::string &str) {
        return const_cast<char *> (str.c_str());
    };

    /*!
     * \brief Data structure for each client connection
     */
    static auto mlfipriv = [](SMFICTX *ctx) {
        return static_cast<mlt::Client *> (smfi_getpriv(ctx));
    };
}  // namespace util
