/*! \file milter.cpp
 *
 * \brief Main file that implements an example milter
 *
 * This file implments all callbacks that are possible for a milter
 * application. They are requistered at the end in one structure called
 * smfiDesc.
 *
 * For the milter API documentation, look here:
 * https://www.mirbsd.org/htman/i386/manDOCS/milter/api.html
 *
 * \author Christian Roessner <c@roessner.co>
 * \version 1606.1.0
 * \date 2016-06-10
 * \copyright Copyright 2016 Christian Roessner <c@roessner.co>
 */

#include "milter.h"

#include <sysexits.h>
#include <pwd.h>    // uid
#include <grp.h>    // gid
#include <syslog.h>

#include <iostream>
#include <string>
#include <fstream>
#include <csignal>
#include <thread>
#include <vector>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include "config.h"
#include "smime.h"
#include "common.h"
#include "mapfile.h"

namespace fs = boost::filesystem;
namespace po = boost::program_options;

//! \brief Turn on/off debugging output
bool debug = false;

//! \brief The internal milter name
static char miltername[] = "sigh";

//! \brief Version number
static const char version[] = "1606.1.0";

//! \brief  Configuration options for the milter
static std::unique_ptr<conf::MilterCfg> config(nullptr);

//! \brief Required headers for the smfi_header()-callback
static std::vector<std::string> header;

/*!
 * \brief Global data structure that maps all callbacks
 */
static struct smfiDesc smfilter = {
        miltername,         // filter name
        SMFI_VERSION,       // version code -- do not change
        0,                  // flags
        mlfi_connect,       // connection info filter
#if defined _CB_HELO
        mlfi_helo,          // SMTP HELO command
#else
        nullptr,
#endif  // defined _CB_HELO
#if defined _CB_ENVFROM
        mlfi_envfrom,       // envelope sender filter
#else
        nullptr,
#endif  // defined _CB_ENVFROM
#if defined ENVRCPT
        mlfi_envrcpt,       // envelope recipient filter
#else
        nullptr,
#endif  // defined _CB_ENVRCPT
#if defined _CB_HEADER
        mlfi_header,        // header filter
#else
        nullptr,
#endif  // defined _CB_HEADER
#if defined _CB_EOH
        mlfi_eoh,           // end of header
#else
        nullptr,
#endif  // defined _CB_EOH
#if defined _CB_BODY
        mlfi_body,          // body block filter
#else
        nullptr,
#endif  // defined _CB_BODY
#if defined _CB_EOM
        mlfi_eom,           // end of message
#else
        nullptr,
#endif  // defined _CB_CB_EOM
#if defined _CB_ABORT
        mlfi_abort,         // message aborted
#else
        nullptr,
#endif  // defined _CB_ABORT
        mlfi_close,         // connection cleanup
#if defined _CB_UNKNOWN
        mlfi_unknown,       // unknown/unimplemented SMTP commands
#else
        nullptr,
#endif  // defnined _CB_UNKNOWN
#if defined _CB_DATA
        mlfi_data,          // DATA command filter
#else
        nullptr,
#endif  // defined _CB_DATA
        mlfi_negotiate      // option negotiation at connection startup
};

/*!
 * \brief xxfi_connect() callback
 */
sfsistat mlfi_connect(SMFICTX *ctx, char *hostname, struct sockaddr *hostaddr) {
    assert(ctx != nullptr);

    mlt::Client *client;

    try {
        client = new mlt::Client {hostname, hostaddr};
    }
    catch (const std::bad_alloc& ba) {
        std::cerr << "Error: bad_alloc caught: " << ba.what() << std::endl;
        return SMFIS_TEMPFAIL;
    }
    catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return SMFIS_TEMPFAIL;
    }

    // Store new client data
    smfi_setpriv(ctx, static_cast<void *>(client));

    if (::debug) {
        std::cout << "id=" << client->id
                  << " connect from hostname="
                  << " socket=" << client->ipAndPort << std::endl;
    }
    syslog(LOG_INFO, "id=%ld connect from hostname=%s socket=%s",
           client->id, client->hostname.c_str(), client->ipAndPort.c_str());

    return SMFIS_CONTINUE;
}

#if defined _CB_HELO
/*!
 * \brief xxfi_helo() callback
 */
sfsistat mlfi_helo(SMFICTX *ctx, char *helohost) {
    return SMFIS_CONTINUE;
}
#endif  // defined _CB_HELO

#if defined _CB_ENVFROM
/*!
 * \brief xxfi_envfrom() callback
 */
sfsistat mlfi_envfrom(SMFICTX *ctx, char **smtp_argv) {
    assert(ctx != nullptr);

    auto *client = util::mlfipriv(ctx);
    if (!client->createContentFile(::config->getValue("tmpdir")))
        return SMFIS_TEMPFAIL;

    // Copy envelope sender address
    char *mailfrom = strdup(smtp_argv[0]);
    if (mailfrom == nullptr) {
        perror("Error: Unable to copy envfrom address");
        return SMFIS_TEMPFAIL;
    }

    client->sessionData["envfrom"] = mailfrom;

    return SMFIS_CONTINUE;
}
#endif  // defined _CB_ENVFROM

#if defined _CB_ENVRCPT
/*!
 * \brief xxfi_envrcpt() callback
 */
sfsistat mlfi_envrcpt(SMFICTX *ctx, char **smtp_argv) {
    return SMFIS_CONTINUE;
}
#endif  // defined _CB_ENVRCPT

# if defined _CB_DATA
/*!
 * \brief xxfi_data() callback
 */
sfsistat mlfi_data(SMFICTX *ctx) {
    return SMFIS_CONTINUE;
}
#endif  // defined _CB_DATA

# if defined _CB_UNKNOWN
/*!
 * \brief xxfi_unknown() callback
 */
sfsistat mlfi_unknown(SMFICTX *ctx, const char *cmd) {
    return SMFIS_CONTINUE;
}
#endif  // defined _CB_UNKNOWN

#if defined _CB_HEADER
/*!
 * \brief xxfi_header() callback
 */
sfsistat mlfi_header(
        SMFICTX *ctx, char *header_key, char *header_value) {
    assert(ctx != nullptr);

    auto *client = util::mlfipriv(ctx);

    for (std::size_t i=0; i<::header.size(); i++) {
        if (strncasecmp(header_key, ::header.at(i).c_str(),
                        ::header.at(i).size()) == 0) {
            client->markedHeaders.push_back(
                    std::make_pair(header_key, header_value));

            // Found MIME-VERSION
            if (strncasecmp(header_key,
                            std::string("MIME-Version").c_str(),
                            12) == 0)
                client->mailflags |= mlt::mailflags::TYPE_MIME;

            // Found multipart message
            if (strncasecmp(header_key,
                            std::string("Content-Type").c_str(),
                            12) == 0)
                if (strstr(header_value, "multipart/") != nullptr)
                    client->mailflags |= mlt::mailflags::TYPE_MULTIPART;

            // Found out own header
            if (strncasecmp(header_key,
                            mlt_header_name,
                            sizeof(mlt_header_name)) == 0) {
                continue;
            }

            if (fprintf(client->fcontent,
                        "%s: %s\r\n",
                        header_key,
                        header_value) < 0) {
                std::cerr << "Error: Unable to write header" << std::endl;
                return SMFIS_TEMPFAIL;
            }

            break;
        }
    }

    return SMFIS_CONTINUE;
}
#endif  // defined _CB_HEADER

#if defined _CB_EOH
/*!
 * \brief xxfi_eoh() callback
 */
sfsistat mlfi_eoh(SMFICTX *ctx) {
    assert(ctx != nullptr);

    auto *client = util::mlfipriv(ctx);

    /*
     * Content-Type set without MIME-Version violates RFC2045
     */
    if (client->mailflags & mlt::mailflags::TYPE_MULTIPART
            && (client->mailflags & mlt::mailflags::TYPE_MIME) == 0) {
        char reply[] = "RFC2045 violation";
        char status[] = "554";  // Transaction failed
        char code[] = "5.6.0";  // Invalid mail format
        smfi_setreply(ctx, status, code, reply);
        return SMFIS_REJECT;
    }

    if (fprintf(client->fcontent, "\r\n") <= 0) {
        std::cerr << "Error: Unable to write end of header" << std::endl;
        return SMFIS_TEMPFAIL;
    }

    return SMFIS_CONTINUE;
}
#endif  // defined _CB_EOH

#if defined _CB_BODY
/*!
 * \brief xxfi_body() callback
 */
sfsistat mlfi_body(SMFICTX *ctx, unsigned char *bodyp, size_t body_len) {
    assert(ctx != nullptr);

    if (body_len == 0)
        return SMFIS_CONTINUE;

    auto *client = util::mlfipriv(ctx);

    if (client->optionalPreamble
        && client->mailflags & mlt::mailflags::TYPE_MULTIPART) {
        unsigned char *bodyit = bodyp;
        size_t remaining = body_len;

        /*
         * Remove preamble, RFC2046, 5.1.1
         */
        while (strncmp(
                (const char *) bodyit, std::string("--").c_str(), 2) != 0) {
            if (remaining > 0) {
                bodyit++;
                remaining--;
            }
        }
        bodyp = bodyit;
        body_len = remaining;

        client->optionalPreamble = false;
    }

    if (fwrite(bodyp, body_len, 1, client->fcontent) <= 0) {
        std::cerr << "Error: Unable to write body" << std::endl;
        return SMFIS_TEMPFAIL;
    }

    return SMFIS_CONTINUE;
}
#endif  // defined _CB_BODY

#if defined _CB_EOM
/*!
 * \brief xxfi_eom() callback
 */
sfsistat mlfi_eom(SMFICTX *ctx) {
    assert(ctx != nullptr);

    std::string mapfile = ::config->getValue("mapfile");
    if (mapfile.empty()) {
        std::cerr << "Error: No map file defined" << std::endl;
        return SMFIS_TEMPFAIL;
    }

    auto *client = util::mlfipriv(ctx);

    if (client->getFcontentStatus()) {
        if (fseek(client->fcontent, 0L, SEEK_SET) == -1) {
            perror("Error: Unwilling to rewind temp file");
            return SMFIS_TEMPFAIL;
        }
    } else {
        std::cerr << "Error: Temp file is not open" << std::endl;
        return SMFIS_TEMPFAIL;
    }

    smime::Smime smimeMsg {ctx};

    smimeMsg.sign();
    if (!smimeMsg.isSmimeSigned()) {
        if (::debug)
            std::cout << "Email was not signed" << std::endl;

        return SMFIS_CONTINUE;
    } else {
        std::string logmsg = "Signed mail for email address "
                             + std::string(client->sessionData["envfrom"]);
        if (::debug)
            std::cout << logmsg << std::endl;
        syslog(LOG_INFO, "%s", logmsg.c_str());
    }

    if (client->genericError)
        return SMFIS_TEMPFAIL;

    smfi_addheader(
            ctx, util::ccp(mlt_header_name), util::ccp(
                    "S/MIME sigh milter - version " + std::string(::version)));

    /*
     * Clear data structures
     */
    client->reset();

    return SMFIS_CONTINUE;
}
#endif  // defined _CB_EOM

#if defined _CB_ABORT
/*!
 * \brief xxfi_abort() callback
 */
sfsistat mlfi_abort(SMFICTX *ctx) {
    return SMFIS_ACCEPT;
}
#endif  // defined _CB_ABORT

/*!
 * \brief xxfi_close() callback
 */
sfsistat mlfi_close(SMFICTX *ctx) {
    assert(ctx != nullptr);

    auto *client = util::mlfipriv(ctx);

    if (::debug) {
        std::cout << "id=" << client->id
                  << " disconnect from hostname="
                  << " socket=" << client->ipAndPort << std::endl;
    }
    syslog(LOG_INFO, "id=%ld disconnect from hostname=%s socket=%s",
           client->id, client->hostname.c_str(), client->ipAndPort.c_str());

    delete client;
    smfi_setpriv(ctx, nullptr);

    return SMFIS_ACCEPT;
}

/*!
 * \brief xxfi_negotiate() callback
 *
 * Negotiate milter and MTA capabilities
 */
sfsistat mlfi_negotiate(
        SMFICTX *ctx,
        u_long f0, u_long f1, u_long f2, u_long f3,
        u_long *pf0, u_long *pf1, u_long *pf2, u_long *pf3) {
    assert(ctx != nullptr);

    if ((f0 & SMFIF_ADDHDRS) != 0)
        *pf0 |= SMFIF_ADDHDRS;
    else
        return SMFIS_REJECT;
    if ((f0 & SMFIF_CHGHDRS) != 0)
        *pf0 |= SMFIF_CHGHDRS;
    else
        return SMFIS_REJECT;
    if ((f0 & SMFIF_CHGBODY) != 0)
        *pf0 |= SMFIF_CHGBODY;
    else
        return SMFIS_REJECT;

    *pf2 = 0;
    *pf3 = 0;

    return SMFIS_CONTINUE;
}

/*!
 * \brief Define the milter socket and register the global data structure
 */
static void initMilter(const std::string &con) {
    if (smfi_setconn(const_cast<char *> (con.c_str())) == MI_FAILURE) {
        std::cerr << "Error: smfi_setconn() failed" << std::endl;
        exit(EX_UNAVAILABLE);
    }

    if (smfi_register(smfilter) == MI_FAILURE) {
        std::cerr << "Error: smfi_register() failed" << std::endl;
        exit(EX_UNAVAILABLE);
    }
}

/*!
 * \brief Signal handling
 */
static void signalHandler(int sig) {
    switch (sig) {
        case SIGINT:
        case SIGTERM:
        case SIGQUIT:
            std::cout << "Caught signal " << sig
                      << ". Terminating" << std::endl;
            if (::debug) {
                std::cout << "Calling smfi_stop()...";
                std::cout.flush();
            }
            smfi_stop();
            if (::debug) {
                std::cout << "done" << std::endl;
                std::cout.flush();
            }
            break;
        case SIGSEGV:
            std::cerr << "Error: Segmentation fault occurred. Aborting now"
                      << std::endl;
            exit(EX_SOFTWARE);
        case SIGHUP:
            std::cout << "Caught signal " << sig
                      << ". Reloading mapfile" << std::endl;
            mapfile::Map::readMap(::config->getValue("mapfile"));
            syslog(LOG_NOTICE, "%s", std::string("Mapfile reloaded").c_str());
            break;
        default:
        { /* empty */ }
    }
}

int main(int argc, const char *argv[]) {
    std::string mfsocket;   // Milter socket. Defaults to inet:4000@127.0.0.1
    std::string mfuser;     // Run milter as a different user
    std::string mfgroup;    // Run milter with a different group
    std::string mfcfgfile;  // Configuration file for the milter
    std::string mfpidfile;  // PID file of the milter
#if !__APPLE__ && !defined _NOT_DAEMONIZE
    bool mfdaemon = false;  // Run the daemon in background
#endif  // !__APPLE__ && !defined _NOT_DAEMONIZE

    uid_t uid;
    gid_t gid;
    struct passwd *pwd;
    struct group *grp;

    if (signal(SIGINT, signalHandler) == SIG_ERR)
        perror("Error: Installing SIGINT failed");
    if (signal(SIGTERM, signalHandler) == SIG_ERR)
        perror("Error: Installing SIGTERM failed");
    if (signal(SIGSEGV, signalHandler) == SIG_ERR)
        perror("Error: Installing SIGSEGV failed");
    if (signal(SIGQUIT, signalHandler) == SIG_ERR)
        perror("Error: Installing SIGQUIT failed");
    if (signal(SIGHUP, signalHandler) == SIG_ERR)
        perror("Error: Installing SIGHUP failed");

    if (signal(SIGABRT, SIG_IGN) == SIG_ERR)
        perror("Error: Installing SIGABRT failed");

    // Parse command line arguments
    po::options_description desc("The following options are available");
    // Return a proxy object that overloads "operator()"
    desc.add_options()
            ("help,h", "produce help message")
            ("socket,s", po::value<std::string>(&mfsocket),
             "milter socket")
            ("user,u", po::value<std::string>(&mfuser),
             "Drop privileges to this user")
            ("group,g", po::value<std::string>(&mfgroup),
             "Drop privileges to this group")
            ("config,c", po::value<std::string>(&mfcfgfile)->default_value
                    ("/etc/sigh.cfg"), "Configuration file for this milter")
            ("debug", po::bool_switch()->default_value(false),
             "Turn on debugging output")
            ("pidfile,p", po::value<std::string>(&mfpidfile),
             "PID file for the milter")
#if !__APPLE__ && !defined _NOT_DAEMONIZE
            // daemon() is deprecated on OS X 10.5 and newer
            ("daemon,d", po::bool_switch()->default_value(false),
             "run daemon in background")
#endif  // !__APPLE__ && !defined _NOT_DAEMONIZE
    ;

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
    }
    catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        std::cout << desc << std::endl;
        exit(EX_USAGE);
    }
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        exit(EX_USAGE);
    }

    // Turn on debugging output
    if (vm["debug"].as<bool>())
       ::debug = true;

    // Read configuration file
    ::config = std::make_unique<conf::MilterCfg>(vm);

    if (vm.count("socket") == 0)
        mfsocket = ::config->getValue("socket");
    if (vm.count("user") == 0)
        mfuser = ::config->getValue("user");
    if (vm.count("group") == 0)
        mfgroup = ::config->getValue("group");
    if (vm.count("pidfile") == 0)
        mfpidfile = ::config->getValue("pidfile");
#if !__APPLE__ && !defined _NOT_DAEMONIZE
    if (!vm["daemon"].as<bool>())
        mfdaemon = ::config->getValue<bool>("daemon");
    else
        mfdaemon = true;
#endif  // !__APPLE__ && !defined _NOT_DAEMONIZE

    mapfile::Map::readMap(::config->getValue("mapfile"));

    grp = getgrnam(mfgroup.c_str());
    if (grp) {
        gid = grp->gr_gid;
        if (getuid() == 0) {
            if (initgroups(mfuser.c_str(), gid) != 0) {
                perror("Error: Unable to initialize group access list");
                exit(EX_OSERR);
            }
            if (::debug)
                std::cout << "Initialized group access list" << std::endl;
        } else {
            std::cerr << "Only the root user can initialize the group access "
                                 "list" << std::endl;
        }
        if (setgid(gid) != 0) {
            perror("Error: Unable to switch group");
            exit(EX_OSERR);
        }
        if (::debug)
            std::cout << "Switched to group " << mfgroup << std::endl;
    } else {
        std::cerr << "Error: Unknown group " << mfgroup << std::endl;
        exit(EX_NOUSER);
    }
    pwd = getpwnam(mfuser.c_str());
    if (pwd) {
        uid = pwd->pw_uid;
        if (setuid(uid) != 0) {
            perror("Error: Unable to switch user");
            exit(EX_OSERR);
        }
        if (::debug)
            std::cout << "Switched to user " << mfuser << std::endl;
    } else {
        std::cerr << "Error: Unknown user " << mfuser << std::endl;
        exit(EX_NOUSER);
    }

    initMilter(mfsocket);

#if !__APPLE__ && !defined _NOT_DAEMONIZE
    // daemon() is deprecated on OS X 10.5 and newer
    if (mfdaemon) {
        if (daemon(0, 0) != 0) {
            perror("Error: Could not daemonize!");
            exit(EX_OSERR);
        }
    }
#endif  // !__APPLE__ && !defined _NOT_DAEMONIZE

    if (!mfpidfile.empty()) {
        std::ofstream out {mfpidfile};
        if (out.is_open()) {
            out << getpid();
            if (::debug)
                std::cout << "PID file created" << std::endl;
        } else
            std::cerr << "Error: Unable to create PID file" << std::endl;
        out.close();
    }

    // Define headers
    ::header.push_back(mlt_header_name);
    ::header.push_back("MIME-Version");
    ::header.push_back("Content-ID");
    ::header.push_back("Content-Type");
    ::header.push_back("Content-Disposition");
    ::header.push_back("Content-Description");
    ::header.push_back("Content-Transfer-Encoding");

    // Workaround for stolen signals
    std::thread milter {[]() {
        try {
            smfi_main();
        }
        catch (...) { /* empty */ }
    }};

    openlog(miltername, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_MAIL);

    std::string logmsg = "Starting milter "
                         + std::string(miltername)
                         + " - version "
                         + std::string(version);
    syslog(LOG_NOTICE, "%s", logmsg.c_str());

    // Wait for signals
    milter.join();

    if (!mfpidfile.empty()) {
        try {
            if (fs::exists(fs::path(mfpidfile))
                && fs::is_regular(fs::path(mfpidfile))) {
                fs::remove(mfpidfile);
                if (::debug)
                    std::cout << "PID file removed" << std::endl;
            }
        }
        catch (const std::exception &e) {
            std::cerr << "Error: " << e.what()  << std::endl;
            exit(EX_OSERR);
        }
    }

    logmsg = "Milter stopped";
    syslog(LOG_NOTICE, "%s", logmsg.c_str());

    closelog();

    return EX_OK;
}
