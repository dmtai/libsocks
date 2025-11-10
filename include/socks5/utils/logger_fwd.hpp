#pragma once

#include <string>
#include <memory>
#include <functional>
#include <atomic>
#include <socks5/utils/api_macro.hpp>

namespace socks5::logger {

enum SOCKS5_API Level : int {
  trace = 0,
  debug,
  info,
  warn,
  error,
  critical,
  off,
};

using LogLevelAtomic = std::atomic<Level>;
using LoggerBasePtr = std::shared_ptr<class LoggerBase>;
using LoggerCb =
    std::function<void(const char* filename, int line, const char* funcname,
                       Level, const std::string& msg)>;

/**
 * @brief Set a callback that will be called for logging.
 *
 * @param logger_cb callback that will be called for logging.
 * @param lvl current log level.
 * @throws std::exception
 */
SOCKS5_API void SetLogger(LoggerCb logger_cb, Level lvl);

/**
 * @brief Set a pointer to LoggerBasePtr.
 *
 * @throws std::exception
 */
SOCKS5_API void SetLogger(LoggerBasePtr logger);

/**
 * @brief Create a logger that outputs the result to file.
 *
 * @param log_path path to log file.
 * @param lvl current log level.
 * @return LoggerBasePtr
 * @throws std::exception
 */
SOCKS5_API LoggerBasePtr MakeLogger(const std::string& log_path, Level lvl);

/**
 * @brief Create a logger that outputs the result to stdout.
 *
 * @param lvl current log level.
 * @return LoggerBasePtr
 * @throws std::exception
 */
SOCKS5_API LoggerBasePtr MakeStdoutLogger(Level lvl);

/**
 * @brief Get current log level.
 *
 * @return LogLevelAtomic&
 */
SOCKS5_API LogLevelAtomic& GetLevel() noexcept;

/**
 * @brief Set current log level.
 *
 * @param lvl new log level.
 */
SOCKS5_API void SetLevel(Level lvl) noexcept;

/**
 * @brief Enable logging. Stdout logger enabled by default. Default log level -
 * debug.
 *
 * @param enable enable/disable logging.
 */
SOCKS5_API void EnableLogging(bool enable);

/**
 * @brief Check if logging is enabled.
 *
 * @return std::atomic_bool& true if logging is enabled, false otherwise.
 */
SOCKS5_API std::atomic_bool& IsLoggingEnabled();

}  // namespace socks5::logger