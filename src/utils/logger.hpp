#pragma once

#include <optional>
#include <string>
#include <fmt/core.h>
#include <socks5/utils/non_copyable.hpp>
#include <spdlog/spdlog.h>

namespace socks5::logger {

using SpdlogPtr = std::shared_ptr<spdlog::logger>;
using LoggerBasePtr = std::shared_ptr<class LoggerBase>;

enum Level : int {
  trace = spdlog::level::level_enum::trace,
  debug = spdlog::level::level_enum::debug,
  info = spdlog::level::level_enum::info,
  warn = spdlog::level::level_enum::warn,
  error = spdlog::level::level_enum::err,
  critical = spdlog::level::level_enum::critical,
  off = spdlog::level::level_enum::off,
};

using LoggerCb =
    std::function<void(const char* filename, int line, const char* funcname,
                       Level, const std::string& msg)>;
using LoggerCbPtr = std::shared_ptr<LoggerCb>;
using LoggerCbAtomicPtr = std::atomic<std::shared_ptr<LoggerCb>>;

using LogLevelAtomic = std::atomic<Level>;
using LogLevelOpt = std::optional<Level>;

void EnableLogging(bool enable);
std::atomic_bool& IsLoggingEnabled();

LoggerCbPtr GetLogger();
void SetLogger(LoggerCb logger_cb, Level lvl);
void SetLogger(LoggerBasePtr logger);

LogLevelAtomic& GetLevel() noexcept;
void SetLevel(Level lvl) noexcept;

class LoggerBase : utils::NonCopyable {
 public:
  static const std::string kDefaultLogFormat;

  explicit LoggerBase(SpdlogPtr logger);

  Level GetLevel() const;
  void SetLevel(Level lvl);
  void SetLogFormat(const std::string& fmt);
  void Flush();
  void Log(const char* filename, int line, const char* funcname, Level lvl,
           const std::string& msg) noexcept;
  void Log(const char* filename, int line, const char* funcname, Level lvl,
           const char* msg) noexcept;

 private:
  const SpdlogPtr logger_;
};

class Logger final : public LoggerBase {
 public:
  static const std::string kName;
  Logger(const std::string& log_path, Level lvl);
};

LoggerBasePtr MakeLogger(const std::string& log_path, Level lvl);
LoggerBasePtr MakeStdoutLogger(Level lvl);

class StdoutLogger final : public LoggerBase {
 public:
  static const std::string kName;
  explicit StdoutLogger(Level lvl);
};

namespace detail {

template <typename T>
T Fmt(const T& msg) {
  return msg;
}

template <typename... Args>
std::string Fmt(fmt::format_string<Args...> fmt, Args&&... args) {
  return fmt::format(fmt, std::forward<Args>(args)...);
}

}  // namespace detail

#define SOCKS5_LOG_LEVEL(LEVEL) socks5::logger::Level::LEVEL

#define SOCKS5_CHECK_LOG_LEVEL(LEVEL) \
  (SOCKS5_LOG_LEVEL(LEVEL) >= socks5::logger::GetLevel().load())

#define SOCKS5_CHECK_LOGGING_ENABLED() socks5::logger::IsLoggingEnabled().load()

#define SOCKS5_CHECK_NEED_TO_LOG(LEVEL) \
  SOCKS5_CHECK_LOGGING_ENABLED() && SOCKS5_CHECK_LOG_LEVEL(LEVEL)

#define SOCKS5_LOG_TO_LOGGER(LOGGER, LEVEL, ...)                         \
  do {                                                                   \
    try {                                                                \
      if (SOCKS5_CHECK_NEED_TO_LOG(LEVEL)) {                             \
        (*LOGGER)(__FILE__, __LINE__, __func__, SOCKS5_LOG_LEVEL(LEVEL), \
                  socks5::logger::detail::Fmt(__VA_ARGS__));             \
      }                                                                  \
    } catch (const std::exception& ex) {                                 \
      (*LOGGER)(__FILE__, __LINE__, __func__, SOCKS5_LOG_LEVEL(LEVEL),   \
                ex.what());                                              \
    }                                                                    \
  } while (0)

#define SOCKS5_GET_LOGGER() socks5::logger::GetLogger()
#define SOCKS5_LOG(LEVEL, ...) \
  SOCKS5_LOG_TO_LOGGER(SOCKS5_GET_LOGGER(), LEVEL, ##__VA_ARGS__)

}  // namespace socks5::logger