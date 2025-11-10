#include <utils/logger.hpp>
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace socks5::logger {

namespace {

constexpr std::string_view kDefaultLogFilePath{"./socks5.log"};
constexpr Level kDefaultLogLevel{Level::debug};
constexpr bool kIsLoggingEnabledByDefault{true};

}  // namespace

const std::string LoggerBase::kDefaultLogFormat = "[%Y-%m-%d %T.%e][%t][%l] %v";

LoggerBase::LoggerBase(SpdlogPtr logger) : logger_(logger) {
  SetLogFormat(kDefaultLogFormat);
}

void LoggerBase::SetLogFormat(const std::string& fmt) {
  logger_->set_pattern(fmt);
}

void LoggerBase::Flush() { logger_->flush(); }

void LoggerBase::Log(const char* filename, int line, const char* funcname,
                     Level lvl, const std::string& msg) noexcept {
  try {
    logger_->log(spdlog::source_loc{filename, line, funcname},
                 static_cast<spdlog::level::level_enum>(lvl), msg);
  } catch (...) {
  }
}

void LoggerBase::Log(const char* filename, int line, const char* funcname,
                     Level lvl, const char* msg) noexcept {
  try {
    logger_->log(spdlog::source_loc{filename, line, funcname},
                 static_cast<spdlog::level::level_enum>(lvl), msg);
  } catch (...) {
  }
}

Level LoggerBase::GetLevel() const {
  return static_cast<Level>(logger_->level());
}

void LoggerBase::SetLevel(Level lvl) {
  logger_->set_level(static_cast<spdlog::level::level_enum>(lvl));
}

const std::string Logger::kName = "main";

Logger::Logger(const std::string& log_path, Level lvl)
    : LoggerBase{
          spdlog::basic_logger_mt<spdlog::async_factory>(kName, log_path)} {
  SetLevel(lvl);
}

const std::string StdoutLogger::kName = "stdout";

StdoutLogger::StdoutLogger(Level lvl)
    : LoggerBase{spdlog::stdout_color_mt(kName)} {
  SetLevel(lvl);
}

LoggerBasePtr MakeLogger(const std::string& log_path, Level lvl) {
  return std::make_shared<Logger>(log_path, lvl);
}

LoggerBasePtr MakeStdoutLogger(Level lvl) {
  return std::make_shared<StdoutLogger>(lvl);
}

std::atomic_bool& IsLoggingEnabled() {
  static std::atomic_bool logging_enabled{kIsLoggingEnabledByDefault};
  return logging_enabled;
}

void EnableLogging(bool enable) { IsLoggingEnabled() = enable; }

LoggerCbPtr GetLogger() {
  static LoggerCbAtomicPtr logger_cb{std::make_shared<LoggerCb>(
      [logger = std::make_shared<StdoutLogger>(kDefaultLogLevel)](
          const char* filename, int line, const char* funcname, Level lvl,
          const std::string& msg) {
        logger->Log(filename, line, funcname, lvl, msg);
        logger->Flush();
      })};
  return logger_cb;
}

void SetLogger(LoggerCb logger_cb, Level lvl) {
  SetLevel(lvl);
  GetLogger() = std::make_shared<LoggerCb>(std::move(logger_cb));
}

void SetLogger(LoggerBasePtr logger) {
  SetLevel(logger->GetLevel());
  GetLogger() = std::make_shared<LoggerCb>(
      [logger = logger](const char* filename, int line, const char* funcname,
                        Level lvl, const std::string& msg) {
        logger->Log(filename, line, funcname, lvl, msg);
      });
}

LogLevelAtomic& GetLevel() noexcept {
  static LogLevelAtomic lvl{kDefaultLogLevel};
  return lvl;
}

void SetLevel(Level lvl) noexcept { GetLevel() = lvl; }

}  // namespace socks5::logger