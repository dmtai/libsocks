#if defined(SOCKS5_SHARED_LIB)
#if defined(_WIN32)
#ifdef SOCKS5_EXPORTS
#define SOCKS5_API __declspec(dllexport)
#else
#define SOCKS5_API __declspec(dllimport)
#endif
#else
#define SOCKS5_API __attribute__((visibility("default")))
#endif
#else
#define SOCKS5_API
#endif