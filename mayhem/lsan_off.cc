// Disable LeakSanitizer for every fuzz and standalone binary (leaks are not the bug class we fuzz for).
extern "C" int __lsan_is_turned_off() { return 1; }
