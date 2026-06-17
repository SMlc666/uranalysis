__attribute__((used))
static const char ura_message[] = "ura-corpus-hello";

__attribute__((noinline))
int ura_mix(int value) {
    if (value == 7) {
        return value + ura_message[0];
    }
    return value - 3;
}

#if defined(_WIN32)
void mainCRTStartup(void) {
    volatile int sink = ura_mix(7);
    (void)sink;
}
#else
void _start(void) {
    volatile int sink = ura_mix(7);
    (void)sink;
}
#endif
