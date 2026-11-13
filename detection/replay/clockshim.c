/*
 * clockshim - LD_PRELOAD library for the noise replay (test-only, never in the lab).
 *
 * Adds an offset (seconds, may be fractional/negative) read from CLOCKSHIM_FILE
 * (default /var/ossec/tmp/clockshim.offset) to time(), gettimeofday() and
 * clock_gettime() for the realtime AND monotonic clocks, so the replay driver can move
 * the clock of wazuh-analysisd before each event. analysisd measures correlation
 * windows (frequency/timeframe/ignore) on a monotonic clock and <time> on the wall
 * clock, so both must move. The offset only grows during a replay (events are in time
 * order and the replayed day is in the future), so the monotonic clock stays monotonic.
 *
 * analysisd compares correlation windows with a CACHED time(NULL), refreshed by a thread
 * that loops on sleep(1). In a fast replay that cache would lag by up to one real second
 * (= many simulated minutes), so in analysisd sleep(n) lasts n MILLISECONDS: the cache
 * follows the shifted clock within ~1 ms and the driver waits a few ms per event.
 *
 * Everything above applies only in the process named wazuh-analysisd; the other Wazuh
 * daemons, which inherit LD_PRELOAD from the container, keep the real clock.
 *
 * Wazuh daemons chroot into /var/ossec after start-up: the file is opened by its full
 * path on the first clock call (before the chroot) and the descriptor is kept; the
 * chroot-relative path is a fallback. The image ships the file, so it always exists.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static double offset_s;
static int active = -1; /* 1 in wazuh-analysisd, 0 elsewhere, -1 not checked yet */
static int offset_fd = -1;

static int (*real_clock_gettime)(clockid_t, struct timespec *);

/* Read on every call (mtime is too coarse: events arrive faster than its resolution).
 * The descriptor stays open; the driver overwrites a fixed-width record in place with
 * one pwrite (no truncation), so a read never sees half a number. */
static void refresh_offset(void) {
    char buf[64];
    if (offset_fd < 0) {
        const char *path = getenv("CLOCKSHIM_FILE");
        offset_fd = open(path ? path : "/var/ossec/tmp/clockshim.offset", O_RDONLY | O_CLOEXEC);
        if (offset_fd < 0) offset_fd = open("/tmp/clockshim.offset", O_RDONLY | O_CLOEXEC);
        if (offset_fd < 0) return;
    }
    ssize_t n = pread(offset_fd, buf, sizeof buf - 1, 0);
    if (n > 0) {
        buf[n] = '\0';
        char *end;
        double value = strtod(buf, &end);
        if (end != buf) offset_s = value;
    }
}

static void real_now(struct timespec *ts) {
    if (!real_clock_gettime) real_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");
    real_clock_gettime(CLOCK_REALTIME, ts);
}

static int is_active(void) {
    if (active < 0) active = strcmp(program_invocation_short_name, "wazuh-analysisd") == 0;
    return active;
}

static void shifted(struct timespec *ts) {
    if (!is_active()) return;
    refresh_offset();
    long long ns = (long long)ts->tv_sec * 1000000000LL + ts->tv_nsec + (long long)(offset_s * 1e9);
    ts->tv_sec = ns / 1000000000LL;
    ts->tv_nsec = ns % 1000000000LL;
    if (ts->tv_nsec < 0) { ts->tv_nsec += 1000000000LL; ts->tv_sec -= 1; }
}

int clock_gettime(clockid_t clk, struct timespec *ts) {
    if (!real_clock_gettime) real_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");
    int rc = real_clock_gettime(clk, ts);
    if (rc == 0 && (clk == CLOCK_REALTIME || clk == CLOCK_REALTIME_COARSE || clk == CLOCK_MONOTONIC
                    || clk == CLOCK_MONOTONIC_COARSE || clk == CLOCK_MONOTONIC_RAW || clk == CLOCK_BOOTTIME))
        shifted(ts);
    return rc;
}

time_t time(time_t *out) {
    struct timespec ts;
    real_now(&ts);
    shifted(&ts);
    if (out) *out = ts.tv_sec;
    return ts.tv_sec;
}

int gettimeofday(struct timeval *tv, void *tz) {
    (void)tz;
    struct timespec ts;
    real_now(&ts);
    shifted(&ts);
    if (tv) { tv->tv_sec = ts.tv_sec; tv->tv_usec = ts.tv_nsec / 1000; }
    return 0;
}

unsigned int sleep(unsigned int seconds) {
    struct timespec req;
    if (is_active()) {
        req.tv_sec = seconds / 1000;
        req.tv_nsec = (long)(seconds % 1000) * 1000000L;
    } else {
        req.tv_sec = seconds;
        req.tv_nsec = 0;
    }
    while (nanosleep(&req, &req) != 0 && errno == EINTR) {}
    return 0;
}
